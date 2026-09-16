// Package audit is an append-only log whose history cannot be quietly edited.
//
// Each entry carries the hash of the entry before it, so changing anything in
// the middle breaks every hash after it. Links alone cannot see the tail being
// cut off, because every remaining link is still intact, so the log also keeps
// a Head: the entry count and the hash of the last entry. Verifying against a
// head detects truncation.
//
// That is not the same as tamper-proof, and the README says so. A head kept
// next to the entries can be rewritten along with them; it only protects the
// log when it is stored somewhere the person editing the log cannot reach.
// Without that anchor, someone who can rewrite the whole file can rewrite the
// whole chain. What it does mean is that partial editing, which is what
// actually happens when someone is covering something up, is detectable.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Entry is one recorded decision.
type Entry struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Principal string    `json:"principal"`
	Actor     string    `json:"actor"`
	Tool      string    `json:"tool"`
	Args      string    `json:"args"`
	Decision  string    `json:"decision"`
	Rule      string    `json:"rule"`
	Outcome   string    `json:"outcome"`
	Model     string    `json:"model,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// Head commits to a whole log: how many entries it holds and the hash of the
// last one. Publishing or storing it elsewhere is what makes deleting recent
// entries detectable.
type Head struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash"`
}

// Sink writes an entry to durable storage. It is called in sequence order,
// under the log's lock, before the entry joins the chain.
type Sink func(Entry) error

// genesis is the PrevHash of the first entry and the Hash of an empty log.
var genesis = strings.Repeat("0", 64)

// Log is a hash-chained sequence of entries. Safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	entries []Entry
	head    Head
	sink    Sink
	now     func() time.Time
	// redact holds field names whose values are replaced before writing.
	redact map[string]bool
}

// New returns an empty Log.
//
// The default redaction list covers the field names that carry secrets in
// almost every codebase. A log that records an audit trail and a password in
// the same line has made things worse, not better.
func New() *Log {
	return &Log{
		head: Head{Hash: genesis},
		now:  time.Now,
		redact: map[string]bool{
			"password": true, "token": true, "secret": true,
			"api_key": true, "apikey": true, "authorization": true,
			"card_number": true, "cvv": true, "private_key": true,
		},
	}
}

// SetClock replaces the time source for tests.
func (l *Log) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = f
}

// SetSink sets where entries are written before they join the chain.
//
// Without a sink the log lives only in memory, and Record cannot fail.
func (l *Log) SetSink(s Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = s
}

// Redact adds a field name to the redaction set.
func (l *Log) Redact(field string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.redact[strings.ToLower(field)] = true
}

// Record appends an entry and returns it as written.
//
// An entry joins the chain only once the sink has accepted it. A failed write
// leaves the log exactly as it was, so the chain never holds an entry that
// storage does not, and the same record can be tried again.
func (l *Log) Record(e Entry, args map[string]any) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Seq = l.head.Count + 1
	e.Time = l.now().UTC()
	e.Args = l.renderArgs(args)
	e.PrevHash = l.head.Hash
	e.Hash = hashEntry(e)
	if l.sink != nil {
		if err := l.sink(e); err != nil {
			return Entry{}, fmt.Errorf("audit: writing entry %d: %w", e.Seq, err)
		}
	}

	l.entries = append(l.entries, e)
	l.head = Head{Count: e.Seq, Hash: e.Hash}
	return e, nil
}

// Entries returns a copy of the log.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// Head returns the log's current commitment to its length and last entry.
func (l *Log) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// Len reports how many entries are held.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Verify walks the chain and checks it against the log's head.
//
// It returns the sequence number rather than just an error because "the log
// is broken" is far less useful during an incident than "the log is broken
// from entry 41 onward".
func (l *Log) Verify() (badSeq uint64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return VerifyChain(l.entries, l.head)
}

// VerifyChain checks entries read back from storage against a head kept
// somewhere else, and reports the first entry that does not hold.
//
// Edits, reordering and deletions in the middle break a link. Deleting the
// most recent entries breaks no link at all, which is why the head is
// required: the walk has to end at exactly the entry the head names. When
// entries are missing from the end, the first missing sequence number is
// reported.
func VerifyChain(entries []Entry, head Head) (badSeq uint64, err error) {
	prev := genesis
	for _, e := range entries {
		if e.PrevHash != prev {
			return e.Seq, fmt.Errorf("audit: entry %d does not follow entry %d", e.Seq, e.Seq-1)
		}
		if got := hashEntry(e); got != e.Hash {
			return e.Seq, fmt.Errorf("audit: entry %d has been modified", e.Seq)
		}
		prev = e.Hash
	}

	n := uint64(len(entries))
	switch {
	case n < head.Count:
		return n + 1, fmt.Errorf("audit: log ends at entry %d but the head commits to %d entries", n, head.Count)
	case n > head.Count:
		return head.Count + 1, fmt.Errorf("audit: log has %d entries but the head commits to %d", n, head.Count)
	case prev != head.Hash:
		return n, fmt.Errorf("audit: last entry %d does not match the head", n)
	}
	return 0, nil
}

func (l *Log) renderArgs(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	safe := make(map[string]any, len(args))
	for k, v := range args {
		if l.redact[strings.ToLower(k)] {
			safe[k] = "[redacted]"
			continue
		}
		safe[k] = v
	}
	b, err := json.Marshal(safe)
	if err != nil {
		keys := make([]string, 0, len(safe))
		for k := range safe {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return "[unencodable: " + strings.Join(keys, ",") + "]"
	}
	return string(b)
}

// hashEntry hashes every field except Hash itself.
func hashEntry(e Entry) string {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		// Entry contains only encodable types, so this cannot happen with a
		// value that came from Record. Panicking beats returning a hash that
		// silently fails to cover part of the entry.
		panic("audit: entry is not encodable: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
