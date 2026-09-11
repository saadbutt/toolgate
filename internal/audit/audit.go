// Package audit is an append-only log whose history cannot be quietly edited.
//
// Each entry carries the hash of the entry before it, so changing anything in
// the middle breaks every hash after it. That is not the same as tamper-proof,
// and the README says so: without an external anchor, someone who can rewrite
// the whole file can rewrite the whole chain. It does mean that partial
// editing, which is what actually happens when someone is covering something
// up, is detectable.
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

// Log is a hash-chained sequence of entries. Safe for concurrent use.
type Log struct {
	mu      sync.Mutex
	entries []Entry
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
		now: time.Now,
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

// Redact adds a field name to the redaction set.
func (l *Log) Redact(field string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.redact[strings.ToLower(field)] = true
}

// Record appends an entry and returns it as written.
func (l *Log) Record(e Entry, args map[string]any) Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Seq = uint64(len(l.entries)) + 1
	e.Time = l.now().UTC()
	e.Args = l.renderArgs(args)
	if len(l.entries) > 0 {
		e.PrevHash = l.entries[len(l.entries)-1].Hash
	} else {
		e.PrevHash = strings.Repeat("0", 64)
	}
	e.Hash = hashEntry(e)

	l.entries = append(l.entries, e)
	return e
}

// Entries returns a copy of the log.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.entries...)
}

// Len reports how many entries are held.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Verify walks the chain and reports the first entry that does not hold.
//
// It returns the sequence number rather than just an error because "the log
// is broken" is far less useful during an incident than "the log is broken
// from entry 41 onward".
func (l *Log) Verify() (badSeq uint64, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	prev := strings.Repeat("0", 64)
	for _, e := range l.entries {
		if e.PrevHash != prev {
			return e.Seq, fmt.Errorf("audit: entry %d does not follow entry %d", e.Seq, e.Seq-1)
		}
		if got := hashEntry(e); got != e.Hash {
			return e.Seq, fmt.Errorf("audit: entry %d has been modified", e.Seq)
		}
		prev = e.Hash
	}
	return 0, nil
}

// Tamper edits a stored entry in place without repairing the chain.
//
// This exists so the demo and the tests can show detection working. It is the
// only way to modify history through this API, it is named so that nobody
// calls it by accident, and nothing in the request path references it.
func (l *Log) Tamper(seq uint64, mutate func(*Entry)) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.entries {
		if l.entries[i].Seq == seq {
			mutate(&l.entries[i])
			return true
		}
	}
	return false
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
