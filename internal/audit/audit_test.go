package audit_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/saadbutt/toolgate/internal/audit"
)

func seed(l *audit.Log, n int) {
	for i := 0; i < n; i++ {
		l.Record(audit.Entry{Tool: "t", Decision: "allow", Rule: "r", Outcome: "ok"},
			map[string]any{"i": i})
	}
}

func TestCleanChainVerifies(t *testing.T) {
	l := audit.New()
	seed(l, 10)
	if bad, err := l.Verify(); err != nil {
		t.Fatalf("entry %d: %v", bad, err)
	}
}

func TestEditedEntryIsDetectedAtTheRightSequence(t *testing.T) {
	l := audit.New()
	seed(l, 10)
	l.Tamper(6, func(e *audit.Entry) { e.Outcome = "refused" })

	bad, err := l.Verify()
	if err == nil {
		t.Fatal("edit not detected")
	}
	if bad != 6 {
		t.Fatalf("reported entry %d, want 6", bad)
	}
}

// TestRehashingAnEntryStillBreaksTheChain covers the smarter attacker: fix
// the entry's own hash and the link to the next entry still fails.
func TestRehashingAnEntryStillBreaksTheChain(t *testing.T) {
	l := audit.New()
	seed(l, 5)

	entries := l.Entries()
	target := entries[2]
	target.Outcome = "ok"
	l.Tamper(3, func(e *audit.Entry) {
		e.Outcome = "something else"
		// Attacker recomputes what they think the hash should be, but they
		// cannot update entry 4's PrevHash without breaking 5, and so on.
		e.Hash = target.Hash
	})
	if _, err := l.Verify(); err == nil {
		t.Fatal("chain accepted a re-hashed entry")
	}
}

func TestFirstEntryLinksToZeroHash(t *testing.T) {
	l := audit.New()
	seed(l, 1)
	e := l.Entries()[0]
	if e.PrevHash != strings.Repeat("0", 64) {
		t.Fatalf("genesis prev hash is %q", e.PrevHash)
	}
}

func TestSequenceIsContiguous(t *testing.T) {
	l := audit.New()
	seed(l, 25)
	for i, e := range l.Entries() {
		if e.Seq != uint64(i+1) {
			t.Fatalf("entry %d has seq %d", i, e.Seq)
		}
	}
}

func TestDefaultRedactionCoversCommonSecretNames(t *testing.T) {
	l := audit.New()
	for _, field := range []string{"password", "token", "api_key", "CVV", "private_key"} {
		l.Record(audit.Entry{Tool: "t"}, map[string]any{field: "should-not-appear"})
	}
	for _, e := range l.Entries() {
		if strings.Contains(e.Args, "should-not-appear") {
			t.Fatalf("secret leaked: %s", e.Args)
		}
	}
}

func TestCustomRedaction(t *testing.T) {
	l := audit.New()
	l.Redact("iban")
	l.Record(audit.Entry{Tool: "t"}, map[string]any{"iban": "DE00 1234"})
	if strings.Contains(l.Entries()[0].Args, "DE00") {
		t.Fatal("custom redaction ignored")
	}
}

func TestConcurrentRecordKeepsChainIntact(t *testing.T) {
	l := audit.New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			l.Record(audit.Entry{Tool: "t", Outcome: "ok"}, map[string]any{"i": i})
		}(i)
	}
	wg.Wait()

	if l.Len() != 100 {
		t.Fatalf("recorded %d entries", l.Len())
	}
	if bad, err := l.Verify(); err != nil {
		t.Fatalf("concurrent writes broke the chain at %d: %v", bad, err)
	}
}

// TestTruncatedLogIsDetected covers the easiest edit to make and the one that
// looks most like covering something up: deleting the most recent entries.
// Every remaining link is intact, so only a commitment to the head notices.
func TestTruncatedLogIsDetected(t *testing.T) {
	l := audit.New()
	seed(l, 6)
	if bad, err := l.Verify(); err != nil {
		t.Fatalf("clean log failed at %d: %v", bad, err)
	}

	l.Truncate(1)
	bad, err := l.Verify()
	if err == nil {
		t.Fatal("log with its last entry removed still verified")
	}
	if bad != 6 {
		t.Fatalf("reported entry %d, want 6, the first one missing", bad)
	}
}

// TestStoredCopyIsVerifiedAgainstAnAnchoredHead is the deployment shape: the
// entries are written somewhere, the head is kept somewhere else, and the
// stored copy is checked against it later.
func TestStoredCopyIsVerifiedAgainstAnAnchoredHead(t *testing.T) {
	l := audit.New()
	seed(l, 6)
	stored, anchored := l.Entries(), l.Head()

	if bad, err := audit.VerifyChain(stored, anchored); err != nil {
		t.Fatalf("clean copy failed at %d: %v", bad, err)
	}
	if bad, err := audit.VerifyChain(stored[:4], anchored); err == nil || bad != 5 {
		t.Fatalf("copy missing its last two entries: bad=%d err=%v", bad, err)
	}
	if bad, err := audit.VerifyChain(nil, anchored); err == nil || bad != 1 {
		t.Fatalf("emptied copy: bad=%d err=%v", bad, err)
	}

	edited := append([]audit.Entry(nil), stored...)
	edited[2].Principal = "someone-else"
	if bad, err := audit.VerifyChain(edited, anchored); err == nil || bad != 3 {
		t.Fatalf("edited copy: bad=%d err=%v", bad, err)
	}

	// A head that has moved on is not satisfied by an older, intact prefix.
	seed(l, 1)
	if _, err := audit.VerifyChain(stored, l.Head()); err == nil {
		t.Fatal("a copy that stops short of the current head verified")
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	l := audit.New()
	if bad, err := l.Verify(); err != nil {
		t.Fatalf("empty log failed at %d: %v", bad, err)
	}
	if h := l.Head(); h.Count != 0 || h.Hash != strings.Repeat("0", 64) {
		t.Fatalf("empty log head is %+v", h)
	}
}

// TestFailedWriteLeavesTheLogUnchanged covers storage refusing a write. The
// entry must not join the chain, or the log would claim a record that
// storage does not hold, and a retry must produce a clean chain.
func TestFailedWriteLeavesTheLogUnchanged(t *testing.T) {
	l := audit.New()
	var stored []audit.Entry
	down := false
	l.SetSink(func(e audit.Entry) error {
		if down {
			return errors.New("disk full")
		}
		stored = append(stored, e)
		return nil
	})
	seed(l, 2)
	head := l.Head()

	down = true
	if _, err := l.Record(audit.Entry{Tool: "t", Outcome: "ok"}, nil); err == nil {
		t.Fatal("a failed write was reported as recorded")
	}
	if l.Len() != 2 || l.Head() != head {
		t.Fatalf("failed write changed the log: len=%d head=%+v", l.Len(), l.Head())
	}

	down = false
	e, err := l.Record(audit.Entry{Tool: "t", Outcome: "ok"}, nil)
	if err != nil || e.Seq != 3 {
		t.Fatalf("retry: seq=%d err=%v", e.Seq, err)
	}
	if bad, err := audit.VerifyChain(stored, l.Head()); err != nil {
		t.Fatalf("what storage holds does not verify, from %d: %v", bad, err)
	}
}
