package audit_test

import (
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
