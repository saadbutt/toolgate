package confirm_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saadbutt/toolgate/internal/confirm"
	"github.com/saadbutt/toolgate/internal/tools"
)

func args() tools.Args {
	return tools.Args{"invoice_id": "INV-1", "amount_cents": int64(4200), "reason": "dupe"}
}

func TestConfirmReturnsFrozenArguments(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, tok, err := s.Create("issue_refund", args(), "refund $42", "agent-1", "saad")
	if err != nil {
		t.Fatal(err)
	}
	name, frozen, err := s.Confirm(in.ID, tok, "saad")
	if err != nil {
		t.Fatal(err)
	}
	if name != "issue_refund" || frozen["amount_cents"] != int64(4200) {
		t.Fatalf("got %s %#v", name, frozen)
	}
}

// TestMutatingTheCallersArgsDoesNotChangeTheIntent covers the aliasing bug:
// if the store kept the caller's map, the agent could edit an approved
// action after it was approved.
func TestMutatingTheCallersArgsDoesNotChangeTheIntent(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	a := args()
	in, tok, _ := s.Create("issue_refund", a, "refund", "agent-1", "saad")

	a["amount_cents"] = int64(999_999)

	_, frozen, err := s.Confirm(in.ID, tok, "saad")
	if err != nil {
		t.Fatal(err)
	}
	if frozen["amount_cents"] != int64(4200) {
		t.Fatalf("intent followed the caller's mutation: %v", frozen["amount_cents"])
	}
}

// TestMutatingTheReturnedIntentDoesNotChangeTheStore covers the other alias:
// the intent Create hands back. If it were the store's own record, whoever
// requested the action could rewrite the amount, the approver or the tool
// after a human approved it.
func TestMutatingTheReturnedIntentDoesNotChangeTheStore(t *testing.T) {
	s := confirm.NewStore(5 * time.Minute)
	in, _, err := s.Create("issue_refund",
		tools.Args{"amount_cents": int64(4200)},
		"refund $42", "agent-1", "human-1")
	if err != nil {
		t.Fatal(err)
	}

	in.Args["amount_cents"] = int64(128000)
	in.Approver = "agent-1"
	in.Tool = "wire_money"

	got, err := s.Pending(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Args["amount_cents"] != int64(4200) {
		t.Errorf("args mutated through the returned intent: %v", got.Args["amount_cents"])
	}
	if got.Approver != "human-1" {
		t.Errorf("approver mutated through the returned intent: %q", got.Approver)
	}
	if got.Tool != "issue_refund" {
		t.Errorf("tool mutated through the returned intent: %q", got.Tool)
	}
}

func TestTokenIsSingleUse(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, tok, _ := s.Create("t", args(), "", "a", "saad")
	if _, _, err := s.Confirm(in.ID, tok, "saad"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Confirm(in.ID, tok, "saad"); !errors.Is(err, confirm.ErrAlreadyUsed) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentConfirmOnlyOneWins(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, tok, _ := s.Create("t", args(), "", "a", "saad")

	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.Confirm(in.ID, tok, "saad"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent confirmations succeeded, want 1", wins.Load())
	}
}

func TestWrongTokenIsRejected(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, _, _ := s.Create("t", args(), "", "a", "saad")
	if _, _, err := s.Confirm(in.ID, "deadbeef", "saad"); !errors.Is(err, confirm.ErrBadToken) {
		t.Fatalf("got %v", err)
	}
}

func TestWrongApproverIsRejected(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, tok, _ := s.Create("t", args(), "", "a", "saad")
	if _, _, err := s.Confirm(in.ID, tok, "mallory"); !errors.Is(err, confirm.ErrWrongApprover) {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredIntentIsRejected(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	in, tok, _ := s.Create("t", args(), "", "a", "saad")

	now = now.Add(2 * time.Minute)
	if _, _, err := s.Confirm(in.ID, tok, "saad"); !errors.Is(err, confirm.ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyArgsDetectsTampering(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, _, _ := s.Create("t", args(), "", "a", "saad")

	if err := s.VerifyArgs(in.ID, args()); err != nil {
		t.Fatalf("identical args rejected: %v", err)
	}
	bad := args()
	bad["amount_cents"] = int64(4201)
	if err := s.VerifyArgs(in.ID, bad); !errors.Is(err, confirm.ErrArgsMismatch) {
		t.Fatalf("one-cent change accepted: %v", err)
	}
}

// TestHashIsStableAcrossMapOrdering guards the determinism the whole
// confirmation check rests on.
func TestHashIsStableAcrossMapOrdering(t *testing.T) {
	a := tools.Args{"z": "last", "a": "first", "m": int64(5)}
	b := tools.Args{"m": int64(5), "a": "first", "z": "last"}
	ha, err := confirm.HashArgs(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := confirm.HashArgs(b)
	if ha != hb {
		t.Fatalf("hash depends on map ordering:\n%s\n%s", ha, hb)
	}
}

func TestPendingDoesNotLeakTheToken(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	in, tok, _ := s.Create("t", args(), "", "a", "saad")
	got, err := s.Pending(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Reading the store must not let you approve. Confirm with a token
	// derived from anything visible here would be the failure.
	if _, _, err := s.Confirm(got.ID, "", "saad"); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, _, err := s.Confirm(got.ID, tok, "saad"); err != nil {
		t.Fatalf("real token rejected: %v", err)
	}
}

func TestReapRemovesExpired(t *testing.T) {
	s := confirm.NewStore(time.Minute)
	now := time.Now()
	s.SetClock(func() time.Time { return now })
	for i := 0; i < 3; i++ {
		_, _, _ = s.Create("t", args(), "", "a", "saad")
	}
	now = now.Add(2 * time.Minute)
	if n := s.Reap(); n != 3 {
		t.Fatalf("reaped %d, want 3", n)
	}
}
