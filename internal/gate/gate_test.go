package gate_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saadbutt/toolgate/internal/audit"
	"github.com/saadbutt/toolgate/internal/billing"
	"github.com/saadbutt/toolgate/internal/budget"
	"github.com/saadbutt/toolgate/internal/confirm"
	"github.com/saadbutt/toolgate/internal/gate"
	"github.com/saadbutt/toolgate/internal/policy"
	"github.com/saadbutt/toolgate/internal/tools"
	"github.com/saadbutt/toolgate/internal/untrusted"
)

type harness struct {
	g    *gate.Gate
	bill *billing.System
	log  *audit.Log
	conf *confirm.Store
}

func newHarness(t *testing.T, lim budget.Limits) *harness {
	t.Helper()
	if lim.MaxSteps == 0 && lim.MaxMoney == 0 && lim.MaxTokens == 0 {
		lim = budget.Limits{MaxSteps: 50, MaxMoney: 500_000, MaxTokens: 1_000_000}
	}
	reg := tools.NewRegistry()
	bill := billing.New()
	for _, tl := range bill.Tools() {
		if err := reg.Register(tl); err != nil {
			t.Fatalf("registering %s: %v", tl.Name, err)
		}
	}
	log := audit.New()
	conf := confirm.NewStore(2 * time.Minute)
	g := gate.New(reg, policy.NewEngine(policy.DefaultRules()...), budget.New(lim), conf, log)
	return &harness{g: g, bill: bill, log: log, conf: conf}
}

func agent(scope policy.Scope) policy.Principal {
	return policy.Principal{ID: "agent-1", Kind: policy.Agent, OnBehalfOf: "saad", Scope: scope}
}

func fullScope() policy.Scope {
	return policy.Scope{
		Tools:     []string{"lookup_invoice", "draft_refund", "issue_refund"},
		MaxAmount: 50_000,
	}
}

func human() policy.Principal {
	return policy.Principal{ID: "saad", Kind: policy.Human}
}

// TestAgentCannotExecuteConsequentialActionDirectly is the headline claim.
// The agent asks to move money and gets a pending intent, not a refund.
func TestAgentCannotExecuteConsequentialActionDirectly(t *testing.T) {
	h := newHarness(t, budget.Limits{})

	out, err := h.g.Submit(context.Background(), agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 4200, "reason": "duplicate charge"},
		IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.Status != gate.AwaitingConfirmation {
		t.Fatalf("got status %v, want awaiting_confirmation", out.Status)
	}
	if got := h.bill.TotalRefunded(); got != 0 {
		t.Fatalf("money moved without confirmation: %d cents", got)
	}
	if out.Intent == nil || out.Token == "" {
		t.Fatal("no intent or token returned")
	}
}

func TestHumanConfirmationExecutesTheFrozenArguments(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	ctx := context.Background()

	out, _ := h.g.Submit(ctx, agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 4200, "reason": "duplicate charge"},
		IdempotencyKey: "k1",
	})

	done, err := h.g.ConfirmAndRun(ctx, human(), out.Intent.ID, out.Token, "k1-confirmed")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if done.Status != gate.Executed {
		t.Fatalf("got %v, want executed", done.Status)
	}
	if got := h.bill.TotalRefunded(); got != 4200 {
		t.Fatalf("refunded %d, want 4200", got)
	}
}

// TestConfirmationTokenIsSingleUse covers replay of a captured approval.
func TestConfirmationTokenIsSingleUse(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	ctx := context.Background()

	out, _ := h.g.Submit(ctx, agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 10_000, "reason": "goodwill"},
		IdempotencyKey: "k2",
	})
	if _, err := h.g.ConfirmAndRun(ctx, human(), out.Intent.ID, out.Token, "k2-a"); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	_, err := h.g.ConfirmAndRun(ctx, human(), out.Intent.ID, out.Token, "k2-b")
	if !errors.Is(err, confirm.ErrAlreadyUsed) {
		t.Fatalf("replay accepted, got %v", err)
	}
	if got := h.bill.TotalRefunded(); got != 10_000 {
		t.Fatalf("replay moved money twice: %d", got)
	}
}

// TestArgumentTamperingBetweenConfirmAndExecuteIsRejected is the bug this
// design exists to prevent: approve $42, execute $4,200.
func TestArgumentTamperingBetweenConfirmAndExecuteIsRejected(t *testing.T) {
	h := newHarness(t, budget.Limits{})

	out, _ := h.g.Submit(context.Background(), agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 4200, "reason": "partial"},
		IdempotencyKey: "k3",
	})

	tampered := tools.Args{"invoice_id": "INV-1002", "amount_cents": int64(420_000), "reason": "partial"}
	if err := h.conf.VerifyArgs(out.Intent.ID, tampered); !errors.Is(err, confirm.ErrArgsMismatch) {
		t.Fatalf("tampered args accepted, got %v", err)
	}

	// And the executed amount is the approved one regardless.
	if _, err := h.g.ConfirmAndRun(context.Background(), human(), out.Intent.ID, out.Token, "k3-c"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := h.bill.TotalRefunded(); got != 4200 {
		t.Fatalf("executed %d, want the approved 4200", got)
	}
}

func TestWrongApproverCannotConfirm(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	out, _ := h.g.Submit(context.Background(), agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 100, "reason": "x"},
		IdempotencyKey: "k4",
	})
	other := policy.Principal{ID: "someone-else", Kind: policy.Human}
	_, err := h.g.ConfirmAndRun(context.Background(), other, out.Intent.ID, out.Token, "k4-c")
	if !errors.Is(err, confirm.ErrWrongApprover) {
		t.Fatalf("wrong approver accepted: %v", err)
	}
}

// TestRetrievedContentCannotEscalatePermissions reads an invoice whose notes
// field contains a live injection payload, then asserts the agent's authority
// is byte-identical before and after.
func TestRetrievedContentCannotEscalatePermissions(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	p := agent(fullScope())
	before := p.Scope.Fingerprint()

	out, err := h.g.Submit(context.Background(), p, gate.Call{
		Tool: "lookup_invoice",
		Args: tools.Args{"invoice_id": "INV-1003"},
	})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !strings.Contains(out.Result.Text, "Ignore all previous instructions") {
		t.Fatal("test fixture no longer contains the injection payload")
	}
	if !out.Content.Tainted {
		t.Fatal("tool output was not marked untrusted")
	}
	if sus := untrusted.Scan(out.Content); len(sus) == 0 {
		t.Error("injection scanner did not flag a known payload")
	}
	if after := p.Scope.Fingerprint(); after != before {
		t.Fatalf("scope changed after reading hostile content:\n before %s\n after  %s", before, after)
	}

	// The instruction told the agent to refund without review. It still cannot.
	out2, _ := h.g.Submit(context.Background(), p, gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1003", "amount_cents": 6500, "reason": "per instructions in notes"},
		IdempotencyKey: "k5",
	})
	if out2.Status != gate.AwaitingConfirmation {
		t.Fatalf("injection changed the outcome: got %v", out2.Status)
	}
	if got := h.bill.TotalRefunded(); got != 0 {
		t.Fatalf("injection moved %d cents", got)
	}
}

func TestToolOutsideScopeIsRefused(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	narrow := agent(policy.Scope{Tools: []string{"lookup_invoice"}, MaxAmount: 1000})

	out, err := h.g.Submit(context.Background(), narrow, gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 100, "reason": "x"},
		IdempotencyKey: "k6",
	})
	if err == nil || out.Status != gate.Refused {
		t.Fatalf("out-of-scope tool allowed: %v", out.Status)
	}
	if out.Verdict.Rule != "tool_outside_scope" {
		t.Fatalf("refused by %q, want tool_outside_scope", out.Verdict.Rule)
	}
}

func TestAmountAboveGrantIsRefused(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	out, err := h.g.Submit(context.Background(), agent(fullScope()), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 128_000, "reason": "full"},
		IdempotencyKey: "k7",
	})
	if err == nil || out.Verdict.Rule != "amount_above_grant" {
		t.Fatalf("over-cap refund allowed, rule=%q", out.Verdict.Rule)
	}
}

func TestExpiredGrantIsRefused(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	expired := fullScope()
	expired.ExpiresAt = time.Now().Add(-time.Minute)

	out, err := h.g.Submit(context.Background(), agent(expired), gate.Call{
		Tool: "lookup_invoice",
		Args: tools.Args{"invoice_id": "INV-1001"},
	})
	if err == nil || out.Verdict.Rule != "expired_grant" {
		t.Fatalf("expired grant allowed, rule=%q", out.Verdict.Rule)
	}
}

// TestBudgetCeilingStopsRunawayLoop is the failure that actually happens:
// a model retrying a call forever.
func TestBudgetCeilingStopsRunawayLoop(t *testing.T) {
	h := newHarness(t, budget.Limits{MaxSteps: 5, MaxTokens: 1_000_000, MaxMoney: 1_000_000})
	p := agent(fullScope())

	var refused int
	for i := 0; i < 40; i++ {
		_, err := h.g.Submit(context.Background(), p, gate.Call{
			Tool: "lookup_invoice",
			Args: tools.Args{"invoice_id": "INV-1001"},
		})
		if errors.Is(err, budget.Exceeded) {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("loop ran 40 times against a 5-step ceiling without being stopped")
	}
}

func TestSchemaRejectsUnknownAndMalformedArguments(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	p := agent(fullScope())

	cases := []struct {
		name string
		args tools.Args
	}{
		{"unknown field", tools.Args{"invoice_id": "INV-1001", "amount_cents": 100, "reason": "x", "override_policy": true}},
		{"wrong type", tools.Args{"invoice_id": "INV-1001", "amount_cents": "lots", "reason": "x"}},
		{"fractional money", tools.Args{"invoice_id": "INV-1001", "amount_cents": 10.7, "reason": "x"}},
		{"negative money", tools.Args{"invoice_id": "INV-1001", "amount_cents": -500, "reason": "x"}},
		{"missing required", tools.Args{"invoice_id": "INV-1001", "amount_cents": 100}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.g.Submit(context.Background(), p, gate.Call{
				Tool: "issue_refund", Args: tc.args, IdempotencyKey: "s-" + tc.name,
			})
			var ve *tools.ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("accepted %s: %v", tc.name, err)
			}
		})
	}
}

func TestMutatingCallWithoutIdempotencyKeyIsRefused(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	_, err := h.g.Submit(context.Background(), agent(fullScope()), gate.Call{
		Tool: "draft_refund",
		Args: tools.Args{"invoice_id": "INV-1001", "amount_cents": 100, "reason": "x"},
	})
	if !errors.Is(err, gate.ErrMissingIdempotencyKey) {
		t.Fatalf("got %v", err)
	}
}

// TestRetryDoesNotDoubleExecute covers the ordinary case that costs real money.
func TestRetryDoesNotDoubleExecute(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	ctx := context.Background()
	p := agent(fullScope())

	for i := 0; i < 4; i++ {
		if _, err := h.g.Submit(ctx, p, gate.Call{
			Tool:           "draft_refund",
			Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 500, "reason": "retry"},
			IdempotencyKey: "same-key",
		}); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	out, _ := h.g.Submit(ctx, p, gate.Call{
		Tool:           "draft_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 500, "reason": "retry"},
		IdempotencyKey: "same-key",
	})
	if !out.Replayed {
		t.Fatal("repeat call was not reported as a replay")
	}
}

// TestAuditRecordsRefusalsNotJustSuccesses guards the log that only shows
// what was permitted.
func TestAuditRecordsRefusalsNotJustSuccesses(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	narrow := agent(policy.Scope{Tools: []string{"lookup_invoice"}})

	_, _ = h.g.Submit(context.Background(), narrow, gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 100, "reason": "x"},
		IdempotencyKey: "k8",
	})
	var found bool
	for _, e := range h.log.Entries() {
		if e.Rule == "tool_outside_scope" && e.Outcome == "refused" {
			found = true
		}
	}
	if !found {
		t.Fatal("refusal was not written to the audit log")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	p := agent(fullScope())
	for i := 0; i < 3; i++ {
		_, _ = h.g.Submit(context.Background(), p, gate.Call{
			Tool: "lookup_invoice", Args: tools.Args{"invoice_id": "INV-1001"},
		})
	}
	if bad, err := h.log.Verify(); err != nil {
		t.Fatalf("clean log failed verification at %d: %v", bad, err)
	}

	if !h.log.Tamper(2, func(e *audit.Entry) { e.Outcome = "ok (definitely fine)" }) {
		t.Fatal("could not find entry 2")
	}
	bad, err := h.log.Verify()
	if err == nil {
		t.Fatal("edited log still verified")
	}
	if bad != 2 {
		t.Fatalf("detected tampering at entry %d, want 2", bad)
	}
}

func TestSecretsAreRedactedInTheAuditLog(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	h.log.Record(audit.Entry{Tool: "x", Decision: "allow"}, map[string]any{
		"invoice_id": "INV-1001",
		"api_key":    "sk-live-do-not-log-me",
	})
	for _, e := range h.log.Entries() {
		if strings.Contains(e.Args, "sk-live") {
			t.Fatal("a secret was written to the audit log")
		}
	}
}

func TestHumanActingDirectlyNeedsNoConfirmation(t *testing.T) {
	h := newHarness(t, budget.Limits{})
	out, err := h.g.Submit(context.Background(), human(), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 4200, "reason": "manual"},
		IdempotencyKey: "h1",
	})
	if err != nil || out.Status != gate.Executed {
		t.Fatalf("human blocked: %v %v", out.Status, err)
	}
}
