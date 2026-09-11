package policy_test

import (
	"testing"
	"time"

	"github.com/saadbutt/toolgate/internal/policy"
	"github.com/saadbutt/toolgate/internal/tools"
)

func consequential() tools.Tool {
	return tools.Tool{
		Name: "issue_refund", Risk: tools.Consequential, Idempotent: true,
		Schema: tools.Schema{Fields: []tools.Field{
			{Name: "amount_cents", Type: tools.Money, Required: true},
		}},
	}
}

func readTool() tools.Tool {
	return tools.Tool{Name: "lookup_invoice", Risk: tools.Read}
}

func engine() *policy.Engine { return policy.NewEngine(policy.DefaultRules()...) }

func agentWith(scope policy.Scope) policy.Principal {
	return policy.Principal{ID: "a", Kind: policy.Agent, OnBehalfOf: "saad", Scope: scope}
}

func TestEmptyEngineDeniesEverything(t *testing.T) {
	v := policy.NewEngine().Evaluate(policy.Request{
		Principal: agentWith(policy.Scope{Tools: []string{"lookup_invoice"}}),
		Tool:      readTool(), Now: time.Now(),
	})
	if v.Decision != policy.Deny || v.Rule != "default_deny" {
		t.Fatalf("empty engine allowed something: %+v", v)
	}
}

func TestConsequentialAlwaysNeedsConfirmationForAgents(t *testing.T) {
	v := engine().Evaluate(policy.Request{
		Principal: agentWith(policy.Scope{Tools: []string{"issue_refund"}, MaxAmount: 100_000}),
		Tool:      consequential(),
		Args:      tools.Args{"amount_cents": int64(500)},
		Now:       time.Now(),
	})
	if v.Decision != policy.NeedsConfirmation {
		t.Fatalf("got %v via %s", v.Decision, v.Rule)
	}
}

// TestDenyRulesRunBeforeAllowRules is about ordering. An expired grant must
// lose even when a later rule would have permitted the call.
func TestDenyRulesRunBeforeAllowRules(t *testing.T) {
	expired := policy.Scope{Tools: []string{"lookup_invoice"}, ExpiresAt: time.Now().Add(-time.Hour)}
	v := engine().Evaluate(policy.Request{
		Principal: agentWith(expired), Tool: readTool(), Now: time.Now(),
	})
	if v.Decision != policy.Deny || v.Rule != "expired_grant" {
		t.Fatalf("expired grant decided by %s: %v", v.Rule, v.Decision)
	}
}

func TestScopeIsNotWidenedByAnything(t *testing.T) {
	s := policy.Scope{Tools: []string{"lookup_invoice"}, MaxAmount: 100}
	before := s.Fingerprint()

	// Pass it through evaluation repeatedly, including calls it refuses.
	e := engine()
	for i := 0; i < 5; i++ {
		e.Evaluate(policy.Request{
			Principal: agentWith(s), Tool: consequential(),
			Args: tools.Args{"amount_cents": int64(999_999)}, Now: time.Now(),
		})
	}
	if after := s.Fingerprint(); after != before {
		t.Fatalf("scope moved:\n%s\n%s", before, after)
	}
}

func TestFingerprintIsOrderIndependent(t *testing.T) {
	a := policy.Scope{Tools: []string{"b", "a", "c"}, MaxAmount: 5}
	b := policy.Scope{Tools: []string{"c", "b", "a"}, MaxAmount: 5}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("%s != %s", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFingerprintChangesWhenGrantChanges(t *testing.T) {
	a := policy.Scope{Tools: []string{"x"}, MaxAmount: 5}
	b := policy.Scope{Tools: []string{"x", "y"}, MaxAmount: 5}
	c := policy.Scope{Tools: []string{"x"}, MaxAmount: 6}
	if a.Fingerprint() == b.Fingerprint() || a.Fingerprint() == c.Fingerprint() {
		t.Fatal("fingerprint does not distinguish different grants")
	}
}

func TestHumanIsNotBoundByAgentScope(t *testing.T) {
	h := policy.Principal{ID: "saad", Kind: policy.Human}
	v := engine().Evaluate(policy.Request{
		Principal: h, Tool: consequential(),
		Args: tools.Args{"amount_cents": int64(1_000_000)}, Now: time.Now(),
	})
	if v.Decision != policy.Allow {
		t.Fatalf("human refused by %s", v.Rule)
	}
}

func TestServicePrincipalIsStillSubjectToScope(t *testing.T) {
	svc := policy.Principal{ID: "svc", Kind: policy.Service, Scope: policy.Scope{Tools: []string{"other"}}}
	v := engine().Evaluate(policy.Request{Principal: svc, Tool: readTool(), Now: time.Now()})
	if v.Decision != policy.Deny || v.Rule != "tool_outside_scope" {
		t.Fatalf("internal service bypassed policy: %+v", v)
	}
}
