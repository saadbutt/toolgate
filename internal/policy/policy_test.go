package policy_test

import (
	"sync"
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
		Principal: agentWith(policy.Scope{Tools: policy.NewToolSet("lookup_invoice")}),
		Tool:      readTool(), Now: time.Now(),
	})
	if v.Decision != policy.Deny || v.Rule != "default_deny" {
		t.Fatalf("empty engine allowed something: %+v", v)
	}
}

func TestConsequentialAlwaysNeedsConfirmationForAgents(t *testing.T) {
	v := engine().Evaluate(policy.Request{
		Principal: agentWith(policy.Scope{Tools: policy.NewToolSet("issue_refund"), MaxAmount: 100_000}),
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
	expired := policy.Scope{Tools: policy.NewToolSet("lookup_invoice"), ExpiresAt: time.Now().Add(-time.Hour)}
	v := engine().Evaluate(policy.Request{
		Principal: agentWith(expired), Tool: readTool(), Now: time.Now(),
	})
	if v.Decision != policy.Deny || v.Rule != "expired_grant" {
		t.Fatalf("expired grant decided by %s: %v", v.Rule, v.Decision)
	}
}

func TestScopeIsNotWidenedByAnything(t *testing.T) {
	s := policy.Scope{Tools: policy.NewToolSet("lookup_invoice"), MaxAmount: 100}
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
	a := policy.Scope{Tools: policy.NewToolSet("b", "a", "c"), MaxAmount: 5}
	b := policy.Scope{Tools: policy.NewToolSet("c", "b", "a"), MaxAmount: 5}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("%s != %s", a.Fingerprint(), b.Fingerprint())
	}
}

func TestFingerprintChangesWhenGrantChanges(t *testing.T) {
	a := policy.Scope{Tools: policy.NewToolSet("x"), MaxAmount: 5}
	b := policy.Scope{Tools: policy.NewToolSet("x", "y"), MaxAmount: 5}
	c := policy.Scope{Tools: policy.NewToolSet("x"), MaxAmount: 6}
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
	svc := policy.Principal{ID: "svc", Kind: policy.Service, Scope: policy.Scope{Tools: policy.NewToolSet("other")}}
	v := engine().Evaluate(policy.Request{Principal: svc, Tool: readTool(), Now: time.Now()})
	if v.Decision != policy.Deny || v.Rule != "tool_outside_scope" {
		t.Fatalf("internal service bypassed policy: %+v", v)
	}
}

// TestEngineIsSafeForConcurrentUse adds rules while other goroutines
// evaluate. The caller keeps the engine it handed to the gate, so this is
// reachable at runtime. Run it under -race.
func TestEngineIsSafeForConcurrentUse(t *testing.T) {
	e := engine()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			e.Add(policy.Rule{Name: "never", Then: policy.Deny, Match: func(policy.Request) bool { return false }})
		}()
		go func() {
			defer wg.Done()
			e.Evaluate(policy.Request{
				Principal: agentWith(policy.Scope{Tools: policy.NewToolSet("lookup_invoice")}),
				Tool:      readTool(), Now: time.Now(),
			})
		}()
	}
	wg.Wait()
}

// TestRuleCannotWidenTheCallersScopeThroughACopy covers a rule writing to the
// request it was handed. Whatever it does to its copy of the scope, the
// caller's grant is unchanged.
func TestRuleCannotWidenTheCallersScopeThroughACopy(t *testing.T) {
	scope := policy.Scope{Tools: policy.NewToolSet("lookup_invoice")}
	before := scope.Fingerprint()
	e := policy.NewEngine(policy.Rule{
		Name: "writes_through_its_copy", Then: policy.Deny,
		Match: func(r policy.Request) bool {
			r.Principal.Scope.Tools.Names()[0] = "issue_refund"
			r.Principal.Scope.Tools = policy.NewToolSet("issue_refund")
			return false
		},
	})
	e.Evaluate(policy.Request{Principal: agentWith(scope), Tool: readTool(), Now: time.Now()})
	if after := scope.Fingerprint(); after != before {
		t.Fatalf("a rule widened the caller's scope:\n before %s\n after  %s", before, after)
	}
}

// TestToolSetDoesNotShareMemoryWithItsCaller covers both directions: the
// slice a set was built from, and the slice Names hands back.
func TestToolSetDoesNotShareMemoryWithItsCaller(t *testing.T) {
	names := []string{"lookup_invoice"}
	s := policy.Scope{Tools: policy.NewToolSet(names...)}

	names[0] = "issue_refund"
	s.Tools.Names()[0] = "issue_refund"

	if s.Allows("issue_refund") || !s.Allows("lookup_invoice") {
		t.Fatalf("tool set changed through a caller's slice: %v", s.Tools.Names())
	}
}
