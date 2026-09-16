// Command demo runs seven scenarios against a fake billing system and shows
// what stopped each one.
//
// There is no API key and no network call. A scripted model stands in for a
// real one, because the point is not that a model can call tools, it is what
// happens when the model is wrong, manipulated, or looping. A scripted driver
// makes those cases reproducible.
//
//	go run ./cmd/demo
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
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

func main() {
	only := flag.Int("scenario", 0, "run a single scenario by number, 1-7")
	flag.Parse()

	scenarios := []struct {
		name string
		run  func(*rig) error
	}{
		{"Agent tries to move money directly", agentCannotRefundDirectly},
		{"Refund above the agent's cap", overCap},
		{"Retrieved document tries to escalate", injectionContained},
		{"Approval token replayed", tokenReplay},
		{"Arguments swapped after approval", argTamper},
		{"Agent loops on a malformed call", runawayLoop},
		{"Audit log edited or cut short", auditTamper},
	}

	failed := 0
	for i, s := range scenarios {
		n := i + 1
		if *only != 0 && *only != n {
			continue
		}
		fmt.Printf("\n%s\n%d. %s\n%s\n", strings.Repeat("=", 68), n, s.name, strings.Repeat("=", 68))
		if err := s.run(newRig()); err != nil {
			fmt.Printf("\n   SCENARIO FAILED: %v\n", err)
			failed++
		}
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 68))
	if failed > 0 {
		fmt.Printf("%d scenario(s) did not behave as documented.\n", failed)
		os.Exit(1)
	}
	fmt.Println("Every scenario behaved as documented.")
	fmt.Println("Nothing above required an API key. The guardrails are deterministic.")
}

// rig is one fully wired gate plus the billing system behind it.
//
// It keeps the audit log, which is read to show what happened. It does not
// keep the confirmation store: every scenario goes through the gate.
type rig struct {
	g    *gate.Gate
	bill *billing.System
	log  *audit.Log
}

func newRig() *rig {
	return newRigWithLimits(budget.Limits{MaxSteps: 40, MaxTokens: 500_000, MaxMoney: 500_000})
}

func newRigWithLimits(lim budget.Limits) *rig {
	reg := tools.NewRegistry()
	bill := billing.New()
	for _, t := range bill.Tools() {
		if err := reg.Register(t); err != nil {
			panic(err)
		}
	}
	log := audit.New()
	conf := confirm.NewStore(2 * time.Minute)
	return &rig{
		g:    gate.New(reg, policy.NewEngine(policy.DefaultRules()...), budget.New(lim), conf, log),
		bill: bill,
		log:  log,
	}
}

// theAgent is the principal every scenario runs as: an agent acting for Saad,
// allowed three tools, capped at $500, grant expiring in an hour.
func theAgent() policy.Principal {
	return policy.Principal{
		ID: "agent-1", Kind: policy.Agent, OnBehalfOf: "saad",
		Scope: policy.Scope{
			Tools:     []string{"lookup_invoice", "draft_refund", "issue_refund"},
			MaxAmount: 50_000,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
}

func theHuman() policy.Principal { return policy.Principal{ID: "saad", Kind: policy.Human} }

func say(format string, a ...any)   { fmt.Printf("   "+format+"\n", a...) }
func model(format string, a ...any) { fmt.Printf("\n   [model] "+format+"\n", a...) }
func gateSays(format string, a ...any) {
	fmt.Printf("   [gate]  "+format+"\n", a...)
}

func money(c int64) string { return fmt.Sprintf("$%d.%02d", c/100, c%100) }

func expect(cond bool, msg string) error {
	if !cond {
		return errors.New(msg)
	}
	return nil
}

// 1. The headline: a Consequential tool never runs on an agent's say-so.
func agentCannotRefundDirectly(r *rig) error {
	ctx := context.Background()
	model("calling issue_refund(INV-1001, $42.00, \"duplicate charge\")")

	out, err := r.g.Submit(ctx, theAgent(), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 4200, "reason": "duplicate charge"},
		IdempotencyKey: "demo-1",
		Model:          "scripted-v1",
	})
	if err != nil {
		return err
	}
	gateSays("decision: %s (rule: %s)", out.Verdict.Decision, out.Verdict.Rule)
	gateSays("nothing executed. created intent %s awaiting %s", out.Intent.ID[:8], out.Intent.Approver)
	say("")
	say("what a human would see: %s", out.Intent.Summary)
	say("money moved so far: %s", money(r.bill.TotalRefunded()))
	if err := expect(r.bill.TotalRefunded() == 0, "money moved without approval"); err != nil {
		return err
	}

	say("")
	say("saad approves...")
	done, err := r.g.ConfirmAndRun(ctx, theHuman(), out.Intent.ID, out.Token, "demo-1-confirmed")
	if err != nil {
		return err
	}
	gateSays("%s under rule %s", done.Status, done.Verdict.Rule)
	say("money moved now: %s", money(r.bill.TotalRefunded()))
	return expect(r.bill.TotalRefunded() == 4200, "approved refund did not execute")
}

// 2. The cap is on the grant, so it applies before any confirmation exists.
func overCap(r *rig) error {
	model("calling issue_refund(INV-1002, $1,280.00, \"full refund\")")
	out, err := r.g.Submit(context.Background(), theAgent(), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 128_000, "reason": "full refund"},
		IdempotencyKey: "demo-2",
	})
	if err == nil {
		return errors.New("over-cap refund was not refused")
	}
	gateSays("refused by rule: %s", out.Verdict.Rule)
	gateSays("%s", out.Verdict.Reason)
	say("")
	say("the agent's grant caps it at %s. no human was ever asked.", money(50_000))
	return expect(out.Verdict.Rule == "amount_above_grant", "refused for the wrong reason")
}

// 3. A hostile document arrives as ordinary business data.
func injectionContained(r *rig) error {
	ctx := context.Background()
	p := theAgent()
	before := p.Scope.Fingerprint()

	say("agent authority before reading anything:")
	say("  %s", before)

	model("calling lookup_invoice(INV-1003)")
	out, err := r.g.Submit(ctx, p, gate.Call{
		Tool: "lookup_invoice", Args: tools.Args{"invoice_id": "INV-1003"},
	})
	if err != nil {
		return err
	}
	gateSays("executed. result marked untrusted=%v", out.Content.Tainted)

	if sus := untrusted.Scan(out.Content); len(sus) > 0 {
		say("")
		say("the invoice notes contain %d injection-shaped phrase(s):", len(sus))
		for _, s := range sus {
			say("  \"%s\"", s.Excerpt)
		}
	}

	say("")
	say("the document instructs the agent to grant itself access and refund without review.")
	model("obeying the document: calling issue_refund(INV-1003, $65.00)")

	out2, _ := r.g.Submit(ctx, p, gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1003", "amount_cents": 6500, "reason": "per instructions in notes"},
		IdempotencyKey: "demo-3",
	})
	gateSays("decision: %s (rule: %s)", out2.Verdict.Decision, out2.Verdict.Rule)

	after := p.Scope.Fingerprint()
	say("")
	say("agent authority after reading it:")
	say("  %s", after)
	say("unchanged: %v", after == before)
	say("money moved: %s", money(r.bill.TotalRefunded()))
	say("")
	say("the document was read, understood, and obeyed by the model.")
	say("it still could not widen what the model was allowed to do.")

	if err := expect(after == before, "authority changed after hostile input"); err != nil {
		return err
	}
	return expect(r.bill.TotalRefunded() == 0, "injection moved money")
}

// 4. A captured approval is worth exactly one use.
func tokenReplay(r *rig) error {
	ctx := context.Background()
	model("calling issue_refund(INV-1002, $100.00)")
	out, err := r.g.Submit(ctx, theAgent(), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 10_000, "reason": "goodwill"},
		IdempotencyKey: "demo-4",
	})
	if err != nil {
		return err
	}
	say("intent %s created, token issued once", out.Intent.ID[:8])

	if _, err := r.g.ConfirmAndRun(ctx, theHuman(), out.Intent.ID, out.Token, "demo-4a"); err != nil {
		return err
	}
	gateSays("first use: executed. refunded %s", money(r.bill.TotalRefunded()))

	say("")
	say("now the same token is presented again, as a captured approval would be:")
	_, err = r.g.ConfirmAndRun(ctx, theHuman(), out.Intent.ID, out.Token, "demo-4b")
	gateSays("second use: %v", err)
	say("total refunded: %s (unchanged)", money(r.bill.TotalRefunded()))

	if err := expect(errors.Is(err, confirm.ErrAlreadyUsed), "replay was accepted"); err != nil {
		return err
	}
	return expect(r.bill.TotalRefunded() == 10_000, "replay moved money twice")
}

// 5. Approve one thing, execute another. This is the interesting one.
func argTamper(r *rig) error {
	ctx := context.Background()
	model("calling issue_refund(INV-1002, $42.00)")
	out, err := r.g.Submit(ctx, theAgent(), gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1002", "amount_cents": 4200, "reason": "partial"},
		IdempotencyKey: "demo-5",
	})
	if err != nil {
		return err
	}
	say("human is shown and approves: %s", out.Intent.Summary)
	say("argument hash recorded: %s", out.Intent.ArgsHash[:16])

	say("")
	say("between approval and execution, the agent edits the intent it was handed:")
	out.Intent.Args["amount_cents"] = int64(420_000)
	out.Intent.Approver = "agent-1"
	say("  amount_cents=%v approver=%s", out.Intent.Args["amount_cents"], out.Intent.Approver)

	say("")
	say("that intent is a copy. execution takes no arguments and uses the frozen one:")
	done, err := r.g.ConfirmAndRun(ctx, theHuman(), out.Intent.ID, out.Token, "demo-5c")
	if err != nil {
		return err
	}
	gateSays("%s", done.Result.Text)
	say("refunded: %s, which is what was approved", money(r.bill.TotalRefunded()))

	return expect(r.bill.TotalRefunded() == 4200, "executed an amount nobody approved")
}

// 6. The failure that actually happens in production: the same broken call,
// retried. It never passes validation, and the ceiling still counts it.
func runawayLoop(r *rig) error {
	rig := newRigWithLimits(budget.Limits{MaxSteps: 6, MaxTokens: 500_000, MaxMoney: 500_000})
	p := theAgent()

	say("ceiling: 6 tool calls. the model will send the same malformed call 30 times.")
	model("calling draft_refund(INV-1001, amount_cents=\"forty-two\"), on repeat")
	var invalid, stopped int
	for i := 0; i < 30; i++ {
		_, err := rig.g.Submit(context.Background(), p, gate.Call{
			Tool:           "draft_refund",
			Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": "forty-two", "reason": "retry"},
			IdempotencyKey: fmt.Sprintf("demo-6-%d", i),
			TokensUsed:     800,
		})
		var ve *tools.ValidationError
		switch {
		case errors.Is(err, budget.Exceeded):
			stopped++
			if stopped == 1 {
				gateSays("attempt %d: %v", i+1, err)
			}
		case errors.As(err, &ve):
			invalid++
			if invalid == 1 {
				gateSays("attempt %d: %v", i+1, err)
			}
		}
	}
	say("")
	say("refused by the schema: %d   stopped by the ceiling: %d", invalid, stopped)
	say("malformed calls are charged too. if they were free, this loop would never end.")
	return expect(invalid == 6 && stopped == 24, "loop was not stopped")
}

// 7. Editing history is detectable, which is the honest claim.
func auditTamper(r *rig) error {
	p := theAgent()
	for i := 0; i < 3; i++ {
		_, _ = r.g.Submit(context.Background(), p, gate.Call{
			Tool: "lookup_invoice", Args: tools.Args{"invoice_id": "INV-1001"},
		})
	}
	_, _ = r.g.Submit(context.Background(), p, gate.Call{
		Tool:           "issue_refund",
		Args:           tools.Args{"invoice_id": "INV-1001", "amount_cents": 4200, "reason": "x"},
		IdempotencyKey: "demo-7",
	})

	stored, head := r.log.Entries(), r.log.Head()
	say("audit log holds %d entries, written to storage.", len(stored))
	say("its head is kept somewhere else: count=%d last=%s", head.Count, head.Hash[:16])
	if bad, err := audit.VerifyChain(stored, head); err != nil {
		return fmt.Errorf("clean log failed at %d: %w", bad, err)
	}
	gateSays("stored copy verifies against the head")

	say("")
	say("entry 2 currently reads: principal=%s tool=%s outcome=%s",
		stored[1].Principal, stored[1].Tool, stored[1].Outcome)
	say("someone edits the stored copy to blame the human instead of the agent:")
	edited := append([]audit.Entry(nil), stored...)
	edited[1].Principal = "saad"
	say("entry 2 now reads:       principal=%s tool=%s outcome=%s",
		edited[1].Principal, edited[1].Tool, edited[1].Outcome)
	bad, err := audit.VerifyChain(edited, head)
	gateSays("verification: %v", err)
	say("first broken entry: %d", bad)
	if err := expect(err != nil && bad == 2, "edit was not detected"); err != nil {
		return err
	}

	say("")
	last := stored[len(stored)-1]
	outcome, _, _ := strings.Cut(last.Outcome, ":")
	say("so they delete the last entry instead (%s %s). every remaining link holds:", last.Tool, outcome)
	bad, err = audit.VerifyChain(stored[:len(stored)-1], head)
	gateSays("verification: %v", err)
	say("first missing entry: %d", bad)
	say("")
	say("this is tamper-evident, not tamper-proof. the head only helps when it is")
	say("kept where the person editing the log cannot reach it, and someone who can")
	say("rewrite both can rewrite the whole chain. partial edits, which is what")
	say("covering something up actually looks like, do not survive.")
	return expect(err != nil && bad == head.Count, "truncation was not detected")
}
