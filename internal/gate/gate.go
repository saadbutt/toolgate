// Package gate is the single path a tool call has to take.
//
// Order matters and is fixed: validate, charge, decide, execute, record.
// Nothing here lets a caller skip a step or reorder them, because every
// interesting failure in agent systems comes from a step that was skipped
// once, for a good reason, in a hurry.
package gate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/saadbutt/toolgate/internal/audit"
	"github.com/saadbutt/toolgate/internal/budget"
	"github.com/saadbutt/toolgate/internal/confirm"
	"github.com/saadbutt/toolgate/internal/exec"
	"github.com/saadbutt/toolgate/internal/policy"
	"github.com/saadbutt/toolgate/internal/tools"
	"github.com/saadbutt/toolgate/internal/untrusted"
)

// Status is what happened to a submitted call.
type Status int

const (
	// Executed means the tool ran.
	Executed Status = iota
	// AwaitingConfirmation means a pending intent was created instead.
	AwaitingConfirmation
	// Refused means policy, schema or budget said no.
	Refused
)

func (s Status) String() string {
	switch s {
	case Executed:
		return "executed"
	case AwaitingConfirmation:
		return "awaiting_confirmation"
	default:
		return "refused"
	}
}

// Outcome is the result of submitting a call.
type Outcome struct {
	Status Status
	Result tools.Result
	// Content is the tool's text output, already marked untrusted.
	Content untrusted.Content
	// Intent is set when Status is AwaitingConfirmation.
	Intent *confirm.Intent
	// Token is the one-time approval token, returned once.
	Token string
	// Verdict records what policy decided and which rule decided it.
	Verdict policy.Verdict
	// Reason is a human-readable explanation, always populated.
	Reason string
	// Replayed is true when an idempotency key short-circuited execution.
	Replayed bool
}

// Call is a request from an agent.
type Call struct {
	Tool string
	Args tools.Args
	// IdempotencyKey is required for Write and Consequential tools.
	IdempotencyKey string
	// TokensUsed is what the model spent deciding to make this call.
	TokensUsed int64
	// Model identifies what produced the call, for the audit trail.
	Model string
}

// Gate wires the pieces together.
type Gate struct {
	Tools   *tools.Registry
	Policy  *policy.Engine
	Budget  *budget.Ledger
	Confirm *confirm.Store
	Audit   *audit.Log
	Exec    *exec.Executor

	now func() time.Time
}

// New returns a Gate.
func New(reg *tools.Registry, pol *policy.Engine, bud *budget.Ledger, conf *confirm.Store, log *audit.Log) *Gate {
	g := &Gate{
		Tools:   reg,
		Policy:  pol,
		Budget:  bud,
		Confirm: conf,
		Audit:   log,
		now:     time.Now,
	}
	g.Exec = exec.New(func(rec exec.Record) error {
		log.Record(audit.Entry{
			Tool:     rec.Tool,
			Decision: "executed",
			Rule:     "exec_record",
			Outcome:  rec.State.String(),
		}, map[string]any{"idempotency_key": rec.Key})
		return nil
	})
	return g
}

// SetClock replaces the time source for tests.
func (g *Gate) SetClock(f func() time.Time) { g.now = f }

// ErrMissingIdempotencyKey means a mutating call arrived without a key.
var ErrMissingIdempotencyKey = errors.New("gate: write and consequential calls need an idempotency key")

// Submit runs one call through the whole path.
//
// Every refusal is recorded. A gate that only logs what it permitted tells
// you nothing about what someone tried.
func (g *Gate) Submit(ctx context.Context, p policy.Principal, c Call) (Outcome, error) {
	tool, err := g.Tools.Lookup(c.Tool)
	if err != nil {
		g.deny(p, c.Tool, c.Args, "unknown_tool", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	// 1. Validate before anything else. Unvalidated arguments must never
	// reach policy, because policy decisions are made about their values.
	clean, err := tool.Schema.Validate(c.Args)
	if err != nil {
		g.deny(p, tool.Name, c.Args, "schema_invalid", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	if tool.Risk != tools.Read && c.IdempotencyKey == "" {
		g.deny(p, tool.Name, clean, "missing_idempotency_key", ErrMissingIdempotencyKey.Error(), c.Model)
		return Outcome{Status: Refused, Reason: ErrMissingIdempotencyKey.Error()}, ErrMissingIdempotencyKey
	}

	// 2. Charge the budget before deciding. A refused call still consumed a
	// step, otherwise an agent can probe the policy engine for free.
	req := policy.Request{Principal: p, Tool: tool, Args: clean, Now: g.now()}
	amount, _ := req.Amount()
	if err := g.Budget.Charge(p.ID, c.TokensUsed, amount); err != nil {
		g.deny(p, tool.Name, clean, "budget_exceeded", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	// 3. Decide. Authority comes from p.Scope and nothing else.
	verdict := g.Policy.Evaluate(req)

	switch verdict.Decision {
	case policy.Deny:
		g.record(p, tool.Name, clean, verdict, "refused", c.Model)
		return Outcome{Status: Refused, Verdict: verdict, Reason: verdict.Reason},
			fmt.Errorf("gate: refused by %s: %s", verdict.Rule, verdict.Reason)

	case policy.NeedsConfirmation:
		approver := p.OnBehalfOf
		if approver == "" {
			approver = p.ID
		}
		intent, token, err := g.Confirm.Create(
			tool.Name, clean, summarise(tool, clean), p.ID, approver,
		)
		if err != nil {
			return Outcome{Status: Refused, Reason: err.Error()}, err
		}
		g.record(p, tool.Name, clean, verdict, "pending:"+intent.ID, c.Model)
		return Outcome{
			Status:  AwaitingConfirmation,
			Intent:  intent,
			Token:   token,
			Verdict: verdict,
			Reason:  verdict.Reason,
		}, nil
	}

	// 4. Execute.
	key := c.IdempotencyKey
	if key == "" {
		key = tool.Name + ":read:" + g.now().Format(time.RFC3339Nano)
	}
	res, replayed, err := g.Exec.Do(ctx, key, tool, clean)
	if err != nil {
		g.record(p, tool.Name, clean, verdict, "error:"+err.Error(), c.Model)
		return Outcome{Status: Refused, Verdict: verdict, Reason: err.Error()}, err
	}

	g.record(p, tool.Name, clean, verdict, outcomeWord(replayed), c.Model)
	return Outcome{
		Status:   Executed,
		Result:   res,
		Content:  untrusted.FromTool(tool.Name, res.Text),
		Verdict:  verdict,
		Reason:   verdict.Reason,
		Replayed: replayed,
	}, nil
}

// ConfirmAndRun approves a pending intent and executes the frozen arguments.
//
// The arguments are not a parameter. That is the design: the caller cannot
// supply them, so the caller cannot change them between approval and effect.
func (g *Gate) ConfirmAndRun(ctx context.Context, approver policy.Principal, intentID, token, idempotencyKey string) (Outcome, error) {
	toolName, frozen, err := g.Confirm.Confirm(intentID, token, approver.ID)
	if err != nil {
		g.deny(approver, "confirm", nil, "confirmation_rejected", err.Error(), "")
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	tool, err := g.Tools.Lookup(toolName)
	if err != nil {
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}
	if idempotencyKey == "" {
		idempotencyKey = "intent:" + intentID
	}

	res, replayed, err := g.Exec.Do(ctx, idempotencyKey, tool, frozen)
	verdict := policy.Verdict{
		Decision: policy.Allow,
		Rule:     "human_confirmed",
		Reason:   "executed under human approval of intent " + intentID,
	}
	if err != nil {
		g.record(approver, tool.Name, frozen, verdict, "error:"+err.Error(), "")
		return Outcome{Status: Refused, Verdict: verdict, Reason: err.Error()}, err
	}

	g.record(approver, tool.Name, frozen, verdict, outcomeWord(replayed), "")
	return Outcome{
		Status:   Executed,
		Result:   res,
		Content:  untrusted.FromTool(tool.Name, res.Text),
		Verdict:  verdict,
		Reason:   verdict.Reason,
		Replayed: replayed,
	}, nil
}

func (g *Gate) record(p policy.Principal, tool string, args tools.Args, v policy.Verdict, outcome, model string) {
	g.Audit.Record(audit.Entry{
		Principal: p.ID,
		Actor:     p.Kind.String(),
		Tool:      tool,
		Decision:  v.Decision.String(),
		Rule:      v.Rule,
		Outcome:   outcome,
		Model:     model,
	}, map[string]any(args))
}

func (g *Gate) deny(p policy.Principal, tool string, args tools.Args, rule, reason, model string) {
	g.record(p, tool, args, policy.Verdict{Decision: policy.Deny, Rule: rule, Reason: reason}, "refused", model)
}

func outcomeWord(replayed bool) string {
	if replayed {
		return "replayed"
	}
	return "ok"
}

// summarise builds the sentence a human reads before approving.
//
// It is generated from validated arguments, never from model-written prose.
// If the model could write the summary, it could describe one action and
// request another.
func summarise(t tools.Tool, args tools.Args) string {
	s := t.Description
	if s == "" {
		s = t.Name
	}
	for _, f := range t.Schema.Fields {
		v, ok := args[f.Name]
		if !ok {
			continue
		}
		if f.Type == tools.Money {
			if n, ok := v.(int64); ok {
				s += fmt.Sprintf(" | %s: %s", f.Name, money(n))
				continue
			}
		}
		s += fmt.Sprintf(" | %s: %v", f.Name, v)
	}
	return s
}

func money(cents int64) string {
	return fmt.Sprintf("$%d.%02d", cents/100, cents%100)
}
