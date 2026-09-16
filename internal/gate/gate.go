// Package gate is the single path a tool call has to take.
//
// Order matters and is fixed: charge a step, validate, charge money, decide,
// execute, record. Nothing here lets a caller skip a step or reorder them,
// because every interesting failure in agent systems comes from a step that
// was skipped once, for a good reason, in a hurry.
package gate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
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
//
// Every collaborator is unexported. If the executor were reachable, calling
// it directly would run a tool with no policy, no budget and no record, and
// "the single path" would be a convention rather than a property.
type Gate struct {
	tools   *tools.Registry
	policy  *policy.Engine
	budget  *budget.Ledger
	confirm *confirm.Store
	audit   *audit.Log
	exec    *exec.Executor

	now func() time.Time

	// requesters holds who asked for each pending intent, as they were when
	// they asked. The approval covers the arguments, not the authority behind
	// them, so ConfirmAndRun decides again against this.
	mu         sync.Mutex
	requesters map[string]requester
}

type requester struct {
	principal policy.Principal
	expires   time.Time
}

// New returns a Gate.
func New(reg *tools.Registry, pol *policy.Engine, bud *budget.Ledger, conf *confirm.Store, log *audit.Log) *Gate {
	g := &Gate{
		tools:      reg,
		policy:     pol,
		budget:     bud,
		confirm:    conf,
		audit:      log,
		now:        time.Now,
		requesters: make(map[string]requester),
	}
	// The executor's record of an effect is the one entry that must not be
	// lost, so a failed write is handed back. The executor then holds the call
	// as applied but unrecorded until Reconcile writes it.
	g.exec = exec.New(func(rec exec.Record) error {
		_, err := log.Record(audit.Entry{
			Tool:     rec.Tool,
			Decision: "executed",
			Rule:     "exec_record",
			Outcome:  "applied",
		}, map[string]any{"idempotency_key": rec.Key})
		return err
	})
	return g
}

// SetClock replaces the time source for tests.
func (g *Gate) SetClock(f func() time.Time) { g.now = f }

// Unrecorded lists executed calls whose effect happened but whose audit record
// could not be written.
func (g *Gate) Unrecorded() []exec.Record { return g.exec.Unrecorded() }

// Reconcile retries the audit record for every call Unrecorded lists. Run it
// on a timer, and whenever storage comes back.
func (g *Gate) Reconcile() (fixed int, err error) { return g.exec.Reconcile() }

var (
	// ErrMissingIdempotencyKey means a mutating call arrived without a key.
	ErrMissingIdempotencyKey = errors.New("gate: write and consequential calls need an idempotency key")
	// ErrNoApprover means a call needs confirmation but the principal acts on
	// behalf of no human who could give it.
	ErrNoApprover = errors.New("gate: confirmation needed but no human is named to approve it")
	// ErrApproverNotHuman means something other than a human tried to approve
	// an intent.
	ErrApproverNotHuman = errors.New("gate: only a human may approve an intent")
	// ErrUnknownIntent means the intent was not created by this gate, so no
	// policy decision stands behind it.
	ErrUnknownIntent = errors.New("gate: intent was not created through this gate")
)

// Submit runs one call through the whole path.
//
// Every refusal is recorded. A gate that only logs what it permitted tells
// you nothing about what someone tried.
func (g *Gate) Submit(ctx context.Context, p policy.Principal, c Call) (Outcome, error) {
	// 1. Charge the step before anything about the call is known to be valid.
	// Malformed calls are the most common model failure, so a ceiling that
	// only counted well-formed ones would miss the loop it exists to stop.
	if err := g.budget.Charge(p.ID, c.TokensUsed, 0); err != nil {
		g.deny(p, clip(c.Tool), rawArgs(c.Args), "budget_exceeded", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	tool, err := g.tools.Lookup(c.Tool)
	if err != nil {
		g.deny(p, clip(c.Tool), rawArgs(c.Args), "unknown_tool", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	// 2. Validate before anything else sees the arguments. Unvalidated
	// arguments must never reach policy, because policy decisions are made
	// about their values.
	clean, err := tool.Schema.Validate(c.Args)
	if err != nil {
		g.deny(p, tool.Name, rawArgs(c.Args), "schema_invalid", err.Error(), c.Model)
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	if tool.Risk != tools.Read && c.IdempotencyKey == "" {
		g.deny(p, tool.Name, clean, "missing_idempotency_key", ErrMissingIdempotencyKey.Error(), c.Model)
		return Outcome{Status: Refused, Reason: ErrMissingIdempotencyKey.Error()}, ErrMissingIdempotencyKey
	}

	// 3. Charge the money before deciding, now that validated arguments say
	// how much. A refused refund still counts, otherwise an agent can probe
	// its cap for free.
	req := policy.Request{Principal: p, Tool: tool, Args: clean, Now: g.now()}
	if amount, ok := req.Amount(); ok {
		if err := g.budget.ChargeMoney(p.ID, amount); err != nil {
			g.deny(p, tool.Name, clean, "budget_exceeded", err.Error(), c.Model)
			return Outcome{Status: Refused, Reason: err.Error()}, err
		}
	}

	// 4. Decide. Authority comes from p.Scope and nothing else.
	verdict := g.policy.Evaluate(req)

	switch verdict.Decision {
	case policy.Deny:
		return g.refuse(p, tool.Name, clean, verdict, c.Model)

	case policy.NeedsConfirmation:
		// The approver is the human the principal acts for. There is no
		// fallback: a principal acting for no one, or for itself, has nobody
		// who can say yes, so the answer is no.
		approver := p.OnBehalfOf
		if approver == "" || approver == p.ID {
			g.deny(p, tool.Name, clean, "no_approver", ErrNoApprover.Error(), c.Model)
			return Outcome{Status: Refused, Reason: ErrNoApprover.Error()}, ErrNoApprover
		}
		intent, token, err := g.confirm.Create(
			tool.Name, clean, summarise(tool, clean), p.ID, approver,
		)
		if err != nil {
			return Outcome{Status: Refused, Reason: err.Error()}, err
		}
		g.remember(intent, p)
		g.record(p, tool.Name, clean, verdict, "pending:"+intent.ID, c.Model)
		return Outcome{
			Status:  AwaitingConfirmation,
			Intent:  intent,
			Token:   token,
			Verdict: verdict,
			Reason:  verdict.Reason,
		}, nil
	}

	// 5. Execute.
	key := c.IdempotencyKey
	if key == "" {
		key = tool.Name + ":read:" + g.now().Format(time.RFC3339Nano)
	}
	res, replayed, err := g.exec.Do(ctx, key, tool, clean)
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
//
// Approval is not a way around policy. The call is charged, the approver has
// to be a human, and policy is evaluated again for both the principal that
// asked and the human approving, at the time of approval.
func (g *Gate) ConfirmAndRun(ctx context.Context, approver policy.Principal, intentID, token, idempotencyKey string) (Outcome, error) {
	// Charged like any other call, so presenting guesses is not free.
	if err := g.budget.Charge(approver.ID, 0, 0); err != nil {
		g.deny(approver, "confirm", nil, "budget_exceeded", err.Error(), "")
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	// Checked before the token is consumed. Refusing an impostor must leave
	// the intent intact for the human it was meant for.
	if approver.Kind != policy.Human {
		g.deny(approver, "confirm", nil, "approver_not_human", ErrApproverNotHuman.Error(), "")
		return Outcome{Status: Refused, Reason: ErrApproverNotHuman.Error()}, ErrApproverNotHuman
	}

	toolName, frozen, err := g.confirm.Confirm(intentID, token, approver.ID)
	if err != nil {
		g.deny(approver, "confirm", nil, "confirmation_rejected", err.Error(), "")
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	asker, ok := g.takeRequester(intentID)
	if !ok {
		g.deny(approver, toolName, frozen, "unknown_intent", ErrUnknownIntent.Error(), "")
		return Outcome{Status: Refused, Reason: ErrUnknownIntent.Error()}, ErrUnknownIntent
	}

	tool, err := g.tools.Lookup(toolName)
	if err != nil {
		g.deny(approver, toolName, frozen, "unknown_tool", err.Error(), "")
		return Outcome{Status: Refused, Reason: err.Error()}, err
	}

	// Decide again. A grant that expired while the intent waited has expired,
	// whatever the intent's own TTL says.
	now := g.now()
	if v := g.policy.Evaluate(policy.Request{Principal: asker, Tool: tool, Args: frozen, Now: now}); v.Decision == policy.Deny {
		return g.refuse(asker, tool.Name, frozen, v, "")
	}
	// The approver has to be allowed to do this themselves. Approving cannot
	// lend authority the approver does not hold.
	if v := g.policy.Evaluate(policy.Request{Principal: approver, Tool: tool, Args: frozen, Now: now}); v.Decision != policy.Allow {
		return g.refuse(approver, tool.Name, frozen, v, "")
	}

	if idempotencyKey == "" {
		idempotencyKey = "intent:" + intentID
	}

	res, replayed, err := g.exec.Do(ctx, idempotencyKey, tool, frozen)
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

// record writes a decision to the audit log.
//
// A failed write here is not retried. The refusal or pending intent it
// describes stands either way, and an executed effect also has the executor's
// own record, which Reconcile does retry. The README lists this as a limit.
func (g *Gate) record(p policy.Principal, tool string, args tools.Args, v policy.Verdict, outcome, model string) {
	_, _ = g.audit.Record(audit.Entry{
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

func (g *Gate) refuse(p policy.Principal, tool string, args tools.Args, v policy.Verdict, model string) (Outcome, error) {
	g.record(p, tool, args, v, "refused", model)
	return Outcome{Status: Refused, Verdict: v, Reason: v.Reason},
		fmt.Errorf("gate: refused by %s: %s", v.Rule, v.Reason)
}

// remember stores who asked for an intent, and forgets any whose intent has
// expired, so abandoned approvals do not accumulate.
func (g *Gate) remember(in *confirm.Intent, p policy.Principal) {
	// Scope is a value, but its Tools slice is not. Copy it so the caller
	// cannot widen the stored grant through their own slice.
	p.Scope.Tools = append([]string(nil), p.Scope.Tools...)

	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for id, r := range g.requesters {
		if now.After(r.expires) {
			delete(g.requesters, id)
		}
	}
	g.requesters[in.ID] = requester{principal: p, expires: in.ExpiresAt}
}

// takeRequester returns and forgets who asked for an intent. Confirm has
// already made sure only one caller gets this far per intent.
func (g *Gate) takeRequester(intentID string) (policy.Principal, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.requesters[intentID]
	delete(g.requesters, intentID)
	return r.principal, ok
}

// Bounds on how much unvalidated model output one refusal writes to the audit
// log. Arguments that failed validation never had MaxLen applied, and a model
// in a loop can send the same megabyte forever.
const (
	maxRawFields = 16
	maxRawLen    = 128
)

// clip shortens a string that came straight from the model.
func clip(s string) string {
	if len(s) <= maxRawLen {
		return s
	}
	return strings.ToValidUTF8(s[:maxRawLen], "") + "...[truncated]"
}

// rawArgs is what gets recorded for arguments that never passed validation:
// the first maxRawFields fields in key order, keys and strings clipped, and
// anything that is not a scalar replaced by its type.
func rawArgs(args tools.Args) tools.Args {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make(tools.Args, maxRawFields+1)
	for i, k := range keys {
		if i == maxRawFields {
			out["[omitted_fields]"] = len(keys) - maxRawFields
			break
		}
		switch v := args[k].(type) {
		case string:
			out[clip(k)] = clip(v)
		case nil, bool, int, int64, float64:
			out[clip(k)] = v
		default:
			out[clip(k)] = fmt.Sprintf("[%T]", v)
		}
	}
	return out
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
