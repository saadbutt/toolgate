// Package policy decides whether a requested tool call is permitted.
//
// The central claim of this repo lives here: an agent's authority is derived
// from the principal it acts for, it is fixed for the life of a session, and
// nothing the agent reads, receives or requests can widen it.
package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/saadbutt/toolgate/internal/tools"
)

// Kind distinguishes the three things that can hold authority.
//
// The zero Kind is not a kind, and a principal holding it is refused. If zero
// meant Human, a principal whose Kind was forgotten would hold full authority
// with no scope and no confirmation.
type Kind int

const (
	// Human acts with their own authority.
	Human Kind = iota + 1
	// Agent acts with a scoped, expiring subset of a human's authority.
	Agent
	// Service is an internal component. It has its own identity and is still
	// subject to policy, because "internal" is not a security boundary.
	Service
)

// Valid reports whether k is one of the declared kinds.
func (k Kind) Valid() bool { return k >= Human && k <= Service }

func (k Kind) String() string {
	switch k {
	case Human:
		return "human"
	case Agent:
		return "agent"
	case Service:
		return "service"
	default:
		return "unknown"
	}
}

// ToolSet is a fixed set of tool names. Build one with NewToolSet.
//
// Its contents are unexported, never written after construction, and only
// ever handed out as copies. A plain []string would not do: a slice copied by
// value still shares its backing array, so every copy of a Scope could write
// into the grant it was copied from.
type ToolSet struct {
	names []string // sorted, no duplicates
}

// NewToolSet builds a ToolSet. The names are copied, so changing the slice
// afterwards changes nothing.
func NewToolSet(names ...string) ToolSet {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	return ToolSet{names: slices.Compact(sorted)}
}

// Contains reports whether name is in the set.
func (t ToolSet) Contains(name string) bool {
	_, found := slices.BinarySearch(t.names, name)
	return found
}

// Names returns the tool names in sorted order, as a copy.
func (t ToolSet) Names() []string { return append([]string(nil), t.names...) }

// Scope is the capability grant an agent operates under.
//
// It is passed by value everywhere on purpose. There is no method on this
// type that widens it, nothing in the request path holds a pointer that could
// be mutated mid-session, and every field is either a plain value or
// immutable, so a copy cannot reach back into the grant it came from.
type Scope struct {
	// Tools is the complete set of tool names this principal may call.
	Tools ToolSet
	// MaxAmount caps money-moving calls, in minor units.
	MaxAmount int64
	// ExpiresAt bounds the grant in time. Zero means no expiry, which is
	// only appropriate for Human principals.
	ExpiresAt time.Time
}

// Fingerprint returns a stable string identifying exactly this grant.
//
// The demo and the tests use it to assert that a scope did not move after the
// agent processed hostile content. Comparing a fingerprint is a cheap way to
// state "authority is unchanged" as a checkable fact rather than a hope.
func (s Scope) Fingerprint() string {
	names := s.Tools.names
	exp := "never"
	if !s.ExpiresAt.IsZero() {
		exp = s.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("tools=[%s] max=%d exp=%s", strings.Join(names, ","), s.MaxAmount, exp)
}

// Allows reports whether the named tool is inside this grant.
func (s Scope) Allows(tool string) bool { return s.Tools.Contains(tool) }

// Principal is who is asking.
type Principal struct {
	ID   string
	Kind Kind
	// OnBehalfOf is set for Agent principals and names the human whose
	// authority is being exercised.
	OnBehalfOf string
	Scope      Scope
}

// Request is one evaluated call.
type Request struct {
	Principal Principal
	Tool      tools.Tool
	Args      tools.Args
	Now       time.Time
}

// Amount extracts the money field from the request, if the tool has one.
func (r Request) Amount() (int64, bool) {
	for _, f := range r.Tool.Schema.Fields {
		if f.Type == tools.Money {
			if v, ok := r.Args[f.Name].(int64); ok {
				return v, true
			}
		}
	}
	return 0, false
}

// Decision is the outcome of evaluating a request.
type Decision int

const (
	// Deny is the default. Nothing executes without a rule saying otherwise.
	Deny Decision = iota
	// Allow permits immediate execution.
	Allow
	// NeedsConfirmation permits execution only after a human approves the
	// exact arguments.
	NeedsConfirmation
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case NeedsConfirmation:
		return "needs_confirmation"
	default:
		return "deny"
	}
}

// Verdict carries the decision plus the rule that produced it.
//
// Recording which rule fired is not decoration. When someone asks six months
// later why an agent was allowed to do something, "rule: agent_within_scope"
// is an answer and "allowed: true" is not.
type Verdict struct {
	Decision Decision
	Rule     string
	Reason   string
}

// Rule is one ordered policy check. The first rule to match decides.
type Rule struct {
	Name  string
	Match func(Request) bool
	Then  Decision
	// Reason is shown to the caller and written to the audit log.
	Reason string
}

// Engine evaluates requests against an ordered rule set. Safe for concurrent
// use: whoever built the engine still holds it after handing it to a gate.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine returns an engine with no rules, which denies everything.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: append([]Rule(nil), rules...)}
}

// Add appends a rule to the end of the chain.
func (e *Engine) Add(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// Evaluate runs the chain and returns the first matching verdict.
//
// The chain is read under the lock and run outside it. Add only ever appends,
// so the rules seen here cannot change underneath, and a Match function that
// itself touches the engine cannot deadlock.
func (e *Engine) Evaluate(req Request) Verdict {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()
	for _, r := range rules {
		if r.Match(req) {
			return Verdict{Decision: r.Then, Rule: r.Name, Reason: r.Reason}
		}
	}
	return Verdict{
		Decision: Deny,
		Rule:     "default_deny",
		Reason:   "no rule permitted this call",
	}
}

// DefaultRules is the rule set the demo runs with.
//
// Order is the whole design. The validity, expiry and scope checks come
// before anything that could allow, so there is no path where a later
// permissive rule rescues a request that should already have been refused.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:   "unknown_principal_kind",
			Reason: "the principal has no valid kind, so it holds no authority",
			Then:   Deny,
			Match: func(r Request) bool {
				return !r.Principal.Kind.Valid()
			},
		},
		{
			Name:   "unknown_risk",
			Reason: "the tool declares no valid risk class",
			Then:   Deny,
			Match: func(r Request) bool {
				return !r.Tool.Risk.Valid()
			},
		},
		{
			Name:   "expired_grant",
			Reason: "the agent's capability grant has expired",
			Then:   Deny,
			Match: func(r Request) bool {
				exp := r.Principal.Scope.ExpiresAt
				return !exp.IsZero() && r.Now.After(exp)
			},
		},
		{
			Name:   "tool_outside_scope",
			Reason: "this tool is not in the principal's grant",
			Then:   Deny,
			Match: func(r Request) bool {
				if r.Principal.Kind == Human {
					return false
				}
				return !r.Principal.Scope.Allows(r.Tool.Name)
			},
		},
		{
			Name:   "amount_above_grant",
			Reason: "the amount exceeds the principal's cap",
			Then:   Deny,
			Match: func(r Request) bool {
				amt, ok := r.Amount()
				if !ok || r.Principal.Kind == Human {
					return false
				}
				return r.Principal.Scope.MaxAmount > 0 && amt > r.Principal.Scope.MaxAmount
			},
		},
		{
			Name:   "consequential_needs_human",
			Reason: "consequential actions require explicit confirmation",
			Then:   NeedsConfirmation,
			Match: func(r Request) bool {
				return r.Tool.Risk == tools.Consequential && r.Principal.Kind != Human
			},
		},
		{
			Name:   "read_within_scope",
			Reason: "read-only call inside the grant",
			Then:   Allow,
			Match: func(r Request) bool {
				return r.Tool.Risk == tools.Read
			},
		},
		{
			Name:   "write_within_scope",
			Reason: "recoverable write inside the grant",
			Then:   Allow,
			Match: func(r Request) bool {
				return r.Tool.Risk == tools.Write
			},
		},
		{
			Name:   "human_direct",
			Reason: "human acting with their own authority",
			Then:   Allow,
			Match: func(r Request) bool {
				return r.Principal.Kind == Human
			},
		},
	}
}
