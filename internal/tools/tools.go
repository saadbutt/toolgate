// Package tools is the registry of things an agent is allowed to ask for, and
// the schema check that runs before any of them are handed model output.
//
// The rule this package exists to enforce: arguments produced by a language
// model are a request, not a fact. They are validated against a declared
// contract first, and anything that does not match is refused rather than
// coerced into something that looks plausible.
package tools

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Risk determines how much ceremony a call needs before it can happen.
type Risk int

const (
	// Read cannot change anything. Cheap to allow.
	Read Risk = iota
	// Write changes internal state but is recoverable.
	Write
	// Consequential moves money, sends things to third parties, or is
	// otherwise not undoable. Never executes without explicit confirmation.
	Consequential
)

func (r Risk) String() string {
	switch r {
	case Read:
		return "read"
	case Write:
		return "write"
	case Consequential:
		return "consequential"
	default:
		return "unknown"
	}
}

// FieldType is the small set of argument types this registry accepts.
//
// It is deliberately small. A permissive schema language is a place for
// surprises to hide, and every type here has an obvious validation rule.
type FieldType int

const (
	String FieldType = iota
	Int
	Bool
	// Money is an integer minor unit (cents). Floats are not offered on
	// purpose: a rounding error in a refund is a real incident.
	Money
)

func (t FieldType) String() string {
	switch t {
	case String:
		return "string"
	case Int:
		return "int"
	case Bool:
		return "bool"
	case Money:
		return "money"
	default:
		return "unknown"
	}
}

// Field is one declared argument.
type Field struct {
	Name     string
	Type     FieldType
	Required bool
	// Min and Max bound Int and Money fields, and are inclusive.
	Min, Max int64
	// MaxLen bounds String fields.
	MaxLen int
	// Enum, when set, is the complete set of permitted String values.
	Enum []string
}

// Schema is the full argument contract for one tool.
type Schema struct {
	Fields []Field
}

// Args is a decoded set of tool arguments.
type Args map[string]any

// Result is whatever a tool hands back. Text is treated as untrusted by
// everything downstream; see the untrusted package.
type Result struct {
	Text string
	Data map[string]any
}

// Handler performs the actual work of a tool.
type Handler func(ctx context.Context, args Args) (Result, error)

// Tool is one capability, with its contract attached.
type Tool struct {
	Name        string
	Description string
	Risk        Risk
	Schema      Schema
	// Idempotent declares that repeating the call with the same idempotency
	// key must not repeat the effect. Required for Write and Consequential.
	Idempotent bool
	Handler    Handler
}

// Registry holds the tools an agent may ask for by name.
type Registry struct {
	byName map[string]Tool
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]Tool)}
}

var (
	// ErrUnknownTool means the model asked for something not registered.
	ErrUnknownTool = errors.New("tools: unknown tool")
	// ErrNotIdempotent means a mutating tool was registered without an
	// idempotency guarantee.
	ErrNotIdempotent = errors.New("tools: write and consequential tools must be idempotent")
)

// Register adds a tool.
//
// Mutating tools are required to be idempotent at registration time rather
// than at call time. Retries are not optional in a distributed system, so a
// tool that cannot survive one does not belong behind this gate at all.
func (r *Registry) Register(t Tool) error {
	if t.Name == "" {
		return errors.New("tools: tool needs a name")
	}
	if t.Handler == nil {
		return fmt.Errorf("tools: %s has no handler", t.Name)
	}
	if t.Risk != Read && !t.Idempotent {
		return fmt.Errorf("%w: %s", ErrNotIdempotent, t.Name)
	}
	if _, dup := r.byName[t.Name]; dup {
		return fmt.Errorf("tools: %s already registered", t.Name)
	}
	r.byName[t.Name] = t
	return nil
}

// Lookup returns a tool by name.
func (r *Registry) Lookup(name string) (Tool, error) {
	t, ok := r.byName[name]
	if !ok {
		return Tool{}, fmt.Errorf("%w: %q", ErrUnknownTool, name)
	}
	return t, nil
}

// Names lists registered tools in sorted order.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ValidationError describes exactly why an argument set was refused.
//
// It is structured rather than a formatted string because the agent is
// expected to read it and retry. A model that is told "field amount_cents
// exceeds maximum 50000" can correct itself; one told "invalid input" cannot.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return "tools: " + e.Reason
	}
	return fmt.Sprintf("tools: field %q: %s", e.Field, e.Reason)
}

// Validate checks args against the schema and returns a normalised copy.
//
// Normalisation matters: the returned Args is what gets hashed for
// confirmation and what gets executed. If validation and execution could
// disagree about the value of a field, the confirmation step would be
// meaningless.
func (s Schema) Validate(args Args) (Args, error) {
	known := make(map[string]Field, len(s.Fields))
	for _, f := range s.Fields {
		known[f.Name] = f
	}

	// Unknown fields are rejected, not ignored. Silently dropping an
	// unexpected argument is how a caller ends up believing it constrained
	// something it did not.
	extra := make([]string, 0)
	for k := range args {
		if _, ok := known[k]; !ok {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return nil, &ValidationError{Reason: "unexpected fields: " + strings.Join(extra, ", ")}
	}

	out := make(Args, len(s.Fields))
	for _, f := range s.Fields {
		raw, present := args[f.Name]
		if !present {
			if f.Required {
				return nil, &ValidationError{Field: f.Name, Reason: "required"}
			}
			continue
		}
		v, err := coerce(f, raw)
		if err != nil {
			return nil, err
		}
		out[f.Name] = v
	}
	return out, nil
}

func coerce(f Field, raw any) (any, error) {
	switch f.Type {
	case String:
		s, ok := raw.(string)
		if !ok {
			return nil, &ValidationError{Field: f.Name, Reason: "expected string, got " + describe(raw)}
		}
		if f.MaxLen > 0 && len(s) > f.MaxLen {
			return nil, &ValidationError{Field: f.Name, Reason: fmt.Sprintf("longer than %d characters", f.MaxLen)}
		}
		if len(f.Enum) > 0 {
			for _, allowed := range f.Enum {
				if s == allowed {
					return s, nil
				}
			}
			return nil, &ValidationError{Field: f.Name, Reason: "must be one of: " + strings.Join(f.Enum, ", ")}
		}
		return s, nil

	case Int, Money:
		n, err := toInt64(raw)
		if err != nil {
			return nil, &ValidationError{Field: f.Name, Reason: "expected " + f.Type.String() + ", got " + describe(raw)}
		}
		if f.Type == Money && n < 0 {
			return nil, &ValidationError{Field: f.Name, Reason: "must not be negative"}
		}
		if f.Max != 0 && n > f.Max {
			return nil, &ValidationError{Field: f.Name, Reason: fmt.Sprintf("exceeds maximum %d", f.Max)}
		}
		if n < f.Min {
			return nil, &ValidationError{Field: f.Name, Reason: fmt.Sprintf("below minimum %d", f.Min)}
		}
		return n, nil

	case Bool:
		b, ok := raw.(bool)
		if !ok {
			return nil, &ValidationError{Field: f.Name, Reason: "expected bool, got " + describe(raw)}
		}
		return b, nil
	}
	return nil, &ValidationError{Field: f.Name, Reason: "unsupported field type"}
}

// toInt64 accepts the numeric shapes that survive a JSON round trip.
//
// float64 is included because encoding/json decodes every number that way,
// but a fractional value is refused rather than truncated. Quietly turning
// 10.7 into 10 is the kind of helpfulness that loses money.
func toInt64(raw any) (int64, error) {
	switch v := raw.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		if v != float64(int64(v)) {
			return 0, errors.New("not a whole number")
		}
		return int64(v), nil
	default:
		return 0, errors.New("not a number")
	}
}

func describe(v any) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%T", v)
}
