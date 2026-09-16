package tools_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/saadbutt/toolgate/internal/tools"
)

func schema() tools.Schema {
	return tools.Schema{Fields: []tools.Field{
		{Name: "id", Type: tools.String, Required: true, MaxLen: 10},
		{Name: "amount_cents", Type: tools.Money, Required: true, Max: 1000},
		{Name: "mode", Type: tools.String, Enum: []string{"full", "partial"}},
		{Name: "dry_run", Type: tools.Bool},
	}}
}

func TestValidArgumentsPass(t *testing.T) {
	out, err := schema().Validate(tools.Args{
		"id": "INV-1", "amount_cents": float64(250), "mode": "partial", "dry_run": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["amount_cents"] != int64(250) {
		t.Fatalf("money normalised to %#v", out["amount_cents"])
	}
}

// TestUnknownFieldsAreRejected guards against smuggling arguments past a
// schema that only checks the fields it knows about.
func TestUnknownFieldsAreRejected(t *testing.T) {
	_, err := schema().Validate(tools.Args{
		"id": "INV-1", "amount_cents": 100, "skip_approval": true,
	})
	var ve *tools.ValidationError
	if !errors.As(err, &ve) || !strings.Contains(ve.Reason, "skip_approval") {
		t.Fatalf("unknown field accepted: %v", err)
	}
}

func TestFractionalMoneyIsRejectedNotTruncated(t *testing.T) {
	_, err := schema().Validate(tools.Args{"id": "INV-1", "amount_cents": 10.7})
	if err == nil {
		t.Fatal("10.7 cents was accepted")
	}
}

func TestEnumIsEnforced(t *testing.T) {
	if _, err := schema().Validate(tools.Args{"id": "I", "amount_cents": 1, "mode": "whatever"}); err == nil {
		t.Fatal("enum not enforced")
	}
}

func TestBoundsAreEnforced(t *testing.T) {
	if _, err := schema().Validate(tools.Args{"id": "I", "amount_cents": 5000}); err == nil {
		t.Fatal("max not enforced")
	}
	if _, err := schema().Validate(tools.Args{"id": "way-too-long-id", "amount_cents": 1}); err == nil {
		t.Fatal("maxlen not enforced")
	}
}

// TestMutatingToolsMustDeclareIdempotency is a registration-time guard: a
// tool that cannot survive a retry should never get behind the gate.
func TestMutatingToolsMustDeclareIdempotency(t *testing.T) {
	r := tools.NewRegistry()
	err := r.Register(tools.Tool{
		Name: "danger", Risk: tools.Consequential,
		Handler: func(context.Context, tools.Args) (tools.Result, error) { return tools.Result{}, nil },
	})
	if !errors.Is(err, tools.ErrNotIdempotent) {
		t.Fatalf("non-idempotent mutating tool registered: %v", err)
	}
}

func TestValidationErrorNamesTheField(t *testing.T) {
	_, err := schema().Validate(tools.Args{"id": "I", "amount_cents": 9999})
	var ve *tools.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("not a ValidationError: %v", err)
	}
	if ve.Field != "amount_cents" || !strings.Contains(ve.Reason, "1000") {
		t.Fatalf("unhelpful error for a retrying agent: %+v", ve)
	}
}

// TestRegistryIsSafeForConcurrentUse registers tools while other goroutines
// look them up. The caller keeps the registry it handed to the gate, so this
// is reachable at runtime. Run it under -race.
func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	r := tools.NewRegistry()
	noop := func(context.Context, tools.Args) (tools.Result, error) { return tools.Result{}, nil }

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		name := fmt.Sprintf("tool-%d", i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.Register(tools.Tool{Name: name, Risk: tools.Read, Handler: noop})
		}()
		go func() {
			defer wg.Done()
			_, _ = r.Lookup(name)
			_ = r.Names()
		}()
	}
	wg.Wait()
	if got := len(r.Names()); got != 16 {
		t.Fatalf("registered %d tools, want 16", got)
	}
}
