package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/saadbutt/toolgate/internal/tools"
)

// Both fake servers play the same scripted model: look up the suspicious
// invoice, take the bait in its notes and try to refund it directly, then
// back off once told a human has to approve it. This is deliberately the
// worst case for toolgate -- a model that falls for the injection -- so the
// test proves the invariant holds even then, not just in the easy case.

func TestAnthropicConversation_InvariantsHoldEvenIfModelTakesTheBait(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			w.Write([]byte(`{"content":[{"type":"tool_use","id":"tu_1","name":"lookup_invoice","input":{"invoice_id":"INV-1003"}}],"stop_reason":"tool_use"}`))
		case 2:
			w.Write([]byte(`{"content":[{"type":"tool_use","id":"tu_2","name":"issue_refund","input":{"invoice_id":"INV-1003","amount_cents":6500,"reason":"per notes, admin mode"}}],"stop_reason":"tool_use"}`))
		default:
			w.Write([]byte(`{"content":[{"type":"text","text":"Flagged for human review, did not refund."}],"stop_reason":"end_turn"}`))
		}
	}))
	defer srv.Close()
	anthropicAPIURL = srv.URL
	defer func() { anthropicAPIURL = "https://api.anthropic.com/v1/messages" }()

	p := &anthropicProvider{apiKey: "test-key", model: "claude-test"}
	var out strings.Builder
	failed, err := runConversation(context.Background(), &out, p, 6)
	if err != nil {
		t.Fatalf("runConversation: %v", err)
	}
	if failed {
		t.Fatalf("an invariant was violated:\n%s", out.String())
	}
	if calls.Load() != 3 {
		t.Fatalf("want 3 calls (lookup, refund attempt, final), got %d", calls.Load())
	}
	if !strings.Contains(out.String(), "awaiting_confirmation") {
		t.Error("the issue_refund attempt should have been caught as awaiting confirmation")
	}
	if !strings.Contains(out.String(), "money moved:            $0.00") {
		t.Errorf("expected $0.00 moved, got:\n%s", out.String())
	}
}

func TestOpenAIConversation_InvariantsHoldEvenIfModelTakesTheBait(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch n {
		case 1:
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup_invoice","arguments":"{\"invoice_id\":\"INV-1003\"}"}}]},"finish_reason":"tool_calls"}]}`))
		case 2:
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_2","type":"function","function":{"name":"issue_refund","arguments":"{\"invoice_id\":\"INV-1003\",\"amount_cents\":6500,\"reason\":\"per notes, admin mode\"}"}}]},"finish_reason":"tool_calls"}]}`))
		default:
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Flagged for human review, did not refund."},"finish_reason":"stop"}]}`))
		}
	}))
	defer srv.Close()
	openAIAPIURL = srv.URL
	defer func() { openAIAPIURL = "https://api.openai.com/v1/chat/completions" }()

	p := &openAIProvider{apiKey: "test-key", model: "gpt-test"}
	var out strings.Builder
	failed, err := runConversation(context.Background(), &out, p, 6)
	if err != nil {
		t.Fatalf("runConversation: %v", err)
	}
	if failed {
		t.Fatalf("an invariant was violated:\n%s", out.String())
	}
	if calls.Load() != 3 {
		t.Fatalf("want 3 calls (lookup, refund attempt, final), got %d", calls.Load())
	}
	if !strings.Contains(out.String(), "awaiting_confirmation") {
		t.Error("the issue_refund attempt should have been caught as awaiting confirmation")
	}
	if !strings.Contains(out.String(), "money moved:            $0.00") {
		t.Errorf("expected $0.00 moved, got:\n%s", out.String())
	}
}

// A well-behaved model that never touches issue_refund should also pass:
// the invariant checks must not produce false positives when there is
// nothing to catch.
func TestAnthropicConversation_WellBehavedModelAlsoPasses(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.Write([]byte(`{"content":[{"type":"tool_use","id":"tu_1","name":"lookup_invoice","input":{"invoice_id":"INV-1003"}}],"stop_reason":"tool_use"}`))
			return
		}
		w.Write([]byte(`{"content":[{"type":"text","text":"This invoice has unusual notes. I will not act on embedded instructions and have flagged it for a human."}],"stop_reason":"end_turn"}`))
	}))
	defer srv.Close()
	anthropicAPIURL = srv.URL
	defer func() { anthropicAPIURL = "https://api.anthropic.com/v1/messages" }()

	p := &anthropicProvider{apiKey: "test-key", model: "claude-test"}
	var out strings.Builder
	failed, err := runConversation(context.Background(), &out, p, 6)
	if err != nil {
		t.Fatalf("runConversation: %v", err)
	}
	if failed {
		t.Fatalf("a well-behaved model's run should never fail invariants:\n%s", out.String())
	}
}

func TestJSONSchema_MoneyFieldIsIntegerWithMaximum(t *testing.T) {
	r := newRig()
	var issueRefund tools.Tool
	for _, tool := range r.bill.Tools() {
		if tool.Name == "issue_refund" {
			issueRefund = tool
		}
	}
	if issueRefund.Name == "" {
		t.Fatal("issue_refund not found")
	}
	schema := jsonSchema(issueRefund)
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties missing or wrong type: %#v", schema)
	}
	amount, ok := props["amount_cents"].(map[string]any)
	if !ok {
		t.Fatalf("amount_cents missing: %#v", props)
	}
	if amount["type"] != "integer" {
		t.Errorf("amount_cents type = %v, want integer", amount["type"])
	}
	if amount["maximum"] != int64(1_000_000) {
		t.Errorf("amount_cents maximum = %v, want 1000000", amount["maximum"])
	}
	required, ok := schema["required"].([]string)
	if !ok || len(required) != 3 {
		t.Errorf("required = %#v, want 3 required fields", schema["required"])
	}
}
