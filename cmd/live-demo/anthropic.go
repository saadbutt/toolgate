package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/saadbutt/toolgate/internal/tools"
)

type anthropicProvider struct {
	apiKey string
	model  string
}

func (p *anthropicProvider) name() string { return p.model }

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string, or []block
}

type anthropicBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text,omitempty"`
	ID      string          `json:"id,omitempty"`
	Name    string          `json:"name,omitempty"`
	Input   json.RawMessage `json:"input,omitempty"`
	ToolUse string          `json:"tool_use_id,omitempty"`
	Content string          `json:"content,omitempty"`
}

type anthropicRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []anthropicMsg  `json:"messages"`
	Tools     []anthropicTool `json:"tools,omitempty"`
}

type anthropicResponse struct {
	Content    []anthropicBlock `json:"content"`
	StopReason string           `json:"stop_reason"`
	Error      *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *anthropicProvider) run(ctx context.Context, system, user string, toolDefs []tools.Tool,
	maxTurns int, exec func(string, map[string]any) string) (string, int, error) {

	var toolSpecs []anthropicTool
	for _, t := range toolDefs {
		toolSpecs = append(toolSpecs, anthropicTool{
			Name: t.Name, Description: t.Description, InputSchema: jsonSchema(t),
		})
	}

	messages := []anthropicMsg{{Role: "user", Content: user}}

	for turn := 1; turn <= maxTurns; turn++ {
		resp, err := p.call(ctx, system, messages, toolSpecs)
		if err != nil {
			return "", turn, err
		}
		if resp.Error != nil {
			return "", turn, errors.New(resp.Error.Message)
		}

		messages = append(messages, anthropicMsg{Role: "assistant", Content: resp.Content})

		var toolUses []anthropicBlock
		var text string
		for _, b := range resp.Content {
			switch b.Type {
			case "text":
				text += b.Text
			case "tool_use":
				toolUses = append(toolUses, b)
			}
		}

		if len(toolUses) == 0 {
			return text, turn, nil
		}

		var results []anthropicBlock
		for _, tu := range toolUses {
			var args map[string]any
			if err := json.Unmarshal(tu.Input, &args); err != nil {
				args = map[string]any{}
			}
			resultText := exec(tu.Name, args)
			results = append(results, anthropicBlock{
				Type: "tool_result", ToolUse: tu.ID, Content: resultText,
			})
		}
		messages = append(messages, anthropicMsg{Role: "user", Content: results})
	}

	return "", maxTurns, fmt.Errorf("stopped after %d turns without a final reply", maxTurns)
}

func (p *anthropicProvider) call(ctx context.Context, system string, messages []anthropicMsg,
	toolSpecs []anthropicTool) (*anthropicResponse, error) {

	body := anthropicRequest{
		Model: p.model, MaxTokens: 1024, System: system, Messages: messages, Tools: toolSpecs,
	}
	raw, err := postJSON(ctx, anthropicAPIURL, map[string]string{
		"x-api-key":         p.apiKey,
		"anthropic-version": "2023-06-01",
	}, body)
	if err != nil {
		return nil, err
	}
	var resp anthropicResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w (%s)", err, string(raw))
	}
	return &resp, nil
}
