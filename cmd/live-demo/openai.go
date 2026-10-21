package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/saadbutt/toolgate/internal/tools"
)

type openAIProvider struct {
	apiKey string
	model  string
}

func (p *openAIProvider) name() string { return p.model }

type openAIFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type openAITool struct {
	Type     string         `json:"type"`
	Function openAIFunction `json:"function"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAIMsg struct {
	Role       string           `json:"role"`
	Content    *string          `json:"content,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIRequest struct {
	Model    string       `json:"model"`
	Messages []openAIMsg  `json:"messages"`
	Tools    []openAITool `json:"tools,omitempty"`
}

type openAIResponse struct {
	Choices []struct {
		Message      openAIMsg `json:"message"`
		FinishReason string    `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func str(s string) *string { return &s }

func (p *openAIProvider) run(ctx context.Context, system, user string, toolDefs []tools.Tool,
	maxTurns int, exec func(string, map[string]any) string) (string, int, error) {

	var toolSpecs []openAITool
	for _, t := range toolDefs {
		toolSpecs = append(toolSpecs, openAITool{
			Type: "function",
			Function: openAIFunction{
				Name: t.Name, Description: t.Description, Parameters: jsonSchema(t),
			},
		})
	}

	messages := []openAIMsg{
		{Role: "system", Content: str(system)},
		{Role: "user", Content: str(user)},
	}

	for turn := 1; turn <= maxTurns; turn++ {
		resp, err := p.call(ctx, messages, toolSpecs)
		if err != nil {
			return "", turn, err
		}
		if resp.Error != nil {
			return "", turn, errors.New(resp.Error.Message)
		}
		if len(resp.Choices) == 0 {
			return "", turn, errors.New("no choices in response")
		}
		msg := resp.Choices[0].Message
		messages = append(messages, msg)

		if len(msg.ToolCalls) == 0 {
			if msg.Content != nil {
				return *msg.Content, turn, nil
			}
			return "", turn, nil
		}

		for _, tc := range msg.ToolCalls {
			var args map[string]any
			if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil {
				args = map[string]any{}
			}
			resultText := exec(tc.Function.Name, args)
			messages = append(messages, openAIMsg{
				Role: "tool", ToolCallID: tc.ID, Content: str(resultText),
			})
		}
	}

	return "", maxTurns, fmt.Errorf("stopped after %d turns without a final reply", maxTurns)
}

func (p *openAIProvider) call(ctx context.Context, messages []openAIMsg,
	toolSpecs []openAITool) (*openAIResponse, error) {

	body := openAIRequest{Model: p.model, Messages: messages, Tools: toolSpecs}
	raw, err := postJSON(ctx, openAIAPIURL, map[string]string{
		"Authorization": "Bearer " + p.apiKey,
	}, body)
	if err != nil {
		return nil, err
	}
	var resp openAIResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decoding response: %w (%s)", err, string(raw))
	}
	return &resp, nil
}
