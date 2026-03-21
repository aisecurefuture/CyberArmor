package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
)

const defaultBaseURL = "https://api.anthropic.com/v1"

// Client is a native Anthropic provider client with CyberArmor policy and audit hooks.
type Client struct {
	CA      *cyberarmor.Client
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// New builds a native Anthropic provider client.
func New(ca *cyberarmor.Client, apiKey string) *Client {
	return &Client{
		CA:      ca,
		APIKey:  apiKey,
		BaseURL: defaultBaseURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// CreateMessage executes POST /messages with policy enforcement.
func (c *Client) CreateMessage(
	ctx context.Context,
	tenantID string,
	model string,
	messages []map[string]any,
	maxTokens int,
	extra map[string]any,
) (map[string]any, error) {
	if model == "" {
		model = "claude-3-5-sonnet-latest"
	}
	if maxTokens <= 0 {
		maxTokens = 1024
	}

	prompt := extractPrompt(messages)
	decision, err := c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "provider.anthropic.create_message",
		Provider:   "anthropic",
		Model:      model,
		PromptText: prompt,
	})
	if err != nil && !c.CA.IsFailOpen() {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if err == nil && !decision.IsAllowed() && c.CA.GetEnforceMode() == "block" {
		c.CA.EmitEvent("provider.anthropic.blocked", map[string]any{
			"tenant_id": tenantID,
			"model":     model,
			"decision":  decision.Type,
		})
		return nil, &cyberarmor.PolicyViolationError{Decision: decision}
	}
	if err == nil && decision.RequiresRedaction() && len(decision.RedactionTargets) > 0 {
		messages = applySimpleRedaction(messages, decision.RedactionTargets)
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}
	for k, v := range extra {
		body[k] = v
	}
	payload, _ := json.Marshal(body)

	start := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/messages", bytes.NewReader(payload))
	if reqErr != nil {
		return nil, reqErr
	}
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := c.HTTP.Do(req)
	if doErr != nil {
		c.CA.EmitEvent("provider.anthropic.error", map[string]any{
			"tenant_id": tenantID,
			"model":     model,
			"error":     doErr.Error(),
		})
		return nil, doErr
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("anthropic API error %d: %s", resp.StatusCode, string(data))
	}

	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	c.CA.EmitEvent("provider.anthropic.create_message", map[string]any{
		"tenant_id":  tenantID,
		"model":      model,
		"latency_ms": int(time.Since(start).Milliseconds()),
		"response_id": out["id"],
	})
	return out, nil
}

func extractPrompt(messages []map[string]any) string {
	var parts []string
	for _, m := range messages {
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		content, _ := m["content"].(string)
		if content != "" {
			parts = append(parts, content)
		}
	}
	return strings.Join(parts, "\n")
}

func applySimpleRedaction(messages []map[string]any, targets []string) []map[string]any {
	if len(messages) == 0 || len(targets) == 0 {
		return messages
	}
	copyMsgs := make([]map[string]any, len(messages))
	for i := range messages {
		n := map[string]any{}
		for k, v := range messages[i] {
			n[k] = v
		}
		copyMsgs[i] = n
	}
	last := len(copyMsgs) - 1
	content, _ := copyMsgs[last]["content"].(string)
	for _, t := range targets {
		if t != "" {
			content = strings.ReplaceAll(content, t, "[REDACTED]")
		}
	}
	copyMsgs[last]["content"] = content
	return copyMsgs
}
