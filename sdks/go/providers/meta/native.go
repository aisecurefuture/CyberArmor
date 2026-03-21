package meta

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

const nativeBaseURL = "https://api.together.xyz/v1"

// NativeClient is a Meta/Llama gateway-native provider client with CyberArmor hooks.
type NativeClient struct {
	CA      *cyberarmor.Client
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// NewNative builds a Meta native provider client.
func NewNative(ca *cyberarmor.Client, apiKey string) *NativeClient {
	return &NativeClient{
		CA:      ca,
		APIKey:  apiKey,
		BaseURL: nativeBaseURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// ChatCompletions executes Meta-compatible chat completions with policy enforcement.
func (c *NativeClient) ChatCompletions(
	ctx context.Context,
	tenantID string,
	model string,
	messages []map[string]any,
) (map[string]any, error) {
	if model == "" {
		model = "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"
	}

	prompt := extractPromptNative(messages)
	decision, err := c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "provider.meta.chat_completions",
		Provider:   "meta",
		Model:      model,
		PromptText: prompt,
	})
	if err != nil && !c.CA.IsFailOpen() {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if err == nil && !decision.IsAllowed() && c.CA.GetEnforceMode() == "block" {
		return nil, &cyberarmor.PolicyViolationError{Decision: decision}
	}

	body := map[string]any{
		"model":    model,
		"messages": messages,
	}
	payload, _ := json.Marshal(body)
	url := strings.TrimRight(c.BaseURL, "/") + "/chat/completions"
	start := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if reqErr != nil {
		return nil, reqErr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, doErr := c.HTTP.Do(req)
	if doErr != nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("meta API error %d: %s", resp.StatusCode, string(data))
	}

	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	c.CA.EmitEvent("provider.meta.chat_completions", map[string]any{
		"tenant_id":  tenantID,
		"model":      model,
		"latency_ms": int(time.Since(start).Milliseconds()),
	})
	return out, nil
}

func extractPromptNative(messages []map[string]any) string {
	var acc string
	for _, m := range messages {
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		content, _ := m["content"].(string)
		if content == "" {
			continue
		}
		if acc != "" {
			acc += "\n"
		}
		acc += content
	}
	return acc
}
