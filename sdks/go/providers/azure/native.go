package azure

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

const nativeBaseURL = "https://api.openai.azure.com"

// NativeClient is an Azure OpenAI native provider client with CyberArmor hooks.
type NativeClient struct {
	CA      *cyberarmor.Client
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// NewNative builds an Azure OpenAI native provider client.
func NewNative(ca *cyberarmor.Client, apiKey string) *NativeClient {
	return &NativeClient{
		CA:      ca,
		APIKey:  apiKey,
		BaseURL: nativeBaseURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// ChatCompletions calls Azure OpenAI chat completions with policy enforcement.
func (c *NativeClient) ChatCompletions(
	ctx context.Context,
	tenantID string,
	deployment string,
	messages []map[string]any,
) (map[string]any, error) {
	if deployment == "" {
		deployment = "gpt-4o"
	}

	prompt := extractPrompt(messages)
	decision, err := c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "provider.microsoft.chat_completions",
		Provider:   "microsoft",
		Model:      deployment,
		PromptText: prompt,
	})
	if err != nil && !c.CA.IsFailOpen() {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if err == nil && !decision.IsAllowed() && c.CA.GetEnforceMode() == "block" {
		c.CA.EmitEvent("provider.microsoft.blocked", map[string]any{
			"tenant_id": tenantID,
			"model":     deployment,
			"decision":  decision.Type,
		})
		return nil, &cyberarmor.PolicyViolationError{Decision: decision}
	}

	body := map[string]any{
		"messages": messages,
	}
	payload, _ := json.Marshal(body)

	base := strings.TrimRight(c.BaseURL, "/")
	url := fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=2024-10-21", base, deployment)
	start := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if reqErr != nil {
		return nil, reqErr
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("api-key", c.APIKey)

	resp, doErr := c.HTTP.Do(req)
	if doErr != nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("azure API error %d: %s", resp.StatusCode, string(data))
	}

	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	c.CA.EmitEvent("provider.microsoft.chat_completions", map[string]any{
		"tenant_id":  tenantID,
		"model":      deployment,
		"latency_ms": int(time.Since(start).Milliseconds()),
	})
	return out, nil
}

func extractPrompt(messages []map[string]any) string {
	var acc string
	for _, m := range messages {
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		content, _ := m["content"].(string)
		if content != "" {
			if acc != "" {
				acc += "\n"
			}
			acc += content
		}
	}
	return acc
}
