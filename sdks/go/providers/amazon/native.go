package amazon

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

const nativeBaseURL = "https://bedrock-runtime.us-east-1.amazonaws.com"

// NativeClient is an Amazon Bedrock native provider client with CyberArmor hooks.
type NativeClient struct {
	CA      *cyberarmor.Client
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// NewNative builds an Amazon native provider client.
// Note: production Bedrock usage requires AWS SigV4 signing; this wrapper targets
// gateway/presigned deployments where bearer-style auth is accepted.
func NewNative(ca *cyberarmor.Client, apiKey string) *NativeClient {
	return &NativeClient{
		CA:      ca,
		APIKey:  apiKey,
		BaseURL: nativeBaseURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Converse calls Bedrock converse endpoint with policy enforcement.
func (c *NativeClient) Converse(
	ctx context.Context,
	tenantID string,
	modelID string,
	messages []map[string]any,
) (map[string]any, error) {
	if modelID == "" {
		modelID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
	}

	prompt := extractPrompt(messages)
	decision, err := c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "provider.amazon.converse",
		Provider:   "amazon",
		Model:      modelID,
		PromptText: prompt,
	})
	if err != nil && !c.CA.IsFailOpen() {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if err == nil && !decision.IsAllowed() && c.CA.GetEnforceMode() == "block" {
		c.CA.EmitEvent("provider.amazon.blocked", map[string]any{
			"tenant_id": tenantID,
			"model":     modelID,
			"decision":  decision.Type,
		})
		return nil, &cyberarmor.PolicyViolationError{Decision: decision}
	}

	body := map[string]any{
		"modelId":  modelID,
		"messages": messages,
	}
	payload, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/model/%s/converse", strings.TrimRight(c.BaseURL, "/"), modelID)
	start := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if reqErr != nil {
		return nil, reqErr
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, doErr := c.HTTP.Do(req)
	if doErr != nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("amazon API error %d: %s", resp.StatusCode, string(data))
	}

	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	c.CA.EmitEvent("provider.amazon.converse", map[string]any{
		"tenant_id":  tenantID,
		"model":      modelID,
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
