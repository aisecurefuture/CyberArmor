package google

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

const nativeBaseURL = "https://generativelanguage.googleapis.com/v1beta"

// NativeClient is a Google Gemini native provider client with CyberArmor hooks.
type NativeClient struct {
	CA      *cyberarmor.Client
	APIKey  string
	BaseURL string
	HTTP    *http.Client
}

// NewNative builds a Google native provider client.
func NewNative(ca *cyberarmor.Client, apiKey string) *NativeClient {
	return &NativeClient{
		CA:      ca,
		APIKey:  apiKey,
		BaseURL: nativeBaseURL,
		HTTP:    &http.Client{Timeout: 120 * time.Second},
	}
}

// GenerateContent calls Google Gemini generateContent with policy enforcement.
func (c *NativeClient) GenerateContent(
	ctx context.Context,
	tenantID string,
	model string,
	prompt string,
) (map[string]any, error) {
	if model == "" {
		model = "gemini-2.0-flash"
	}

	decision, err := c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "provider.google.generate_content",
		Provider:   "google",
		Model:      model,
		PromptText: prompt,
	})
	if err != nil && !c.CA.IsFailOpen() {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}
	if err == nil && !decision.IsAllowed() && c.CA.GetEnforceMode() == "block" {
		c.CA.EmitEvent("provider.google.blocked", map[string]any{
			"tenant_id": tenantID,
			"model":     model,
			"decision":  decision.Type,
		})
		return nil, &cyberarmor.PolicyViolationError{Decision: decision}
	}

	body := map[string]any{
		"contents": []map[string]any{
			{
				"role": "user",
				"parts": []map[string]any{
					{"text": prompt},
				},
			},
		},
	}
	payload, _ := json.Marshal(body)

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", strings.TrimRight(c.BaseURL, "/"), model, c.APIKey)
	start := time.Now()
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if reqErr != nil {
		return nil, reqErr
	}
	req.Header.Set("Content-Type", "application/json")

	resp, doErr := c.HTTP.Do(req)
	if doErr != nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("google API error %d: %s", resp.StatusCode, string(data))
	}

	var out map[string]any
	if unmarshalErr := json.Unmarshal(data, &out); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	c.CA.EmitEvent("provider.google.generate_content", map[string]any{
		"tenant_id":  tenantID,
		"model":      model,
		"latency_ms": int(time.Since(start).Milliseconds()),
	})
	return out, nil
}
