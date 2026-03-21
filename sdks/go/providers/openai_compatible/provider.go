package openaicompatible

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
)

// Client is a lightweight OpenAI-compatible provider wrapper with CyberArmor enforcement.
type Client struct {
	Provider string
	BaseURL  string
	HTTP     *http.Client
	CA       *cyberarmor.Client
}

// New creates a provider client with CyberArmor-enforced transport.
func New(ca *cyberarmor.Client, provider, baseURL string) *Client {
	return &Client{
		Provider: provider,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		HTTP:     &http.Client{Transport: ca.NewRoundTripper(nil)},
		CA:       ca,
	}
}

// ChatCompletionsEndpoint returns the provider chat-completions endpoint URL.
func (c *Client) ChatCompletionsEndpoint() string {
	return c.BaseURL + "/chat/completions"
}

// EvaluateLLMCall pre-validates a request against CyberArmor policy.
func (c *Client) EvaluateLLMCall(ctx context.Context, model string, promptText string) (cyberarmor.Decision, error) {
	return c.CA.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
		Action:     "llm_call",
		Provider:   c.Provider,
		Model:      model,
		PromptText: promptText,
	})
}

// EmitSuccess emits a success audit event for an LLM call.
func (c *Client) EmitSuccess(model string, latencyMs int64) {
	c.CA.EmitEvent("llm_call", map[string]any{
		"provider":   c.Provider,
		"model":      model,
		"latency_ms": latencyMs,
		"outcome":    "success",
	})
}

// EmitBlocked emits a blocked audit event for an LLM call.
func (c *Client) EmitBlocked(model string, reason string) {
	c.CA.EmitEvent("llm_call", map[string]any{
		"provider": c.Provider,
		"model":    model,
		"outcome":  "blocked",
		"reason":   reason,
	})
}

func (c *Client) String() string {
	return fmt.Sprintf("CyberArmorProvider(provider=%s base=%s)", c.Provider, c.BaseURL)
}

