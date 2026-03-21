// Package cyberarmor provides the CyberArmor AI Identity Control Plane SDK for Go.
// It enforces AI agent identity, policy decisions, and audit logging.
package cyberarmor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Config holds the SDK configuration.
type Config struct {
	ControlPlaneURL string
	AgentID         string
	AgentSecret     string
	EnforceMode     string // "block" or "monitor"
	TimeoutSeconds  float64
	FailOpen        bool
}

// ConfigFromEnv loads configuration from CYBERARMOR_* environment variables.
func ConfigFromEnv() Config {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v := os.Getenv(k); v != "" {
				return v
			}
		}
		return ""
	}
	return Config{
		ControlPlaneURL: get("CYBERARMOR_URL", "https://cp.cyberarmor.ai"),
		AgentID:         get("CYBERARMOR_AGENT_ID"),
		AgentSecret:     get("CYBERARMOR_AGENT_SECRET"),
		EnforceMode:     get("CYBERARMOR_ENFORCE_MODE"),
		TimeoutSeconds:  5.0,
		FailOpen:        get("CYBERARMOR_FAIL_OPEN") != "false",
	}
}

// Client is the main CyberArmor SDK client.
type Client struct {
	Config        Config
	httpClient    *http.Client
	tokenManager  *TokenManager
	policyEnforcer *PolicyEnforcer
	auditEmitter  *AuditEmitter
	logger        *slog.Logger
}

// NewClient creates a new CyberArmor SDK client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ControlPlaneURL == "" {
		envCfg := ConfigFromEnv()
		if cfg.ControlPlaneURL == "" {
			cfg.ControlPlaneURL = envCfg.ControlPlaneURL
		}
		if cfg.AgentID == "" {
			cfg.AgentID = envCfg.AgentID
		}
		if cfg.AgentSecret == "" {
			cfg.AgentSecret = envCfg.AgentSecret
		}
	}
	if cfg.EnforceMode == "" {
		cfg.EnforceMode = "block"
	}
	if cfg.TimeoutSeconds == 0 {
		cfg.TimeoutSeconds = 5.0
	}

	c := &Client{
		Config: cfg,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds * float64(time.Second)),
		},
		logger: slog.Default(),
	}
	c.tokenManager = newTokenManager(c)
	c.policyEnforcer = newPolicyEnforcer(c)
	c.auditEmitter = newAuditEmitter(c)

	c.logger.Info("CyberArmor client initialized",
		"agent_id", cfg.AgentID, "url", cfg.ControlPlaneURL, "mode", cfg.EnforceMode)
	return c, nil
}

// EvaluatePolicy evaluates a policy decision for an AI action.
func (c *Client) EvaluatePolicy(ctx context.Context, opts EvaluatePolicyOptions) (Decision, error) {
	return c.policyEnforcer.Evaluate(ctx, opts)
}

// EmitEvent queues an audit event (non-blocking).
func (c *Client) EmitEvent(eventType string, data map[string]any) string {
	return c.auditEmitter.Emit(eventType, data)
}

// HashPrompt returns SHA-256 hex of prompt text for privacy-preserving audit.
func (c *Client) HashPrompt(text string) string {
	h := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", h)
}

// GetToken returns a valid agent token.
func (c *Client) GetToken(ctx context.Context) (string, error) {
	return c.tokenManager.GetValidToken(ctx)
}

// NewRoundTripper wraps an http.RoundTripper with CyberArmor enforcement.
func (c *Client) NewRoundTripper(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &cyberArmorRoundTripper{client: c, base: base}
}

// Close flushes pending audit events and cleans up.
func (c *Client) Close() {
	c.auditEmitter.Flush()
}

// cyberArmorRoundTripper implements http.RoundTripper with policy enforcement.
type cyberArmorRoundTripper struct {
	client *Client
	base   http.RoundTripper
}

func (rt *cyberArmorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	decision, err := rt.client.EvaluatePolicy(ctx, EvaluatePolicyOptions{
		Action:   "http_call",
		Provider: inferProviderFromHost(req.Host),
	})
	if err != nil && !rt.client.Config.FailOpen {
		return nil, fmt.Errorf("cyberarmor policy evaluation failed: %w", err)
	}
	if err == nil && decision.Type == DecisionTypeDeny && rt.client.Config.EnforceMode == "block" {
		return nil, &PolicyViolationError{Decision: decision}
	}

	req.Header.Set("X-CyberArmor-Agent-Id", rt.client.Config.AgentID)
	req.Header.Set("X-CyberArmor-Trace-Id", generateTraceID())

	resp, err := rt.base.RoundTrip(req)
	rt.client.EmitEvent("http_call", map[string]any{
		"host": req.Host, "method": req.Method, "outcome": "success",
		"policy_decision": map[string]any{"decision": decision.Type},
	})
	return resp, err
}

func inferProviderFromHost(host string) string {
	switch {
	case containsAny(host, "openai.com"):
		return "openai"
	case containsAny(host, "anthropic.com"):
		return "anthropic"
	case containsAny(host, "googleapis.com", "generativelanguage"):
		return "google"
	case containsAny(host, "amazonaws.com", "bedrock"):
		return "amazon"
	case containsAny(host, "azure.com", "openai.azure"):
		return "microsoft"
	case containsAny(host, "x.ai"):
		return "xai"
	case containsAny(host, "perplexity.ai"):
		return "perplexity"
	default:
		return "unknown"
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// doPost is a helper for control plane HTTP calls.
func (c *Client) doPost(ctx context.Context, path string, body any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Config.ControlPlaneURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.Config.AgentSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("control plane error %d: %s", resp.StatusCode, string(data))
	}
	return result, nil
}
