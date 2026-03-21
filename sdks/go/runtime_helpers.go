package cyberarmor

import (
	"context"
	"fmt"
	"net/http"
	"time"

	sdkaudit "github.com/cyberarmor-ai/cyberarmor-go/audit"
	sdkpolicy "github.com/cyberarmor-ai/cyberarmor-go/policy"
)

type EvaluatePolicyOptions = sdkpolicy.EvaluatePolicyOptions
type Decision = sdkpolicy.Decision

const (
	DecisionTypeAllow              = sdkpolicy.DecisionTypeAllow
	DecisionTypeDeny               = sdkpolicy.DecisionTypeDeny
	DecisionTypeAllowWithRedaction = sdkpolicy.DecisionTypeAllowWithRedaction
	DecisionTypeAllowWithLimits    = sdkpolicy.DecisionTypeAllowWithLimits
	DecisionTypeRequireApproval    = sdkpolicy.DecisionTypeRequireApproval
	DecisionTypeAllowWithAuditOnly = sdkpolicy.DecisionTypeAllowWithAuditOnly
	DecisionTypeQuarantine         = sdkpolicy.DecisionTypeQuarantine
)

type PolicyViolationError = sdkpolicy.PolicyViolationError

type TokenManager struct {
	client    *Client
	token     string
	expiresAt time.Time
}

func newTokenManager(c *Client) *TokenManager {
	return &TokenManager{client: c}
}

func (tm *TokenManager) GetValidToken(ctx context.Context) (string, error) {
	if tm.token != "" && time.Now().Before(tm.expiresAt.Add(-1*time.Minute)) {
		return tm.token, nil
	}
	result, err := tm.client.doPost(ctx, fmt.Sprintf("/agents/%s/tokens/issue", tm.client.Config.AgentID), map[string]any{})
	if err != nil {
		if tm.client.Config.FailOpen {
			return tm.client.Config.AgentSecret, nil
		}
		return "", err
	}
	token, _ := result["access_token"].(string)
	if token == "" {
		token, _ = result["token"].(string)
	}
	ttl := 3600
	if ttlAny, ok := result["ttl_seconds"].(float64); ok && ttlAny > 0 {
		ttl = int(ttlAny)
	}
	tm.token = token
	tm.expiresAt = time.Now().Add(time.Duration(ttl) * time.Second)
	if tm.token == "" {
		return tm.client.Config.AgentSecret, nil
	}
	return tm.token, nil
}

type PolicyEnforcer struct {
	inner *sdkpolicy.Enforcer
}

func newPolicyEnforcer(c *Client) *PolicyEnforcer {
	return &PolicyEnforcer{inner: sdkpolicy.NewEnforcer(c)}
}

func (p *PolicyEnforcer) Evaluate(ctx context.Context, opts EvaluatePolicyOptions) (Decision, error) {
	return p.inner.Evaluate(ctx, opts)
}

func (p *PolicyEnforcer) Enforce(d Decision) error {
	return p.inner.Enforce(d)
}

type AuditEmitter struct {
	inner *sdkaudit.Emitter
}

func newAuditEmitter(c *Client) *AuditEmitter {
	return &AuditEmitter{
		inner: sdkaudit.NewEmitter(c, 20, 2*time.Second),
	}
}

func (a *AuditEmitter) Emit(eventType string, data map[string]any) string {
	return a.inner.Emit(eventType, data)
}

func (a *AuditEmitter) Flush() {
	a.inner.Flush()
}

func (c *Client) GetControlPlaneURL() string { return c.Config.ControlPlaneURL }
func (c *Client) GetAgentID() string         { return c.Config.AgentID }
func (c *Client) GetAgentSecret() string     { return c.Config.AgentSecret }
func (c *Client) GetEnforceMode() string     { return c.Config.EnforceMode }
func (c *Client) GetHTTPClient() *http.Client {
	return c.httpClient
}
func (c *Client) IsFailOpen() bool { return c.Config.FailOpen }

func generateTraceID() string {
	return "trc_" + fmt.Sprintf("%d", time.Now().UnixNano())
}
