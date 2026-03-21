package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// EvaluatePolicyOptions holds the context for a policy evaluation request.
type EvaluatePolicyOptions struct {
	Action                string
	Provider              string
	Model                 string
	ToolName              string
	PromptText            string
	DataClassifications   []string
	HumanInitiatorPresent bool
	Environment           string
	SensitivityTier       string
}

// PolicyEnforcerConfig is the minimal interface the enforcer needs from the client.
type PolicyEnforcerConfig interface {
	GetControlPlaneURL() string
	GetAgentID() string
	GetAgentSecret() string
	GetEnforceMode() string
	GetHTTPClient() *http.Client
	IsFailOpen() bool
}

// Enforcer evaluates policies for AI agent actions.
type Enforcer struct {
	cfg PolicyEnforcerConfig
}

// NewEnforcer creates a new policy enforcer.
func NewEnforcer(cfg PolicyEnforcerConfig) *Enforcer {
	return &Enforcer{cfg: cfg}
}

// Evaluate evaluates a policy decision, falling back to local evaluation on CP failure.
func (e *Enforcer) Evaluate(ctx context.Context, opts EvaluatePolicyOptions) (Decision, error) {
	start := time.Now()
	decision, err := e.evaluateRemote(ctx, opts)
	if err != nil {
		return e.localFallback(opts, int(time.Since(start).Milliseconds())), nil
	}
	decision.LatencyMs = int(time.Since(start).Milliseconds())
	return decision, nil
}

// Enforce returns an error if the decision blocks the action.
func (e *Enforcer) Enforce(d Decision) error {
	if !d.IsAllowed() {
		return &PolicyViolationError{Decision: d}
	}
	return nil
}

func (e *Enforcer) evaluateRemote(ctx context.Context, opts EvaluatePolicyOptions) (Decision, error) {
	payload, _ := json.Marshal(map[string]any{
		"agent_id":                e.cfg.GetAgentID(),
		"action_type":             opts.Action,
		"ai_provider":             opts.Provider,
		"model":                   opts.Model,
		"tool_name":               opts.ToolName,
		"prompt_text":             truncate(opts.PromptText, 2000),
		"data_classifications":    opts.DataClassifications,
		"human_initiator_present": opts.HumanInitiatorPresent,
		"environment":             opts.Environment,
		"sensitivity_tier":        opts.SensitivityTier,
	})

	ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx2, http.MethodPost,
		e.cfg.GetControlPlaneURL()+"/policies/evaluate",
		bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", e.cfg.GetAgentSecret())

	resp, err := e.cfg.GetHTTPClient().Do(req)
	if err != nil {
		return Decision{}, fmt.Errorf("policy remote eval: %w", err)
	}
	defer resp.Body.Close()

	var d Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Decision{}, fmt.Errorf("decode policy response: %w", err)
	}
	return d, nil
}

func (e *Enforcer) localFallback(opts EvaluatePolicyOptions, latencyMs int) Decision {
	if e.cfg.GetEnforceMode() == "monitor" {
		return Decision{Type: DecisionTypeAllowWithAuditOnly, ReasonCode: "MONITOR_MODE",
			Explanation: "Monitor mode — logging only", LatencyMs: latencyMs}
	}
	return Decision{Type: DecisionTypeAllow, ReasonCode: "LOCAL_FALLBACK_ALLOW",
		Explanation: "Control plane unreachable; local fallback", LatencyMs: latencyMs}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
