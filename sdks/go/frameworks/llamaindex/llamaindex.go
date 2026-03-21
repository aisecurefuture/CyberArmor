package llamaindex

import (
	"context"
	"fmt"
	"time"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
)

// QueryInvoker represents a framework-native query function (LlamaIndex-style).
type QueryInvoker func(ctx context.Context, query string) (string, error)

// Guard wraps a query invoker with CyberArmor policy enforcement + audit emission.
func Guard(
	client *cyberarmor.Client,
	provider string,
	model string,
	tenantID string,
	invoker QueryInvoker,
) QueryInvoker {
	return func(ctx context.Context, query string) (string, error) {
		start := time.Now()

		decision, err := client.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
			Action:     "framework.llamaindex.query",
			Provider:   provider,
			Model:      model,
			PromptText: query,
		})
		if err != nil && !client.IsFailOpen() {
			return "", fmt.Errorf("policy evaluation failed: %w", err)
		}
		if err == nil && !decision.IsAllowed() && client.GetEnforceMode() == "block" {
			client.EmitEvent("framework.llamaindex.blocked", map[string]any{
				"provider": provider,
				"model":    model,
				"tenant_id": tenantID,
				"decision": decision.Type,
			})
			return "", &cyberarmor.PolicyViolationError{Decision: decision}
		}

		out, invokeErr := invoker(ctx, query)
		client.EmitEvent("framework.llamaindex.query", map[string]any{
			"provider":   provider,
			"model":      model,
			"tenant_id":  tenantID,
			"latency_ms": int(time.Since(start).Milliseconds()),
			"outcome":    map[bool]string{true: "error", false: "success"}[invokeErr != nil],
		})
		return out, invokeErr
	}
}
