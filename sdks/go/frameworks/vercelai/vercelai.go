package vercelai

import (
	"context"
	"fmt"
	"time"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
)

// GenerateInvoker represents a framework-native text generation function (Vercel AI style).
type GenerateInvoker func(ctx context.Context, input string) (string, error)

// Guard wraps a generation invoker with CyberArmor policy enforcement + audit emission.
func Guard(
	client *cyberarmor.Client,
	provider string,
	model string,
	tenantID string,
	invoker GenerateInvoker,
) GenerateInvoker {
	return func(ctx context.Context, input string) (string, error) {
		start := time.Now()

		decision, err := client.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
			Action:     "framework.vercelai.generate",
			Provider:   provider,
			Model:      model,
			PromptText: input,
		})
		if err != nil && !client.IsFailOpen() {
			return "", fmt.Errorf("policy evaluation failed: %w", err)
		}
		if err == nil && !decision.IsAllowed() && client.GetEnforceMode() == "block" {
			client.EmitEvent("framework.vercelai.blocked", map[string]any{
				"provider": provider,
				"model":    model,
				"tenant_id": tenantID,
				"decision": decision.Type,
			})
			return "", &cyberarmor.PolicyViolationError{Decision: decision}
		}

		out, invokeErr := invoker(ctx, input)
		client.EmitEvent("framework.vercelai.generate", map[string]any{
			"provider":   provider,
			"model":      model,
			"tenant_id":  tenantID,
			"latency_ms": int(time.Since(start).Milliseconds()),
			"outcome":    map[bool]string{true: "error", false: "success"}[invokeErr != nil],
		})
		return out, invokeErr
	}
}
