package langchain

import (
	"context"
	"fmt"
	"time"

	cyberarmor "github.com/cyberarmor-ai/cyberarmor-go"
)

// ChatInvoker represents a framework-native chat function (LangChain-style).
type ChatInvoker func(ctx context.Context, prompt string) (string, error)

// Guard wraps a chat invoker with CyberArmor policy enforcement + audit emission.
func Guard(
	client *cyberarmor.Client,
	provider string,
	model string,
	tenantID string,
	invoker ChatInvoker,
) ChatInvoker {
	return func(ctx context.Context, prompt string) (string, error) {
		start := time.Now()

		decision, err := client.EvaluatePolicy(ctx, cyberarmor.EvaluatePolicyOptions{
			Action:     "framework.langchain.chat",
			Provider:   provider,
			Model:      model,
			PromptText: prompt,
		})
		if err != nil && !client.IsFailOpen() {
			return "", fmt.Errorf("policy evaluation failed: %w", err)
		}
		if err == nil && !decision.IsAllowed() && client.GetEnforceMode() == "block" {
			client.EmitEvent("framework.langchain.blocked", map[string]any{
				"provider": provider,
				"model":    model,
				"tenant_id": tenantID,
				"decision": decision.Type,
			})
			return "", &cyberarmor.PolicyViolationError{Decision: decision}
		}

		out, invokeErr := invoker(ctx, prompt)
		client.EmitEvent("framework.langchain.chat", map[string]any{
			"provider":   provider,
			"model":      model,
			"tenant_id":  tenantID,
			"latency_ms": int(time.Since(start).Milliseconds()),
			"outcome":    map[bool]string{true: "error", false: "success"}[invokeErr != nil],
		})
		return out, invokeErr
	}
}
