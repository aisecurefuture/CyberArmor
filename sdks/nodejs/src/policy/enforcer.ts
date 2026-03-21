import { CyberArmorClient } from '../client';
import { Decision, DecisionType, isAllowed, PolicyViolationError } from './decision';

export interface EvaluatePolicyOptions {
  action: string;
  provider?: string;
  model?: string;
  toolName?: string;
  promptText?: string;
  dataClassifications?: string[];
  humanInitiatorPresent?: boolean;
  environment?: string;
  sensitivityTier?: string;
}

export class PolicyEnforcer {
  constructor(private readonly ca: CyberArmorClient) {}

  async evaluate(options: EvaluatePolicyOptions): Promise<Decision> {
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.ca.config.timeoutMs);

      const resp = await fetch(`${this.ca.config.controlPlaneUrl}/policies/evaluate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.ca.config.agentSecret,
        },
        body: JSON.stringify({
          agent_id: this.ca.config.agentId,
          action_type: options.action,
          ai_provider: options.provider ?? 'unknown',
          model: options.model ?? 'unknown',
          tool_name: options.toolName,
          prompt_text: options.promptText?.slice(0, 2000),
          data_classifications: options.dataClassifications ?? [],
          human_initiator_present: options.humanInitiatorPresent ?? false,
          environment: options.environment ?? 'production',
          sensitivity_tier: options.sensitivityTier ?? 'internal',
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (resp.ok) {
        const data: any = await resp.json();
        return {
          decision: (data.decision as DecisionType) ?? DecisionType.ALLOW,
          reasonCode: data.reason_code ?? 'POLICY_PASSED',
          riskScore: data.risk_score ?? 0,
          policyId: data.policy_id,
          redactionTargets: data.redaction_targets ?? [],
          explanation: data.explanation ?? '',
          latencyMs: Date.now() - start,
        };
      }
    } catch {
      // Fallback to local evaluation
    }

    return this._localFallback(options, Date.now() - start);
  }

  enforce(decision: Decision): void {
    if (!isAllowed(decision)) {
      throw new PolicyViolationError(decision);
    }
  }

  private _localFallback(options: EvaluatePolicyOptions, latencyMs: number): Decision {
    if (this.ca.config.enforceMode === 'monitor') {
      return {
        decision: DecisionType.ALLOW_WITH_AUDIT_ONLY,
        reasonCode: 'MONITOR_MODE',
        riskScore: 0,
        latencyMs,
        explanation: 'Monitor mode: logging only',
      };
    }
    return {
      decision: DecisionType.ALLOW,
      reasonCode: 'LOCAL_FALLBACK_ALLOW',
      riskScore: 0,
      latencyMs,
      explanation: 'Control plane unreachable; local fallback',
    };
  }
}
