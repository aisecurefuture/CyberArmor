export enum DecisionType {
  ALLOW = 'ALLOW',
  DENY = 'DENY',
  ALLOW_WITH_REDACTION = 'ALLOW_WITH_REDACTION',
  ALLOW_WITH_LIMITS = 'ALLOW_WITH_LIMITS',
  REQUIRE_APPROVAL = 'REQUIRE_APPROVAL',
  ALLOW_WITH_AUDIT_ONLY = 'ALLOW_WITH_AUDIT_ONLY',
  QUARANTINE = 'QUARANTINE',
}

export interface Decision {
  decision: DecisionType;
  reasonCode: string;
  riskScore: number;
  policyId?: string;
  redactionTargets?: string[];
  rateLimit?: { callsPerMinute?: number; tokensPerDay?: number };
  approvalRequiredFrom?: string;
  explanation?: string;
  latencyMs?: number;
}

export const isAllowed = (d: Decision): boolean =>
  [
    DecisionType.ALLOW,
    DecisionType.ALLOW_WITH_REDACTION,
    DecisionType.ALLOW_WITH_LIMITS,
    DecisionType.ALLOW_WITH_AUDIT_ONLY,
  ].includes(d.decision);

export const requiresRedaction = (d: Decision): boolean =>
  d.decision === DecisionType.ALLOW_WITH_REDACTION;

export class PolicyViolationError extends Error {
  constructor(public readonly decision: Decision) {
    super(
      `Policy violation: ${decision.reasonCode} (decision=${decision.decision})`
    );
    this.name = 'PolicyViolationError';
  }
}
