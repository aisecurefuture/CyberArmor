import crypto from 'crypto';
import { CyberArmorConfig, loadConfigFromEnv } from './config';
import { PolicyEnforcer, EvaluatePolicyOptions } from './policy/enforcer';
import { Decision } from './policy/decision';
import { AuditEmitter } from './audit/emitter';
import { TokenManager } from './identity/tokenManager';

export class CyberArmorClient {
  readonly config: Required<CyberArmorConfig>;
  readonly policyEnforcer: PolicyEnforcer;
  readonly auditEmitter: AuditEmitter;
  readonly tokenManager: TokenManager;

  constructor(config?: Partial<CyberArmorConfig>) {
    const envConfig = loadConfigFromEnv();
    this.config = {
      controlPlaneUrl: config?.controlPlaneUrl || envConfig.controlPlaneUrl,
      agentId: config?.agentId || envConfig.agentId,
      agentSecret: config?.agentSecret || envConfig.agentSecret,
      enforceMode: config?.enforceMode || envConfig.enforceMode || 'block',
      timeoutMs: config?.timeoutMs ?? 5000,
      auditBatchSize: config?.auditBatchSize ?? 50,
      auditFlushIntervalMs: config?.auditFlushIntervalMs ?? 5000,
      failOpen: config?.failOpen ?? envConfig.failOpen ?? true,
    };
    this.tokenManager = new TokenManager(this);
    this.policyEnforcer = new PolicyEnforcer(this);
    this.auditEmitter = new AuditEmitter(this);
  }

  async evaluatePolicy(options: EvaluatePolicyOptions): Promise<Decision> {
    return this.policyEnforcer.evaluate(options);
  }

  emitEvent(eventType: string, data: Record<string, unknown>): string {
    return this.auditEmitter.emit(eventType, data);
  }

  hashPrompt(text: string): string {
    return crypto.createHash('sha256').update(text).digest('hex');
  }

  async getToken(): Promise<string> {
    return this.tokenManager.getValidToken();
  }

  destroy(): void {
    this.auditEmitter.flush();
  }
}
