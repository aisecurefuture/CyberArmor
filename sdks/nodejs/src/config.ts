/** CyberArmor SDK configuration. */
export interface CyberArmorConfig {
  controlPlaneUrl: string;
  agentId: string;
  agentSecret: string;
  enforceMode?: 'block' | 'monitor';
  timeoutMs?: number;
  auditBatchSize?: number;
  auditFlushIntervalMs?: number;
  failOpen?: boolean;
}

export function loadConfigFromEnv(): CyberArmorConfig {
  return {
    controlPlaneUrl:
      process.env.CYBERARMOR_URL || 'https://cp.cyberarmor.ai',
    agentId:
      process.env.CYBERARMOR_AGENT_ID || '',
    agentSecret:
      process.env.CYBERARMOR_AGENT_SECRET || '',
    enforceMode: (process.env.CYBERARMOR_ENFORCE_MODE as 'block' | 'monitor') || 'block',
    failOpen: process.env.CYBERARMOR_FAIL_OPEN !== 'false',
  };
}
