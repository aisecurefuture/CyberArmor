export interface AgentIdentity {
  agentId: string;
  displayName: string;
  agentType: 'autonomous' | 'copilot' | 'workflow' | 'tool';
  ownerTeam: string;
  ownerHumanId?: string;
  application: string;
  environment: 'production' | 'staging' | 'development';
  aiProvider: string;
  model: string;
  framework: string;
  allowedTools: string[];
  deniedTools: string[];
  sensitivityTier: 'public' | 'internal' | 'confidential' | 'restricted';
  tenantId: string;
  status: 'active' | 'suspended' | 'decommissioned';
}
