export interface DelegationChain {
  chainId: string;
  parentHumanId: string;
  agentId: string;
  scope: string[];
  expiresAt?: Date;
  status: 'active' | 'revoked';
}

export const isDelegationValid = (d: DelegationChain): boolean => {
  if (d.status !== 'active') return false;
  if (d.expiresAt && new Date() > d.expiresAt) return false;
  return true;
};

export const hasScope = (d: DelegationChain, required: string): boolean =>
  d.scope.includes(required) || d.scope.includes('*');
