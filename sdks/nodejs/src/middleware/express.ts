import type { CyberArmorClient } from '../client';

export function cyberArmorMiddleware(ca: CyberArmorClient) {
  return async (req: unknown, res: unknown, next: (err?: unknown) => void): Promise<void> => {
    (req as Record<string, unknown>).cyberarmor = ca;
    (req as Record<string, unknown>).cyberArmorAgentId = ca.config.agentId;
    next();
  };
}
