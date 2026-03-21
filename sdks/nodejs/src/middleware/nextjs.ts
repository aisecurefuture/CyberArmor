import type { CyberArmorClient } from '../client';
import { isAllowed } from '../policy/decision';

export function withCyberArmorAPI(
  handler: (req: Request) => Promise<Response>,
  ca: CyberArmorClient,
  options?: { action?: string }
) {
  return async (req: Request): Promise<Response> => {
    const decision = await ca.evaluatePolicy({
      action: options?.action ?? 'api_request',
    });
    if (!isAllowed(decision) && ca.config.enforceMode === 'block') {
      return Response.json({ error: 'Blocked', reason: decision.reasonCode }, { status: 403 });
    }
    return handler(req);
  };
}
