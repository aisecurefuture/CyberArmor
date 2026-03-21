import type { CyberArmorClient } from '../client';
import { isAllowed, PolicyViolationError } from '../policy/decision';

type LlamaIndexLike = {
  complete?: (prompt: string, ...rest: unknown[]) => Promise<unknown>;
  acomplete?: (prompt: string, ...rest: unknown[]) => Promise<unknown>;
};

export function protectLlamaIndexLLM<T extends LlamaIndexLike>(
  llm: T,
  ca: CyberArmorClient,
  model = 'unknown',
): T {
  const wrapped = llm as T;
  if (wrapped.complete) {
    const original = wrapped.complete.bind(wrapped);
    wrapped.complete = (async (prompt: string, ...rest: unknown[]) => {
      const decision = await ca.evaluatePolicy({
        action: 'llm_call',
        model,
        promptText: String(prompt ?? '').slice(0, 2000),
      });
      if (!isAllowed(decision) && ca.config.enforceMode === 'block') {
        throw new PolicyViolationError(decision);
      }
      const start = Date.now();
      const out = await original(prompt, ...rest);
      ca.emitEvent('llm_call', {
        framework: 'llamaindex',
        model,
        outcome: 'success',
        latencyMs: Date.now() - start,
      });
      return out;
    }) as T['complete'];
  }
  if (wrapped.acomplete) {
    const original = wrapped.acomplete.bind(wrapped);
    wrapped.acomplete = (async (prompt: string, ...rest: unknown[]) => {
      const decision = await ca.evaluatePolicy({
        action: 'llm_call',
        model,
        promptText: String(prompt ?? '').slice(0, 2000),
      });
      if (!isAllowed(decision) && ca.config.enforceMode === 'block') {
        throw new PolicyViolationError(decision);
      }
      return original(prompt, ...rest);
    }) as T['acomplete'];
  }
  return wrapped;
}
