import type { CyberArmorClient } from '../client';
import { isAllowed, PolicyViolationError } from '../policy/decision';

export class CyberArmorAnthropic {
  private inner: unknown;
  public messages: { create: (...a: unknown[]) => Promise<unknown>; stream: (...a: unknown[]) => unknown };

  constructor(private readonly ca: CyberArmorClient, options?: Record<string, unknown>) {
    try {
      const Anthropic = require('@anthropic-ai/sdk');
      this.inner = new (Anthropic.default ?? Anthropic)(options ?? {});
    } catch {
      throw new Error('@anthropic-ai/sdk required: npm install @anthropic-ai/sdk');
    }

    const inner = this.inner as { messages: { create: Function; stream: Function } };
    this.messages = {
      create: async (...args: unknown[]) => {
        const opts = (args[0] ?? {}) as Record<string, unknown>;
        const { model = 'claude-sonnet-4-5', messages = [] } = opts as { model?: string; messages?: unknown[] };
        const promptText = (messages as Array<{ content?: string }>).map(m => m.content ?? '').join(' ');
        const decision = await ca.evaluatePolicy({ action: 'llm_call', provider: 'anthropic', model: model as string, promptText: promptText.slice(0, 2000) });
        if (!isAllowed(decision) && ca.config.enforceMode === 'block') throw new PolicyViolationError(decision);
        const start = Date.now();
        const resp = await inner.messages.create(...args);
        ca.emitEvent('llm_call', { provider: 'anthropic', model, latencyMs: Date.now() - start, outcome: 'success' });
        return resp;
      },
      stream: (...args: unknown[]) => inner.messages.stream(...args),
    };
  }
}
