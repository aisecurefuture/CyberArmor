import type { CyberArmorClient } from '../client';
import { PolicyViolationError, isAllowed } from '../policy/decision';

export class CyberArmorOpenAICompatible {
  private inner: any;
  public chat: { completions: { create: (...args: unknown[]) => Promise<unknown> } };
  public embeddings: { create: (...args: unknown[]) => Promise<unknown> };

  constructor(
    private readonly ca: CyberArmorClient,
    private readonly provider: string,
    options?: Record<string, unknown>,
    private readonly defaultModel = 'gpt-4o-mini',
  ) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const OpenAI = require('openai').default ?? require('openai');
      this.inner = new OpenAI(options ?? {});
    } catch {
      throw new Error('openai package required: npm install openai');
    }

    this.chat = {
      completions: {
        create: async (...args: unknown[]) => {
          const options = (args[0] ?? {}) as Record<string, unknown>;
          const { model = this.defaultModel, messages = [], ...rest } = options as {
            model?: string;
            messages?: Array<{ role: string; content: string }>;
          } & Record<string, unknown>;

          const start = Date.now();
          const promptText = messages.map((m) => m.content ?? '').join(' ');
          const decision = await this.ca.evaluatePolicy({
            action: 'llm_call',
            provider: this.provider,
            model: model as string,
            promptText: promptText.slice(0, 2000),
          });

          if (!isAllowed(decision) && this.ca.config.enforceMode === 'block') {
            this.ca.emitEvent('llm_call', {
              provider: this.provider,
              model,
              outcome: 'blocked',
              policyDecision: { decision: decision.decision, reasonCode: decision.reasonCode },
            });
            throw new PolicyViolationError(decision);
          }

          const response = await (this.inner.chat.completions as unknown as {
            create: (opts: Record<string, unknown>) => Promise<unknown>
          }).create({ model, messages, ...rest });

          this.ca.emitEvent('llm_call', {
            provider: this.provider,
            model,
            framework: `${this.provider}-sdk`,
            promptHash: this.ca.hashPrompt(promptText),
            latencyMs: Date.now() - start,
            outcome: 'success',
          });
          return response;
        },
      },
    };

    this.embeddings = {
      create: (opts: unknown) =>
        (this.inner.embeddings as unknown as { create: (o: unknown) => Promise<unknown> }).create(opts),
    };
  }
}

