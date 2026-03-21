/**
 * Vercel AI SDK integration — wraps any LanguageModelV1 provider
 */
import type { CyberArmorClient } from '../client';
import { isAllowed, PolicyViolationError, DecisionType } from '../policy/decision';

// LanguageModelV1 minimal interface
interface LanguageModelV1 {
  readonly specificationVersion: 'v1';
  readonly provider: string;
  readonly modelId: string;
  doGenerate(options: unknown): Promise<unknown>;
  doStream(options: unknown): Promise<unknown>;
}

type ProviderFactory = (...args: unknown[]) => LanguageModelV1;
type ProviderRecord = Record<string, ProviderFactory>;

export class CyberArmorLanguageModel implements LanguageModelV1 {
  readonly specificationVersion = 'v1' as const;
  readonly provider: string;
  readonly modelId: string;

  constructor(
    private readonly ca: CyberArmorClient,
    private readonly inner: LanguageModelV1,
  ) {
    this.provider = inner.provider;
    this.modelId = inner.modelId;
  }

  async doGenerate(options: unknown): Promise<unknown> {
    const opts = options as { prompt?: Array<{ content?: Array<{ text?: string }> }> };
    const promptText = opts.prompt
      ?.flatMap(p => p.content ?? [])
      .map(c => c.text ?? '')
      .join(' ') ?? '';

    const start = Date.now();
    const decision = await this.ca.evaluatePolicy({
      action: 'llm_call',
      provider: this.provider,
      model: this.modelId,
      promptText: promptText.slice(0, 2000),
    });

    if (!isAllowed(decision) && this.ca.config.enforceMode === 'block') {
      this.ca.emitEvent('llm_call', {
        provider: this.provider, model: this.modelId,
        outcome: 'blocked', framework: 'vercel-ai',
      });
      throw new PolicyViolationError(decision);
    }

    const result = await this.inner.doGenerate(options);
    const latencyMs = Date.now() - start;

    this.ca.emitEvent('llm_call', {
      provider: this.provider, model: this.modelId,
      framework: 'vercel-ai', promptHash: this.ca.hashPrompt(promptText),
      outcome: 'success', latencyMs,
      policyDecision: { decision: decision.decision, reasonCode: decision.reasonCode, riskScore: decision.riskScore },
    });

    return result;
  }

  async doStream(options: unknown): Promise<unknown> {
    // For streaming: check policy first, then stream
    const decision = await this.ca.evaluatePolicy({
      action: 'llm_call', provider: this.provider, model: this.modelId,
    });
    if (!isAllowed(decision) && this.ca.config.enforceMode === 'block') {
      throw new PolicyViolationError(decision);
    }
    return this.inner.doStream(options);
  }
}

/**
 * Wrap any Vercel AI SDK provider factory.
 * Works with: createOpenAI, createAnthropic, createGoogleGenerativeAI, createAmazonBedrock, etc.
 *
 * @example
 * const openai = protectVercelAI(ca, createOpenAI({ apiKey: process.env.OPENAI_API_KEY }));
 * const model = openai('gpt-4o');  // Returns CyberArmorLanguageModel
 */
export function protectVercelAI<T extends ProviderRecord>(
  ca: CyberArmorClient,
  provider: T,
): T {
  return new Proxy(provider, {
    get(target, prop: string) {
      const original = target[prop];
      if (typeof original === 'function') {
        return (...args: unknown[]) => {
          const model = original.apply(target, args) as LanguageModelV1;
          return new CyberArmorLanguageModel(ca, model);
        };
      }
      return original;
    },
  }) as T;
}

/**
 * Next.js App Router / Edge middleware wrapper.
 */
export function withCyberArmor(
  handler: (req: Request) => Promise<Response>,
  ca: CyberArmorClient,
): (req: Request) => Promise<Response> {
  return async (req: Request) => {
    const decision = await ca.evaluatePolicy({ action: 'api_request' });
    if (!isAllowed(decision) && ca.config.enforceMode === 'block') {
      return new Response(
        JSON.stringify({ error: 'Blocked by CyberArmor policy', reason: decision.reasonCode }),
        { status: 403, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return handler(req);
  };
}
