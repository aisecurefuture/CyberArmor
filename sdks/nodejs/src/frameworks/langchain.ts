import type { CyberArmorClient } from '../client';
import { isAllowed, PolicyViolationError } from '../policy/decision';

export class CyberArmorCallbackHandler {
  readonly name = 'CyberArmorCallbackHandler';
  private runs = new Map<string, { start: number; model?: string }>();

  constructor(private readonly ca: CyberArmorClient) {}

  async handleLLMStart(
    llm: Record<string, unknown>,
    prompts: string[],
    runId?: string
  ): Promise<void> {
    const model = (llm?.kwargs as Record<string, string>)?.model_name ?? 'unknown';
    const promptText = prompts.join(' ');
    const decision = await this.ca.evaluatePolicy({
      action: 'llm_call', model, promptText: promptText.slice(0, 2000),
    });
    const key = runId ?? 'default';
    this.runs.set(key, { start: Date.now(), model });
    if (!isAllowed(decision) && this.ca.config.enforceMode === 'block') {
      throw new PolicyViolationError(decision);
    }
  }

  handleLLMEnd(output: unknown, runId?: string): void {
    const key = runId ?? 'default';
    const run = this.runs.get(key);
    this.runs.delete(key);
    this.ca.emitEvent('llm_call', {
      framework: 'langchain', model: run?.model,
      latencyMs: run ? Date.now() - run.start : 0, outcome: 'success',
    });
  }

  async handleToolStart(tool: Record<string, unknown>, input: string, runId?: string): Promise<void> {
    const toolName = tool?.name as string ?? 'unknown';
    const decision = await this.ca.evaluatePolicy({ action: 'tool_call', toolName, promptText: input.slice(0, 500) });
    const key = `tool_${runId ?? 'default'}`;
    this.runs.set(key, { start: Date.now() });
    if (!isAllowed(decision) && this.ca.config.enforceMode === 'block') throw new PolicyViolationError(decision);
  }

  handleToolEnd(output: string, runId?: string): void {
    const key = `tool_${runId ?? 'default'}`;
    const run = this.runs.get(key);
    this.runs.delete(key);
    this.ca.emitEvent('tool_call', { framework: 'langchain', outcome: 'success', latencyMs: run ? Date.now() - run.start : 0 });
  }

  handleLLMError(error: Error, runId?: string): void {
    this.runs.delete(runId ?? 'default');
    this.ca.emitEvent('llm_call', { framework: 'langchain', outcome: 'error' });
  }
}

export function protectLangChainLLM<T extends { callbacks?: unknown[] }>(llm: T, ca: CyberArmorClient): T {
  const handler = new CyberArmorCallbackHandler(ca);
  if (!llm.callbacks) { (llm as unknown as { callbacks: unknown[] }).callbacks = []; }
  (llm.callbacks as unknown[]).push(handler);
  return llm;
}
