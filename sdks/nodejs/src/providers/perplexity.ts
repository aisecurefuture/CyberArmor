import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorPerplexity extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'perplexity', options, 'sonar');
  }
}

export function protectedPerplexityClient(
  ca: CyberArmorClient,
  options?: Record<string, unknown>
): CyberArmorPerplexity {
  return new CyberArmorPerplexity(ca, options);
}

