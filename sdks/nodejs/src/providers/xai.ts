import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorXAI extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'xai', options, 'grok-3');
  }
}

export function protectedXAIClient(ca: CyberArmorClient, options?: Record<string, unknown>): CyberArmorXAI {
  return new CyberArmorXAI(ca, options);
}

