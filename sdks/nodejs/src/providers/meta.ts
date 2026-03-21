import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorMeta extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'meta', options, 'llama-3.3-70b-instruct');
  }
}

export function protectedMetaClient(ca: CyberArmorClient, options?: Record<string, unknown>): CyberArmorMeta {
  return new CyberArmorMeta(ca, options);
}

