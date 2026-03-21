import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorAmazon extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'amazon', options, 'amazon.nova-lite-v1:0');
  }
}

export function protectedAmazonClient(ca: CyberArmorClient, options?: Record<string, unknown>): CyberArmorAmazon {
  return new CyberArmorAmazon(ca, options);
}

