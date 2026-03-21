import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorGoogle extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'google', options, 'gemini-2.0-flash');
  }
}

export function protectedGoogleClient(ca: CyberArmorClient, options?: Record<string, unknown>): CyberArmorGoogle {
  return new CyberArmorGoogle(ca, options);
}

