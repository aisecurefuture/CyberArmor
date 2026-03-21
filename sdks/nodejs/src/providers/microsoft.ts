import type { CyberArmorClient } from '../client';
import { CyberArmorOpenAICompatible } from './openaiCompatible';

export class CyberArmorMicrosoft extends CyberArmorOpenAICompatible {
  constructor(ca: CyberArmorClient, options?: Record<string, unknown>) {
    super(ca, 'microsoft', options, 'phi-4');
  }
}

export function protectedMicrosoftClient(
  ca: CyberArmorClient,
  options?: Record<string, unknown>
): CyberArmorMicrosoft {
  return new CyberArmorMicrosoft(ca, options);
}

