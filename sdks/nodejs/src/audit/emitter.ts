import crypto from 'crypto';
import type { CyberArmorClient } from '../client';

interface AuditEventPayload {
  eventId: string;
  traceId: string;
  spanId: string;
  tenantId: string;
  agentId: string;
  eventType: string;
  provider?: string;
  model?: string;
  framework?: string;
  action?: Record<string, unknown>;
  policyDecision?: Record<string, unknown>;
  dataClassification?: string[];
  outcome?: string;
  latencyMs?: number;
  costUsd?: number;
  timestamp: string;
}

export class AuditEmitter {
  private queue: AuditEventPayload[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly ca: CyberArmorClient) {
    if (typeof setInterval !== 'undefined') {
      this.timer = setInterval(
        () => this.flush(),
        this.ca.config.auditFlushIntervalMs
      );
      if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
        (this.timer as NodeJS.Timeout).unref();
      }
    }
  }

  emit(eventType: string, data: Record<string, unknown>): string {
    const eventId = 'evt_' + crypto.randomBytes(10).toString('hex');
    const event: AuditEventPayload = {
      eventId,
      traceId: (data.traceId as string) || 'trc_' + crypto.randomBytes(10).toString('hex'),
      spanId: 'spn_' + crypto.randomBytes(8).toString('hex'),
      tenantId: (data.tenantId as string) || 'default',
      agentId: this.ca.config.agentId,
      eventType,
      provider: data.provider as string,
      model: data.model as string,
      framework: data.framework as string,
      action: data.action as Record<string, unknown>,
      policyDecision: data.policyDecision as Record<string, unknown>,
      dataClassification: data.dataClassification as string[],
      outcome: (data.outcome as string) || 'success',
      latencyMs: data.latencyMs as number,
      costUsd: data.costUsd as number,
      timestamp: new Date().toISOString(),
    };
    this.queue.push(event);
    if (this.queue.length >= this.ca.config.auditBatchSize) {
      void this.flush();
    }
    return eventId;
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = this.queue.splice(0, this.queue.length);
    try {
      await fetch(`${this.ca.config.controlPlaneUrl}/audit/events/batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.ca.config.agentSecret,
        },
        body: JSON.stringify({ events: batch }),
      });
    } catch {
      // Silent — don't break the application
    }
  }

  destroy(): void {
    if (this.timer) clearInterval(this.timer);
    void this.flush();
  }
}
