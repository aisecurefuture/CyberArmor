/**
 * Policy Client — Communicates with AIShields control plane for policy sync and telemetry.
 */

import * as https from 'https';
import * as http from 'http';

interface Policy {
  name: string;
  description: string;
  action: string;
  enabled: boolean;
  priority: number;
  conditions: any;
  compliance_frameworks: string[];
}

export class PolicyClient {
  private url: string;
  private apiKey: string;
  private tenantId: string;
  private policies: Policy[] = [];
  private syncTimer: NodeJS.Timeout | null = null;

  constructor(url: string, apiKey: string, tenantId: string) {
    this.url = url;
    this.apiKey = apiKey;
    this.tenantId = tenantId;
  }

  getPolicyCount(): number { return this.policies.length; }
  getPolicies(): Policy[] { return this.policies; }

  async startSync(intervalSeconds: number) {
    await this.syncPolicies();
    this.syncTimer = setInterval(() => this.syncPolicies(), intervalSeconds * 1000);
  }

  stopSync() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  async syncPolicies(): Promise<void> {
    if (!this.url || !this.apiKey) return;
    try {
      const data = await this.fetch(`/policies/${this.tenantId}`);
      if (Array.isArray(data)) {
        this.policies = data;
      }
    } catch (e) {
      console.debug('[AIShields] Policy sync failed:', e);
    }
  }

  async sendTelemetry(events: any[]): Promise<void> {
    if (!this.url || !this.apiKey) return;
    try {
      await this.fetch('/telemetry/ingest', 'POST', events);
    } catch {}
  }

  private fetch(path: string, method = 'GET', body?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(path, this.url);
      const mod = urlObj.protocol === 'https:' ? https : http;
      const opts: any = {
        hostname: urlObj.hostname,
        port: urlObj.port,
        path: urlObj.pathname,
        method,
        headers: {
          'x-api-key': this.apiKey,
          'Content-Type': 'application/json',
        },
      };

      const req = mod.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try { resolve(JSON.parse(data)); } catch { resolve(data); }
        });
      });
      req.on('error', reject);
      req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')); });
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }
}
