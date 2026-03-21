import type { CyberArmorClient } from '../client';

export class TokenManager {
  private token: string | null = null;
  private expiresAt: number = 0;

  constructor(private readonly ca: CyberArmorClient) {}

  async getValidToken(): Promise<string> {
    const now = Date.now();
    if (!this.token || now >= this.expiresAt - 60_000) {
      await this.refresh();
    }
    return this.token ?? this.ca.config.agentSecret;
  }

  private async refresh(): Promise<void> {
    try {
      const resp = await fetch(
        `${this.ca.config.controlPlaneUrl}/agents/${this.ca.config.agentId}/tokens/issue`,
        {
          method: 'POST',
          headers: { 'x-api-key': this.ca.config.agentSecret, 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        }
      );
      if (resp.ok) {
        const data: any = await resp.json();
        this.token = data.token;
        this.expiresAt = Date.now() + (data.ttl_seconds ?? 3600) * 1000;
      }
    } catch {
      this.token = this.ca.config.agentSecret;
    }
  }

  async revoke(tokenId: string): Promise<boolean> {
    try {
      const resp = await fetch(
        `${this.ca.config.controlPlaneUrl}/agents/${this.ca.config.agentId}/tokens/revoke`,
        {
          method: 'POST',
          headers: { 'x-api-key': this.ca.config.agentSecret, 'Content-Type': 'application/json' },
          body: JSON.stringify({ token_id: tokenId }),
        }
      );
      return resp.ok;
    } catch {
      return false;
    }
  }
}
