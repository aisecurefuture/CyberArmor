import { TelemetryEvent, Incident, Severity } from "../types";

type MessageHandler = (event: TelemetryEvent | Incident) => void;
type ConnectionHandler = (connected: boolean) => void;

export class CyberArmor.aiWebSocket {
  private ws: WebSocket | null = null;
  private url: string;
  private apiKey: string;
  private tenantId: string;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000;
  private reconnectAttempts = 0;
  private handlers: Map<string, Set<MessageHandler>> = new Map();
  private connectionHandlers: Set<ConnectionHandler> = new Set();
  private shouldReconnect = true;
  private pingInterval: ReturnType<typeof setInterval> | null = null;

  constructor(url: string, apiKey: string, tenantId: string) {
    this.url = url.replace(/^http/, "ws");
    this.apiKey = apiKey;
    this.tenantId = tenantId;
  }

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(`${this.url}/ws/telemetry?tenant=${this.tenantId}&key=${this.apiKey}`);

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.reconnectDelay = 1000;
        this.notifyConnection(true);
        this.startPing();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "pong") return;
          const eventType = data.event_type || data.type || "unknown";
          this.notifyHandlers(eventType, data);
          this.notifyHandlers("*", data);
        } catch {}
      };

      this.ws.onclose = () => {
        this.notifyConnection(false);
        this.stopPing();
        if (this.shouldReconnect) this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.ws?.close();
      };
    } catch {
      if (this.shouldReconnect) this.scheduleReconnect();
    }
  }

  disconnect(): void {
    this.shouldReconnect = false;
    this.stopPing();
    this.ws?.close();
    this.ws = null;
  }

  on(eventType: string, handler: MessageHandler): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, new Set());
    }
    this.handlers.get(eventType)!.add(handler);
    return () => this.handlers.get(eventType)?.delete(handler);
  }

  onConnection(handler: ConnectionHandler): () => void {
    this.connectionHandlers.add(handler);
    return () => this.connectionHandlers.delete(handler);
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private notifyHandlers(eventType: string, data: any): void {
    this.handlers.get(eventType)?.forEach((h) => {
      try { h(data); } catch {}
    });
  }

  private notifyConnection(connected: boolean): void {
    this.connectionHandlers.forEach((h) => {
      try { h(connected); } catch {}
    });
  }

  private scheduleReconnect(): void {
    this.reconnectAttempts++;
    const delay = Math.min(this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);
    setTimeout(() => this.connect(), delay);
  }

  private startPing(): void {
    this.pingInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: "ping" }));
      }
    }, 30000);
  }

  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
}
