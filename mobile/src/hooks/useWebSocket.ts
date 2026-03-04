import { useState, useEffect, useRef, useCallback } from "react";
import { AIShieldsWebSocket } from "../services/websocket";
import { TelemetryEvent } from "../types";

export function useWebSocket(serverUrl: string, apiKey: string, tenantId: string) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const wsRef = useRef<AIShieldsWebSocket | null>(null);

  useEffect(() => {
    if (!serverUrl || !apiKey || !tenantId) return;

    const ws = new AIShieldsWebSocket(serverUrl, apiKey, tenantId);
    wsRef.current = ws;

    const unsubConnection = ws.onConnection(setConnected);
    const unsubEvents = ws.on("*", (event: any) => {
      setEvents((prev) => [event, ...prev].slice(0, 500));
    });

    ws.connect();

    return () => {
      unsubConnection();
      unsubEvents();
      ws.disconnect();
      wsRef.current = null;
    };
  }, [serverUrl, apiKey, tenantId]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { connected, events, clearEvents };
}
