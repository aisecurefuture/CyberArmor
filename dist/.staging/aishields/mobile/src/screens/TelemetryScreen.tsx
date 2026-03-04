import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, TouchableOpacity, RefreshControl, StyleSheet } from "react-native";
import { getTelemetry } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { useWebSocket } from "../hooks/useWebSocket";
import { TelemetryEvent, Severity } from "../types";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280",
};

export function TelemetryScreen() {
  const { settings } = useAuth();
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [liveMode, setLiveMode] = useState(false);

  const ws = useWebSocket(
    liveMode ? settings.serverUrl : "",
    settings.apiKey,
    settings.tenantId
  );

  const fetchEvents = useCallback(async () => {
    try {
      const data = await getTelemetry(settings.tenantId, { limit: 100 });
      setEvents(data);
    } catch {}
  }, [settings.tenantId]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);

  // Merge WebSocket events
  useEffect(() => {
    if (liveMode && ws.events.length > 0) {
      setEvents((prev) => {
        const merged = [...ws.events, ...prev];
        const seen = new Set<string>();
        return merged.filter((e) => {
          if (seen.has(e.id)) return false;
          seen.add(e.id);
          return true;
        }).slice(0, 500);
      });
    }
  }, [ws.events, liveMode]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchEvents();
    setRefreshing(false);
  }, [fetchEvents]);

  return (
    <View style={styles.container}>
      <View style={styles.toolbar}>
        <Text style={styles.header}>Telemetry</Text>
        <TouchableOpacity
          style={[styles.liveBtn, liveMode && styles.liveBtnActive]}
          onPress={() => setLiveMode(!liveMode)}
        >
          <View style={[styles.liveDot, liveMode && styles.liveDotActive]} />
          <Text style={[styles.liveBtnText, liveMode && styles.liveBtnTextActive]}>
            {liveMode ? "LIVE" : "PAUSED"}
          </Text>
        </TouchableOpacity>
      </View>

      {liveMode && (
        <Text style={styles.wsStatus}>
          WebSocket: {ws.connected ? "Connected" : "Connecting..."}
        </Text>
      )}

      <FlatList
        data={events}
        keyExtractor={(item) => item.id}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
        renderItem={({ item }) => (
          <View style={[styles.eventCard, { borderLeftColor: SEVERITY_COLORS[item.severity] }]}>
            <View style={styles.eventHeader}>
              <Text style={[styles.severity, { color: SEVERITY_COLORS[item.severity] }]}>
                {item.severity.toUpperCase()}
              </Text>
              <Text style={styles.time}>{formatTime(item.timestamp)}</Text>
            </View>
            <Text style={styles.eventType}>{item.event_type}</Text>
            <Text style={styles.eventMeta}>
              Source: {item.source}{item.user ? ` | User: ${item.user}` : ""}
            </Text>
          </View>
        )}
        ListEmptyComponent={
          <View style={styles.empty}><Text style={styles.emptyText}>No telemetry events</Text></View>
        }
      />
    </View>
  );
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  toolbar: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16 },
  header: { fontSize: 24, fontWeight: "700", color: "#111827" },
  liveBtn: { flexDirection: "row", alignItems: "center", backgroundColor: "#e5e7eb", paddingHorizontal: 12, paddingVertical: 6, borderRadius: 16 },
  liveBtnActive: { backgroundColor: "#fee2e2" },
  liveDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: "#9ca3af", marginRight: 6 },
  liveDotActive: { backgroundColor: "#ef4444" },
  liveBtnText: { fontSize: 12, fontWeight: "700", color: "#4b5563" },
  liveBtnTextActive: { color: "#ef4444" },
  wsStatus: { fontSize: 12, color: "#6b7280", paddingHorizontal: 16, paddingBottom: 8 },
  eventCard: {
    backgroundColor: "#fff",
    marginHorizontal: 16,
    marginVertical: 2,
    borderRadius: 6,
    padding: 10,
    borderLeftWidth: 3,
  },
  eventHeader: { flexDirection: "row", justifyContent: "space-between", marginBottom: 4 },
  severity: { fontSize: 11, fontWeight: "700" },
  time: { fontSize: 11, color: "#9ca3af" },
  eventType: { fontSize: 14, fontWeight: "500", color: "#111827" },
  eventMeta: { fontSize: 12, color: "#6b7280", marginTop: 2 },
  empty: { padding: 48, alignItems: "center" },
  emptyText: { color: "#9ca3af" },
});
