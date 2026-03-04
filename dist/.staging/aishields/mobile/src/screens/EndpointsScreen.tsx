import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, RefreshControl, StyleSheet } from "react-native";
import { StatusBadge } from "../components/StatusBadge";
import { getEndpoints } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { Endpoint } from "../types";

const OS_ICONS: Record<string, string> = { macos: "🍎", windows: "🪟", linux: "🐧" };

export function EndpointsScreen() {
  const { settings } = useAuth();
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const fetchEndpoints = useCallback(async () => {
    try {
      const data = await getEndpoints(settings.tenantId);
      setEndpoints(data);
    } catch {}
  }, [settings.tenantId]);

  useEffect(() => { fetchEndpoints(); }, [fetchEndpoints]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchEndpoints();
    setRefreshing(false);
  }, [fetchEndpoints]);

  const online = endpoints.filter((e) => e.status === "online").length;

  return (
    <FlatList
      style={styles.container}
      data={endpoints}
      keyExtractor={(item) => item.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      ListHeaderComponent={
        <View style={styles.headerRow}>
          <Text style={styles.header}>Endpoints</Text>
          <Text style={styles.count}>{online}/{endpoints.length} online</Text>
        </View>
      }
      renderItem={({ item }) => (
        <View style={styles.card}>
          <View style={styles.row}>
            <Text style={styles.osIcon}>{OS_ICONS[item.os] || "💻"}</Text>
            <View style={{ flex: 1 }}>
              <Text style={styles.hostname}>{item.hostname}</Text>
              <Text style={styles.meta}>{item.os} {item.os_version} | Agent v{item.agent_version}</Text>
              <Text style={styles.meta}>{item.user} | {item.ip_address}</Text>
            </View>
            <View style={styles.rightCol}>
              <StatusBadge status={item.status} />
              <Text style={styles.score}>{item.security_score}%</Text>
            </View>
          </View>
          <View style={styles.features}>
            <FeatureTag label="DLP" enabled={item.dlp_enabled} />
            <FeatureTag label="PQC" enabled={item.pqc_enabled} />
            <Text style={styles.threats}>{item.threats_blocked} blocked</Text>
          </View>
        </View>
      )}
    />
  );
}

function FeatureTag({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <View style={[styles.tag, { backgroundColor: enabled ? "#dcfce7" : "#fee2e2" }]}>
      <Text style={[styles.tagText, { color: enabled ? "#166534" : "#991b1b" }]}>
        {label}: {enabled ? "ON" : "OFF"}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  headerRow: { flexDirection: "row", justifyContent: "space-between", alignItems: "baseline", padding: 16 },
  header: { fontSize: 24, fontWeight: "700", color: "#111827" },
  count: { fontSize: 14, color: "#6b7280" },
  card: {
    backgroundColor: "#fff",
    marginHorizontal: 16,
    marginVertical: 4,
    borderRadius: 8,
    padding: 14,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 2,
    elevation: 1,
  },
  row: { flexDirection: "row", alignItems: "flex-start" },
  osIcon: { fontSize: 24, marginRight: 10, marginTop: 2 },
  hostname: { fontSize: 15, fontWeight: "600", color: "#111827" },
  meta: { fontSize: 12, color: "#6b7280", marginTop: 1 },
  rightCol: { alignItems: "flex-end" },
  score: { fontSize: 14, fontWeight: "600", color: "#3b82f6", marginTop: 4 },
  features: { flexDirection: "row", marginTop: 10, gap: 8, alignItems: "center" },
  tag: { paddingHorizontal: 8, paddingVertical: 2, borderRadius: 4 },
  tagText: { fontSize: 11, fontWeight: "600" },
  threats: { fontSize: 12, color: "#ef4444", marginLeft: "auto" },
});
