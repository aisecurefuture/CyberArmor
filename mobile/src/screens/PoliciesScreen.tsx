import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, Switch, RefreshControl, StyleSheet } from "react-native";
import { getPolicies, togglePolicy } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { Policy } from "../types";

const ACTION_COLORS: Record<string, string> = {
  block: "#ef4444",
  warn: "#f97316",
  monitor: "#3b82f6",
  allow: "#22c55e",
};

export function PoliciesScreen() {
  const { settings } = useAuth();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [refreshing, setRefreshing] = useState(false);

  const fetchPolicies = useCallback(async () => {
    try {
      const data = await getPolicies(settings.tenantId);
      setPolicies(data);
    } catch {}
  }, [settings.tenantId]);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const onToggle = async (policy: Policy) => {
    try {
      await togglePolicy(policy.id, !policy.enabled);
      setPolicies((prev) =>
        prev.map((p) => (p.id === policy.id ? { ...p, enabled: !p.enabled } : p))
      );
    } catch {}
  };

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchPolicies();
    setRefreshing(false);
  }, [fetchPolicies]);

  return (
    <FlatList
      style={styles.container}
      data={policies}
      keyExtractor={(item) => item.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      renderItem={({ item }) => (
        <View style={styles.card}>
          <View style={styles.cardHeader}>
            <View style={{ flex: 1 }}>
              <Text style={styles.name}>{item.name}</Text>
              <Text style={styles.description} numberOfLines={2}>{item.description}</Text>
            </View>
            <Switch value={item.enabled} onValueChange={() => onToggle(item)} />
          </View>
          <View style={styles.meta}>
            <View style={[styles.actionBadge, { backgroundColor: ACTION_COLORS[item.action] + "20" }]}>
              <Text style={[styles.actionText, { color: ACTION_COLORS[item.action] }]}>
                {item.action.toUpperCase()}
              </Text>
            </View>
            <Text style={styles.priority}>Priority: {item.priority}</Text>
          </View>
        </View>
      )}
      ListEmptyComponent={
        <View style={styles.empty}>
          <Text style={styles.emptyText}>No policies configured</Text>
        </View>
      }
    />
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
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
  cardHeader: { flexDirection: "row", alignItems: "flex-start" },
  name: { fontSize: 15, fontWeight: "600", color: "#111827", marginBottom: 4 },
  description: { fontSize: 13, color: "#6b7280" },
  meta: { flexDirection: "row", alignItems: "center", marginTop: 10, gap: 12 },
  actionBadge: { paddingHorizontal: 8, paddingVertical: 2, borderRadius: 4 },
  actionText: { fontSize: 11, fontWeight: "700" },
  priority: { fontSize: 12, color: "#9ca3af" },
  empty: { padding: 48, alignItems: "center" },
  emptyText: { color: "#9ca3af", fontSize: 16 },
});
