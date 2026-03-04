import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, TouchableOpacity, RefreshControl, StyleSheet } from "react-native";
import { IncidentCard } from "../components/IncidentCard";
import { getIncidents } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { Incident, Severity } from "../types";

const SEVERITY_FILTERS: (Severity | "all")[] = ["all", "critical", "high", "medium", "low"];

export function IncidentsScreen({ navigation }: any) {
  const { settings } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [refreshing, setRefreshing] = useState(false);

  const fetchIncidents = useCallback(async () => {
    try {
      const params = filter === "all" ? {} : { severity: filter };
      const data = await getIncidents(settings.tenantId, { ...params, limit: 100 });
      setIncidents(data);
    } catch {}
  }, [settings.tenantId, filter]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchIncidents();
    setRefreshing(false);
  }, [fetchIncidents]);

  const filtered = filter === "all" ? incidents : incidents.filter((i) => i.severity === filter);

  return (
    <View style={styles.container}>
      <View style={styles.filterRow}>
        {SEVERITY_FILTERS.map((s) => (
          <TouchableOpacity
            key={s}
            style={[styles.filterChip, filter === s && styles.filterChipActive]}
            onPress={() => setFilter(s)}
          >
            <Text style={[styles.filterText, filter === s && styles.filterTextActive]}>
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </Text>
          </TouchableOpacity>
        ))}
      </View>

      <FlatList
        data={filtered}
        keyExtractor={(item) => item.id}
        renderItem={({ item }) => (
          <IncidentCard
            incident={item}
            onPress={(inc) => navigation.navigate("AlertDetail", { incident: inc })}
          />
        )}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyText}>No incidents found</Text>
          </View>
        }
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  filterRow: { flexDirection: "row", padding: 12, gap: 8 },
  filterChip: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 16,
    backgroundColor: "#e5e7eb",
  },
  filterChipActive: { backgroundColor: "#3b82f6" },
  filterText: { fontSize: 13, color: "#4b5563", fontWeight: "500" },
  filterTextActive: { color: "#fff" },
  empty: { padding: 48, alignItems: "center" },
  emptyText: { color: "#9ca3af", fontSize: 16 },
});
