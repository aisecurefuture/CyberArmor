import React, { useState, useEffect, useCallback } from "react";
import { View, Text, ScrollView, RefreshControl, StyleSheet } from "react-native";
import { SecurityScoreCard } from "../components/SecurityScoreCard";
import { ThreatChart } from "../components/ThreatChart";
import { getDashboardStats, getThreatTrends } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { DashboardStats, ThreatTrend } from "../types";

export function DashboardScreen() {
  const { settings } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [trends, setTrends] = useState<ThreatTrend[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const fetchData = useCallback(async () => {
    try {
      setError("");
      const [s, t] = await Promise.all([
        getDashboardStats(settings.tenantId),
        getThreatTrends(settings.tenantId),
      ]);
      setStats(s);
      setTrends(t);
    } catch (e: any) {
      setError(e.message || "Failed to load dashboard");
    }
  }, [settings.tenantId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchData();
    setRefreshing(false);
  }, [fetchData]);

  return (
    <ScrollView
      style={styles.container}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
    >
      <Text style={styles.header}>Security Overview</Text>

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <View style={styles.scoreRow}>
        <SecurityScoreCard score={stats?.compliance_score ?? 0} label="Compliance" size={100} />
        <SecurityScoreCard
          score={stats ? (stats.active_endpoints / Math.max(stats.total_endpoints, 1)) * 100 : 0}
          label="Endpoints"
          size={100}
        />
      </View>

      <View style={styles.statsGrid}>
        <StatCard title="Threats Blocked" value={stats?.threats_blocked_today ?? 0} subtitle="Today" color="#ef4444" />
        <StatCard title="Active Policies" value={stats?.active_policies ?? 0} subtitle={`of ${stats?.total_policies ?? 0}`} color="#3b82f6" />
        <StatCard title="Open Incidents" value={stats?.open_incidents ?? 0} subtitle={`${stats?.critical_incidents ?? 0} critical`} color="#f97316" />
        <StatCard title="Endpoints" value={stats?.active_endpoints ?? 0} subtitle={`of ${stats?.total_endpoints ?? 0} online`} color="#22c55e" />
      </View>

      <ThreatChart data={trends} />
    </ScrollView>
  );
}

function StatCard({ title, value, subtitle, color }: { title: string; value: number; subtitle: string; color: string }) {
  return (
    <View style={styles.statCard}>
      <Text style={styles.statTitle}>{title}</Text>
      <Text style={[styles.statValue, { color }]}>{value.toLocaleString()}</Text>
      <Text style={styles.statSubtitle}>{subtitle}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  header: { fontSize: 24, fontWeight: "700", color: "#111827", padding: 16, paddingBottom: 8 },
  error: { color: "#ef4444", fontSize: 14, paddingHorizontal: 16, marginBottom: 8 },
  scoreRow: { flexDirection: "row", justifyContent: "space-around", paddingVertical: 16 },
  statsGrid: { flexDirection: "row", flexWrap: "wrap", paddingHorizontal: 12 },
  statCard: {
    width: "47%",
    backgroundColor: "#fff",
    borderRadius: 8,
    padding: 14,
    margin: "1.5%",
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.06,
    shadowRadius: 2,
    elevation: 1,
  },
  statTitle: { fontSize: 12, color: "#6b7280", marginBottom: 4 },
  statValue: { fontSize: 28, fontWeight: "700" },
  statSubtitle: { fontSize: 12, color: "#9ca3af", marginTop: 2 },
});
