import React, { useState, useEffect, useCallback } from "react";
import { View, Text, FlatList, TouchableOpacity, RefreshControl, ActivityIndicator, StyleSheet } from "react-native";
import { SecurityScoreCard } from "../components/SecurityScoreCard";
import { getComplianceFrameworks, runComplianceAssessment } from "../services/api";
import { useAuth } from "../hooks/useAuth";
import { ComplianceFramework, ComplianceResult } from "../types";

export function ComplianceScreen() {
  const { settings } = useAuth();
  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [results, setResults] = useState<Map<string, ComplianceResult>>(new Map());
  const [assessing, setAssessing] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchFrameworks = useCallback(async () => {
    try {
      const data = await getComplianceFrameworks();
      setFrameworks(data);
    } catch {}
  }, []);

  useEffect(() => { fetchFrameworks(); }, [fetchFrameworks]);

  const runAssessment = async (frameworkId: string) => {
    setAssessing(frameworkId);
    try {
      const result = await runComplianceAssessment(settings.tenantId, [frameworkId]);
      if (result.length > 0) {
        setResults((prev) => new Map(prev).set(frameworkId, result[0]));
      }
    } catch {}
    setAssessing(null);
  };

  const onRefresh = useCallback(async () => {
    setRefreshing(true);
    await fetchFrameworks();
    setRefreshing(false);
  }, [fetchFrameworks]);

  return (
    <FlatList
      style={styles.container}
      data={frameworks}
      keyExtractor={(item) => item.id}
      refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
      ListHeaderComponent={<Text style={styles.header}>Compliance Frameworks</Text>}
      renderItem={({ item }) => {
        const result = results.get(item.id);
        return (
          <View style={styles.card}>
            <View style={styles.cardHeader}>
              <View style={{ flex: 1 }}>
                <Text style={styles.name}>{item.name}</Text>
                <Text style={styles.version}>v{item.version} | {item.control_count} controls</Text>
              </View>
              {result && <SecurityScoreCard score={result.overall_score} label="Score" size={60} strokeWidth={5} />}
            </View>

            {result && (
              <View style={styles.resultRow}>
                <ResultBadge label="Pass" count={result.passed} color="#22c55e" />
                <ResultBadge label="Fail" count={result.failed} color="#ef4444" />
                <ResultBadge label="Partial" count={result.partial} color="#f59e0b" />
                <ResultBadge label="N/A" count={result.not_assessed} color="#9ca3af" />
              </View>
            )}

            <TouchableOpacity
              style={[styles.assessBtn, assessing === item.id && styles.assessBtnDisabled]}
              onPress={() => runAssessment(item.id)}
              disabled={assessing === item.id}
            >
              {assessing === item.id ? (
                <ActivityIndicator size="small" color="#fff" />
              ) : (
                <Text style={styles.assessBtnText}>
                  {result ? "Re-assess" : "Run Assessment"}
                </Text>
              )}
            </TouchableOpacity>
          </View>
        );
      }}
    />
  );
}

function ResultBadge({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <View style={styles.resultBadge}>
      <Text style={[styles.resultCount, { color }]}>{count}</Text>
      <Text style={styles.resultLabel}>{label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  header: { fontSize: 24, fontWeight: "700", color: "#111827", padding: 16 },
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
  cardHeader: { flexDirection: "row", alignItems: "center" },
  name: { fontSize: 15, fontWeight: "600", color: "#111827" },
  version: { fontSize: 12, color: "#9ca3af", marginTop: 2 },
  resultRow: { flexDirection: "row", justifyContent: "space-around", marginTop: 12, paddingTop: 12, borderTopWidth: 1, borderTopColor: "#f3f4f6" },
  resultBadge: { alignItems: "center" },
  resultCount: { fontSize: 20, fontWeight: "700" },
  resultLabel: { fontSize: 11, color: "#6b7280", marginTop: 2 },
  assessBtn: { backgroundColor: "#3b82f6", borderRadius: 6, padding: 10, alignItems: "center", marginTop: 12 },
  assessBtnDisabled: { backgroundColor: "#93c5fd" },
  assessBtnText: { color: "#fff", fontWeight: "600", fontSize: 14 },
});
