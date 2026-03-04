import React from "react";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { Incident, Severity } from "../types";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

const SEVERITY_BG: Record<Severity, string> = {
  critical: "#fef2f2",
  high: "#fff7ed",
  medium: "#fefce8",
  low: "#eff6ff",
  info: "#f9fafb",
};

interface Props {
  incident: Incident;
  onPress: (incident: Incident) => void;
}

export function IncidentCard({ incident, onPress }: Props) {
  const color = SEVERITY_COLORS[incident.severity];
  const bg = SEVERITY_BG[incident.severity];
  const timeAgo = getTimeAgo(incident.created_at);

  return (
    <TouchableOpacity
      style={[styles.card, { borderLeftColor: color }]}
      onPress={() => onPress(incident)}
      activeOpacity={0.7}
    >
      <View style={styles.header}>
        <View style={[styles.badge, { backgroundColor: bg }]}>
          <Text style={[styles.badgeText, { color }]}>
            {incident.severity.toUpperCase()}
          </Text>
        </View>
        <Text style={styles.time}>{timeAgo}</Text>
      </View>
      <Text style={styles.title} numberOfLines={2}>{incident.title}</Text>
      <Text style={styles.description} numberOfLines={2}>{incident.description}</Text>
      <View style={styles.footer}>
        <Text style={styles.meta}>Source: {incident.source}</Text>
        <Text style={[styles.status, { color: incident.status === "open" ? "#ef4444" : "#6b7280" }]}>
          {incident.status.toUpperCase()}
        </Text>
      </View>
    </TouchableOpacity>
  );
}

function getTimeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

const styles = StyleSheet.create({
  card: {
    backgroundColor: "#fff",
    borderRadius: 8,
    padding: 14,
    marginVertical: 4,
    marginHorizontal: 16,
    borderLeftWidth: 4,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.08,
    shadowRadius: 2,
    elevation: 2,
  },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 6 },
  badge: { paddingHorizontal: 8, paddingVertical: 2, borderRadius: 4 },
  badgeText: { fontSize: 11, fontWeight: "700" },
  time: { fontSize: 12, color: "#9ca3af" },
  title: { fontSize: 15, fontWeight: "600", color: "#111827", marginBottom: 4 },
  description: { fontSize: 13, color: "#6b7280", marginBottom: 8 },
  footer: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  meta: { fontSize: 12, color: "#9ca3af" },
  status: { fontSize: 11, fontWeight: "600" },
});
