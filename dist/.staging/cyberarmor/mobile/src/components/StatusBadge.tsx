import React from "react";
import { View, Text, StyleSheet } from "react-native";

type Status = "online" | "offline" | "degraded" | "open" | "resolved" | "acknowledged" | "investigating" | "closed";

const STATUS_CONFIG: Record<string, { bg: string; text: string; dot: string }> = {
  online: { bg: "#dcfce7", text: "#166534", dot: "#22c55e" },
  offline: { bg: "#fee2e2", text: "#991b1b", dot: "#ef4444" },
  degraded: { bg: "#fef3c7", text: "#92400e", dot: "#f59e0b" },
  open: { bg: "#fee2e2", text: "#991b1b", dot: "#ef4444" },
  resolved: { bg: "#dcfce7", text: "#166534", dot: "#22c55e" },
  acknowledged: { bg: "#dbeafe", text: "#1e40af", dot: "#3b82f6" },
  investigating: { bg: "#fef3c7", text: "#92400e", dot: "#f59e0b" },
  closed: { bg: "#f3f4f6", text: "#374151", dot: "#9ca3af" },
};

interface Props {
  status: Status;
  size?: "sm" | "md";
}

export function StatusBadge({ status, size = "sm" }: Props) {
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.offline;
  const isSmall = size === "sm";

  return (
    <View style={[styles.badge, { backgroundColor: config.bg, paddingVertical: isSmall ? 2 : 4, paddingHorizontal: isSmall ? 6 : 10 }]}>
      <View style={[styles.dot, { backgroundColor: config.dot, width: isSmall ? 6 : 8, height: isSmall ? 6 : 8 }]} />
      <Text style={[styles.text, { color: config.text, fontSize: isSmall ? 11 : 13 }]}>
        {status.charAt(0).toUpperCase() + status.slice(1)}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: { flexDirection: "row", alignItems: "center", borderRadius: 12 },
  dot: { borderRadius: 4, marginRight: 4 },
  text: { fontWeight: "600" },
});
