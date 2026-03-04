import React from "react";
import { View, Text, Dimensions, StyleSheet } from "react-native";
import { LineChart } from "react-native-chart-kit";
import { ThreatTrend } from "../types";

interface Props {
  data: ThreatTrend[];
  title?: string;
}

export function ThreatChart({ data, title = "Threats (7 days)" }: Props) {
  if (!data || data.length === 0) {
    return (
      <View style={styles.empty}>
        <Text style={styles.emptyText}>No trend data available</Text>
      </View>
    );
  }

  const screenWidth = Dimensions.get("window").width - 48;
  const labels = data.map((d) => {
    const date = new Date(d.date);
    return `${date.getMonth() + 1}/${date.getDate()}`;
  });

  const chartData = {
    labels: labels.length > 7 ? labels.filter((_, i) => i % 2 === 0) : labels,
    datasets: [
      { data: data.map((d) => d.blocked), color: () => "#ef4444", strokeWidth: 2 },
      { data: data.map((d) => d.warned), color: () => "#f97316", strokeWidth: 2 },
      { data: data.map((d) => d.monitored), color: () => "#3b82f6", strokeWidth: 2 },
    ],
    legend: ["Blocked", "Warned", "Monitored"],
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>{title}</Text>
      <LineChart
        data={chartData}
        width={screenWidth}
        height={200}
        chartConfig={{
          backgroundColor: "#ffffff",
          backgroundGradientFrom: "#ffffff",
          backgroundGradientTo: "#f9fafb",
          decimalPlaces: 0,
          color: (opacity = 1) => `rgba(59, 130, 246, ${opacity})`,
          labelColor: () => "#6b7280",
          propsForDots: { r: "3" },
          propsForBackgroundLines: { stroke: "#e5e7eb" },
        }}
        bezier
        style={styles.chart}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    backgroundColor: "#fff",
    borderRadius: 8,
    padding: 16,
    marginHorizontal: 16,
    marginVertical: 8,
    shadowColor: "#000",
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.08,
    shadowRadius: 2,
    elevation: 2,
  },
  title: { fontSize: 16, fontWeight: "600", color: "#111827", marginBottom: 12 },
  chart: { borderRadius: 8 },
  empty: { padding: 32, alignItems: "center" },
  emptyText: { color: "#9ca3af", fontSize: 14 },
});
