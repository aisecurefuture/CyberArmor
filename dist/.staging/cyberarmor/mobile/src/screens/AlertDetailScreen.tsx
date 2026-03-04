import React, { useState } from "react";
import { View, Text, ScrollView, TouchableOpacity, TextInput, Alert, StyleSheet } from "react-native";
import { StatusBadge } from "../components/StatusBadge";
import { acknowledgeIncident, resolveIncident } from "../services/api";
import { Incident, Severity } from "../types";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280",
};

export function AlertDetailScreen({ route, navigation }: any) {
  const incident: Incident = route.params.incident;
  const [status, setStatus] = useState(incident.status);
  const [resolution, setResolution] = useState("");
  const [showResolve, setShowResolve] = useState(false);

  const handleAcknowledge = async () => {
    try {
      await acknowledgeIncident(incident.id);
      setStatus("acknowledged");
    } catch (e: any) {
      Alert.alert("Error", e.message);
    }
  };

  const handleResolve = async () => {
    if (!resolution.trim()) {
      Alert.alert("Required", "Please enter a resolution note");
      return;
    }
    try {
      await resolveIncident(incident.id, resolution);
      setStatus("resolved");
      setShowResolve(false);
    } catch (e: any) {
      Alert.alert("Error", e.message);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={[styles.headerBanner, { backgroundColor: SEVERITY_COLORS[incident.severity] + "15" }]}>
        <Text style={[styles.severityText, { color: SEVERITY_COLORS[incident.severity] }]}>
          {incident.severity.toUpperCase()}
        </Text>
        <StatusBadge status={status as any} size="md" />
      </View>

      <View style={styles.content}>
        <Text style={styles.title}>{incident.title}</Text>
        <Text style={styles.description}>{incident.description}</Text>

        <Section title="Details">
          <DetailRow label="Incident ID" value={incident.id} />
          <DetailRow label="Source" value={incident.source} />
          <DetailRow label="Category" value={incident.category} />
          <DetailRow label="Action Taken" value={incident.action_taken} />
          {incident.user && <DetailRow label="User" value={incident.user} />}
          {incident.model && <DetailRow label="AI Model" value={incident.model} />}
          {incident.endpoint_id && <DetailRow label="Endpoint" value={incident.endpoint_id} />}
          {incident.assigned_to && <DetailRow label="Assigned To" value={incident.assigned_to} />}
          <DetailRow label="Created" value={new Date(incident.created_at).toLocaleString()} />
          <DetailRow label="Updated" value={new Date(incident.updated_at).toLocaleString()} />
          {incident.resolved_at && (
            <DetailRow label="Resolved" value={new Date(incident.resolved_at).toLocaleString()} />
          )}
        </Section>

        {incident.details && Object.keys(incident.details).length > 0 && (
          <Section title="Additional Context">
            {Object.entries(incident.details).map(([key, value]) => (
              <DetailRow key={key} label={key} value={String(value)} />
            ))}
          </Section>
        )}

        {status === "open" && (
          <View style={styles.actions}>
            <TouchableOpacity style={styles.ackBtn} onPress={handleAcknowledge}>
              <Text style={styles.ackBtnText}>Acknowledge</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.resolveBtn} onPress={() => setShowResolve(true)}>
              <Text style={styles.resolveBtnText}>Resolve</Text>
            </TouchableOpacity>
          </View>
        )}

        {status === "acknowledged" && (
          <TouchableOpacity style={styles.resolveBtn} onPress={() => setShowResolve(true)}>
            <Text style={styles.resolveBtnText}>Resolve Incident</Text>
          </TouchableOpacity>
        )}

        {showResolve && (
          <View style={styles.resolveForm}>
            <Text style={styles.resolveLabel}>Resolution Notes</Text>
            <TextInput
              style={styles.resolveInput}
              multiline
              numberOfLines={4}
              placeholder="Describe the resolution..."
              value={resolution}
              onChangeText={setResolution}
            />
            <View style={styles.resolveActions}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => setShowResolve(false)}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.submitBtn} onPress={handleResolve}>
                <Text style={styles.submitBtnText}>Submit Resolution</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}
      </View>
    </ScrollView>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {children}
    </View>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.detailRow}>
      <Text style={styles.detailLabel}>{label}</Text>
      <Text style={styles.detailValue} selectable>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  headerBanner: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", padding: 16 },
  severityText: { fontSize: 18, fontWeight: "700" },
  content: { padding: 16 },
  title: { fontSize: 20, fontWeight: "700", color: "#111827", marginBottom: 8 },
  description: { fontSize: 14, color: "#4b5563", lineHeight: 22, marginBottom: 16 },
  section: { marginBottom: 20 },
  sectionTitle: { fontSize: 16, fontWeight: "600", color: "#111827", marginBottom: 10, paddingBottom: 6, borderBottomWidth: 1, borderBottomColor: "#e5e7eb" },
  detailRow: { flexDirection: "row", paddingVertical: 6, borderBottomWidth: 1, borderBottomColor: "#f3f4f6" },
  detailLabel: { width: 120, fontSize: 13, color: "#6b7280", fontWeight: "500" },
  detailValue: { flex: 1, fontSize: 13, color: "#111827" },
  actions: { flexDirection: "row", gap: 12, marginTop: 16 },
  ackBtn: { flex: 1, backgroundColor: "#3b82f6", padding: 14, borderRadius: 8, alignItems: "center" },
  ackBtnText: { color: "#fff", fontWeight: "600" },
  resolveBtn: { flex: 1, backgroundColor: "#22c55e", padding: 14, borderRadius: 8, alignItems: "center", marginTop: 16 },
  resolveBtnText: { color: "#fff", fontWeight: "600" },
  resolveForm: { backgroundColor: "#fff", padding: 16, borderRadius: 8, marginTop: 16, borderWidth: 1, borderColor: "#e5e7eb" },
  resolveLabel: { fontSize: 14, fontWeight: "600", color: "#111827", marginBottom: 8 },
  resolveInput: { borderWidth: 1, borderColor: "#d1d5db", borderRadius: 6, padding: 10, fontSize: 14, minHeight: 80, textAlignVertical: "top" },
  resolveActions: { flexDirection: "row", gap: 12, marginTop: 12 },
  cancelBtn: { flex: 1, padding: 10, borderRadius: 6, borderWidth: 1, borderColor: "#d1d5db", alignItems: "center" },
  cancelBtnText: { color: "#6b7280", fontWeight: "500" },
  submitBtn: { flex: 1, padding: 10, borderRadius: 6, backgroundColor: "#22c55e", alignItems: "center" },
  submitBtnText: { color: "#fff", fontWeight: "600" },
});
