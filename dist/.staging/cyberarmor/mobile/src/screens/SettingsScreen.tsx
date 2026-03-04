import React, { useState } from "react";
import { View, Text, TextInput, Switch, TouchableOpacity, ScrollView, Alert, StyleSheet } from "react-native";
import { useAuth } from "../hooks/useAuth";
import { checkBiometricAvailability } from "../services/auth";
import { checkHealth } from "../services/api";

export function SettingsScreen() {
  const { auth, settings, login, logout, updateSettings } = useAuth();
  const [serverUrl, setServerUrl] = useState(settings.serverUrl);
  const [apiKey, setApiKey] = useState(settings.apiKey);
  const [tenantId, setTenantId] = useState(settings.tenantId);
  const [testing, setTesting] = useState(false);

  const handleSave = async () => {
    if (!serverUrl || !apiKey || !tenantId) {
      Alert.alert("Required", "All connection fields are required");
      return;
    }
    const result = await login(serverUrl, apiKey, tenantId);
    if (result.success) {
      Alert.alert("Success", "Connected to CyberArmor.ai server");
    } else {
      Alert.alert("Error", result.error || "Connection failed");
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    try {
      const health = await checkHealth();
      const services = Object.entries(health)
        .map(([k, v]) => `${k}: ${v ? "OK" : "DOWN"}`)
        .join("\n");
      Alert.alert("Connection Test", services);
    } catch (e: any) {
      Alert.alert("Connection Failed", e.message);
    }
    setTesting(false);
  };

  const toggleBiometric = async (value: boolean) => {
    if (value) {
      const { available } = await checkBiometricAvailability();
      if (!available) {
        Alert.alert("Unavailable", "Biometric authentication is not available on this device");
        return;
      }
    }
    await updateSettings({ biometricEnabled: value });
  };

  return (
    <ScrollView style={styles.container}>
      <Section title="Connection">
        <InputField label="Server URL" value={serverUrl} onChangeText={setServerUrl} placeholder="https://aishields.example.com" />
        <InputField label="API Key" value={apiKey} onChangeText={setApiKey} placeholder="Your API key" secureTextEntry />
        <InputField label="Tenant ID" value={tenantId} onChangeText={setTenantId} placeholder="tenant-1" />
        <View style={styles.btnRow}>
          <TouchableOpacity style={styles.testBtn} onPress={handleTestConnection} disabled={testing}>
            <Text style={styles.testBtnText}>{testing ? "Testing..." : "Test Connection"}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.saveBtn} onPress={handleSave}>
            <Text style={styles.saveBtnText}>Save & Connect</Text>
          </TouchableOpacity>
        </View>
      </Section>

      <Section title="Security">
        <ToggleRow label="Biometric Lock" value={settings.biometricEnabled} onToggle={toggleBiometric} description="Require Face ID / fingerprint to open the app" />
      </Section>

      <Section title="Notifications">
        <ToggleRow label="Push Notifications" value={settings.notificationsEnabled} onToggle={(v) => updateSettings({ notificationsEnabled: v })} description="Receive alerts for critical security events" />
      </Section>

      <Section title="Display">
        <ToggleRow label="Dark Mode" value={settings.darkMode} onToggle={(v) => updateSettings({ darkMode: v })} description="Use dark theme" />
        <View style={styles.fieldContainer}>
          <Text style={styles.fieldLabel}>Auto-refresh interval (seconds)</Text>
          <TextInput
            style={styles.input}
            value={String(settings.refreshInterval)}
            onChangeText={(v) => updateSettings({ refreshInterval: parseInt(v) || 30 })}
            keyboardType="numeric"
          />
        </View>
      </Section>

      <Section title="Account">
        {auth.user && (
          <View style={styles.userInfo}>
            <Text style={styles.userName}>{auth.user.name}</Text>
            <Text style={styles.userEmail}>{auth.user.email}</Text>
            <Text style={styles.userRole}>Role: {auth.user.role}</Text>
          </View>
        )}
        <TouchableOpacity style={styles.logoutBtn} onPress={logout}>
          <Text style={styles.logoutBtnText}>Sign Out</Text>
        </TouchableOpacity>
      </Section>

      <Text style={styles.version}>CyberArmor.ai Protect v1.0.0</Text>
    </ScrollView>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      <View style={styles.sectionContent}>{children}</View>
    </View>
  );
}

function InputField({ label, ...props }: { label: string } & any) {
  return (
    <View style={styles.fieldContainer}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput style={styles.input} autoCapitalize="none" autoCorrect={false} {...props} />
    </View>
  );
}

function ToggleRow({ label, value, onToggle, description }: { label: string; value: boolean; onToggle: (v: boolean) => void; description: string }) {
  return (
    <View style={styles.toggleRow}>
      <View style={{ flex: 1 }}>
        <Text style={styles.toggleLabel}>{label}</Text>
        <Text style={styles.toggleDesc}>{description}</Text>
      </View>
      <Switch value={value} onValueChange={onToggle} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#f9fafb" },
  section: { marginBottom: 8 },
  sectionTitle: { fontSize: 13, fontWeight: "600", color: "#6b7280", textTransform: "uppercase", paddingHorizontal: 16, paddingTop: 20, paddingBottom: 8 },
  sectionContent: { backgroundColor: "#fff", paddingHorizontal: 16 },
  fieldContainer: { paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: "#f3f4f6" },
  fieldLabel: { fontSize: 13, color: "#6b7280", marginBottom: 4 },
  input: { fontSize: 15, color: "#111827", padding: 8, borderWidth: 1, borderColor: "#e5e7eb", borderRadius: 6, backgroundColor: "#f9fafb" },
  btnRow: { flexDirection: "row", gap: 12, paddingVertical: 12 },
  testBtn: { flex: 1, padding: 12, borderRadius: 6, borderWidth: 1, borderColor: "#3b82f6", alignItems: "center" },
  testBtnText: { color: "#3b82f6", fontWeight: "600" },
  saveBtn: { flex: 1, padding: 12, borderRadius: 6, backgroundColor: "#3b82f6", alignItems: "center" },
  saveBtnText: { color: "#fff", fontWeight: "600" },
  toggleRow: { flexDirection: "row", alignItems: "center", paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: "#f3f4f6" },
  toggleLabel: { fontSize: 15, fontWeight: "500", color: "#111827" },
  toggleDesc: { fontSize: 12, color: "#9ca3af", marginTop: 2 },
  userInfo: { paddingVertical: 12, borderBottomWidth: 1, borderBottomColor: "#f3f4f6" },
  userName: { fontSize: 16, fontWeight: "600", color: "#111827" },
  userEmail: { fontSize: 14, color: "#6b7280", marginTop: 2 },
  userRole: { fontSize: 13, color: "#3b82f6", marginTop: 4, fontWeight: "500" },
  logoutBtn: { paddingVertical: 14, alignItems: "center" },
  logoutBtnText: { color: "#ef4444", fontWeight: "600", fontSize: 15 },
  version: { textAlign: "center", color: "#9ca3af", fontSize: 12, paddingVertical: 24 },
});
