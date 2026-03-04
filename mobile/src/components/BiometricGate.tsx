import React, { useState, useEffect } from "react";
import { View, Text, TouchableOpacity, StyleSheet, Image } from "react-native";
import { authenticateWithBiometrics, checkBiometricAvailability } from "../services/auth";

interface Props {
  onUnlock: () => void;
  onSkip?: () => void;
}

export function BiometricGate({ onUnlock, onSkip }: Props) {
  const [biometryType, setBiometryType] = useState<string>("Biometrics");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    (async () => {
      const { available, biometryType: type } = await checkBiometricAvailability();
      if (type) setBiometryType(type);
      if (available) attemptAuth();
    })();
  }, []);

  const attemptAuth = async () => {
    setError("");
    const success = await authenticateWithBiometrics();
    if (success) {
      onUnlock();
    } else {
      setError("Authentication failed. Tap to try again.");
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.iconContainer}>
        <Text style={styles.shieldIcon}>🛡️</Text>
      </View>
      <Text style={styles.title}>AIShields Protect</Text>
      <Text style={styles.subtitle}>Authentication required</Text>

      {error ? <Text style={styles.error}>{error}</Text> : null}

      <TouchableOpacity style={styles.button} onPress={attemptAuth} activeOpacity={0.7}>
        <Text style={styles.buttonText}>Unlock with {biometryType}</Text>
      </TouchableOpacity>

      {onSkip && (
        <TouchableOpacity style={styles.skipButton} onPress={onSkip}>
          <Text style={styles.skipText}>Use API Key Instead</Text>
        </TouchableOpacity>
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#0f172a",
    alignItems: "center",
    justifyContent: "center",
    padding: 32,
  },
  iconContainer: { marginBottom: 24 },
  shieldIcon: { fontSize: 64 },
  title: { fontSize: 28, fontWeight: "700", color: "#f8fafc", marginBottom: 8 },
  subtitle: { fontSize: 16, color: "#94a3b8", marginBottom: 32 },
  error: { color: "#f87171", fontSize: 14, marginBottom: 16, textAlign: "center" },
  button: {
    backgroundColor: "#3b82f6",
    paddingVertical: 14,
    paddingHorizontal: 32,
    borderRadius: 8,
    minWidth: 240,
    alignItems: "center",
  },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  skipButton: { marginTop: 16, padding: 8 },
  skipText: { color: "#64748b", fontSize: 14 },
});
