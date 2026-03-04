import AsyncStorage from "@react-native-async-storage/async-storage";
import ReactNativeBiometrics from "react-native-biometrics";
import { AuthState, User, AppSettings } from "../types";

const AUTH_STORAGE_KEY = "@aishields_auth";
const SETTINGS_STORAGE_KEY = "@aishields_settings";

const rnBiometrics = new ReactNativeBiometrics({ allowDeviceCredentials: true });

export async function checkBiometricAvailability(): Promise<{
  available: boolean;
  biometryType: string | undefined;
}> {
  try {
    const { available, biometryType } = await rnBiometrics.isSensorAvailable();
    return { available, biometryType };
  } catch {
    return { available: false, biometryType: undefined };
  }
}

export async function authenticateWithBiometrics(): Promise<boolean> {
  try {
    const { success } = await rnBiometrics.simplePrompt({
      promptMessage: "Authenticate to access AIShields Protect",
      cancelButtonText: "Cancel",
    });
    return success;
  } catch {
    return false;
  }
}

export async function loginWithApiKey(
  serverUrl: string,
  apiKey: string,
  tenantId: string
): Promise<{ success: boolean; user?: User; error?: string }> {
  try {
    const response = await fetch(`${serverUrl}/api/v1/auth/validate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
      body: JSON.stringify({ tenant_id: tenantId }),
    });

    if (!response.ok) {
      return { success: false, error: `Authentication failed: ${response.status}` };
    }

    const data = await response.json();
    const user: User = {
      id: data.user_id || "api-user",
      email: data.email || "api@aishields.ai",
      name: data.name || "API User",
      role: data.role || "admin",
      tenant_id: tenantId,
    };

    const authState: AuthState = {
      authenticated: true,
      user,
      token: apiKey,
      biometricEnabled: false,
    };

    await AsyncStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authState));
    return { success: true, user };
  } catch (error: any) {
    return { success: false, error: error.message || "Network error" };
  }
}

export async function getStoredAuth(): Promise<AuthState | null> {
  try {
    const data = await AsyncStorage.getItem(AUTH_STORAGE_KEY);
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

export async function logout(): Promise<void> {
  await AsyncStorage.removeItem(AUTH_STORAGE_KEY);
}

export async function getSettings(): Promise<AppSettings> {
  try {
    const data = await AsyncStorage.getItem(SETTINGS_STORAGE_KEY);
    if (data) return JSON.parse(data);
  } catch {}
  return {
    serverUrl: "",
    apiKey: "",
    tenantId: "",
    biometricEnabled: false,
    notificationsEnabled: true,
    darkMode: false,
    refreshInterval: 30,
  };
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  await AsyncStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
}
