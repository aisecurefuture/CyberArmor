import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import { AuthState, User, AppSettings } from "../types";
import {
  getStoredAuth, loginWithApiKey, logout as authLogout,
  authenticateWithBiometrics, getSettings, saveSettings,
} from "../services/auth";
import { initApiClient } from "../services/api";

interface AuthContextType {
  auth: AuthState;
  settings: AppSettings;
  login: (serverUrl: string, apiKey: string, tenantId: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  unlockWithBiometrics: () => Promise<boolean>;
  updateSettings: (settings: Partial<AppSettings>) => Promise<void>;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>({
    authenticated: false,
    user: null,
    token: null,
    biometricEnabled: false,
  });
  const [settings, setSettings] = useState<AppSettings>({
    serverUrl: "",
    apiKey: "",
    tenantId: "",
    biometricEnabled: false,
    notificationsEnabled: true,
    darkMode: false,
    refreshInterval: 30,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [storedAuth, storedSettings] = await Promise.all([getStoredAuth(), getSettings()]);
      if (storedSettings) setSettings(storedSettings);
      if (storedAuth?.authenticated && storedAuth.token && storedSettings?.serverUrl) {
        initApiClient(storedSettings.serverUrl, storedAuth.token);
        setAuth(storedAuth);
      }
      setLoading(false);
    })();
  }, []);

  const login = useCallback(async (serverUrl: string, apiKey: string, tenantId: string) => {
    const result = await loginWithApiKey(serverUrl, apiKey, tenantId);
    if (result.success && result.user) {
      initApiClient(serverUrl, apiKey);
      setAuth({ authenticated: true, user: result.user, token: apiKey, biometricEnabled: settings.biometricEnabled });
      await updateSettings({ serverUrl, apiKey, tenantId });
      return { success: true };
    }
    return { success: false, error: result.error };
  }, [settings.biometricEnabled]);

  const logout = useCallback(async () => {
    await authLogout();
    setAuth({ authenticated: false, user: null, token: null, biometricEnabled: false });
  }, []);

  const unlockWithBiometrics = useCallback(async () => {
    return await authenticateWithBiometrics();
  }, []);

  const updateSettings = useCallback(async (partial: Partial<AppSettings>) => {
    const updated = { ...settings, ...partial };
    setSettings(updated);
    await saveSettings(updated);
  }, [settings]);

  return React.createElement(
    AuthContext.Provider,
    { value: { auth, settings, login, logout, unlockWithBiometrics, updateSettings, loading } },
    children
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
