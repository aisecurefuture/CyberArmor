import React, { useState, useEffect } from "react";
import { NavigationContainer } from "@react-navigation/native";
import { createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { createStackNavigator } from "@react-navigation/stack";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { AuthProvider, useAuth } from "./src/hooks/useAuth";
import { configureNotifications } from "./src/services/notifications";
import { BiometricGate } from "./src/components/BiometricGate";
import { DashboardScreen } from "./src/screens/DashboardScreen";
import { IncidentsScreen } from "./src/screens/IncidentsScreen";
import { PoliciesScreen } from "./src/screens/PoliciesScreen";
import { ComplianceScreen } from "./src/screens/ComplianceScreen";
import { EndpointsScreen } from "./src/screens/EndpointsScreen";
import { TelemetryScreen } from "./src/screens/TelemetryScreen";
import { AlertDetailScreen } from "./src/screens/AlertDetailScreen";
import { SettingsScreen } from "./src/screens/SettingsScreen";

const Tab = createBottomTabNavigator();
const Stack = createStackNavigator();

function IncidentsStack() {
  return (
    <Stack.Navigator>
      <Stack.Screen name="IncidentsList" component={IncidentsScreen} options={{ title: "Incidents" }} />
      <Stack.Screen name="AlertDetail" component={AlertDetailScreen} options={{ title: "Incident Detail" }} />
    </Stack.Navigator>
  );
}

function MainTabs() {
  return (
    <Tab.Navigator
      screenOptions={{
        tabBarActiveTintColor: "#3b82f6",
        tabBarInactiveTintColor: "#9ca3af",
        headerStyle: { backgroundColor: "#0f172a" },
        headerTintColor: "#f8fafc",
      }}
    >
      <Tab.Screen name="Dashboard" component={DashboardScreen} options={{ tabBarLabel: "Dashboard" }} />
      <Tab.Screen name="Incidents" component={IncidentsStack} options={{ headerShown: false, tabBarLabel: "Incidents" }} />
      <Tab.Screen name="Policies" component={PoliciesScreen} options={{ tabBarLabel: "Policies" }} />
      <Tab.Screen name="Compliance" component={ComplianceScreen} options={{ tabBarLabel: "Compliance" }} />
      <Tab.Screen name="Endpoints" component={EndpointsScreen} options={{ tabBarLabel: "Endpoints" }} />
      <Tab.Screen name="Telemetry" component={TelemetryScreen} options={{ tabBarLabel: "Telemetry" }} />
      <Tab.Screen name="Settings" component={SettingsScreen} options={{ tabBarLabel: "Settings" }} />
    </Tab.Navigator>
  );
}

function AppContent() {
  const { auth, settings, loading } = useAuth();
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    configureNotifications();
  }, []);

  if (loading) return null;

  if (!auth.authenticated) {
    return <SettingsScreen />;
  }

  if (settings.biometricEnabled && !unlocked) {
    return (
      <BiometricGate
        onUnlock={() => setUnlocked(true)}
        onSkip={() => setUnlocked(true)}
      />
    );
  }

  return (
    <NavigationContainer>
      <MainTabs />
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </SafeAreaProvider>
  );
}
