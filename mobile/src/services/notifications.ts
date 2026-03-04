import PushNotification, { Importance } from "react-native-push-notification";
import { Platform } from "react-native";
import { Severity } from "../types";

const CHANNEL_ID = "aishields-alerts";

export function configureNotifications(): void {
  PushNotification.configure({
    onRegister: (token) => {
      console.log("AIShields Push Token:", token);
    },
    onNotification: (notification) => {
      console.log("AIShields Notification:", notification);
    },
    permissions: { alert: true, badge: true, sound: true },
    popInitialNotification: true,
    requestPermissions: Platform.OS === "ios",
  });

  if (Platform.OS === "android") {
    PushNotification.createChannel(
      {
        channelId: CHANNEL_ID,
        channelName: "AIShields Security Alerts",
        channelDescription: "Critical security alerts from AIShields Protect",
        importance: Importance.HIGH,
        vibrate: true,
        playSound: true,
      },
      (created) => console.log(`Notification channel created: ${created}`)
    );
  }
}

export function showLocalNotification(
  title: string,
  message: string,
  severity: Severity,
  data?: Record<string, unknown>
): void {
  const priorityMap: Record<Severity, string> = {
    critical: "max",
    high: "high",
    medium: "default",
    low: "low",
    info: "min",
  };

  PushNotification.localNotification({
    channelId: CHANNEL_ID,
    title: `[${severity.toUpperCase()}] ${title}`,
    message,
    priority: priorityMap[severity] as any,
    importance: severity === "critical" ? "max" : "high",
    vibrate: severity === "critical" || severity === "high",
    playSound: severity === "critical" || severity === "high",
    userInfo: data || {},
    smallIcon: "ic_notification",
    largeIcon: "ic_launcher",
    bigText: message,
  });
}

export function showIncidentNotification(
  incidentId: string,
  title: string,
  severity: Severity,
  source: string
): void {
  showLocalNotification(
    title,
    `Source: ${source} | Tap to view details`,
    severity,
    { incidentId, type: "incident" }
  );
}

export function clearAllNotifications(): void {
  PushNotification.cancelAllLocalNotifications();
}

export function setBadgeCount(count: number): void {
  if (Platform.OS === "ios") {
    PushNotification.setApplicationIconBadgeNumber(count);
  }
}
