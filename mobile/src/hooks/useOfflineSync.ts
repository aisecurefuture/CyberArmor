import { useState, useEffect, useCallback } from "react";
import { AppState, AppStateStatus } from "react-native";
import { flushOfflineQueue } from "../services/api";

export function useOfflineSync() {
  const [syncing, setSyncing] = useState(false);
  const [pendingCount, setPendingCount] = useState(0);

  const sync = useCallback(async () => {
    setSyncing(true);
    try {
      const flushed = await flushOfflineQueue();
      setPendingCount((prev) => Math.max(0, prev - flushed));
      return flushed;
    } catch {
      return 0;
    } finally {
      setSyncing(false);
    }
  }, []);

  // Auto-sync when app comes to foreground
  useEffect(() => {
    const handleAppState = (state: AppStateStatus) => {
      if (state === "active") sync();
    };
    const sub = AppState.addEventListener("change", handleAppState);
    return () => sub.remove();
  }, [sync]);

  return { syncing, pendingCount, sync };
}
