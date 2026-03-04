import axios, { AxiosInstance, AxiosError } from "axios";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { buildHeaders, REQUEST_TIMEOUT, MAX_RETRIES, RETRY_DELAY } from "../config/api";
import {
  DashboardStats, Incident, Policy, Endpoint,
  ComplianceFramework, ComplianceResult, TelemetryEvent, ThreatTrend,
} from "../types";

const OFFLINE_QUEUE_KEY = "@aishields_offline_queue";

interface QueuedRequest {
  method: string;
  url: string;
  data?: unknown;
  timestamp: number;
}

let client: AxiosInstance | null = null;

export function initApiClient(serverUrl: string, apiKey: string): AxiosInstance {
  client = axios.create({
    baseURL: `${serverUrl}/api/v1`,
    timeout: REQUEST_TIMEOUT,
    headers: buildHeaders(apiKey),
  });

  // Retry interceptor
  client.interceptors.response.use(undefined, async (error: AxiosError) => {
    const config: any = error.config;
    if (!config || config._retryCount >= MAX_RETRIES) {
      // Queue for offline sync if network error
      if (!error.response) {
        await queueRequest(config);
      }
      return Promise.reject(error);
    }
    config._retryCount = (config._retryCount || 0) + 1;
    await new Promise((r) => setTimeout(r, RETRY_DELAY * config._retryCount));
    return client!.request(config);
  });

  return client;
}

function getClient(): AxiosInstance {
  if (!client) throw new Error("API client not initialized. Call initApiClient first.");
  return client;
}

// Offline queue management
async function queueRequest(config: any): Promise<void> {
  if (!config) return;
  try {
    const queue = await getOfflineQueue();
    queue.push({
      method: config.method,
      url: config.url,
      data: config.data,
      timestamp: Date.now(),
    });
    // Keep only last 100 items
    const trimmed = queue.slice(-100);
    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(trimmed));
  } catch {}
}

async function getOfflineQueue(): Promise<QueuedRequest[]> {
  try {
    const data = await AsyncStorage.getItem(OFFLINE_QUEUE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export async function flushOfflineQueue(): Promise<number> {
  const queue = await getOfflineQueue();
  if (queue.length === 0) return 0;

  let flushed = 0;
  const api = getClient();
  for (const req of queue) {
    try {
      await api.request({ method: req.method, url: req.url, data: req.data });
      flushed++;
    } catch {
      break; // Still offline, stop flushing
    }
  }

  if (flushed > 0) {
    const remaining = queue.slice(flushed);
    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(remaining));
  }

  return flushed;
}

// Dashboard
export async function getDashboardStats(tenantId: string): Promise<DashboardStats> {
  const { data } = await getClient().get(`/dashboard/stats`, { params: { tenant_id: tenantId } });
  return data;
}

export async function getThreatTrends(tenantId: string, days: number = 7): Promise<ThreatTrend[]> {
  const { data } = await getClient().get(`/dashboard/trends`, { params: { tenant_id: tenantId, days } });
  return data;
}

// Incidents
export async function getIncidents(tenantId: string, params?: {
  severity?: string; status?: string; limit?: number; offset?: number;
}): Promise<Incident[]> {
  const { data } = await getClient().get(`/incidents`, { params: { tenant_id: tenantId, ...params } });
  return data;
}

export async function getIncident(id: string): Promise<Incident> {
  const { data } = await getClient().get(`/incidents/${id}`);
  return data;
}

export async function acknowledgeIncident(id: string): Promise<void> {
  await getClient().post(`/incidents/${id}/acknowledge`);
}

export async function resolveIncident(id: string, resolution: string): Promise<void> {
  await getClient().post(`/incidents/${id}/resolve`, { resolution });
}

// Policies
export async function getPolicies(tenantId: string): Promise<Policy[]> {
  const { data } = await getClient().get(`/policies`, { params: { tenant_id: tenantId } });
  return data;
}

export async function togglePolicy(id: string, enabled: boolean): Promise<void> {
  await getClient().patch(`/policies/${id}`, { enabled });
}

// Endpoints
export async function getEndpoints(tenantId: string): Promise<Endpoint[]> {
  const { data } = await getClient().get(`/endpoints`, { params: { tenant_id: tenantId } });
  return data;
}

// Compliance
export async function getComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const { data } = await getClient().get(`/compliance/frameworks`);
  return data;
}

export async function runComplianceAssessment(
  tenantId: string, frameworks: string[]
): Promise<ComplianceResult[]> {
  const { data } = await getClient().post(`/compliance/assess/${tenantId}`, { frameworks });
  return data;
}

// Telemetry
export async function getTelemetry(tenantId: string, params?: {
  source?: string; severity?: string; limit?: number;
}): Promise<TelemetryEvent[]> {
  const { data } = await getClient().get(`/telemetry`, { params: { tenant_id: tenantId, ...params } });
  return data;
}

// Health
export async function checkHealth(): Promise<Record<string, boolean>> {
  const { data } = await getClient().get(`/health`);
  return data;
}
