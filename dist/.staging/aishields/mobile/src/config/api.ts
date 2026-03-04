export interface ServiceConfig {
  name: string;
  port: number;
  healthPath: string;
}

export const SERVICES: Record<string, ServiceConfig> = {
  controlPlane: { name: "Control Plane", port: 8000, healthPath: "/health" },
  policy: { name: "Policy Engine", port: 8001, healthPath: "/health" },
  detection: { name: "Detection", port: 8002, healthPath: "/health" },
  response: { name: "Response", port: 8003, healthPath: "/health" },
  identity: { name: "Identity", port: 8004, healthPath: "/health" },
  siem: { name: "SIEM Connector", port: 8005, healthPath: "/health" },
  compliance: { name: "Compliance", port: 8006, healthPath: "/health" },
  proxy: { name: "Proxy Agent", port: 8010, healthPath: "/health" },
};

export const DEFAULT_SERVER_URL = "https://aishields.example.com";
export const API_VERSION = "v1";
export const REQUEST_TIMEOUT = 15000;
export const MAX_RETRIES = 3;
export const RETRY_DELAY = 1000;

export function getServiceUrl(baseUrl: string, service: keyof typeof SERVICES): string {
  const svc = SERVICES[service];
  // In production, all services are behind the ingress on the same host
  return `${baseUrl}/api/${API_VERSION}`;
}

export const PQC_HEADER_PREFIX = "PQC:";

export function buildHeaders(apiKey: string, pqcEnabled: boolean = true): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  if (apiKey) {
    headers["x-api-key"] = pqcEnabled ? `${PQC_HEADER_PREFIX}${apiKey}` : apiKey;
  }

  return headers;
}
