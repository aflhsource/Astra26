const API_BASE =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:5001/api/v1";

export type DemoScenario =
  | "clean"
  | "valid-transformation"
  | "tamper"
  | "replay"
  | "expired"
  | "unknown-source"
  | "unauthorized-transformation"
  | "context-mismatch";

export interface DemoExchange {
  transactionId: string;
  source: { sourceId: string };
  resourceType: string;
  payload: unknown;
  context: { audience: string; purpose: string };
  verification: {
    decision: "ALLOW" | "REVIEW" | "QUARANTINE";
    reasonCodes: string[];
  };
  trustScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  trustPassId?: string;
}

export interface DemoRunResult {
  scenario: DemoScenario;
  exchange: DemoExchange;
  attempts?: DemoExchange[];
}

export interface DashboardSummary {
  totalExchanges: number;
  allowed: number;
  review: number;
  quarantined: number;
  averageTrustScore: number;
  recentExchanges: DemoExchange[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  const body = (await response.json()) as {
    success?: boolean;
    data?: T;
    error?: { message?: string };
  };
  if (!response.ok || !body.success || body.data === undefined) {
    throw new Error(
      body.error?.message ?? `Request failed with HTTP ${response.status}`,
    );
  }
  return body.data;
}

export function runDemoScenario(
  scenario: DemoScenario,
): Promise<DemoRunResult> {
  return request<DemoRunResult>(`/simulation/scenarios/${scenario}`, {
    method: "POST",
    body: "{}",
  });
}

export function consumeDownstream(input: {
  transactionId: string;
  trustPassId: string;
  payload: unknown;
  audience: string;
  purpose: string;
}): Promise<{ transactionId: string; consumed: boolean; decision: string }> {
  return request("/downstream/consume", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function getDashboardSummary(): Promise<DashboardSummary> {
  return request<DashboardSummary>("/dashboard/summary");
}

export function getExchanges(): Promise<DemoExchange[]> {
  return request<DemoExchange[]>("/exchanges");
}
