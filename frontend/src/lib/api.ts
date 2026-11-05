/**
 * Frontend HTTP API Client for communicating with @dsh/backend
 * Note: Frontend never connects directly to the PostgreSQL database.
 */

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000/api/v1";

export interface HealthResponse {
  status: string;
  service?: string;
  database?: string;
  latencyMs?: number;
  timestamp: string;
}

export async function fetchBackendHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    method: "GET",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Backend health check failed with status ${response.status}`);
  }
  return response.json() as Promise<HealthResponse>;
}
