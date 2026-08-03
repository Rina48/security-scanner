import type { ScanMode, ScanResult } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:4310";

export interface CreateScanOptions {
  credentialCheck?: boolean;
}

function authorizationHeaders(apiToken: string, includeJson = false): Record<string, string> {
  if (!apiToken) throw new Error("API token gerekli.");
  return {
    authorization: `Bearer ${apiToken}`,
    ...(includeJson ? { "content-type": "application/json" } : {}),
  };
}

async function readErrorMessage(response: Response, fallbackMessage: string): Promise<string> {
  const payload = (await response.json().catch(() => ({}))) as { message?: unknown };
  return typeof payload.message === "string" ? payload.message : fallbackMessage;
}

async function ensureOk(response: Response, fallbackMessage: string): Promise<void> {
  if (response.ok) return;
  throw new Error(await readErrorMessage(response, fallbackMessage));
}

export async function createScan(
  apiToken: string,
  targetUrl: string,
  mode: ScanMode,
  options?: CreateScanOptions,
): Promise<ScanResult> {
  const body: Record<string, unknown> = {
    targetUrl,
    mode,
    ...(options?.credentialCheck && { credentialCheck: true }),
  };

  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: "POST",
    headers: authorizationHeaders(apiToken, true),
    body: JSON.stringify(body),
  });

  await ensureOk(response, "Scan could not be completed.");

  return response.json();
}

export async function analyzeBody(
  apiToken: string,
  sourceLabel: string,
  body: string,
): Promise<ScanResult> {
  const response = await fetch(`${API_BASE_URL}/api/body-scans`, {
    method: "POST",
    headers: authorizationHeaders(apiToken, true),
    body: JSON.stringify({ sourceLabel, body }),
  });

  await ensureOk(response, "Body analysis failed.");

  return response.json();
}

export async function clearScans(apiToken: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    method: "DELETE",
    headers: authorizationHeaders(apiToken),
  });
  await ensureOk(response, "Geçmiş temizlenemedi.");
}

export async function fetchScans(apiToken: string): Promise<ScanResult[]> {
  const response = await fetch(`${API_BASE_URL}/api/scans`, {
    headers: authorizationHeaders(apiToken),
  });
  await ensureOk(response, "Failed to fetch scan history.");
  const payload = (await response.json()) as { scans: ScanResult[] };
  return payload.scans;
}
