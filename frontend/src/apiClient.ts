import type { ScanMode, ScanResult } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:4310";

export type ApiErrorCode =
  | "invalid-token"
  | "api-unreachable"
  | "target-not-authorized"
  | "invalid-request"
  | "resource-limited"
  | "request-failed"
  | "unexpected";

export class ApiClientError extends Error {
  readonly code: ApiErrorCode;
  readonly status?: number;

  constructor(code: ApiErrorCode, message: string, status?: number) {
    super(message);
    this.name = "ApiClientError";
    this.code = code;
    this.status = status;
  }
}

export interface CreateScanOptions {
  credentialCheck?: boolean;
  signal?: AbortSignal;
}

function authorizationHeaders(apiToken: string, includeJson = false): Record<string, string> {
  return {
    authorization: `Bearer ${apiToken}`,
    ...(includeJson ? { "content-type": "application/json" } : {}),
  };
}

function errorForStatus(status: number): ApiClientError {
  if (status === 401) {
    return new ApiClientError("invalid-token", "API token kabul edilmedi.", status);
  }
  if (status === 403) {
    return new ApiClientError(
      "target-not-authorized",
      "Bu hedef seçilen tarama için yetkili değil.",
      status,
    );
  }
  if (status === 400) {
    return new ApiClientError("invalid-request", "İstek bilgileri geçerli değil.", status);
  }
  if (status === 429 || status === 503) {
    return new ApiClientError(
      "resource-limited",
      "Tarama kapasitesi şu anda dolu.",
      status,
    );
  }
  if (status >= 500) {
    return new ApiClientError("request-failed", "API isteği tamamlayamadı.", status);
  }
  return new ApiClientError("unexpected", "Beklenmeyen bir API yanıtı alındı.", status);
}

async function requestJson<T>(
  path: string,
  apiToken: string,
  init?: RequestInit,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        ...authorizationHeaders(apiToken, Boolean(init?.body)),
        ...init?.headers,
      },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiClientError("api-unreachable", "API servisine ulaşılamadı.");
  }

  if (!response.ok) throw errorForStatus(response.status);

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiClientError("unexpected", "API yanıtı okunamadı.", response.status);
  }
}

export async function connectToApi(apiToken: string): Promise<ScanResult[]> {
  return fetchScans(apiToken);
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

  return requestJson<ScanResult>("/api/scans", apiToken, {
    method: "POST",
    body: JSON.stringify(body),
    signal: options?.signal,
  });
}

export async function analyzeBody(
  apiToken: string,
  sourceLabel: string,
  body: string,
  signal?: AbortSignal,
): Promise<ScanResult> {
  return requestJson<ScanResult>("/api/body-scans", apiToken, {
    method: "POST",
    body: JSON.stringify({ sourceLabel, body }),
    signal,
  });
}

export async function clearScans(apiToken: string): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/scans`, {
      method: "DELETE",
      headers: authorizationHeaders(apiToken),
    });
  } catch {
    throw new ApiClientError("api-unreachable", "API servisine ulaşılamadı.");
  }
  if (!response.ok) throw errorForStatus(response.status);
}

export async function fetchScans(apiToken: string): Promise<ScanResult[]> {
  const payload = await requestJson<{ scans: ScanResult[] }>("/api/scans", apiToken);
  return payload.scans;
}
