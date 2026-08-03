import { createScanReport } from "../reporting/reportGenerator.js";
import { runResponseLeakScanner } from "./passive/responseLeakScanner.js";
import type { ScanResult, Severity } from "../types.js";

export interface BodyScanRequest {
  /** Label for the report — typically the URL the response was captured from. */
  sourceLabel: string;
  /** Raw response body text (HTML, JSON, plain text, etc.). */
  body: string;
  severityOverrides?: Record<string, Severity>;
}

/**
 * Runs leak detection on a caller-supplied response body without making any
 * network request. Used for offline analysis of saved/captured responses.
 * Header, cookie and TLS checks are skipped since there is no live connection.
 */
export function runBodyScan(request: BodyScanRequest): ScanResult {
  const startedAt = new Date().toISOString();
  const findings = runResponseLeakScanner(request.body, request.sourceLabel);

  return createScanReport({
    targetUrl: request.sourceLabel,
    mode: "passive",
    findings,
    isActiveAllowed: false,
    startedAt,
    severityOverrides: request.severityOverrides,
    responseBody: request.body,
  });
}
