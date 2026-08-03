import { randomUUID } from "node:crypto";
import { deduplicateFindings } from "../utils/fingerprintDedup.js";
import { filterFalsePositives } from "../utils/falsePositiveFilter.js";
import { maskSecrets } from "../utils/secretMasker.js";
import { redactScanResult, redactScannerFinding } from "../utils/reportRedaction.js";
import { applyOverrides } from "../utils/severityOverride.js";
import { buildExecutiveSummary, calculateRiskSummary } from "./riskEngine.js";
import type { ScanMode, ScanResult, ScannerFinding, Severity } from "../types.js";

export function createScanReport(input: {
  targetUrl: string;
  mode: ScanMode;
  findings: ScannerFinding[];
  isActiveAllowed: boolean;
  startedAt: string;
  severityOverrides?: Record<string, Severity>;
  responseBody?: string;
  /** Async tarama için önceden üretilmiş ID kullanılır */
  scanId?: string;
}): ScanResult {
  const afterOverrides = applyOverrides(input.findings, input.severityOverrides);
  const afterFpFilter = filterFalsePositives(afterOverrides, input.responseBody ?? "");
  const afterDedup = deduplicateFindings(afterFpFilter);
  const afterMasking = afterDedup.map(redactScannerFinding);
  const targetUrl = maskSecrets(input.targetUrl);

  const { score } = calculateRiskSummary(afterMasking);
  const executiveSummary = buildExecutiveSummary(targetUrl, afterMasking);

  return redactScanResult({
    scanId: input.scanId ?? randomUUID(),
    targetUrl,
    mode: input.mode,
    isActiveAllowed: input.isActiveAllowed,
    score,
    findings: afterMasking,
    executiveSummary,
    startedAt: input.startedAt,
    completedAt: new Date().toISOString(),
  });
}
