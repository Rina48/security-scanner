import type { ScannerFinding, ScanResult, Severity } from "../types";

export function createFinding(
  severity: Severity = "medium",
  title = `${severity} bulgu`,
): ScannerFinding {
  return {
    id: `finding-${severity}-${title}`,
    category: "headers",
    title,
    severity,
    confidence: "high",
    evidence: `${title} kanıtı`,
    remediation: `${title} düzeltmesi`,
    endpoint: "https://example.test/path",
  };
}

export function createScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  const findings = overrides.findings ?? [createFinding()];
  const findingCounts = {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => finding.severity === "low").length,
  };

  return {
    scanId: "scan-1",
    targetUrl: "https://example.test",
    mode: "passive",
    isActiveAllowed: false,
    score: 42,
    findings,
    executiveSummary: {
      riskLevel: "medium",
      headline: "Kontrollü test taraması",
      businessRisk: "Test verisi üzerinden doğrulanan risk özeti.",
      immediateActions: ["Öncelikli bulguyu inceleyin."],
      findingCounts,
    },
    startedAt: "2026-01-01T10:00:00.000Z",
    completedAt: "2026-01-01T10:01:00.000Z",
    ...overrides,
  };
}
