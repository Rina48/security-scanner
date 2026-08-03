import type { ScannerFinding, Severity } from "../types.js";

const VALID_SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low"]);

function isValidSeverity(value: unknown): value is Severity {
  return typeof value === "string" && VALID_SEVERITIES.has(value as Severity);
}

/**
 * Applies caller-supplied severity overrides to findings.
 * Overrides are keyed by finding ID. Invalid values are silently ignored.
 */
export function applyOverrides(
  findings: ScannerFinding[],
  overrides: Record<string, Severity> | undefined,
): ScannerFinding[] {
  if (!overrides || Object.keys(overrides).length === 0) {
    return findings;
  }

  return findings.map((finding) => {
    const override = overrides[finding.id];
    if (isValidSeverity(override)) {
      return { ...finding, severity: override };
    }
    return finding;
  });
}
