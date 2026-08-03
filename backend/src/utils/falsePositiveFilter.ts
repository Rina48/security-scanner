import type { ScannerFinding } from "../types.js";

interface SuppressRule {
  findingId: string;
  reason: string;
  /**
   * If the response body contains this pattern, the finding is suppressed
   * because it is likely a documentation page, test fixture or local dev env.
   */
  suppressWhenBodyContains: RegExp;
}

const SUPPRESS_RULES: SuppressRule[] = [
  {
    findingId: "php-warning-disclosure",
    reason: "Common words like 'Warning' or 'Notice' appear in many docs/blogs",
    suppressWhenBodyContains: /(<!DOCTYPE html>.*?<title>[^<]*(docs?|guide|tutorial|blog))/is,
  },
  {
    findingId: "internal-api-endpoint-disclosure",
    reason: "The '.local' TLD is a documented example in many README/API docs",
    suppressWhenBodyContains: /(<title>[^<]*(documentation|readme|swagger|openapi))/i,
  },
];

/**
 * Removes findings that are likely false positives based on response body context.
 * Suppressed findings are surfaced as low-confidence informational items instead
 * of being silently dropped, so auditors can review the decision.
 */
export function filterFalsePositives(
  findings: ScannerFinding[],
  responseBody: string,
): ScannerFinding[] {
  return findings.map((finding) => {
    const suppression = SUPPRESS_RULES.find(
      (rule) =>
        rule.findingId === finding.id && rule.suppressWhenBodyContains.test(responseBody),
    );

    if (!suppression) {
      return finding;
    }

    return {
      ...finding,
      severity: "low" as const,
      confidence: "low" as const,
      evidence: `[FP-SUPPRESSED: ${suppression.reason}] ${finding.evidence}`,
    };
  });
}
