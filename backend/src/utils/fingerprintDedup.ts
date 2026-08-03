import type { ScannerFinding } from "../types.js";

const CONFIDENCE_ORDER: Record<ScannerFinding["confidence"], number> = {
  high: 1,
  medium: 2,
  low: 3,
};

/**
 * Removes duplicate findings by ID, keeping the one with the highest confidence.
 * When two modules detect the same logical issue, only the most confident signal wins.
 */
export function deduplicateFindings(findings: ScannerFinding[]): ScannerFinding[] {
  const bestByFingerprint = new Map<string, ScannerFinding>();

  for (const finding of findings) {
    const existing = bestByFingerprint.get(finding.id);
    if (!existing) {
      bestByFingerprint.set(finding.id, finding);
      continue;
    }

    const isMoreConfident =
      CONFIDENCE_ORDER[finding.confidence] < CONFIDENCE_ORDER[existing.confidence];
    if (isMoreConfident) {
      bestByFingerprint.set(finding.id, finding);
    }
  }

  return Array.from(bestByFingerprint.values());
}
