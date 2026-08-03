import type { ScannerFinding } from "../../types.js";
import { LEAK_EVIDENCE_POST_CHARS, LEAK_EVIDENCE_PRE_CHARS } from "../constants.js";
import { LEAK_RULES } from "./leakRules.js";

function getEvidenceSnippet(content: string, pattern: RegExp): string {
  const matchedIndex = content.search(pattern);
  if (matchedIndex < 0) {
    return "Eşleşme bulundu ancak kanıt snippet'i alınamadı.";
  }

  const start = Math.max(0, matchedIndex - LEAK_EVIDENCE_PRE_CHARS);
  const end = Math.min(content.length, matchedIndex + LEAK_EVIDENCE_POST_CHARS);
  return content.slice(start, end).replace(/\s+/g, " ").trim();
}

export function runResponseLeakScanner(
  responseBody: string,
  endpoint: string,
): ScannerFinding[] {
  return LEAK_RULES.filter((rule) => rule.pattern.test(responseBody)).map((rule) => ({
    id: rule.id,
    category: "leak" as const,
    title: rule.title,
    severity: rule.severity,
    confidence: "high" as const,
    evidence: getEvidenceSnippet(responseBody, rule.pattern),
    remediation: rule.remediation,
    endpoint,
  }));
}
