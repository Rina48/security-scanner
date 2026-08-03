import type { ScanResult, ScannerFinding } from "../types.js";
import { maskSecrets, REDACTED_VALUE } from "./secretMasker.js";

const COOKIE_SECURITY_EVIDENCE_PATTERN = /^(Cookie: [!#$%&'*+\-.^_`|~0-9A-Za-z]+; Secure=(?:present|missing); HttpOnly=(?:present|missing); SameSite=(?:Strict|Lax|None|Invalid|missing))([\s\S]*)$/;
const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function canonicalizeLegacyCookieEvidence(evidence: string): string {
  const headerValue = evidence
    .replace(/^Set-Cookie\s*:\s*/i, "")
    .split(/\r?\n/, 1)[0]
    ?.trim();
  if (!headerValue) return REDACTED_VALUE;

  const [nameValue = "", ...attributes] = headerValue.split(";");
  const separatorIndex = nameValue.indexOf("=");
  if (separatorIndex <= 0) return REDACTED_VALUE;
  const name = nameValue.slice(0, separatorIndex).trim();
  if (!COOKIE_NAME_PATTERN.test(name)) return REDACTED_VALUE;

  let secure = false;
  let httpOnly = false;
  let sameSite = "missing";
  for (const rawAttribute of attributes) {
    const [rawKey = "", rawValue = ""] = rawAttribute.split("=", 2);
    const key = rawKey.trim().toLowerCase();
    if (key === "secure") secure = true;
    if (key === "httponly") httpOnly = true;
    if (key === "samesite") {
      const normalized = rawValue.trim().toLowerCase();
      sameSite = normalized === "strict"
        ? "Strict"
        : normalized === "lax"
          ? "Lax"
          : normalized === "none"
            ? "None"
            : "Invalid";
    }
  }

  return [
    `Cookie: ${name}`,
    `Secure=${secure ? "present" : "missing"}`,
    `HttpOnly=${httpOnly ? "present" : "missing"}`,
    `SameSite=${sameSite}`,
  ].join("; ");
}

function redactFindingEvidence(finding: ScannerFinding): string {
  if (finding.category !== "cookies") return maskSecrets(finding.evidence);
  const metadataEvidence = finding.evidence.match(COOKIE_SECURITY_EVIDENCE_PATTERN);
  if (!metadataEvidence) return canonicalizeLegacyCookieEvidence(finding.evidence);
  const [, safeMetadata = "", remainder = ""] = metadataEvidence;
  return `${safeMetadata}${maskSecrets(remainder)}`;
}

export function redactScannerFinding(finding: ScannerFinding): ScannerFinding {
  return {
    ...finding,
    title: maskSecrets(finding.title),
    evidence: redactFindingEvidence(finding),
    remediation: maskSecrets(finding.remediation),
    endpoint: maskSecrets(finding.endpoint),
  };
}

export function redactScanResult(scanResult: ScanResult): ScanResult {
  return {
    ...scanResult,
    targetUrl: maskSecrets(scanResult.targetUrl),
    findings: scanResult.findings.map(redactScannerFinding),
    executiveSummary: {
      ...scanResult.executiveSummary,
      headline: maskSecrets(scanResult.executiveSummary.headline),
      businessRisk: maskSecrets(scanResult.executiveSummary.businessRisk),
      immediateActions: scanResult.executiveSummary.immediateActions.map(maskSecrets),
    },
  };
}
