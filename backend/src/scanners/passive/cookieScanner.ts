import { Headers } from "undici";
import type { ScannerFinding } from "../../types.js";

function parseSetCookieHeader(headers: Headers): string[] {
  const allCookies = headers.get("set-cookie");
  if (!allCookies) {
    return [];
  }

  return allCookies
    .split(/,(?=[^;]+=[^;]+)/g)
    .map((cookieValue) => cookieValue.trim())
    .filter(Boolean);
}

export function runCookieScanner(headers: Headers, endpoint: string): ScannerFinding[] {
  const findings: ScannerFinding[] = [];
  const cookies = parseSetCookieHeader(headers);

  for (const cookie of cookies) {
    const lowerCookie = cookie.toLowerCase();
    const cookieName = cookie.split("=")[0]?.trim() ?? "unknown-cookie";

    if (!lowerCookie.includes("secure")) {
      findings.push({
        id: `cookie-without-secure-${cookieName}`,
        category: "cookies",
        title: `${cookieName} cookie missing Secure flag`,
        severity: "high",
        confidence: "high",
        evidence: cookie,
        remediation:
          "Set the Secure attribute so cookies are only transmitted over HTTPS.",
        endpoint,
      });
    }

    if (!lowerCookie.includes("httponly")) {
      findings.push({
        id: `cookie-without-httponly-${cookieName}`,
        category: "cookies",
        title: `${cookieName} cookie missing HttpOnly flag`,
        severity: "medium",
        confidence: "high",
        evidence: cookie,
        remediation:
          "Set HttpOnly to reduce cookie theft via client-side script access.",
        endpoint,
      });
    }

    if (!lowerCookie.includes("samesite")) {
      findings.push({
        id: `cookie-without-samesite-${cookieName}`,
        category: "cookies",
        title: `${cookieName} cookie missing SameSite attribute`,
        severity: "medium",
        confidence: "high",
        evidence: cookie,
        remediation:
          "Set SameSite to Lax or Strict to reduce cross-site request risks.",
        endpoint,
      });
    }
  }

  return findings;
}
