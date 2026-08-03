import { Headers } from "undici";
import type { ScannerFinding } from "../../types.js";

interface CookieSecurityMetadata {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | "Invalid" | null;
}

const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function normalizeSameSite(value: string): CookieSecurityMetadata["sameSite"] {
  switch (value.trim().toLowerCase()) {
    case "strict":
      return "Strict";
    case "lax":
      return "Lax";
    case "none":
      return "None";
    default:
      return "Invalid";
  }
}

function toSecurityMetadata(setCookieValue: string): CookieSecurityMetadata {
  const [nameValue = "", ...attributes] = setCookieValue.split(";");
  const separatorIndex = nameValue.indexOf("=");
  const rawName = separatorIndex >= 0
    ? nameValue.slice(0, separatorIndex).trim()
    : "";
  const name = COOKIE_NAME_PATTERN.test(rawName) ? rawName : "unknown-cookie";

  let secure = false;
  let httpOnly = false;
  let sameSite: CookieSecurityMetadata["sameSite"] = null;
  for (const rawAttribute of attributes) {
    const [rawKey = "", rawValue = ""] = rawAttribute.split("=", 2);
    const key = rawKey.trim().toLowerCase();
    if (key === "secure") secure = true;
    if (key === "httponly") httpOnly = true;
    if (key === "samesite") sameSite = normalizeSameSite(rawValue);
  }

  return { name, secure, httpOnly, sameSite };
}

function parseSetCookieHeaders(headers: Headers): CookieSecurityMetadata[] {
  const allCookies = headers.get("set-cookie");
  if (!allCookies) return [];

  return allCookies
    .split(/,(?=[^;,]+=[^;,]+)/g)
    .map((cookieValue) => toSecurityMetadata(cookieValue.trim()));
}

function securityEvidence(cookie: CookieSecurityMetadata): string {
  return [
    `Cookie: ${cookie.name}`,
    `Secure=${cookie.secure ? "present" : "missing"}`,
    `HttpOnly=${cookie.httpOnly ? "present" : "missing"}`,
    `SameSite=${cookie.sameSite ?? "missing"}`,
  ].join("; ");
}

export function runCookieScanner(headers: Headers, endpoint: string): ScannerFinding[] {
  const findings: ScannerFinding[] = [];
  const cookies = parseSetCookieHeaders(headers);

  for (const cookie of cookies) {
    const evidence = securityEvidence(cookie);

    if (!cookie.secure) {
      findings.push({
        id: `cookie-without-secure-${cookie.name}`,
        category: "cookies",
        title: `${cookie.name} cookie missing Secure flag`,
        severity: "high",
        confidence: "high",
        evidence,
        remediation:
          "Set the Secure attribute so cookies are only transmitted over HTTPS.",
        endpoint,
      });
    }

    if (!cookie.httpOnly) {
      findings.push({
        id: `cookie-without-httponly-${cookie.name}`,
        category: "cookies",
        title: `${cookie.name} cookie missing HttpOnly flag`,
        severity: "medium",
        confidence: "high",
        evidence,
        remediation:
          "Set HttpOnly to reduce cookie theft via client-side script access.",
        endpoint,
      });
    }

    if (cookie.sameSite === null || cookie.sameSite === "Invalid") {
      findings.push({
        id: `cookie-without-samesite-${cookie.name}`,
        category: "cookies",
        title: `${cookie.name} cookie missing SameSite attribute`,
        severity: "medium",
        confidence: "high",
        evidence,
        remediation:
          "Set SameSite to Lax or Strict to reduce cross-site request risks.",
        endpoint,
      });
    }
  }

  return findings;
}
