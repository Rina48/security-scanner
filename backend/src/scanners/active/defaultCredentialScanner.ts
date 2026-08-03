/**
 * Default credential checker.
 * Yalnızca izinli hedefler için çalışır; credentialCheck: true ile tetiklenir.
 * Proxy + rastgele gecikme ile IDS tetiklemesi azaltılır.
 */

import type { ScannerFinding } from "../../types.js";
import { isResourceLimitError } from "../../security/resourceLimits.js";
import { logRedactedError } from "../../utils/safeLogging.js";
import { abortError, throwIfAborted, withTimeoutSignal } from "../../utils/abort.js";
import { BROWSER_HEADERS } from "../../utils/httpHeaders.js";
import { credentialRandomDelay, fetchWithProxy, isProxyConfigured } from "../../utils/httpClient.js";

const PROBE_TIMEOUT_MS = 15_000;
const LOGIN_ERROR_PATTERNS = /invalid|wrong|failed|hatalı|geçersiz|yanlış|hata|error|incorrect|unbekannt|erreur/i;

interface CredentialPair {
  username: string;
  password: string;
}

const DEFAULT_CREDENTIALS: CredentialPair[] = [
  // Genel admin
  { username: "admin", password: "admin" },
  { username: "admin", password: "password" },
  { username: "admin", password: "123456" },
  { username: "admin", password: "admin123" },
  { username: "root", password: "root" },
  { username: "administrator", password: "administrator" },
  { username: "test", password: "test" },
  { username: "guest", password: "guest" },
  { username: "sysadmin", password: "sysadmin" },
  { username: "superadmin", password: "admin123" },
];

interface FormConfig {
  userParam: string;
  passParam: string;
}

const FORM_CONFIGS: FormConfig[] = [
  { userParam: "Email", passParam: "Parola" },
  { userParam: "UserName", passParam: "Password" },
  { userParam: "username", passParam: "password" },
  { userParam: "user", passParam: "pass" },
  { userParam: "login", passParam: "password" },
  { userParam: "email", passParam: "password" },
  { userParam: "kullanici", passParam: "sifre" },
];

function looksLikeLoginFailure(body: string): boolean {
  return LOGIN_ERROR_PATTERNS.test(body);
}

function extractAntiForgeryToken(html: string): string | null {
  const m = html.match(/name=["']__RequestVerificationToken["']\s+value=["']([^"']+)["']/i)
    ?? html.match(/id=["']__RequestVerificationToken["']\s+value=["']([^"']+)["']/i);
  return m ? m[1] : null;
}

async function tryLogin(
  loginUrl: string,
  credentials: CredentialPair,
  formConfig: FormConfig,
  extraParams?: Record<string, string>,
  cookieHeader?: string,
  signal?: AbortSignal,
): Promise<{ success: boolean; status: number; body: string }> {
  throwIfAborted(signal);
  const params: Record<string, string> = {
    [formConfig.userParam]: credentials.username,
    [formConfig.passParam]: credentials.password,
    ...extraParams,
  };
  const body = new URLSearchParams(params).toString();

  const headers: Record<string, string> = {
    ...BROWSER_HEADERS,
    "Content-Type": "application/x-www-form-urlencoded",
    ...(cookieHeader && { Cookie: cookieHeader }),
  };

  const response = await withTimeoutSignal(signal, PROBE_TIMEOUT_MS, (requestSignal) =>
    fetchWithProxy(loginUrl, {
      method: "POST",
      redirect: "manual",
      headers,
      body,
      signal: requestSignal,
    }));

  const responseBody = response.body;
  const success =
    response.status === 302 ||
    response.status === 303 ||
    (response.status === 200 && !looksLikeLoginFailure(responseBody));

  return {
    success,
    status: response.status,
    body: responseBody,
  };
}

export interface DefaultCredentialOptions {
  /** Test edilecek login URL'leri. Boşsa robots.txt'tan login-benzeri yollar kullanılır. */
  loginUrls?: string[];
  signal?: AbortSignal;
}

export async function runDefaultCredentialScanner(
  targetUrl: string,
  options?: DefaultCredentialOptions,
  extraPaths?: string[]
): Promise<ScannerFinding[]> {
  const signal = options?.signal;
  throwIfAborted(signal);
  const origin = new URL(targetUrl).origin;
  const findings: ScannerFinding[] = [];

  if (!isProxyConfigured()) {
    console.warn(
      "[defaultCredentialScanner] Proxy tanımlı değil (SECURITY_SCANNER_PROXY/HTTP_PROXY). Brute force denemeleri doğrudan hedefe gidecek — gizlilik riski."
    );
  } else {
    console.warn(
      "[defaultCredentialScanner] Proxy ile DNS pinning garanti edilemediği için credential testi kapatıldı.",
    );
    return findings;
  }

  const loginPaths = [
    ...(options?.loginUrls ?? []),
    ...(extraPaths ?? []).filter(
      (p) =>
        /login|signin|auth|giris|mainlogin|account/i.test(p) &&
        p.length > 3
    ),
  ];

  const pathsToTest = loginPaths.length
    ? loginPaths
    : [
        "/Account/Login",
        "/Login",
        "/login",
        "/admin",
        "/admin/login",
        "/Yonetim/Login",
        "/signin",
        "/giris",
      ];

  const urlsToTest = [
    ...new Set(
      pathsToTest.map((p) =>
        p.startsWith("http") ? p : `${origin}${p.startsWith("/") ? p : `/${p}`}`
      )
    ),
  ];

  for (const loginUrl of urlsToTest) {
    throwIfAborted(signal);
    try {
      const getRes = await withTimeoutSignal(signal, PROBE_TIMEOUT_MS, (requestSignal) =>
        fetchWithProxy(loginUrl, {
          method: "GET",
          redirect: "follow",
          headers: BROWSER_HEADERS,
          signal: requestSignal,
        }));

      if (getRes.status < 200 || getRes.status >= 300 || getRes.status === 404) continue;

      const getBody = getRes.body;
      if (
        !/form|input.*password|type=["']password["']/i.test(getBody) &&
        !loginUrl.includes("MainLogin")
      ) {
        continue;
      }

      const antiforgeryToken = extractAntiForgeryToken(getBody);
      const sc = getRes.headers.get("set-cookie");
      const setCookies: string[] = sc ? [sc] : [];
      const cookieHeader = setCookies
        .map((c) => c.split(";")[0]?.trim())
        .filter(Boolean)
        .join("; ") || undefined;
      const extraParams = antiforgeryToken
        ? { __RequestVerificationToken: antiforgeryToken }
        : undefined;

      for (const cred of DEFAULT_CREDENTIALS) {
        throwIfAborted(signal);
        await credentialRandomDelay(signal);

        for (const form of FORM_CONFIGS) {
          throwIfAborted(signal);
          try {
            const { success, status } = await tryLogin(
              loginUrl,
              cred,
              form,
              extraParams,
              cookieHeader,
              signal,
            );
            if (success) {
              findings.push({
                id: `default-credential-${loginUrl.replace(/[^a-z0-9]/gi, "-")}`,
                category: "active",
                title: `Varsayılan kimlik bilgisi ile giriş başarılı: ${cred.username}`,
                severity: "critical",
                confidence: "high",
                evidence: `POST ${loginUrl} — ${form.userParam}=${cred.username} — HTTP ${status}`,
                remediation:
                  "Varsayılan/zayıf şifreleri derhal değiştirin. Güçlü parola politikası uygulayın, çok faktörlü kimlik doğrulama ekleyin.",
                endpoint: loginUrl,
              });
              break;
            }
          } catch (err) {
            if (signal?.aborted) throw abortError(signal);
            if (isResourceLimitError(err)) throw err;
            logRedactedError("[defaultCredentialScanner] Probe failed:", err);
          }
        }
      }
    } catch (err) {
      if (signal?.aborted) throw abortError(signal);
      if (isResourceLimitError(err)) throw err;
      logRedactedError("[defaultCredentialScanner] Fetch failed:", err);
    }
  }

  return findings;
}
