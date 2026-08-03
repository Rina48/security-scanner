import { safeFetchText } from "../security/egressPolicy.js";
import { abortError, throwIfAborted, withTimeoutSignal } from "./abort.js";
import { BROWSER_HEADERS } from "./httpHeaders.js";

const ROBOTS_FETCH_TIMEOUT_MS = 5_000;

/**
 * robots.txt dosyasını çeker ve Disallow kurallarından yol listesi döner.
 * Sadece User-agent: * bölümündeki Disallow'lar kullanılır.
 * Boş veya yalnızca "/" olan Disallow atlanır (tüm site engelli anlamına gelir, probe edilemez).
 */
export interface RobotsFetchOptions {
  fetchText?: typeof safeFetchText;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export async function fetchRobotsPaths(
  origin: string,
  options: RobotsFetchOptions = {},
): Promise<string[]> {
  const robotsUrl = `${origin.replace(/\/$/, "")}/robots.txt`;
  const fetchText = options.fetchText ?? safeFetchText;
  throwIfAborted(options.signal);

  try {
    const response = await withTimeoutSignal(
      options.signal,
      options.timeoutMs ?? ROBOTS_FETCH_TIMEOUT_MS,
      (requestSignal) => fetchText(
        robotsUrl,
        {
          method: "GET",
          redirect: "follow",
          signal: requestSignal,
          headers: BROWSER_HEADERS,
        },
        { access: "active" },
      ),
    );

    if (response.status < 200 || response.status >= 300) return [];

    const paths = parseDisallowPaths(response.body);
    return paths;
  } catch (err: unknown) {
    if (options.signal?.aborted) throw abortError(options.signal);
    console.error("[security-scanner] robots.txt fetch failed:", err);
    return [];
  }
}

function parseDisallowPaths(robotsTxt: string): string[] {
  const paths: string[] = [];
  const lines = robotsTxt.split(/\r?\n/);
  let inWildcardSection = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("#") || trimmed === "") continue;

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx < 0) continue;

    const key = trimmed.slice(0, colonIdx).trim().toLowerCase();
    const value = trimmed.slice(colonIdx + 1).trim();

    if (key === "user-agent") {
      inWildcardSection = value === "*";
      continue;
    }

    if (key === "disallow" && inWildcardSection && value) {
      // "/" = tüm site engelli, probe edilemez
      if (value === "/") continue;
      // Yolu normalize et: sonundaki * wildcard'ı kaldır, / ile başlat
      const path = value.split("*")[0].trim();
      if (path && path.startsWith("/") && path.length > 1) {
        paths.push(path);
      }
    }
  }

  // Tekrarları kaldır
  return [...new Set(paths)];
}
