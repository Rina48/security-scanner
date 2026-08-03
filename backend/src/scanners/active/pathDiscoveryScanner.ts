import type { ScannerFinding } from "../../types.js";
import { abortError, throwIfAborted } from "../../utils/abort.js";
import { fetchPathWithBypass } from "../../utils/wafBypass.js";
import { PATH_DISCOVERY_CONCURRENCY } from "../constants.js";
import { SENSITIVE_PATHS, type SensitivePath } from "./sensitivePaths.js";

async function checkPath(
  origin: string,
  entry: SensitivePath,
  signal?: AbortSignal,
): Promise<ScannerFinding | null> {
  throwIfAborted(signal);
  const probeUrl = `${origin}${entry.path}`;
  try {
    const { status } = await fetchPathWithBypass(probeUrl, entry.path, { signal });
    if (status !== 200) return null;

    return {
      id: `exposed-path-${entry.path.replace(/[^a-z0-9]/gi, "-")}`,
      category: "active",
      title: entry.title,
      severity: entry.severity,
      confidence: "high",
      evidence: `HTTP 200 yanıtı alındı: ${probeUrl}`,
      remediation: entry.remediation,
      endpoint: probeUrl,
    };
  } catch (err: unknown) {
    if (signal?.aborted) throw abortError(signal);
    console.error("[pathDiscoveryScanner] Path probe failed:", err);
    return null;
  }
}

function normalizeExtraPath(path: string): string {
  const withSlash = path.startsWith("/") ? path : `/${path}`;
  return withSlash.replace(/\/$/, "");
}

function buildExtraEntries(
  extraPaths: string[] | undefined,
  knownPaths: Set<string>,
): SensitivePath[] {
  if (!extraPaths?.length) return [];

  return extraPaths
    .filter((path) => {
      const normalized = normalizeExtraPath(path);
      return normalized.length > 1 && !knownPaths.has(normalized);
    })
    .map((path) => ({
      path: path.startsWith("/") ? path : `/${path}`,
      title: `robots.txt ile keşfedilen yol dışarıya açık: ${path}`,
      severity: "medium" as const,
      remediation:
        "robots.txt Disallow kuralları hassas dizinleri ifşa eder. Bu yolların gerçekten erişime kapalı olduğundan emin olun.",
    }));
}

export interface PathDiscoveryOptions {
  /** robots.txt Disallow'dan keşfedilen ek yollar (örn. /internal, /reports) */
  extraPaths?: string[];
  signal?: AbortSignal;
}

export async function runPathDiscoveryScanner(
  targetUrl: string,
  options?: PathDiscoveryOptions,
): Promise<ScannerFinding[]> {
  throwIfAborted(options?.signal);
  const origin = new URL(targetUrl).origin;
  const findings: ScannerFinding[] = [];

  const knownPaths = new Set(SENSITIVE_PATHS.map((p) => p.path.replace(/\/$/, "")));
  const extraEntries = buildExtraEntries(options?.extraPaths, knownPaths);
  const allPaths = [...SENSITIVE_PATHS, ...extraEntries];

  // CONCURRENCY kadar isteği aynı anda gönder, sıralı batch ile ilerle.
  for (let i = 0; i < allPaths.length; i += PATH_DISCOVERY_CONCURRENCY) {
    throwIfAborted(options?.signal);
    const batch = allPaths.slice(i, i + PATH_DISCOVERY_CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map((entry) => checkPath(origin, entry, options?.signal)),
    );
    throwIfAborted(options?.signal);

    for (const result of results) {
      if (result.status === "fulfilled" && result.value !== null) {
        findings.push(result.value);
      }
    }
  }

  return findings;
}
