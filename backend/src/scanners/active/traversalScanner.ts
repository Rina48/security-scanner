import type { ScannerFinding } from "../../types.js";
import { throwIfAborted } from "../../utils/abort.js";
import { scannerFetch } from "../../utils/scannerHttp.js";
import { SHORT_PROBE_TIMEOUT_MS } from "../constants.js";
import type { ActiveScannerOptions } from "./activeScannerOptions.js";

// Linux/Unix sistem dosyası parmak izleri
const UNIX_PATTERNS = [
  /root:x:0:0/,          // /etc/passwd
  /\[boot loader\]/i,    // /boot.ini
  /daemon:x:\d+/,        // /etc/passwd
];

// Windows sistem dosyası parmak izleri
const WINDOWS_PATTERNS = [
  /\[boot loader\]/i,
  /\[operating systems\]/i,
  /windows\\system32/i,
  /\[extensions\]/i,
];

const ALL_LEAK_PATTERNS = [...UNIX_PATTERNS, ...WINDOWS_PATTERNS];

// Klasik ve kodlanmış yol geçiş yükleri
const TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "../../../../etc/passwd",
  "../../../../../etc/passwd",
  "../../../../../../etc/passwd",
  "....//....//....//etc/passwd",
  "..%2F..%2F..%2Fetc%2Fpasswd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..\\..\\..\\windows\\win.ini",
  "..%5C..%5C..%5Cwindows%5Cwin.ini",
];

// Yol geçişine açık olabilecek yaygın parametre adları
const TRAVERSAL_PARAMS = [
  "file", "path", "page", "include", "template", "doc", "document", "load", "read", "src",
];

async function probeTraversal(
  url: URL,
  param: string,
  payload: string,
  signal?: AbortSignal,
): Promise<string | null> {
  throwIfAborted(signal);
  const probe = new URL(url.toString());
  probe.searchParams.set(param, payload);

  const { body, status } = await scannerFetch(probe.toString(), {
    timeoutMs: SHORT_PROBE_TIMEOUT_MS,
    scope: "traversalScanner",
    signal,
  });

  if (status < 200 || status >= 400) return null;

  const matched = ALL_LEAK_PATTERNS.find((pattern) => pattern.test(body));
  return matched ? probe.toString() : null;
}

export async function runTraversalScanner(
  targetUrl: string,
  options: ActiveScannerOptions = {},
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const findings: ScannerFinding[] = [];
  const url = new URL(targetUrl);

  // URL'de mevcut parametre yoksa yaygın parametre adlarını dene; varsa onları da ekle.
  const existingParams = Array.from(url.searchParams.keys());
  const paramsToTest = existingParams.length > 0
    ? [...new Set([...existingParams, ...TRAVERSAL_PARAMS])]
    : TRAVERSAL_PARAMS;

  // Tüm (param, payload) kombinasyonlarını oluştur, ilk pozitif bulguda dur.
  outer:
  for (const param of paramsToTest) {
    for (const payload of TRAVERSAL_PAYLOADS) {
      throwIfAborted(options.signal);
      const hitUrl = await probeTraversal(url, param, payload, options.signal);
      if (hitUrl) {
        findings.push({
          id: "path-traversal-indicator",
          category: "active",
          title: "Yol geçişi (Path Traversal / LFI) göstergesi tespit edildi",
          severity: "critical",
          confidence: "high",
          evidence: `'${param}' parametresine '${payload}' yükü gönderildiğinde sistem dosyası içeriği tespit edildi.\nProbe URL: ${hitUrl}`,
          remediation:
            "Dosya yolu parametrelerini asla doğrudan kullanmayın. İzin verilen dosyaları bir whitelist ile kısıtlayın, '../' dizisini temizleyin ve realpath() ile normalize edilmiş yolun beklenen dizin içinde olduğunu doğrulayın.",
          endpoint: hitUrl,
        });
        break outer;
      }
    }
  }

  return findings;
}
