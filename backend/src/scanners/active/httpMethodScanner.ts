import type { ScannerFinding } from "../../types.js";
import { throwIfAborted } from "../../utils/abort.js";
import { scannerFetch } from "../../utils/scannerHttp.js";
import { SHORT_PROBE_TIMEOUT_MS } from "../constants.js";
import type { ActiveScannerOptions } from "./activeScannerOptions.js";

// TRACE aktif ise XST (Cross-Site Tracing) saldırılarına kapı açar.
// PUT/DELETE aktif ise dosya yükleme veya silme mümkün olabilir.
const DANGEROUS_METHODS = new Set(["TRACE", "PUT", "DELETE", "CONNECT"]);
const MAX_SAFE_METHOD_COUNT = 6;

export async function runHttpMethodScanner(
  targetUrl: string,
  options: ActiveScannerOptions = {},
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const findings: ScannerFinding[] = [];

  const { status, headers } = await scannerFetch(targetUrl, {
    method: "OPTIONS",
    timeoutMs: SHORT_PROBE_TIMEOUT_MS,
    scope: "httpMethodScanner",
    signal: options.signal,
  });

  if (status === 0) return findings;

  const allowHeader = headers.get("allow");
  const publicHeader = headers.get("public");
  const rawMethods = allowHeader ?? publicHeader ?? "";

  if (!rawMethods) return findings;

  const enabledMethods = rawMethods
    .split(",")
    .map((m) => m.trim().toUpperCase())
    .filter(Boolean);

  const dangerous = enabledMethods.filter((m) => DANGEROUS_METHODS.has(m));

  if (dangerous.includes("TRACE")) {
    findings.push({
      id: "http-trace-enabled",
      category: "active",
      title: "HTTP TRACE metodu etkin (XST riski)",
      severity: "medium",
      confidence: "high",
      evidence: `Allow: ${rawMethods}`,
      remediation:
        "HTTP TRACE metodunu web sunucusunda devre dışı bırakın. Apache için 'TraceEnable Off', Nginx için 'if ($request_method = TRACE) { return 405; }' ekleyin.",
      endpoint: targetUrl,
    });
  }

  const writeMethodsFound = dangerous.filter((m) => m === "PUT" || m === "DELETE");
  if (writeMethodsFound.length > 0) {
    findings.push({
      id: "http-write-methods-enabled",
      category: "active",
      title: `Tehlikeli HTTP yazma metodları etkin: ${writeMethodsFound.join(", ")}`,
      severity: "high",
      confidence: "high",
      evidence: `Allow: ${rawMethods}`,
      remediation:
        "REST API gerektirmeyen endpoint'lerde PUT ve DELETE metodlarını kapatın. Web sunucusunda izin verilen metodları açıkça kısıtlayın.",
      endpoint: targetUrl,
    });
  }

  if (enabledMethods.length > MAX_SAFE_METHOD_COUNT) {
    findings.push({
      id: "http-excessive-methods",
      category: "active",
      title: "Gereğinden fazla HTTP metodu etkin",
      severity: "low",
      confidence: "medium",
      evidence: `${enabledMethods.length} metod tespit edildi: ${rawMethods}`,
      remediation:
        "Uygulamanın ihtiyaç duymadığı HTTP metodlarını web sunucusunda devre dışı bırakın.",
      endpoint: targetUrl,
    });
  }

  return findings;
}
