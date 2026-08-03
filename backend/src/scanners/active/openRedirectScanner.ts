import type { ScannerFinding } from "../../types.js";
import { throwIfAborted } from "../../utils/abort.js";
import { scannerFetch } from "../../utils/scannerHttp.js";
import { SHORT_PROBE_TIMEOUT_MS } from "../constants.js";
import type { ActiveScannerOptions } from "./activeScannerOptions.js";

// Saldırganların açık yönlendirme için hedeflediği yaygın parametre adları
const REDIRECT_PARAMS = [
  "redirect", "redirect_to", "redirect_url",
  "url", "next", "next_url",
  "return", "return_to", "returnUrl", "return_url",
  "redir", "destination", "dest",
  "location", "goto", "target",
  "forward", "forward_url",
];

// Canary domain — bu domain'e yönlendirilme tespit edilirse açık redirect onaylanır.
const CANARY = "//open-redirect-probe.invalid";
const CANARY_MARKER = "open-redirect-probe.invalid";

export async function runOpenRedirectScanner(
  targetUrl: string,
  options: ActiveScannerOptions = {},
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const findings: ScannerFinding[] = [];
  const url = new URL(targetUrl);

  for (const param of REDIRECT_PARAMS) {
    throwIfAborted(options.signal);
    const probe = new URL(url.toString());
    probe.searchParams.set(param, CANARY);

    const { status, headers } = await scannerFetch(probe.toString(), {
      // Yönlendirmeyi takip etme — Location başlığını incele.
      redirect: "manual",
      timeoutMs: SHORT_PROBE_TIMEOUT_MS,
      scope: "openRedirectScanner",
      signal: options.signal,
    });

    if (status < 300 || status >= 400) continue;

    const location = headers.get("location") ?? "";
    if (!location.includes(CANARY_MARKER)) continue;

    findings.push({
      id: "open-redirect-indicator",
      category: "active",
      title: `Açık yönlendirme (Open Redirect) göstergesi tespit edildi — '${param}' parametresi`,
      severity: "medium",
      confidence: "high",
      evidence: `Parametre: '${param}', Yanıt: HTTP ${status}, Location: ${location}`,
      remediation:
        "Yönlendirme URL'lerini whitelist ile doğrulayın. Dış domain'lere yönlendirmeye izin vermeyin. Göreli yollar veya onaylı domain listesi kullanın.",
      endpoint: probe.toString(),
    });
    // İlk pozitif bulgudan sonra devam etme — tekrarlanan bulgulardan kaçın.
    break;
  }

  return findings;
}
