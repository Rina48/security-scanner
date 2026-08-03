import type { ScannerFinding } from "../../types.js";
import { throwIfAborted } from "../../utils/abort.js";
import { scannerFetch } from "../../utils/scannerHttp.js";
import {
  CMD_INJECTION_TIME_PARAM_LIMIT,
  CMD_INJECTION_TIME_THRESHOLD_MS,
  TIMING_PROBE_TIMEOUT_MS,
} from "../constants.js";
import type { ActiveScannerOptions } from "./activeScannerOptions.js";

// Komut çıktısı parmak izleri — enjeksiyon başarılıysa yanıtta görünür.
const CMD_OUTPUT_PATTERNS = [
  /uid=\d+\([^)]+\)/,          // Linux: uid=33(www-data)
  /gid=\d+\([^)]+\)/,          // Linux: gid=33(www-data)
  /root:x:0:0/,                 // /etc/passwd başlangıcı
  /Microsoft Windows/i,         // Windows 'ver' çıktısı
  /Windows NT \d+\.\d+/i,       // Windows NT sürümü
];

// Test edilecek parametre adları
const CMD_PARAMS = [
  "cmd", "exec", "command", "q", "query", "search", "input", "data", "id", "user",
];

// Komut enjeksiyonu yükleri (çıktı tabanlı)
const OUTPUT_PAYLOADS = [
  "; id",
  "| id",
  "& id",
  "$(id)",
  "`id`",
  "; whoami",
  "| whoami",
  "& ver",                       // Windows
  "| type C:\\Windows\\win.ini", // Windows
];

// Zaman tabanlı yükler — gecikme oluşturarak kör enjeksiyon tespiti
const TIME_PAYLOADS = [
  "; sleep 4",
  "| sleep 4",
  "& sleep 4",
  "$(sleep 4)",
  "; ping -c 4 127.0.0.1",
  "& timeout /t 4", // Windows
];

function buildProbeUrl(base: URL, param: string, payload: string): string {
  const probe = new URL(base.toString());
  probe.searchParams.set(param, payload);
  return probe.toString();
}

function detectOutputBased(body: string): RegExp | undefined {
  return CMD_OUTPUT_PATTERNS.find((pattern) => pattern.test(body));
}

async function tryOutputBased(
  base: URL,
  params: string[],
  signal?: AbortSignal,
): Promise<ScannerFinding | null> {
  for (const param of params) {
    for (const payload of OUTPUT_PAYLOADS) {
      throwIfAborted(signal);
      const probeUrl = buildProbeUrl(base, param, payload);
      const { body } = await scannerFetch(probeUrl, {
        timeoutMs: TIMING_PROBE_TIMEOUT_MS,
        scope: "cmdInjectionScanner",
        signal,
      });
      const matched = detectOutputBased(body);
      if (matched) {
        return {
          id: "cmd-injection-output-indicator",
          category: "active",
          title: "Komut enjeksiyonu (Command Injection) göstergesi — çıktı tespiti",
          severity: "critical",
          confidence: "high",
          evidence: `Parametre: '${param}', Yük: '${payload}'\nKomut çıktısı parmak izi yanıtta tespit edildi (kalıp: ${matched}).`,
          remediation:
            "Kullanıcı girdilerini asla işletim sistemi komutlarına dahil etmeyin. shell_exec, exec, system gibi fonksiyonlardan kaçının. Zorunluysa whitelist doğrulama ve komut argümanı olarak escapeshellarg() kullanın.",
          endpoint: probeUrl,
        };
      }
    }
  }
  return null;
}

async function tryTimingBased(
  base: URL,
  params: string[],
  signal?: AbortSignal,
): Promise<ScannerFinding | null> {
  for (const param of params.slice(0, CMD_INJECTION_TIME_PARAM_LIMIT)) {
    for (const payload of TIME_PAYLOADS) {
      throwIfAborted(signal);
      const probeUrl = buildProbeUrl(base, param, payload);
      const { elapsedMs } = await scannerFetch(probeUrl, {
        timeoutMs: TIMING_PROBE_TIMEOUT_MS,
        scope: "cmdInjectionScanner",
        signal,
      });
      if (elapsedMs >= CMD_INJECTION_TIME_THRESHOLD_MS) {
        return {
          id: "cmd-injection-timing-indicator",
          category: "active",
          title: "Komut enjeksiyonu (Command Injection) göstergesi — zaman gecikmesi tespiti",
          severity: "high",
          confidence: "medium",
          evidence: `Parametre: '${param}', Yük: '${payload}'\nYanıt süresi: ${elapsedMs}ms (eşik: ${CMD_INJECTION_TIME_THRESHOLD_MS}ms). Gecikme kör komut enjeksiyonuna işaret edebilir.`,
          remediation:
            "Kullanıcı girdilerini işletim sistemi komutlarına dahil etmeyin. Girdi doğrulaması ve whitelist uygulayın.",
          endpoint: probeUrl,
        };
      }
    }
  }
  return null;
}

export async function runCmdInjectionScanner(
  targetUrl: string,
  options: ActiveScannerOptions = {},
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const url = new URL(targetUrl);

  const existingParams = Array.from(url.searchParams.keys());
  const paramsToTest = existingParams.length > 0
    ? [...new Set([...existingParams, ...CMD_PARAMS])]
    : CMD_PARAMS;

  const outputFinding = await tryOutputBased(url, paramsToTest, options.signal);
  if (outputFinding) return [outputFinding];

  const timingFinding = await tryTimingBased(url, paramsToTest, options.signal);
  return timingFinding ? [timingFinding] : [];
}
