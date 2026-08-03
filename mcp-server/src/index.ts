import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { spawn, type ChildProcess } from "child_process";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { z } from "zod";

const BACKEND_URL = process.env.SECURITY_SCANNER_BACKEND_URL ?? "http://127.0.0.1:4310";
const API_TOKEN = process.env.SECURITY_SCANNER_API_TOKEN?.trim() ?? "";
const __dirname = dirname(fileURLToPath(import.meta.url));
const BACKEND_DIR = resolve(__dirname, "../../backend");

const HEALTH_CHECK_TIMEOUT_MS = 2_000;
const BACKEND_POLL_INTERVAL_MS = 600;
const BACKEND_START_TIMEOUT_MS = 25_000;
const BACKEND_REUSE_WAIT_MS = 15_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const SCAN_REQUEST_TIMEOUT_MS = 300_000; // 5 dk — aktif tarama 100+ istek atar
const BODY_SCAN_TIMEOUT_MS = 30_000;

let backendProcess: ChildProcess | null = null;
let backendStarted = false;

if (API_TOKEN.length < 32) {
  throw new Error("SECURITY_SCANNER_API_TOKEN en az 32 karakter olmalıdır.");
}

async function isBackendRunning(): Promise<boolean> {
  try {
    const res = await fetch(`${BACKEND_URL}/api/health`, {
      signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT_MS),
    });
    return res.ok;
  } catch (err) {
    process.stderr.write(
      `[security-scanner-mcp] Health check failed: ${err instanceof Error ? err.message : String(err)}\n`
    );
    return false;
  }
}

async function waitForBackend(maxWaitMs = BACKEND_START_TIMEOUT_MS): Promise<boolean> {
  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    if (await isBackendRunning()) return true;
    await new Promise((r) => setTimeout(r, BACKEND_POLL_INTERVAL_MS));
  }
  return false;
}

async function ensureBackend(): Promise<void> {
  if (await isBackendRunning()) return;
  if (backendStarted) {
    const ready = await waitForBackend(BACKEND_REUSE_WAIT_MS);
    if (!ready) throw new Error("Backend başlatılamadı — zaman aşımı.");
    return;
  }

  backendStarted = true;
  backendProcess = spawn("npm", ["run", "dev"], {
    cwd: BACKEND_DIR,
    shell: true,
    stdio: "ignore",
    detached: false,
  });

  backendProcess.on("error", (err) => {
    process.stderr.write(`[security-scanner-mcp] Backend başlatma hatası: ${err.message}\n`);
  });

  const ready = await waitForBackend();
  if (!ready) {
    backendProcess.kill();
    throw new Error(
      "Backend 25 saniyede başlamadı. 'security-scanner/backend' klasörünü ve npm bağımlılıklarını kontrol edin."
    );
  }

  process.stderr.write("[security-scanner-mcp] Backend başarıyla başlatıldı.\n");
}

async function apiRequest<T = Record<string, unknown>>(
  path: string,
  init: RequestInit & { timeout?: number }
): Promise<T> {
  await ensureBackend();
  const { timeout: customTimeout, ...fetchInit } = init;
  const timeout = customTimeout ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const headers = new Headers(fetchInit.headers);
  headers.set("Authorization", `Bearer ${API_TOKEN}`);
  const res = await fetch(`${BACKEND_URL}${path}`, {
    ...fetchInit,
    headers,
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API hatası (${res.status}): ${text || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

function toMcpContent(data: unknown): { content: Array<{ type: "text"; text: string }> } {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function stopBackend(): void {
  if (backendProcess && !backendProcess.killed) {
    backendProcess.kill("SIGTERM");
    backendProcess = null;
  }
}

process.on("exit", stopBackend);
process.on("SIGINT", () => { stopBackend(); process.exit(0); });
process.on("SIGTERM", () => { stopBackend(); process.exit(0); });

// ─── MCP Server ───────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "security-scanner",
  version: "1.0.0",
});

server.tool(
  "scan_url",
  "Bir URL'yi güvenlik açıkları için tarar. Pasif mod public hedeflerde çalışır. Aktif mod yalnızca sunucudaki ALLOWED_ACTIVE_HOSTS exact-host allowlist'i ile izin verilen hedeflerde çalışır.",
  {
    url: z.string().url().describe("Taranacak URL (örn: https://example.edu.tr)"),
    mode: z
      .enum(["passive", "active"])
      .default("passive")
      .describe("passive = yanıt analizi (her URL), active = SQLi/XSS/path traversal (sadece localhost/lab)"),
    async: z
      .boolean()
      .default(false)
      .describe("true ise arka planda tarar, 202 + scanId döner; get_scan ile sonucu al. Aktif taramada timeout önlemek için önerilir."),
    credentialCheck: z
      .boolean()
      .default(false)
      .describe("Aktif modda varsayılan credential testi. Yalnızca izinli hedefler için; proxy ve gecikme ile gizlilik artırılır."),
  },
  async ({ url, mode, async: useAsync, credentialCheck }) => {
    const body = {
      targetUrl: url,
      mode,
      ...(useAsync && { async: true }),
      ...(credentialCheck && { credentialCheck: true }),
    };
    const timeout = useAsync ? 15_000 : SCAN_REQUEST_TIMEOUT_MS;
    const result = await apiRequest("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      timeout,
    });
    return toMcpContent(result);
  },
);

server.tool(
  "list_recent_scans",
  "Son 30 taramanın özetini listeler. Her tarama için hedef URL, mod, skor ve tamamlanma zamanı döner.",
  {},
  async () => {
    const result = await apiRequest("/api/scans", {});
    return toMcpContent(result);
  },
);

server.tool(
  "get_scan",
  "Belirli bir taramanın tam detaylarını getirir. scanId parametresi list_recent_scans çıktısından alınabilir.",
  {
    scanId: z.string().describe("Tarama kimliği (örn: ef4bb9eb-bcf1-414a-a8ee-5fb53c336ea4)"),
  },
  async ({ scanId }) => {
    const result = await apiRequest(`/api/scans/${encodeURIComponent(scanId)}`, {});
    return toMcpContent(result);
  },
);

server.tool(
  "scan_body",
  "Bir HTTP yanıt gövdesini (response body) çevrimdışı olarak güvenlik açıkları için analiz eder. Canlı URL erişimi olmadan, kopyalanan sayfa içeriği veya log dosyası üzerinde analiz yapmak için kullanılır.",
  {
    label: z.string().min(1).max(512).describe("Kaynak etiketi (örn: 'uygulama hata sayfası')"),
    body: z.string().min(1).describe("Analiz edilecek HTTP yanıt gövdesi metni"),
  },
  async ({ label, body }) => {
    const result = await apiRequest("/api/body-scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sourceLabel: label, body }),
      timeout: BODY_SCAN_TIMEOUT_MS,
    });
    return toMcpContent(result);
  },
);

server.tool(
  "clear_scans",
  "Tüm tarama geçmişini siler. Sonraki list_recent_scans boş döner. Geçmişi sıfırlamak veya eski kayıtları temizlemek için kullanılır.",
  {},
  async () => {
    const result = await apiRequest("/api/scans", { method: "DELETE" });
    return toMcpContent(result);
  },
);

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
