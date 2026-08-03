import type { Express, RequestHandler } from "express";
import { z } from "zod";
import {
  EgressPolicyError,
  safeFetchText,
  type SafeFetchOptions,
  type SafeFetchResult,
} from "../security/egressPolicy.js";
import { isLoopbackAddress } from "../security/networkAddress.js";
import { BROWSER_HEADERS } from "../utils/httpHeaders.js";

/**
 * Pentest yardımcı endpoint. Varsayılan olarak kayıt edilmez; etkin olduğunda
 * yalnızca doğrudan loopback istemciden ve server-side exact-host allowlist ile çalışır.
 */
const probeSchema = z
  .object({
    targetUrl: z.string().url(),
    method: z.enum(["GET", "POST", "HEAD"]).optional().default("GET"),
    body: z.string().max(1_000_000).optional(),
    contentType: z.string().max(256).optional(),
  })
  .strict();

const PROBE_TIMEOUT_MS = 15_000;

type ProbeFetch = (
  url: string,
  init: Parameters<typeof safeFetchText>[1],
  options: SafeFetchOptions,
) => Promise<SafeFetchResult>;

export function createProbeHandler(
  fetchTarget: ProbeFetch = safeFetchText,
): RequestHandler {
  return async (request, response) => {
    if (!isLoopbackAddress(request.socket.remoteAddress)) {
      response.status(403).json({ message: "Bu endpoint yalnızca localhost erişimine açıktır." });
      return;
    }

    try {
      const parsed = probeSchema.parse(request.body);

      const fetchHeaders: Record<string, string> = { ...BROWSER_HEADERS };
      if (parsed.method === "POST" && parsed.contentType) {
        fetchHeaders["content-type"] = parsed.contentType;
      }

      const fetchResp = await fetchTarget(parsed.targetUrl, {
        method: parsed.method,
        redirect: "follow",
        headers: fetchHeaders,
        body: parsed.method === "POST" && parsed.body ? parsed.body : undefined,
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      }, {
        access: "probe",
      });

      const respHeaders: Record<string, string> = {};
      for (const headerName of ["content-type", "content-length"]) {
        const value = fetchResp.headers.get(headerName);
        if (value) respHeaders[headerName] = value;
      }

      response.json({
        status: fetchResp.status,
        headers: respHeaders,
        bodyLength: fetchResp.body.length,
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        response.status(400).json({ message: "Invalid payload.", details: error.issues });
        return;
      }
      if (error instanceof EgressPolicyError) {
        response.status(403).json({ message: "Hedef izin listesi dışında." });
        return;
      }
      console.error("[probeRoutes] Probe failed.");
      response.status(500).json({ message: "Probe failed." });
    }
  };
}

export function registerProbeRoutes(app: Express): void {
  app.post("/api/probe", createProbeHandler());
}
