import { z } from "zod";
import { isActiveScanAllowed } from "../policy/targetPolicyGuard.js";
import type { Environment } from "../security/serverConfig.js";
import { severityEnum, targetUrlSchema } from "./schemas.js";

export const scanRequestSchema = z
  .object({
    targetUrl: targetUrlSchema,
    mode: z.enum(["passive", "active"]),
    severityOverrides: z.record(z.string(), severityEnum).optional(),
    /** true ise tarama arka planda çalışır, 202 + scanId döner. */
    async: z.boolean().optional().default(false),
    /** Aktif modda varsayılan credential testi. */
    credentialCheck: z.boolean().optional().default(false),
  })
  .strict();

export type ParsedScanRequest = z.infer<typeof scanRequestSchema>;

export type ScanAuthorization =
  | { allowed: true }
  | { allowed: false; status: 403; message: string };

export function authorizeScanRequest(
  request: Pick<ParsedScanRequest, "targetUrl" | "mode">,
  env: Environment = process.env,
): ScanAuthorization {
  if (request.mode !== "active" || isActiveScanAllowed(request.targetUrl, request.mode, env)) {
    return { allowed: true };
  }
  return {
    allowed: false,
    status: 403,
    message: "Active scan target is not authorized.",
  };
}
