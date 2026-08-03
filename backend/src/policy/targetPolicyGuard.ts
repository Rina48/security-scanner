import { URL } from "node:url";
import {
  getActiveHostAllowlist,
  normalizeUrlHostname,
  type Environment,
} from "../security/serverConfig.js";
import { ScanMode } from "../types.js";

export function isActiveScanAllowed(
  targetUrl: string,
  mode: ScanMode,
  env: Environment = process.env,
): boolean {
  if (mode !== "active") return false;

  try {
    const parsed = new URL(targetUrl);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
      return false;
    }
    return getActiveHostAllowlist(env).has(normalizeUrlHostname(parsed));
  } catch {
    return false;
  }
}
