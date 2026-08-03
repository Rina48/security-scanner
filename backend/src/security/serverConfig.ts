import { isIP } from "node:net";

export type Environment = Record<string, string | undefined>;

export interface ServerConfig {
  apiToken: string;
  bindHost: string;
  port: number;
  allowedOrigins: ReadonlySet<string>;
  probeEnabled: boolean;
}

const DEFAULT_BIND_HOST = "127.0.0.1";
const DEFAULT_PORT = 4310;
const MIN_API_TOKEN_LENGTH = 32;

function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
}

export function normalizeHostname(value: string): string {
  const trimmed = value.trim().toLowerCase().replace(/\.$/, "");
  if (!trimmed) {
    throw new Error("Host adı boş olamaz.");
  }

  if (isIP(stripIpv6Brackets(trimmed))) {
    return stripIpv6Brackets(trimmed);
  }

  if (trimmed.includes("://") || /[/?#@]/.test(trimmed)) {
    throw new Error("Allowlist girdileri yalnızca host adı içermelidir.");
  }

  const parsed = new URL(`http://${trimmed}`);
  if (parsed.port || parsed.hostname === "") {
    throw new Error("Allowlist girdileri port içeremez.");
  }

  return stripIpv6Brackets(parsed.hostname.toLowerCase().replace(/\.$/, ""));
}

export function normalizeUrlHostname(url: URL): string {
  return stripIpv6Brackets(url.hostname.toLowerCase().replace(/\.$/, ""));
}

export function parseExactHostAllowlist(
  rawValue: string | undefined,
): ReadonlySet<string> {
  const hosts = (rawValue ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map(normalizeHostname);

  return new Set(hosts);
}

export function getActiveHostAllowlist(
  env: Environment = process.env,
): ReadonlySet<string> {
  return parseExactHostAllowlist(env.ALLOWED_ACTIVE_HOSTS);
}

export function getActivePrivateHostAllowlist(
  env: Environment = process.env,
): ReadonlySet<string> {
  return parseExactHostAllowlist(env.ALLOWED_ACTIVE_PRIVATE_HOSTS);
}

export function getPassivePrivateHostAllowlist(
  env: Environment = process.env,
): ReadonlySet<string> {
  return parseExactHostAllowlist(env.ALLOWED_PASSIVE_HOSTS);
}

export function getProbeHostAllowlist(
  env: Environment = process.env,
): ReadonlySet<string> {
  return parseExactHostAllowlist(env.ALLOWED_PROBE_HOSTS);
}

function parseAllowedOrigins(rawValue: string | undefined): ReadonlySet<string> {
  const origins = new Set<string>();
  for (const rawOrigin of (rawValue ?? "").split(",")) {
    const value = rawOrigin.trim();
    if (!value) continue;

    const parsed = new URL(value);
    if (
      !["http:", "https:"].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error("CORS allowlist girdileri yalnızca HTTP(S) origin içermelidir.");
    }
    origins.add(parsed.origin);
  }
  return origins;
}

function parsePort(rawValue: string | undefined): number {
  if (!rawValue) return DEFAULT_PORT;
  const port = Number(rawValue);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT 1-65535 arasında bir tam sayı olmalıdır.");
  }
  return port;
}

export function loadServerConfig(env: Environment = process.env): ServerConfig {
  const apiToken = env.SECURITY_SCANNER_API_TOKEN?.trim() ?? "";
  if (apiToken.length < MIN_API_TOKEN_LENGTH) {
    throw new Error(
      `SECURITY_SCANNER_API_TOKEN en az ${MIN_API_TOKEN_LENGTH} karakter olmalıdır.`,
    );
  }

  const bindHost = env.SECURITY_SCANNER_BIND_HOST?.trim() || DEFAULT_BIND_HOST;

  return {
    apiToken,
    bindHost,
    port: parsePort(env.PORT),
    allowedOrigins: parseAllowedOrigins(env.SECURITY_SCANNER_ALLOWED_ORIGINS),
    probeEnabled: env.SECURITY_SCANNER_PROBE_ENABLED === "true",
  };
}
