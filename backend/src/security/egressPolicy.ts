import { lookup } from "node:dns/promises";
import type { LookupOptions } from "node:dns";
import { isIP, type LookupFunction } from "node:net";
import { Agent, fetch as undiciFetch, Headers } from "undici";
import {
  consumeOutboundRequest,
  getResponseBodyByteLimit,
  recordExecutionLimitFailure,
  ResourceLimitError,
} from "./resourceLimits.js";
import {
  getActiveHostAllowlist,
  getActivePrivateHostAllowlist,
  getPassivePrivateHostAllowlist,
  getProbeHostAllowlist,
  normalizeHostname,
  normalizeUrlHostname,
  type Environment,
} from "./serverConfig.js";
import {
  isAllowlistedPrivateNetworkAddress,
  isBlockedNetworkAddress,
  isMetadataNetworkAddress,
} from "./networkAddress.js";

export type EgressAccess = "passive" | "active" | "probe";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface EgressPolicy {
  requiredHosts?: ReadonlySet<string>;
  privateHostAllowlist: ReadonlySet<string>;
}

export interface ValidatedTarget {
  url: URL;
  hostname: string;
  addresses: readonly ResolvedAddress[];
  selectedAddress: ResolvedAddress;
}

export interface SafeFetchResult {
  status: number;
  headers: Headers;
  body: string;
  url: string;
}

export interface SafeFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
  redirect?: "follow" | "manual" | "error";
}

interface ResponseLike {
  status: number;
  headers: Headers;
  text(maxBytes?: number): Promise<string>;
}

export type EgressResolver = (hostname: string) => Promise<ResolvedAddress[]>;
export type ValidatedRequest = (
  target: ValidatedTarget,
  init: SafeFetchInit,
) => Promise<ResponseLike>;

export interface SafeFetchOptions {
  access: EgressAccess;
  env?: Environment;
  maxRedirects?: number;
  resolver?: EgressResolver;
  request?: ValidatedRequest;
  maxResponseBodyBytes?: number;
}

const DEFAULT_MAX_REDIRECTS = 5;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export class EgressPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EgressPolicyError";
  }
}

export function getEgressPolicy(
  access: EgressAccess,
  env: Environment = process.env,
): EgressPolicy {
  if (access === "active") {
    const hosts = getActiveHostAllowlist(env);
    return {
      requiredHosts: hosts,
      privateHostAllowlist: getActivePrivateHostAllowlist(env),
    };
  }
  if (access === "probe") {
    const hosts = getProbeHostAllowlist(env);
    return { requiredHosts: hosts, privateHostAllowlist: hosts };
  }
  return {
    privateHostAllowlist: getPassivePrivateHostAllowlist(env),
  };
}

export const defaultResolver: EgressResolver = async (hostname) => {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results
    .filter((entry): entry is { address: string; family: 4 | 6 } =>
      entry.family === 4 || entry.family === 6,
    )
    .map((entry) => ({ address: entry.address, family: entry.family }));
};

function canonicalizeAddress(address: string): string {
  const normalized = address.startsWith("[") && address.endsWith("]")
    ? address.slice(1, -1)
    : address;
  if (normalized.includes("%") || isIP(normalized) === 0) {
    throw new EgressPolicyError("DNS geçerli bir IP adresi döndürmedi.");
  }
  return normalized.toLowerCase();
}

export async function resolveEgressTarget(
  rawUrl: string,
  policy: EgressPolicy,
  resolver: EgressResolver = defaultResolver,
): Promise<ValidatedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new EgressPolicyError("Geçersiz hedef URL.");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new EgressPolicyError("Yalnızca HTTP ve HTTPS hedeflerine izin verilir.");
  }
  if (url.username || url.password) {
    throw new EgressPolicyError("URL userinfo kullanımına izin verilmez.");
  }

  const hostname = normalizeUrlHostname(url);
  if (policy.requiredHosts && !policy.requiredHosts.has(hostname)) {
    throw new EgressPolicyError("Hedef sunucu allowlist dışında.");
  }

  const directFamily = isIP(hostname);
  const resolved = directFamily
    ? [{ address: hostname, family: directFamily as 4 | 6 }]
    : await resolver(hostname);
  if (resolved.length === 0) {
    throw new EgressPolicyError("Hedef için DNS kaydı bulunamadı.");
  }

  const uniqueAddresses = new Map<string, ResolvedAddress>();
  for (const entry of resolved) {
    const address = canonicalizeAddress(entry.address);
    const family = isIP(address);
    if (family !== 4 && family !== 6) {
      throw new EgressPolicyError("DNS adres ailesi geçersiz.");
    }
    uniqueAddresses.set(`${family}:${address}`, { address, family });
  }

  const addresses = [...uniqueAddresses.values()];
  if (addresses.some((entry) => isMetadataNetworkAddress(entry.address))) {
    throw new EgressPolicyError("Metadata servis adreslerine erişim yasaktır.");
  }

  const privateAccessAllowed = policy.privateHostAllowlist.has(hostname);
  for (const entry of addresses) {
    if (!isBlockedNetworkAddress(entry.address)) continue;
    if (
      !privateAccessAllowed ||
      !isAllowlistedPrivateNetworkAddress(entry.address)
    ) {
      throw new EgressPolicyError("Hedef yasaklı bir ağ adresine çözümleniyor.");
    }
  }

  const selectedAddress = addresses[0];
  if (!selectedAddress) {
    throw new EgressPolicyError("Hedef için kullanılabilir adres bulunamadı.");
  }

  return { url, hostname, addresses, selectedAddress };
}

type LookupCallback = Parameters<LookupFunction>[2];

function normalizeLookupFamily(
  family: LookupOptions["family"],
): 0 | 4 | 6 | null {
  if (family === undefined || family === 0) return 0;
  if (family === 4 || family === "IPv4") return 4;
  if (family === 6 || family === "IPv6") return 6;
  return null;
}

function createPinnedLookupError(hostname: string, message: string): NodeJS.ErrnoException {
  return Object.assign(new Error(message), {
    code: "ENOTFOUND",
    syscall: "getaddrinfo",
    hostname,
  });
}

function failPinnedLookup(
  callback: LookupCallback,
  hostname: string,
  all: boolean | undefined,
  message: string,
): void {
  callback(
    createPinnedLookupError(hostname, message),
    all ? [] : "",
    0,
  );
}

export function createPinnedLookup(
  expectedHostname: string,
  addresses: readonly ResolvedAddress[],
): LookupFunction {
  return (hostname, options, callback) => {
    let normalizedHostname: string;
    try {
      normalizedHostname = normalizeHostname(hostname);
    } catch {
      failPinnedLookup(callback, hostname, options.all, "Geçersiz bağlantı host adı.");
      return;
    }

    if (normalizedHostname !== expectedHostname) {
      failPinnedLookup(callback, hostname, options.all, "Bağlantı host adı doğrulanan hedefle eşleşmiyor.");
      return;
    }

    const requestedFamily = normalizeLookupFamily(options.family);
    if (requestedFamily === null) {
      failPinnedLookup(callback, hostname, options.all, "Desteklenmeyen IP adres ailesi.");
      return;
    }

    const candidates = requestedFamily === 0
      ? addresses
      : addresses.filter((entry) => entry.family === requestedFamily);
    if (candidates.length === 0) {
      failPinnedLookup(callback, hostname, options.all, "İstenen ailede doğrulanmış adres yok.");
      return;
    }

    if (options.all === true) {
      callback(
        null,
        candidates.map((entry) => ({
          address: entry.address,
          family: entry.family,
        })),
      );
      return;
    }

    const selected = candidates[0];
    if (!selected) {
      failPinnedLookup(callback, hostname, options.all, "Doğrulanmış bağlantı adresi yok.");
      return;
    }
    callback(null, selected.address, selected.family);
  };
}

export interface PinnedConnectOptions {
  lookup: LookupFunction;
  servername?: string;
}

export interface PinnedTransportOptions {
  url: URL;
  connect: PinnedConnectOptions;
}

export function createPinnedTransportOptions(
  target: ValidatedTarget,
): PinnedTransportOptions {
  return {
    url: target.url,
    connect: {
      lookup: createPinnedLookup(target.hostname, target.addresses),
      servername: isIP(target.hostname) === 0 ? target.hostname : undefined,
    },
  };
}

function responseBodyLimitError(maxBytes: number): ResourceLimitError {
  const error = new ResourceLimitError(
    "response-body-limit",
    503,
    `Uzak yanıt gövdesi ${maxBytes} byte sınırını aştı.`,
  );
  recordExecutionLimitFailure(error);
  return error;
}

interface ResponseBodyStream {
  cancel(reason?: unknown): Promise<void>;
  getReader(): {
    cancel(reason?: unknown): Promise<void>;
    read(): Promise<{ done: boolean; value?: Uint8Array }>;
    releaseLock(): void;
  };
}

async function readResponseTextWithLimit(
  body: ResponseBodyStream | null,
  headers: Headers,
  maxBytes: number,
): Promise<string> {
  const contentLength = headers.get("content-length");
  if (contentLength && /^\d+$/.test(contentLength)) {
    const declaredBytes = Number(contentLength);
    if (Number.isSafeInteger(declaredBytes) && declaredBytes > maxBytes) {
      const error = responseBodyLimitError(maxBytes);
      await body?.cancel(error).catch(() => undefined);
      throw error;
    }
  }

  if (!body) return "";
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let receivedBytes = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      receivedBytes += value.byteLength;
      if (receivedBytes > maxBytes) {
        const error = responseBodyLimitError(maxBytes);
        await reader.cancel(error).catch(() => undefined);
        throw error;
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    reader.releaseLock();
  }
}

export const defaultValidatedRequest: ValidatedRequest = async (target, init) => {
  const transport = createPinnedTransportOptions(target);
  const dispatcher = new Agent({ connect: transport.connect });
  const requestController = new AbortController();
  let disposed = false;
  const onAbort = (): void => {
    requestController.abort(init.signal?.reason);
  };
  init.signal?.addEventListener("abort", onAbort, { once: true });
  if (init.signal?.aborted) onAbort();

  const dispose = async (error?: Error): Promise<void> => {
    if (disposed) return;
    disposed = true;
    init.signal?.removeEventListener("abort", onAbort);
    if (error) {
      requestController.abort(error);
      await dispatcher.destroy(error);
      return;
    }
    await dispatcher.close();
  };

  try {
    const response = await undiciFetch(transport.url, {
      method: init.method,
      headers: init.headers,
      body: init.body,
      signal: requestController.signal,
      redirect: "manual",
      dispatcher,
    });
    return {
      status: response.status,
      headers: response.headers,
      async text(maxBytes = getResponseBodyByteLimit()) {
        try {
          return await readResponseTextWithLimit(
            response.body,
            response.headers,
            maxBytes,
          );
        } catch (error) {
          await dispose(error instanceof Error ? error : new Error("Response read failed."));
          throw error;
        } finally {
          const abortReason = requestController.signal.reason;
          await dispose(
            requestController.signal.aborted
              ? (abortReason instanceof Error
                  ? abortReason
                  : new DOMException("The operation was aborted", "AbortError"))
              : undefined,
          );
        }
      },
    };
  } catch (error) {
    await dispose(error instanceof Error ? error : new Error("Request failed."));
    throw error;
  }
};

function nextRedirectInit(status: number, init: SafeFetchInit): SafeFetchInit {
  const method = (init.method ?? "GET").toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
    const headers = { ...(init.headers ?? {}) };
    for (const name of Object.keys(headers)) {
      if (["content-type", "content-length"].includes(name.toLowerCase())) {
        delete headers[name];
      }
    }
    return { ...init, method: "GET", body: undefined, headers };
  }
  return init;
}

export async function safeFetchText(
  rawUrl: string,
  init: SafeFetchInit = {},
  options: SafeFetchOptions,
): Promise<SafeFetchResult> {
  const policy = getEgressPolicy(options.access, options.env);
  const resolver = options.resolver ?? defaultResolver;
  const request = options.request ?? defaultValidatedRequest;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxResponseBodyBytes = options.maxResponseBodyBytes
    ?? getResponseBodyByteLimit();
  const redirectMode = init.redirect ?? "follow";

  let currentUrl = rawUrl;
  let currentInit = init;
  for (let redirectCount = 0; ; redirectCount += 1) {
    const target = await resolveEgressTarget(currentUrl, policy, resolver);
    consumeOutboundRequest();
    const response = await request(target, currentInit);
    const isRedirect = REDIRECT_STATUSES.has(response.status);

    if (!isRedirect || redirectMode === "manual") {
      const body = await response.text(maxResponseBodyBytes);
      return {
        status: response.status,
        headers: response.headers,
        body,
        url: target.url.toString(),
      };
    }

    await response.text(maxResponseBodyBytes);
    if (redirectMode === "error") {
      throw new EgressPolicyError("Redirect yanıtına izin verilmedi.");
    }
    if (redirectCount >= maxRedirects) {
      throw new EgressPolicyError("Redirect üst sınırı aşıldı.");
    }

    const location = response.headers.get("location");
    if (!location) {
      throw new EgressPolicyError("Redirect yanıtında Location başlığı yok.");
    }
    currentUrl = new URL(location, target.url).toString();
    currentInit = nextRedirectInit(response.status, currentInit);
  }
}
