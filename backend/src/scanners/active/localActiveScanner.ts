import type { ScannerFinding } from "../../types.js";
import { isResourceLimitError } from "../../security/resourceLimits.js";
import { abortError, throwIfAborted } from "../../utils/abort.js";
import { fetchWithBypass } from "../../utils/wafBypass.js";
import {
  ACTIVE_PROBE_TIMEOUT_MS,
  SQLI_BODY_LENGTH_DELTA_THRESHOLD,
} from "../constants.js";
import {
  SQL_ERROR_PATTERNS,
  SQLI_GET_PARAMS,
  SQLI_PAYLOADS,
  SQLI_POST_PARAMS,
  XSS_MARKER,
  XSS_PARAMS,
  XSS_PAYLOADS,
} from "./probePayloads.js";
import type { ActiveScannerOptions } from "./activeScannerOptions.js";

type ProbeMethod = "GET" | "POST";

function fetchProbe(
  url: string,
  param: string,
  payload: string,
  method: ProbeMethod,
  signal?: AbortSignal,
): Promise<{ body: string; status: number }> {
  throwIfAborted(signal);
  if (method === "GET") {
    const probe = new URL(url);
    probe.searchParams.set(param, payload);
    return fetchWithBypass(probe.toString(), {
      method: "GET",
      timeoutMs: ACTIVE_PROBE_TIMEOUT_MS,
      signal,
    });
  }

  const body = new URLSearchParams({ [param]: payload }).toString();
  return fetchWithBypass(url, {
    method: "POST",
    body,
    contentType: "application/x-www-form-urlencoded",
    timeoutMs: ACTIVE_PROBE_TIMEOUT_MS,
    signal,
  });
}

function buildProbeEndpoint(url: string, param: string, payload: string, method: ProbeMethod): string {
  if (method === "POST") return url;
  const probe = new URL(url);
  probe.searchParams.set(param, payload);
  return probe.toString();
}

function mergeParams(targetUrl: string, defaultParams: string[]): string[] {
  const existingParams = Array.from(new URL(targetUrl).searchParams.keys());
  if (existingParams.length === 0) return defaultParams;
  return [...new Set([...existingParams, ...defaultParams])];
}

function hasSqlError(body: string): boolean {
  return SQL_ERROR_PATTERNS.some((pattern) => pattern.test(body));
}

function hasReflectedXss(body: string): boolean {
  return body.includes(`<${XSS_MARKER}>`) || body.includes(`javascript:${XSS_MARKER}`);
}

function buildSqliFinding(args: {
  param: string;
  payload: string;
  method: ProbeMethod;
  hasError: boolean;
  lengthDelta: number;
  endpoint: string;
}): ScannerFinding {
  const idSuffix = args.method === "POST" ? `post-${args.param}` : args.param;
  const methodLabel = args.method === "POST" ? "POST gövdesinde " : "";
  const evidence = args.hasError
    ? `${methodLabel}'${args.param}' parametresine SQL yükü gönderildiğinde veritabanı hata mesajı tespit edildi.\nYük: ${args.payload}`
    : `${methodLabel}'${args.param}' parametresine SQL yükü gönderildiğinde yanıt boyutu ${args.lengthDelta} karakter değişti.\nYük: ${args.payload}`;

  return {
    id: `sqli-indicator-${idSuffix}`,
    category: "active",
    title:
      args.method === "POST"
        ? `SQL enjeksiyonu göstergesi (POST) — '${args.param}' parametresi`
        : `SQL enjeksiyonu göstergesi — '${args.param}' parametresi`,
    severity: "critical",
    confidence: args.hasError ? "high" : "medium",
    evidence,
    remediation:
      args.method === "POST"
        ? "Parameterize sorgular (hazır ifadeler) kullanın. POST form verilerini de güvence altına alın."
        : "Parameterize sorgular (hazır ifadeler) kullanın. ORM'lerin güvenli API'lerini tercih edin. Veritabanı hata mesajlarını son kullanıcıya asla göstermeyin.",
    endpoint: args.endpoint,
  };
}

function buildXssFinding(args: {
  param: string;
  payload: string;
  method: ProbeMethod;
  endpoint: string;
}): ScannerFinding {
  const idSuffix = args.method === "POST" ? `post-${args.param}` : args.param;
  const evidence =
    args.method === "POST"
      ? `POST gövdesinde '${args.param}' parametresine gönderilen XSS işaretçisi yanıtta kodlanmadan yansıtıldı.\nYük: ${args.payload}`
      : `'${args.param}' parametresine gönderilen XSS işaretçisi yanıtta kodlanmadan yansıtıldı.\nYük: ${args.payload}`;

  return {
    id: `reflected-xss-${idSuffix}`,
    category: "active",
    title:
      args.method === "POST"
        ? `Yansıtılan XSS göstergesi (POST) — '${args.param}' parametresi`
        : `Yansıtılan XSS göstergesi — '${args.param}' parametresi`,
    severity: "high",
    confidence: "high",
    evidence,
    remediation:
      args.method === "POST"
        ? "Tüm kullanıcı girdilerini (GET ve POST) bağlama uygun çıktı kodlamasıyla işleyin."
        : "Tüm kullanıcı girdilerini bağlama uygun çıktı kodlamasıyla işleyin (HTML, JS, URL). htmlspecialchars() veya framework'ün otomatik kodlama mekanizmasını kullanın. Content-Security-Policy başlığı ekleyin.",
    endpoint: args.endpoint,
  };
}

async function fetchBaselineBody(
  targetUrl: string,
  method: ProbeMethod,
  signal?: AbortSignal,
): Promise<string> {
  throwIfAborted(signal);
  try {
    if (method === "GET") {
      const { body } = await fetchWithBypass(targetUrl, {
        method: "GET",
        timeoutMs: ACTIVE_PROBE_TIMEOUT_MS,
        signal,
      });
      return body;
    }

    const { body } = await fetchWithBypass(targetUrl, {
      method: "POST",
      body: new URLSearchParams({ a: "1" }).toString(),
      contentType: "application/x-www-form-urlencoded",
      timeoutMs: ACTIVE_PROBE_TIMEOUT_MS,
      signal,
    });
    return body;
  } catch (err) {
    if (signal?.aborted) throw abortError(signal);
    if (isResourceLimitError(err)) throw err;
    console.error(`[localActiveScanner] ${method} baseline fetch failed:`, err);
    return "";
  }
}

async function probeSqli(
  targetUrl: string,
  method: ProbeMethod,
  params: string[],
  signal?: AbortSignal,
): Promise<ScannerFinding[]> {
  throwIfAborted(signal);
  const findings: ScannerFinding[] = [];
  const baseBody = await fetchBaselineBody(targetUrl, method, signal);

  for (const param of params) {
    let detected = false;
    for (const payload of SQLI_PAYLOADS) {
      throwIfAborted(signal);
      if (detected) break;

      try {
        const { body } = await fetchProbe(targetUrl, param, payload, method, signal);
        const hasError = hasSqlError(body);
        const lengthDelta = Math.abs(body.length - baseBody.length);
        const hasMajorDelta = lengthDelta > SQLI_BODY_LENGTH_DELTA_THRESHOLD;

        if (hasError || hasMajorDelta) {
          findings.push(
            buildSqliFinding({
              param,
              payload,
              method,
              hasError,
              lengthDelta,
              endpoint: buildProbeEndpoint(targetUrl, param, payload, method),
            }),
          );
          detected = true;
        }
      } catch (err) {
        if (signal?.aborted) throw abortError(signal);
        if (isResourceLimitError(err)) throw err;
        console.error(`[localActiveScanner] SQLi ${method} probe failed:`, err);
      }
    }
  }

  return findings;
}

async function probeXss(
  targetUrl: string,
  method: ProbeMethod,
  params: string[],
  signal?: AbortSignal,
): Promise<ScannerFinding[]> {
  throwIfAborted(signal);
  const findings: ScannerFinding[] = [];

  for (const param of params) {
    let detected = false;
    for (const payload of XSS_PAYLOADS) {
      throwIfAborted(signal);
      if (detected) break;

      try {
        const { body } = await fetchProbe(targetUrl, param, payload, method, signal);
        if (hasReflectedXss(body)) {
          findings.push(
            buildXssFinding({
              param,
              payload,
              method,
              endpoint: buildProbeEndpoint(targetUrl, param, payload, method),
            }),
          );
          detected = true;
        }
      } catch (err) {
        if (signal?.aborted) throw abortError(signal);
        if (isResourceLimitError(err)) throw err;
        console.error(`[localActiveScanner] XSS ${method} probe failed:`, err);
      }
    }
  }

  return findings;
}

export async function runLocalActiveScanner(
  targetUrl: string,
  options: ActiveScannerOptions = {},
): Promise<ScannerFinding[]> {
  throwIfAborted(options.signal);
  const getSqliParams = mergeParams(targetUrl, SQLI_GET_PARAMS);
  const getXssParams = mergeParams(targetUrl, XSS_PARAMS);

  const results = await Promise.allSettled([
    probeSqli(targetUrl, "GET", getSqliParams, options.signal),
    probeXss(targetUrl, "GET", getXssParams, options.signal),
    probeSqli(targetUrl, "POST", SQLI_POST_PARAMS, options.signal),
    probeXss(targetUrl, "POST", XSS_PARAMS, options.signal),
  ]);

  throwIfAborted(options.signal);

  return results.flatMap((result) => (result.status === "fulfilled" ? result.value : []));
}
