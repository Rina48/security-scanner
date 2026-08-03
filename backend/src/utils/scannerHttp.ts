/**
 * Aktif tarayıcı modülleri için ortak HTTP istemcisi.
 *
 * Tüm istekler `BROWSER_HEADERS` ile gerçek bir tarayıcı olarak gider ve
 * tek bir noktada timeout + hata loglama uygular. WAF bypass gerektiren
 * yollar için `wafBypass.ts` modülünü kullanın; bu helper "tek atış" istekler
 * için sade ve hızlı bir kontrat sunar.
 */

import { Headers } from "undici";
import { safeFetchText } from "../security/egressPolicy.js";
import { SHORT_PROBE_TIMEOUT_MS } from "../scanners/constants.js";
import { abortError, throwIfAborted, withTimeoutSignal } from "./abort.js";
import { BROWSER_HEADERS } from "./httpHeaders.js";

export interface ScannerFetchOptions {
  method?: "GET" | "POST" | "HEAD" | "OPTIONS";
  timeoutMs?: number;
  /** "follow" (varsayılan), "manual" (3xx Location incelemek için), "error". */
  redirect?: "follow" | "manual" | "error";
  /** Ek başlıklar (BROWSER_HEADERS ile birleştirilir). */
  extraHeaders?: Record<string, string>;
  /** POST gövdesi (string ya da URLSearchParams string'i). */
  body?: string;
  /** POST gövdesi varsa content-type — yoksa `application/x-www-form-urlencoded`. */
  contentType?: string;
  /** Modül adı — log mesajlarında kullanılır. */
  scope?: string;
  /** Taramanın üst seviye iptal sinyali. */
  signal?: AbortSignal;
}

export interface ScannerFetchResult {
  body: string;
  status: number;
  headers: Headers;
  /** Toplam istek süresi (ms). Zaman tabanlı testler için kullanışlı. */
  elapsedMs: number;
}

/**
 * BROWSER_HEADERS + timeout + hata yutma davranışıyla tek bir fetch çağrısı.
 * Hata durumunda istisna fırlatmaz; çağıran taraf `status: 0` ile boş body alır.
 */
export async function scannerFetch(
  url: string,
  options: ScannerFetchOptions = {},
): Promise<ScannerFetchResult> {
  const {
    method = "GET",
    timeoutMs = SHORT_PROBE_TIMEOUT_MS,
    redirect = "follow",
    extraHeaders,
    body,
    contentType = "application/x-www-form-urlencoded",
    scope = "scannerFetch",
    signal,
  } = options;

  throwIfAborted(signal);

  const headers: Record<string, string> = { ...BROWSER_HEADERS, ...extraHeaders };
  if (method === "POST" && body) {
    headers["content-type"] = contentType;
  }

  const start = Date.now();
  try {
    const response = await withTimeoutSignal(signal, timeoutMs, (requestSignal) =>
      safeFetchText(
        url,
        {
          method,
          redirect,
          signal: requestSignal,
          headers,
          body: method === "POST" && body ? body : undefined,
        },
        { access: "active" },
      ));
    return {
      body: response.body,
      status: response.status,
      headers: response.headers,
      elapsedMs: Date.now() - start,
    };
  } catch (err: unknown) {
    if (signal?.aborted) throw abortError(signal);
    console.error(`[${scope}] HTTP probe failed:`, err instanceof Error ? err.message : err);
    return {
      body: "",
      status: 0,
      headers: new Headers(),
      elapsedMs: Date.now() - start,
    };
  }
}
