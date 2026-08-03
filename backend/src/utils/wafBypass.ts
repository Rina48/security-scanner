/**
 * WAF bypass yardımcıları — 403 alındığında alternatif tekniklerle yeniden deneme.
 * Sızma testi amacı: WAF imzalarını aşarak uygulamaya ulaşmak.
 */
import { safeFetchText } from "../security/egressPolicy.js";
import { abortError, throwIfAborted, withTimeoutSignal } from "./abort.js";
import { BROWSER_HEADERS } from "./httpHeaders.js";

/** Payload'ı WAF bypass için encode edilmiş varyantlara dönüştürür. */
export function encodePayloadVariants(payload: string): string[] {
  const variants = new Set<string>([payload]);

  variants.add(encodeURIComponent(payload));
  variants.add(encodeURIComponent(encodeURIComponent(payload)));

  const mixedCase = payload
    .replace(/\bor\b/gi, "Or")
    .replace(/\bunion\b/gi, "UnIoN")
    .replace(/\bselect\b/gi, "SeLeCt")
    .replace(/\band\b/gi, "AnD");
  variants.add(mixedCase);

  if (payload.includes(" ")) {
    variants.add(payload.replace(/ /g, "/**/"));
  }

  return Array.from(variants);
}

/**
 * WAF bypass için alternatif header setleri.
 * Yalnızca gerçek tarayıcılarda görülebilecek User-Agent varyantları kullanılır.
 * X-Forwarded-For, X-Real-IP, sentetik Referer ve bot/crawler UA'ları
 * sunucu log'larında tarama parmak izi bıraktığından dahil edilmez.
 */
export function getBypassHeaderSets(
  base: Record<string, string>,
  _origin?: string
): Record<string, string>[] {
  return [
    // Varsayılan — Chrome/Windows
    { ...base },
    // Firefox/Windows varyantı
    {
      ...base,
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
      "accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    },
    // Chrome/macOS varyantı
    {
      ...base,
      "user-agent":
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    },
    // Edge/Windows varyantı
    {
      ...base,
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
    },
  ];
}

/** Path discovery için bypass varyantları (yol normalizasyonu). */
export function getPathBypassVariants(path: string): string[] {
  const variants = new Set<string>([path]);
  variants.add(path.replace(/(?<!\/)\//g, "/./"));
  variants.add(path.replace(/\//g, "/%2e"));
  variants.add(path + "?");
  variants.add(path + "?.aspx");
  return Array.from(variants);
}

export interface FetchWithBypassOptions {
  method?: "GET" | "POST" | "HEAD";
  body?: string;
  contentType?: string;
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** 403 alındığında bypass header'larıyla yeniden dener. */
export async function fetchWithBypass(
  url: string,
  options: FetchWithBypassOptions = {}
): Promise<{ body: string; status: number }> {
  const {
    method = "GET",
    body,
    contentType = "application/x-www-form-urlencoded",
    timeoutMs = 7_000,
    signal,
  } = options;

  throwIfAborted(signal);

  const origin = new URL(url).origin;
  const headerSets = getBypassHeaderSets(BROWSER_HEADERS, origin);

  for (const headers of headerSets) {
    throwIfAborted(signal);
    const reqHeaders: Record<string, string> =
      method === "POST" && body
        ? { ...headers, "content-type": contentType }
        : { ...headers };

    try {
      const response = await withTimeoutSignal(signal, timeoutMs, (requestSignal) =>
        safeFetchText(
          url,
          {
            method,
            redirect: "follow",
            signal: requestSignal,
            headers: reqHeaders,
            body: method === "POST" && body ? body : undefined,
          },
          { access: "active" },
        ));
      if (response.status !== 403) {
        return { body: response.body, status: response.status };
      }
    } catch (error) {
      if (signal?.aborted) throw abortError(signal);
      // Bir varyant hata verirse sonrakine geç
    }
  }

  return { body: "", status: 403 };
}

/** Path probe için: önce normal, 403 ise bypass header + path varyantları dener. */
export async function fetchPathWithBypass(
  probeUrl: string,
  path: string,
  options: { signal?: AbortSignal } = {},
): Promise<{ body: string; status: number }> {
  throwIfAborted(options.signal);
  const origin = new URL(probeUrl).origin;
  const pathVariants = getPathBypassVariants(path);
  const headerSets = getBypassHeaderSets(BROWSER_HEADERS, origin);

  const methods: ("HEAD" | "GET")[] = ["HEAD", "GET"];

  for (const pathVariant of pathVariants) {
    throwIfAborted(options.signal);
    const fullUrl = `${origin}${pathVariant}`;
    for (const headers of headerSets) {
      for (const reqMethod of methods) {
        throwIfAborted(options.signal);
        try {
          const response = await withTimeoutSignal(
            options.signal,
            5_000,
            (requestSignal) => safeFetchText(
              fullUrl,
              {
                method: reqMethod,
                redirect: "manual",
                signal: requestSignal,
                headers,
              },
              { access: "active" },
            ),
          );
          if (response.status !== 403) {
            return { body: response.body, status: response.status };
          }
        } catch (error) {
          if (options.signal?.aborted) throw abortError(options.signal);
          // Devam et
        }
      }
    }
  }

  return { body: "", status: 403 };
}
