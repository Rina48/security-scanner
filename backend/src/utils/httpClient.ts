/**
 * Credential taraması için gecikme ve güvenli egress yardımcıları.
 * DNS pinning garanti edilemediğinden proxy tanımı varsa istek fail-closed reddedilir.
 */

import {
  safeFetchText,
  type SafeFetchInit,
  type SafeFetchResult,
} from "../security/egressPolicy.js";
import { abortableDelay } from "./abort.js";

const PROXY_URL =
  process.env.SECURITY_SCANNER_PROXY ||
  process.env.HTTPS_PROXY ||
  process.env.HTTP_PROXY;

/** İstekler arasında rastgele bekleme — IDS/rate limit tetiklemeyi azaltır. */
const MIN_DELAY_MS = 2_000;
const MAX_DELAY_MS = 6_000;

/** Credential testi için daha uzun gecikme — gizlilik artırır. */
const CREDENTIAL_MIN_DELAY_MS = Number(process.env.SECURITY_SCANNER_CREDENTIAL_MIN_DELAY_MS) || 3_000;
const CREDENTIAL_MAX_DELAY_MS = Number(process.env.SECURITY_SCANNER_CREDENTIAL_MAX_DELAY_MS) || 8_000;

export function sleepMs(ms: number, signal?: AbortSignal): Promise<void> {
  return abortableDelay(ms, signal);
}

/** Rastgele gecikme (min–max arası). */
export function randomDelay(signal?: AbortSignal): Promise<void> {
  const ms = MIN_DELAY_MS + Math.random() * (MAX_DELAY_MS - MIN_DELAY_MS);
  return sleepMs(Math.floor(ms), signal);
}

/** Credential denemeleri arası gizlilik odaklı gecikme (3–8 sn varsayılan). */
export function credentialRandomDelay(signal?: AbortSignal): Promise<void> {
  const min = Math.min(CREDENTIAL_MIN_DELAY_MS, CREDENTIAL_MAX_DELAY_MS);
  const max = Math.max(CREDENTIAL_MIN_DELAY_MS, CREDENTIAL_MAX_DELAY_MS);
  const ms = min + Math.random() * (max - min);
  return sleepMs(Math.floor(ms), signal);
}

/**
 * Eski çağrı sözleşmesini koruyan güvenli fetch. Proxy tanımlıysa doğrudan trafik
 * sızıntısını önlemek için istek göndermez.
 */
export async function fetchWithProxy(
  input: string | URL,
  init?: SafeFetchInit,
): Promise<SafeFetchResult> {
  if (PROXY_URL) {
    throw new Error("Proxy kullanımı sabitlenmiş egress doğrulamasıyla uyumlu değil.");
  }
  return safeFetchText(input.toString(), init, { access: "active" });
}

export function isProxyConfigured(): boolean {
  return Boolean(PROXY_URL);
}
