/**
 * Tarayıcı modülleri arası ortak ayarlar.
 * Timeout/threshold gibi sabitlerin tek kaynaktan yönetilmesini sağlar.
 */

/** İlk passive fetch için zaman aşımı (TLS/HTTP cevabı bekleme süresi). */
export const INITIAL_FETCH_TIMEOUT_MS = 30_000;

/** Aktif probe'lar (SQLi/XSS) için kısa zaman aşımı — yavaş cevap = test sırasında atlanır. */
export const ACTIVE_PROBE_TIMEOUT_MS = 7_000;

/** Path discovery / OPTIONS / redirect probe'ları için kısa zaman aşımı. */
export const SHORT_PROBE_TIMEOUT_MS = 6_000;

/** Path bypass varyantları için iyice kısa zaman aşımı. */
export const BYPASS_PROBE_TIMEOUT_MS = 5_000;

/** Komut enjeksiyonu zaman tabanlı testte gözlemlenecek istek üst sınırı. */
export const TIMING_PROBE_TIMEOUT_MS = 10_000;

/** Path discovery: aynı anda gönderilecek probe sayısı. */
export const PATH_DISCOVERY_CONCURRENCY = 10;

/** SQLi tespit eşiği — yanıt gövdesi bu kadar karakter değişirse şüpheli. */
export const SQLI_BODY_LENGTH_DELTA_THRESHOLD = 1_000;

/** Komut enjeksiyonu zaman gecikmesi eşiği (ms). */
export const CMD_INJECTION_TIME_THRESHOLD_MS = 3_500;

/** Komut enjeksiyonu zaman tabanlı testte denenecek parametre sayısı üst sınırı. */
export const CMD_INJECTION_TIME_PARAM_LIMIT = 5;

/** Response leak kanıt snippet'i: eşleşmeden önce/sonra alınan karakter sayısı. */
export const LEAK_EVIDENCE_PRE_CHARS = 80;
export const LEAK_EVIDENCE_POST_CHARS = 160;
