/**
 * Tüm HTTP isteklerinde kullanılan ortak başlıklar.
 * Gerçek bir Chrome tarayıcısını taklit ederek ağ trafiğine karışır.
 * User-agent veya Accept başlığını buradan güncellemek tüm modüllere yansır.
 *
 * Özel tarama başlıkları (X-Scanner, X-Forwarded-For, pragma vb.) kasıtlı
 * olarak dahil edilmemiştir; sunucu log'larında tarama parmak izi bırakır.
 */
export const BROWSER_HEADERS: Record<string, string> = {
  "user-agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
  "accept":
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  "accept-language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
  "accept-encoding": "gzip, deflate, br",
};
