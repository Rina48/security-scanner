import { Headers } from "undici";
import type { ScannerFinding } from "../../types.js";

const REQUIRED_HEADERS = [
  {
    name: "content-security-policy",
    title: "Content-Security-Policy başlığı eksik",
    severity: "high" as const,
    remediation:
      "Betik enjeksiyonu ve veri sızıntısı riskini azaltmak için katı bir CSP politikası tanımlayın.",
  },
  {
    name: "strict-transport-security",
    title: "Strict-Transport-Security başlığı eksik",
    severity: "medium" as const,
    remediation:
      "HTTPS'i zorlamak ve protokol düşürme saldırılarını önlemek için HSTS'yi etkinleştirin.",
  },
  {
    name: "x-content-type-options",
    title: "X-Content-Type-Options başlığı eksik",
    severity: "medium" as const,
    remediation: "X-Content-Type-Options başlığını 'nosniff' olarak ayarlayın.",
  },
  {
    name: "x-frame-options",
    title: "X-Frame-Options başlığı eksik",
    severity: "medium" as const,
    remediation:
      "Tıklama korsanlığı riskini azaltmak için X-Frame-Options başlığını DENY veya SAMEORIGIN olarak ayarlayın.",
  },
  {
    name: "referrer-policy",
    title: "Referrer-Policy başlığı eksik",
    severity: "low" as const,
    remediation:
      "Hassas URL meta verilerinin sızıntısını önlemek için katı bir Referrer-Policy ayarlayın.",
  },
  {
    name: "permissions-policy",
    title: "Permissions-Policy başlığı eksik",
    severity: "low" as const,
    remediation:
      "Kamera, mikrofon, konum gibi tarayıcı özelliklerini kısıtlamak için Permissions-Policy (eski adı Feature-Policy) başlığını tanımlayın.",
  },
  {
    name: "cross-origin-opener-policy",
    title: "Cross-Origin-Opener-Policy (COOP) başlığı eksik",
    severity: "low" as const,
    remediation:
      "Cross-site window açılması ve Spectre benzeri saldırıları azaltmak için COOP başlığını (örn. same-origin) tanımlayın.",
  },
  {
    name: "cross-origin-embedder-policy",
    title: "Cross-Origin-Embedder-Policy (COEP) başlığı eksik",
    severity: "low" as const,
    remediation:
      "Cross-origin kaynakları izole etmek için COEP başlığını (örn. require-corp) tanımlayın. COOP ile birlikte kullanıldığında SharedArrayBuffer gibi özellikler güvenli hale gelir.",
  },
];

export function runSecurityHeaderScanner(
  headers: Headers,
  endpoint: string,
): ScannerFinding[] {
  const findings: ScannerFinding[] = [];

  for (const requiredHeader of REQUIRED_HEADERS) {
    const value = headers.get(requiredHeader.name);
    if (!value) {
      findings.push({
        id: `missing-${requiredHeader.name}`,
        category: "headers",
        title: requiredHeader.title,
        severity: requiredHeader.severity,
        confidence: "high",
        evidence: `Başlık bulunamadı: ${requiredHeader.name}`,
        remediation: requiredHeader.remediation,
        endpoint,
      });
    }
  }

  const corsOrigin = headers.get("access-control-allow-origin");
  const corsCredentials = headers.get("access-control-allow-credentials")?.toLowerCase().trim();
  const isCredentialsWithWildcard =
    corsCredentials === "true" && (corsOrigin?.trim() === "*" || !corsOrigin);

  if (corsOrigin?.trim() === "*" && !isCredentialsWithWildcard) {
    findings.push({
      id: "overly-permissive-cors",
      category: "headers",
      title: "Aşırı izinli CORS politikası",
      severity: "medium",
      confidence: "medium",
      evidence: "Access-Control-Allow-Origin joker karakter (*) olarak ayarlanmış",
      remediation:
        "CORS kaynaklarını yalnızca uygulamanızın ihtiyaç duyduğu güvenilir alan adlarıyla kısıtlayın.",
      endpoint,
    });
  }

  if (isCredentialsWithWildcard) {
    findings.push({
      id: "cors-credentials-with-wildcard",
      category: "headers",
      title: "CORS credentials ile joker/eksik origin — kritik yanlış yapılandırma",
      severity: "critical",
      confidence: "high",
      evidence:
        "Access-Control-Allow-Credentials: true ile Access-Control-Allow-Origin joker (*) veya eksik. Çerez ve kimlik bilgileri sızabilir.",
      remediation:
        "Credentials ile CORS kullanırken Access-Control-Allow-Origin'de belirli domain listesi verin. Joker (*) ile credentials asla kullanılamaz.",
      endpoint,
    });
  }

  const serverHeader = headers.get("server");
  if (serverHeader) {
    // Sürüm numaraları saldırganlara bilinen CVE'leri hedefleme imkânı tanır.
    const hasVersionNumber = /[\d]+\.[\d]+/.test(serverHeader);
    if (hasVersionNumber) {
      findings.push({
        id: "server-version-disclosure",
        category: "headers",
        title: "Sunucu sürüm numarası yanıt başlıklarında ifşa olmuş",
        severity: "medium",
        confidence: "high",
        evidence: `Server: ${serverHeader}`,
        remediation:
          "Web sunucunuzu sürüm bilgisini gizleyecek şekilde yapılandırın. Apache için ServerTokens Prod, Nginx için server_tokens off ayarını kullanın.",
        endpoint,
      });
    }
  }

  const poweredByHeader = headers.get("x-powered-by");
  if (poweredByHeader) {
    findings.push({
      id: "x-powered-by-disclosure",
      category: "headers",
      title: "Teknoloji yığını X-Powered-By başlığıyla ifşa olmuş",
      severity: "medium",
      confidence: "high",
      evidence: `X-Powered-By: ${poweredByHeader}`,
      remediation:
        "X-Powered-By başlığını kaldırın. PHP için expose_php = Off, Express için helmet veya app.disable('x-powered-by') kullanın.",
      endpoint,
    });
  }

  return findings;
}
