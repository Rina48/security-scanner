interface MaskRule {
  pattern: RegExp;
  label: string;
  /** Eşleşmenin sonunda korunacak suffix group dizini (0 = yok). */
  suffixGroupIndex?: number;
  /** Secret'ın güvenli bir prefix'i yoksa eşleşmenin tamamını değiştirir. */
  replaceWholeMatch?: boolean;
}

export const REDACTED_VALUE = "[REDACTED]";
const REDACTED_QUERY_VALUE = "REDACTED";

const MASK_RULES: MaskRule[] = [
  // ── Laravel / Genel Uygulama ────────────────────────────────────────────────
  { pattern: /(APP_KEY\s*["=:]\s*["']?)(base64:[A-Za-z0-9+/=]{10,})/gi, label: "APP_KEY" },
  { pattern: /(APP_KEY\s*["=:]\s*["']?)([A-Fa-f0-9]{32,})/gi, label: "APP_KEY" },
  { pattern: /(DB_PASSWORD\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "DB_PASSWORD" },
  { pattern: /(DB_PASSWORD_SECOND\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "DB_PASSWORD_SECOND" },
  { pattern: /(DB_PASSWORD_API\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "DB_PASSWORD_API" },
  { pattern: /(MAIL_PASSWORD\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "MAIL_PASSWORD" },
  { pattern: /(REDIS_PASSWORD\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "REDIS_PASSWORD" },
  { pattern: /(PUSHER_APP_SECRET\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "PUSHER_APP_SECRET" },

  // ── AWS ────────────────────────────────────────────────────────────────────
  { pattern: /(AWS_SECRET_ACCESS_KEY\s*["=:]\s*["']?)([^\s"'\n]{4,})/gi, label: "AWS_SECRET_ACCESS_KEY" },
  { pattern: /(AKIA)([A-Z0-9]{16})\b/g, label: "AWS_ACCESS_KEY_ID" },

  // ── Stripe ─────────────────────────────────────────────────────────────────
  { pattern: /(sk_live_)([A-Za-z0-9]{20,})\b/g, label: "STRIPE_SECRET_KEY" },
  { pattern: /(sk_test_)([A-Za-z0-9]{20,})\b/g, label: "STRIPE_TEST_KEY" },

  // ── GitHub ─────────────────────────────────────────────────────────────────
  { pattern: /(ghp_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_TOKEN" },
  { pattern: /(gho_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_OAUTH_TOKEN" },
  { pattern: /(github_pat_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_PAT" },

  // ── Google ─────────────────────────────────────────────────────────────────
  { pattern: /(AIza)([A-Za-z0-9\-_]{35})\b/g, label: "GOOGLE_API_KEY" },

  // ── Sentry DSN ─────────────────────────────────────────────────────────────
  { pattern: /(https:\/\/)([a-f0-9]{32}@[^\s"'<]+)/gi, label: "SENTRY_DSN" },

  // ── Webhook ve token'lar ───────────────────────────────────────────────────
  { pattern: /(https:\/\/hooks\.slack\.com\/services\/)(T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g, label: "SLACK_WEBHOOK" },
  {
    pattern: /https:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/g,
    label: "DISCORD_WEBHOOK",
    replaceWholeMatch: true,
  },
  {
    pattern: /\b\d{8,10}:AA[A-Za-z0-9\-_]{33}\b/g,
    label: "TELEGRAM_BOT_TOKEN",
    replaceWholeMatch: true,
  },
  {
    pattern: /\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b/g,
    label: "JWT",
    replaceWholeMatch: true,
  },

  // ── PEM Özel Anahtar ───────────────────────────────────────────────────────
  { pattern: /(-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)([^-]+)(-----END)/gi, label: "PRIVATE_KEY_BODY", suffixGroupIndex: 3 },

  // ── Firebase ───────────────────────────────────────────────────────────────
  { pattern: /(apiKey\s*:\s*["'])([A-Za-z0-9\-_]{30,})(["'])/gi, label: "FIREBASE_API_KEY", suffixGroupIndex: 3 },

  // ── Sosyal medya & oturum ──────────────────────────────────────────────────
  { pattern: /((?:access_token|accessToken)["'\s:=]+["']?)([A-Za-z0-9_\-.]{20,})/gi, label: "ACCESS_TOKEN" },
  {
    pattern: /((?:PHPSESSID|sessionid|jsessionid|SESSION|session_id)["'\s=:]+["']?)([A-Za-z0-9_\-]{12,})/gi,
    label: "SESSION_ID",
  },
];

const SENSITIVE_NAME_PARTS = new Set([
  "auth",
  "authorization",
  "cookie",
  "credential",
  "credentials",
  "key",
  "passwd",
  "password",
  "pwd",
  "secret",
  "session",
  "token",
]);

const SENSITIVE_COMPACT_NAME = /^(?:(?:api|access|refresh|id|client|private|auth|authentication)?(?:token|key|secret|password|passwd|pwd|session|sessionid|credential|credentials)|(?:php|j)?sessionid)$/i;
const QUERY_PARAMETER_PATTERN = /([?&])([^=?&#\s"'<>]+)=([^&#\s"'<>]*)/gu;
const ABSOLUTE_URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const SENSITIVE_HEADER_PATTERN = /(^|[\s{,[('"])((?:authorization|proxy-authorization|authentication-info|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-amz-security-token)\s*[:=]\s*)([^\r\n]+)/gim;
const NAMED_VALUE_PATTERN = /(^|[\s{,[('"])(["']?)([A-Za-z0-9_%.-]+)\2(\s*[:=]\s*)(["']?)([^"'&,;}\]\s]+)\5/gmu;

function decodeParameterName(value: string): string {
  let decoded = value.replace(/\+/g, " ");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded;
}

export function isSensitiveName(value: string): boolean {
  const decoded = decodeParameterName(value)
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase();
  const parts = decoded.split(/[^a-z0-9]+/).filter(Boolean);
  return parts.some((part) => SENSITIVE_NAME_PARTS.has(part))
    || SENSITIVE_COMPACT_NAME.test(parts.join(""));
}

function isAlreadyRedacted(value: string): boolean {
  return value === REDACTED_QUERY_VALUE
    || value === REDACTED_VALUE
    || value.startsWith("[REDACTED")
    || /^\[[A-Z0-9_-]+-REDACTED/i.test(value)
    || /^\[[A-Z0-9_-]+-REDACTED\]$/i.test(value);
}

function maskKnownSecretFormats(text: string): string {
  let masked = text;
  for (const { pattern, label, suffixGroupIndex, replaceWholeMatch } of MASK_RULES) {
    if (replaceWholeMatch) {
      masked = masked.replace(pattern, `[${label}-REDACTED]`);
    } else if (suffixGroupIndex) {
      masked = masked.replace(
        pattern,
        (_match, prefix: string, _secret: string, suffix: string) =>
          `${prefix}[${label}-REDACTED]${suffix}`,
      );
    } else {
      masked = masked.replace(
        pattern,
        (_match, prefix: string) => `${prefix}[${label}-REDACTED]`,
      );
    }
  }
  return masked;
}

function removeUrlUserInfo(text: string): string {
  return text.replace(ABSOLUTE_URL_PATTERN, (candidate) => {
    const trailing = candidate.match(/[),.;!?]+$/)?.[0] ?? "";
    const urlText = trailing ? candidate.slice(0, -trailing.length) : candidate;
    try {
      const parsed = new URL(urlText);
      if (!parsed.username && !parsed.password) return candidate;
      parsed.username = "";
      parsed.password = "";
      return `${parsed.toString()}${trailing}`;
    } catch {
      return candidate;
    }
  });
}

function maskSensitiveQueryParameters(text: string): string {
  return text.replace(
    QUERY_PARAMETER_PATTERN,
    (match, separator: string, rawName: string) =>
      isSensitiveName(rawName)
        ? `${separator}${rawName}=${REDACTED_QUERY_VALUE}`
        : match,
  );
}

function maskSensitiveHeaders(text: string): string {
  return text.replace(
    SENSITIVE_HEADER_PATTERN,
    (_match, boundary: string, header: string) => `${boundary}${header}${REDACTED_VALUE}`,
  );
}

function maskNamedSensitiveValues(text: string): string {
  return text.replace(
    NAMED_VALUE_PATTERN,
    (
      match,
      boundary: string,
      keyQuote: string,
      key: string,
      separator: string,
      valueQuote: string,
      value: string,
    ) => {
      if (!isSensitiveName(key) || isAlreadyRedacted(value)) return match;
      return `${boundary}${keyQuote}${key}${keyQuote}${separator}${valueQuote}${REDACTED_VALUE}${valueQuote}`;
    },
  );
}

export function urlHasUserInfo(value: string): boolean {
  try {
    const parsed = new URL(value);
    return Boolean(parsed.username || parsed.password);
  } catch {
    return false;
  }
}

export function assertUrlHasNoUserInfo(value: string): void {
  if (urlHasUserInfo(value)) {
    throw new Error("URL userinfo is not allowed.");
  }
}

/**
 * Rapor, kalıcılık, API ve log sınırlarında kullanılacak bağlama duyarlı maskeleme.
 * Opaque değerleri biçiminden tahmin etmek yerine hassas header ve alan adlarını esas alır.
 */
export function maskSecrets(text: string): string {
  const knownFormatsMasked = maskKnownSecretFormats(text);
  const withoutUserInfo = removeUrlUserInfo(knownFormatsMasked);
  const queryMasked = maskSensitiveQueryParameters(withoutUserInfo);
  const headersMasked = maskSensitiveHeaders(queryMasked);
  return maskNamedSensitiveValues(headersMasked);
}
