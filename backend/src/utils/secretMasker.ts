interface MaskRule {
  pattern: RegExp;
  label: string;
  /** Eşleşmenin sonunda korunacak suffix group dizini (0 = yok). */
  suffixGroupIndex?: number;
}

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
  // AWS Access Key ID: 'AKIA' önekini koru, 16 karakterlik kimlik kısmını gizle
  { pattern: /(AKIA)([A-Z0-9]{16})\b/g, label: "AWS_ACCESS_KEY_ID" },

  // ── Stripe ─────────────────────────────────────────────────────────────────
  { pattern: /(sk_live_)([A-Za-z0-9]{20,})\b/g, label: "STRIPE_SECRET_KEY" },
  { pattern: /(sk_test_)([A-Za-z0-9]{20,})\b/g, label: "STRIPE_TEST_KEY" },

  // ── GitHub ─────────────────────────────────────────────────────────────────
  { pattern: /(ghp_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_TOKEN" },
  { pattern: /(gho_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_OAUTH_TOKEN" },
  { pattern: /(github_pat_)([A-Za-z0-9_]{30,})\b/g, label: "GITHUB_PAT" },

  // ── Google ─────────────────────────────────────────────────────────────────
  // 'AIza' önekini koru, geri kalanı gizle
  { pattern: /(AIza)([A-Za-z0-9\-_]{35})\b/g, label: "GOOGLE_API_KEY" },

  // ── Sentry DSN ─────────────────────────────────────────────────────────────
  // URL şemasını koru, public key ve endpoint'i gizle
  { pattern: /(https:\/\/)([a-f0-9]{32}@[^\s"'<]+)/gi, label: "SENTRY_DSN" },

  // ── Slack Webhook ──────────────────────────────────────────────────────────
  { pattern: /(https:\/\/hooks\.slack\.com\/services\/)(T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g, label: "SLACK_WEBHOOK" },

  // ── Discord Webhook ────────────────────────────────────────────────────────
  { pattern: /(https:\/\/(?:discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/)([A-Za-z0-9_\-]+)/g, label: "DISCORD_WEBHOOK" },

  // ── Telegram Bot Token ─────────────────────────────────────────────────────
  { pattern: /(\d{8,10}:AA)([A-Za-z0-9\-_]{33})\b/g, label: "TELEGRAM_BOT_TOKEN" },

  // ── JWT ────────────────────────────────────────────────────────────────────
  // header.payload'ı koru, imzayı gizle
  { pattern: /(eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.)([A-Za-z0-9\-_]{10,})/g, label: "JWT_SIGNATURE" },

  // ── PEM Özel Anahtar ───────────────────────────────────────────────────────
  // Başlık satırını koru, anahtar gövdesini gizle
  { pattern: /(-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)([^-]+)(-----END)/gi, label: "PRIVATE_KEY_BODY", suffixGroupIndex: 3 },

  // ── Firebase ───────────────────────────────────────────────────────────────
  // 'apiKey: "' kısmını koru, değeri gizle, kapanış tırnağı koru
  { pattern: /(apiKey\s*:\s*["'])([A-Za-z0-9\-_]{30,})(["'])/gi, label: "FIREBASE_API_KEY", suffixGroupIndex: 3 },

  // ── Sosyal medya & oturum ──────────────────────────────────────────────────
  { pattern: /((?:access_token|accessToken)["'\s:=]+["']?)([A-Za-z0-9_\-.]{40,})/gi, label: "ACCESS_TOKEN" },
  {
    pattern: /((?:PHPSESSID|sessionid|jsessionid|SESSION|session_id)["'\s=:]+["']?)([A-Za-z0-9_\-]{20,})/gi,
    label: "SESSION_ID",
  },
];

export function maskSecrets(text: string): string {
  let masked = text;
  for (const { pattern, label, suffixGroupIndex } of MASK_RULES) {
    if (suffixGroupIndex) {
      // Üç group: (prefix)(gizlenecek)(suffix)
      masked = masked.replace(
        pattern,
        (_match, prefix: string, _secret: string, suffix: string) =>
          `${prefix}[${label}-REDACTED]${suffix}`,
      );
    } else {
      // İki group: (prefix)(gizlenecek)
      masked = masked.replace(
        pattern,
        (_match, prefix: string) => `${prefix}[${label}-REDACTED]`,
      );
    }
  }
  return masked;
}
