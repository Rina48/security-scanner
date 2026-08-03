import type { ScannerFinding } from "../../types.js";

export interface LeakRule {
  id: string;
  title: string;
  severity: ScannerFinding["severity"];
  pattern: RegExp;
  remediation: string;
}

/**
 * HTTP yanıt gövdesinde tespit edilen sızıntı kalıpları.
 *
 * Yeni bir kural eklerken:
 *   - `id` benzersiz olmalı (dedup için kullanılır)
 *   - `pattern` mümkün olduğunca dar tutulmalı (false-positive azaltır)
 *   - `severity` ifşanın iş etkisine göre seçilmeli
 *   - `remediation` Türkçe ve eyleme dönük olmalı
 */
export const LEAK_RULES: LeakRule[] = [
  {
    id: "debug-page-exposure",
    title: "Hata ayıklama sayfası son kullanıcıya açık",
    severity: "critical",
    pattern: /(whoops|application frames|stack trace|laravel.*exception)/i,
    remediation:
      "Üretim ortamında hata ayıklama modunu kapatın (APP_DEBUG=false). Son kullanıcıya yalnızca genel hata mesajı gösterin; teknik detayları yalnızca sunucu tarafı loglarına yazın.",
  },
  {
    id: "env-variable-leak",
    title: "Ortam değişkenleri HTTP yanıtında ifşa olmuş",
    severity: "critical",
    pattern:
      /(APP_DEBUG|APP_ENV|DB_HOST|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|MAIL_PASSWORD)\s*["=]/i,
    remediation:
      "HTTP yanıtlarında ortam değişkenlerini asla göstermeyin. Tüm sırları hemen yenileyin ve .env dosyasını sürüm kontrolüne dahil etmeyin.",
  },
  {
    id: "internal-path-disclosure",
    title: "Sunucu iç dizin yolu ifşa olmuş",
    severity: "high",
    pattern: /(\/home\/|\/var\/www\/|[A-Za-z]:\\Users\\|public_html|vendor\/laravel)/i,
    remediation:
      "Hata çıktılarında sunucu dosya yollarını gizleyin. Merkezi bir hata işleyici kullanarak teknik detayları yalnızca loglara yazın.",
  },
  {
    id: "php-warning-disclosure",
    title: "PHP çalışma zamanı uyarısı/hatası kullanıcıya gösterilmiş",
    severity: "high",
    pattern: /(Undefined offset|Warning|Notice|Fatal error|ErrorException)/i,
    remediation:
      "Girdi doğrulamasını güçlendirin ve üretim ortamında PHP hata çıktısını kapatın (display_errors = Off).",
  },
  {
    id: "tls-verification-disabled",
    title: "Uygulama kodunda TLS sertifika doğrulaması devre dışı",
    severity: "high",
    // 'verify' => false kalıbı sızdırılan kaynak snippet'lerde görünür.
    pattern: /['"']verify['"']\s*=>\s*false/i,
    remediation:
      "TLS sertifika doğrulamasını etkinleştirin. HTTP istemcilerinde 'verify' => false asla kullanmayın; bunun yerine doğru yapılandırılmış bir CA paketi kullanın.",
  },
  {
    id: "eol-php-version-disclosed",
    title: "Destek süresi dolmuş PHP sürümü ifşa olmuş",
    severity: "high",
    pattern: /php[\/\-_ ]?(5\.\d|7\.[0-3])\b/i,
    remediation:
      "Desteklenen bir PHP sürümüne yükseltin (8.2+). Destek süresi dolmuş sürümler güvenlik yaması almaz. Ayrıca expose_php = Off ayarıyla PHP sürüm bilgisini gizleyin.",
  },
  {
    id: "internal-api-endpoint-disclosure",
    title: "İç API uç nokta URL'si yanıtta ifşa olmuş",
    severity: "medium",
    pattern: /https?:\/\/[a-z0-9\-]+\.(internal|local|intra|corp|omuapi)[^\s"'<]*/i,
    remediation:
      "İç servis URL'lerini hata yanıtlarında asla göstermeyin. İç çağrıları bir API geçidi üzerinden yönlendirin ve hata ayıklama çıktısını kapatın.",
  },
  {
    id: "debug-env-local-mode",
    title: "Uygulama üretim ortamında yerel/hata ayıklama modunda çalışıyor",
    severity: "critical",
    pattern: /APP_ENV["'\s]*[=:]["'\s]*local/i,
    remediation:
      "APP_ENV=production ve APP_DEBUG=false yapın. Güvenli bir .env dosyasıyla yeniden dağıtın ve sırları asla sürüm kontrolüne eklemeyin.",
  },
  {
    id: "app-key-leaked",
    title: "Uygulama şifreleme anahtarı (APP_KEY) ifşa olmuş",
    severity: "critical",
    // APP_KEY ifşası oturum sahteciliğine, çerez şifre çözmeye ve tam sistem ele geçirmeye olanak tanır.
    pattern: /APP_KEY["'\s]*[=:]?\s*["']?(base64:[A-Za-z0-9+/=]{30,}|[A-Fa-f0-9]{32,})/i,
    remediation:
      "'php artisan key:generate' komutuyla APP_KEY'i hemen yenileyin. Tüm aktif oturumları geçersiz kılın ve eski anahtarla şifrelenmiş verileri yeniden şifreleyin.",
  },
  {
    id: "server-ip-disclosure",
    title: "Sunucu IP adresi yanıt gövdesinde ifşa olmuş",
    severity: "high",
    pattern: /SERVER_ADDR["'\s]*[=:]?\s*["']?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
    remediation:
      "SERVER_ADDR bilgisini hata çıktılarından gizleyin. Ters proxy kullanın ve kaynak sunucu IP'lerini son kullanıcılara asla göstermeyin.",
  },
  {
    id: "multi-database-topology-disclosure",
    title: "Çoklu veritabanı topolojisi ifşa olmuş (ikincil/API bağlantıları)",
    severity: "high",
    pattern: /DB_(CONNECTION|HOST|DATABASE)_(SECOND|API|REPLICA|SLAVE)/i,
    remediation:
      "Veritabanı bağlantı topolojisini yanıtlarda asla göstermeyin. Hata ayıklama çıktısını kapatın ve sırları bir vault'ta merkezileştirin.",
  },
  {
    id: "default-credential-disclosure",
    title: "Varsayılan veya boş kimlik bilgisi yapılandırmada tespit edildi",
    severity: "critical",
    // REDIS_PASSWORD=null, MAIL_PASSWORD=null vb. kimlik doğrulamasız servislere işaret eder.
    pattern: /(REDIS_PASSWORD|MAIL_PASSWORD|DB_PASSWORD)["'\s]*[=:]?\s*["']?null\b/i,
    remediation:
      "Tüm servisler için güçlü ve benzersiz şifreler belirleyin. Üretimde kimlik bilgilerini asla 'null' bırakmayın. İç servislere ağ erişimini kısıtlayın.",
  },
  {
    id: "eol-apache-version-disclosed",
    title: "Destek süresi dolmuş Apache sürümü ifşa olmuş",
    severity: "high",
    // Apache 2.4.0–2.4.6 (CentOS 7 varsayılanı) destek dışı; 2.4.7+ hâlâ desteklenir.
    pattern: /Apache\/2\.4\.[0-6]\b/i,
    remediation:
      "Apache'yi en son kararlı sürüme yükseltin. ServerTokens Prod ve ServerSignature Off ayarlarıyla sürüm bilgisini başlıklarda gizleyin.",
  },
  {
    id: "source-code-snippet-leak",
    title: "Uygulama kaynak kod parçası yanıtta ifşa olmuş",
    severity: "critical",
    // $request->route() gibi PHP kaynak kalıplarını tespit eder.
    pattern: /\$\w+->(route|input|get|post|request)\s*\(/i,
    remediation:
      "Kaynak kodu son kullanıcılara asla göstermeyin. Hata ayıklama modunu kapatın ve genel hata mesajları döndüren küresel bir hata işleyici uygulayın.",
  },
  {
    id: "middleware-chain-disclosure",
    title: "Tam ara katman/pipeline zinciri ifşa olmuş",
    severity: "medium",
    // Laravel ve Symfony ara katman sınıf adları kimlik doğrulama, oturum ve güvenlik yapısını ortaya çıkarır.
    pattern: /Illuminate\\(Routing|Foundation|Session|Cookie)\\Middleware\\/i,
    remediation:
      "Hata çıktılarında framework iç yapısını gizleyin. Teknik detayları yalnızca sunucu tarafında loglayan özel bir hata işleyici kullanın.",
  },
  {
    id: "sql-error-disclosure",
    title: "Veritabanı (SQL) hata mesajı kullanıcıya gösterilmiş",
    severity: "high",
    pattern:
      /(?:You have an error in your SQL syntax|SQLSTATE\[\d]+|mysql_fetch|Warning:?\s*mysql|ERROR:\s*syntax error|Incorrect syntax near|sözdizimi hatası|veritabanı hatası|SQL hatası)/i,
    remediation:
      "SQL hatalarını son kullanıcıya göstermeyin. Genel bir hata mesajı döndürün; teknik detayları yalnızca sunucu loglarına yazın. Prepared statement kullanarak SQL injection riskini azaltın.",
  },
  {
    id: "private-ip-disclosure",
    title: "Özel (iç) IP adresi yanıt gövdesinde ifşa olmuş",
    severity: "medium",
    // 10.x, 172.16-31.x, 192.168.x — RFC 1918 özel adres aralıkları
    pattern:
      /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
    remediation:
      "Hata çıktılarında iç ağ IP adreslerini gizleyin. Ters proxy kullanın ve sunucu topolojisini son kullanıcıya ifşa etmeyin.",
  },
  {
    id: "session-id-in-response",
    title: "Oturum ID'si yanıt gövdesinde veya URL'de ifşa olmuş",
    severity: "high",
    pattern:
      /(?:PHPSESSID|sessionid|jsessionid|SESSION|session_id)["'\s=:]+["']?[A-Za-z0-9_\-]{20,}/i,
    remediation:
      "Oturum ID'lerini URL'de veya HTML içinde taşımayın. HttpOnly çerez kullanın ve oturum kimlik bilgisini güvenli, httpOnly bayraklı çerezde saklayın.",
  },

  // ── Bulut & Servis Kimlik Bilgileri ────────────────────────────────────────

  {
    id: "aws-access-key-id-leak",
    title: "AWS erişim anahtarı (Access Key ID) ifşa olmuş",
    severity: "critical",
    // AWS Access Key ID'leri 'AKIA' veya 'ASIA' önekiyle başlar ve 20 karakter uzunluğundadır.
    pattern: /\b(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b/,
    remediation:
      "AWS IAM konsolundan anahtarı hemen devre dışı bırakın ve yenisini oluşturun. CloudTrail loglarını yetkisiz erişim için inceleyin. Sırları kodda veya yanıtlarda asla bulundurmayın; AWS Secrets Manager veya ortam değişkeni kullanın.",
  },
  {
    id: "aws-secret-access-key-leak",
    title: "AWS gizli erişim anahtarı (Secret Access Key) ifşa olmuş",
    severity: "critical",
    // AWS Secret Access Key genellikle 40 Base64 karakterinden oluşur ve env adıyla birlikte görülür.
    pattern: /AWS_SECRET_ACCESS_KEY["'\s]*[=:]?\s*["']?([A-Za-z0-9+/]{40})\b/i,
    remediation:
      "Anahtarı hemen iptal edin. IAM politikalarını en az ayrıcalık ilkesine göre gözden geçirin. Sırları AWS Secrets Manager veya SSM Parameter Store üzerinde yönetin.",
  },
  {
    id: "stripe-secret-key-leak",
    title: "Stripe gizli API anahtarı ifşa olmuş",
    severity: "critical",
    // Stripe canlı gizli anahtarları 'sk_live_', test anahtarları 'sk_test_' önekiyle başlar.
    pattern: /\b(sk_live_|sk_test_)[A-Za-z0-9]{24,}\b/,
    remediation:
      "Stripe Dashboard üzerinden anahtarı hemen iptal edin ve yenisini oluşturun. Tüm API anahtarlarını sunucu tarafında ortam değişkeni olarak saklayın; hiçbir zaman istemciye veya HTTP yanıtına yansıtmayın.",
  },
  {
    id: "github-token-leak",
    title: "GitHub kişisel erişim token'ı (PAT) ifşa olmuş",
    severity: "critical",
    // GitHub PAT'ları 'ghp_', 'gho_', 'github_pat_' önekiyle başlar.
    pattern: /\b(ghp_|gho_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{30,}\b/,
    remediation:
      "GitHub Settings > Developer Settings > Personal Access Tokens bölümünden token'ı hemen iptal edin. Repository'lere yetkisiz push yapıldı mı denetleyin. GitHub Secret Scanning uyarılarını aktif edin.",
  },
  {
    id: "google-api-key-leak",
    title: "Google API anahtarı ifşa olmuş",
    severity: "high",
    // Google API anahtarları 'AIza' önekiyle başlar ve 39 karakter uzunluğundadır.
    pattern: /\bAIza[A-Za-z0-9\-_]{35}\b/,
    remediation:
      "Google Cloud Console'dan anahtarı iptal edin ve yenisini oluşturun. API kısıtlamalarını (HTTP Referrer veya IP) etkinleştirin ve yalnızca gerekli API'lere izin verin.",
  },
  {
    id: "sentry-dsn-leak",
    title: "Sentry DSN (veri kaynak adı) ifşa olmuş",
    severity: "high",
    // Sentry DSN formatı: https://<public_key>@<org>.ingest.sentry.io/<project_id>
    pattern: /https:\/\/[a-f0-9]{32}@(o\d+\.ingest\.sentry\.io|sentry\.io)\/\d+/i,
    remediation:
      "Sentry proje ayarlarından DSN'yi yenileyin. DSN ile hatalı veri gönderimi veya kota tüketimi mümkün olduğundan sunucu tarafında saklayın ve istemciye yalnızca gerekirse kısıtlı kapsamla gönderin.",
  },
  {
    id: "slack-webhook-leak",
    title: "Slack Incoming Webhook URL'si ifşa olmuş",
    severity: "high",
    // Slack webhook URL'leri 'hooks.slack.com/services/' içerir.
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    remediation:
      "Slack App yönetim panelinden webhook'u iptal edin. Webhook URL'lerini kaynak kodda veya yanıtlarda asla sabit kodlamayın; ortam değişkeni veya bir sır kasası kullanın.",
  },
  {
    id: "discord-webhook-leak",
    title: "Discord Webhook URL'si ifşa olmuş",
    severity: "high",
    // Discord webhook URL'leri 'discord.com/api/webhooks/' yolunu içerir.
    pattern: /https:\/\/(discord\.com|discordapp\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/,
    remediation:
      "Discord sunucu ayarlarından webhook'u silin ve yenisini oluşturun. Webhook URL'lerini kaynak kodda veya HTTP yanıtlarında sabit kodlamayın.",
  },
  {
    id: "telegram-bot-token-leak",
    title: "Telegram Bot Token ifşa olmuş",
    severity: "high",
    // Telegram bot token formatı: <bot_id>:<alfanümerik_gizli>
    pattern: /\b\d{8,10}:AA[A-Za-z0-9\-_]{33}\b/,
    remediation:
      "BotFather'a '/revoke' komutu göndererek token'ı iptal edin. Yeni token oluşturun ve ortam değişkeni olarak saklayın.",
  },
  {
    id: "social-media-access-token-leak",
    title: "Sosyal medya (Instagram/Facebook) erişim token'ı ifşa olmuş",
    severity: "high",
    // access_token / accessToken ile uzun token — ODTÜ tarzı client-side ifşa
    pattern:
      /(?:access_token|accessToken)["'\s:=]+["']?[A-Za-z0-9_\-.]{40,}|"access_token"\s*:\s*"[A-Za-z0-9_\-.]{40,}"/i,
    remediation:
      "Sosyal medya API token'larını istemci tarafına veya HTML'e asla gömme. Server-side proxy kullanın; token'ları sunucu ortamında saklayın ve hemen yenileyin.",
  },

  // ── Kimlik Doğrulama Token'ları ────────────────────────────────────────────

  {
    id: "jwt-token-leak",
    title: "JWT (JSON Web Token) yanıt gövdesinde ifşa olmuş",
    severity: "high",
    // JWT üç Base64URL bölümünden oluşur; başlık 'eyJ' ile başlar.
    pattern: /eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}/,
    remediation:
      "Token'ı hemen geçersiz kılın ve oturumu sonlandırın. JWT'leri yalnızca HTTPS üzerinden ve Authorization başlığında gönderin; yanıt gövdesine veya loglara yazmayın. Kısa ömürlü token'lar kullanın.",
  },
  {
    id: "bearer-token-header-leak",
    title: "Authorization Bearer token yanıtta ifşa olmuş",
    severity: "high",
    // 'Authorization: Bearer <token>' veya 'bearer_token=' kalıbı
    pattern: /(Authorization["'\s]*[=:]\s*["']?Bearer\s+[A-Za-z0-9\-_.~+/]{20,}|bearer_token["'\s]*[=:]\s*["']?[A-Za-z0-9\-_.~+/]{20,})/i,
    remediation:
      "Bearer token'ı hemen iptal edin. Authorization başlıklarını veya token değerlerini asla loglara veya HTTP yanıt gövdelerine yazmayın.",
  },

  // ── Kriptografik Anahtar & Sertifika ──────────────────────────────────────

  {
    id: "private-key-pem-leak",
    title: "PEM formatında özel anahtar (RSA/EC/DSA) ifşa olmuş",
    severity: "critical",
    // PEM özel anahtarları '-----BEGIN ... PRIVATE KEY-----' başlığıyla gelir.
    pattern: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i,
    remediation:
      "Anahtarı hemen iptal edin ve yenisini oluşturun. İlgili sertifikaları da yenileyin. Özel anahtarları kaynak koda, logları veya HTTP yanıtlarına asla eklemeyin; güvenli bir anahtar kasası kullanın.",
  },

  // ── Veritabanı Bağlantı Dizesi ─────────────────────────────────────────────

  {
    id: "database-connection-string-leak",
    title: "Veritabanı bağlantı dizesi yanıtta ifşa olmuş",
    severity: "critical",
    // mysql://, postgresql://, mongodb+srv:// vb. şema içeren bağlantı dizeleri
    pattern: /(mysql|postgresql|postgres|mongodb(\+srv)?|mssql|sqlserver):\/\/[^@\s"'<]{3,}@[^\s"'<]{3,}/i,
    remediation:
      "Bağlantı dizesindeki şifreyi hemen yenileyin. Bağlantı bilgilerini ortam değişkeni veya bir sır kasasında saklayın; asla kaynak kod veya HTTP yanıtında bulundurmayın.",
  },

  // ── Diğer Framework / Servis Sırları ──────────────────────────────────────

  {
    id: "laravel-telescope-leak",
    title: "Laravel Telescope debug arayüzü dışarıya açık",
    severity: "high",
    // Telescope hata ayıklama arayüzünün HTML işareti
    pattern: /(laravel[-\s]telescope|\/telescope\/requests)/i,
    remediation:
      "Telescope'u üretimde devre dışı bırakın (TELESCOPE_ENABLED=false) veya IP tabanlı erişim kısıtlaması uygulayın.",
  },
  {
    id: "graphql-introspection-exposed",
    title: "GraphQL introspection şeması dışarıya açık",
    severity: "medium",
    // GraphQL introspection yanıtı __schema veya __type içerir.
    pattern: /"__schema"\s*:\s*\{|"__type"\s*:\s*\{/,
    remediation:
      "Üretimde GraphQL introspection sorgularını devre dışı bırakın. Şema bilgisi saldırganlara API yüzeyi haritası sağlar.",
  },
];
