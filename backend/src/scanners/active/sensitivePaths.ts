import type { ScannerFinding } from "../../types.js";

export interface SensitivePath {
  path: string;
  title: string;
  severity: ScannerFinding["severity"];
  remediation: string;
}

/**
 * Path discovery için bilinen hassas yollar.
 *
 * Yeni yol eklerken:
 *   - `path` "/" ile başlamalı
 *   - `severity` ifşanın iş etkisini yansıtmalı
 *   - Aynı dosyanın ".bak", ".old" varyantları için ayrı kayıtlar oluşturulabilir
 *   - Statik liste dışında `robots.txt` Disallow'larından da yollar eklenir
 *     (bkz. `pathDiscoveryScanner.ts`)
 */
export const SENSITIVE_PATHS: SensitivePath[] = [
  // Ortam dosyaları
  { path: "/.env", title: ".env dosyası dışarıya açık", severity: "critical", remediation: "Web sunucusunu .env dosyasını servis etmeyecek şekilde yapılandırın. Nginx'te 'location ~ /\\.env { deny all; }' kuralı ekleyin." },
  { path: "/.env.local", title: ".env.local dosyası dışarıya açık", severity: "critical", remediation: ".env* kalıbındaki tüm dosyaları web sunucusu kurallarıyla engelleyin." },
  { path: "/.env.production", title: ".env.production dosyası dışarıya açık", severity: "critical", remediation: ".env* kalıbındaki tüm dosyaları web sunucusu kurallarıyla engelleyin." },
  { path: "/.env.backup", title: ".env.backup dosyası dışarıya açık", severity: "critical", remediation: "Yedek dosyaları web kökünün dışında saklayın." },

  // PHP bilgi sayfaları
  { path: "/phpinfo.php", title: "PHP bilgi sayfası (phpinfo) dışarıya açık", severity: "critical", remediation: "Üretim ortamından phpinfo.php dosyasını silin. PHP yapılandırması hassas sunucu bilgisi içerir." },
  { path: "/info.php", title: "PHP bilgi sayfası (info.php) dışarıya açık", severity: "critical", remediation: "Üretim ortamından info.php dosyasını silin." },
  { path: "/test.php", title: "Test PHP dosyası dışarıya açık", severity: "high", remediation: "Test dosyalarını üretim sunucusundan kaldırın." },

  // Git deposu ifşası
  { path: "/.git/HEAD", title: "Git deposu dışarıya açık", severity: "critical", remediation: ".git dizinine web erişimini engelleyin. 'location /.git { deny all; }' kuralı ekleyin. Saldırganlar kaynak kodu tamamen indirebilir." },
  { path: "/.git/config", title: "Git yapılandırması dışarıya açık", severity: "critical", remediation: ".git dizinine web erişimini engelleyin." },
  { path: "/.gitignore", title: ".gitignore dosyası dışarıya açık", severity: "low", remediation: "Uygulama dosyası dizin yapısını ifşa edebilir; erişimi engelleyin." },

  // Yedek / sürüm dosyaları
  { path: "/backup.sql", title: "SQL yedek dosyası dışarıya açık", severity: "critical", remediation: "Veritabanı yedeklerini web kökünden kaldırın ve güvenli bir konuma taşıyın." },
  { path: "/db.sql", title: "Veritabanı dump dosyası dışarıya açık", severity: "critical", remediation: "Veritabanı dosyalarını web kökünde asla bulundurmayın." },
  { path: "/dump.sql", title: "SQL dump dosyası dışarıya açık", severity: "critical", remediation: "Veritabanı dosyalarını web kökünde asla bulundurmayın." },
  { path: "/database.sql", title: "Veritabanı dump dosyası dışarıya açık", severity: "critical", remediation: "Veritabanı dosyalarını web kökünden kaldırın." },
  { path: "/App_Data/database.mdf", title: "SQL Server veritabanı dosyası dışarıya açık", severity: "critical", remediation: "App_Data dizinine web erişimini engelleyin. Connection string ifşası riski." },
  { path: "/App_Data/aspnetdb.mdf", title: "ASP.NET membership veritabanı dışarıya açık", severity: "critical", remediation: "App_Data dizinine web erişimini engelleyin." },
  { path: "/backup.zip", title: "ZIP yedek arşivi dışarıya açık", severity: "critical", remediation: "Yedek arşivlerini web kökünden kaldırın." },
  { path: "/backup.tar.gz", title: "Tar yedek arşivi dışarıya açık", severity: "critical", remediation: "Yedek arşivlerini web kökünden kaldırın." },

  // Framework yapılandırma dosyaları
  { path: "/wp-config.php", title: "WordPress wp-config.php dışarıya açık", severity: "critical", remediation: "wp-config.php dosyasına doğrudan erişimi web sunucusu kuralıyla engelleyin." },
  { path: "/wp-config.php.bak", title: "WordPress yapılandırma yedeği dışarıya açık", severity: "critical", remediation: "Yapılandırma yedeklerini web kökünden kaldırın." },
  { path: "/config.php", title: "config.php dışarıya açık", severity: "high", remediation: "PHP yapılandırma dosyalarını web erişimine kapatın." },
  { path: "/configuration.php", title: "Joomla configuration.php dışarıya açık", severity: "critical", remediation: "configuration.php dosyasına web erişimini engelleyin." },
  { path: "/config/database.php", title: "Veritabanı yapılandırması dışarıya açık", severity: "critical", remediation: "config/ dizinini web erişimine kapatın." },
  { path: "/web.config", title: "ASP.NET web.config dışarıya açık", severity: "critical", remediation: "web.config connection string ve yapılandırma içerir. IIS'te bu dosyaya erişimi engelleyin." },
  { path: "/Web.config", title: "ASP.NET Web.config dışarıya açık", severity: "critical", remediation: "web.config connection string içerir. Web erişimini engelleyin." },
  { path: "/web.config.bak", title: "ASP.NET web.config yedeği dışarıya açık", severity: "critical", remediation: "Yapılandırma yedeklerini web kökünden kaldırın." },
  { path: "/elmah.axd", title: "ELMAH hata logu dışarıya açık", severity: "critical", remediation: "ELMAH veritabanı bağlantısı ve hata detayları ifşa eder. Üretimde devre dışı bırakın." },
  { path: "/trace.axd", title: "ASP.NET trace.axd dışarıya açık", severity: "critical", remediation: "Trace sayfası sunucu durumu ve istek detayları ifşa eder. trace enabled=\"false\" yapın." },
  { path: "/ECM", title: "ECM (Etik Kurul Yönetimi) kök dizini dışarıya açık", severity: "high", remediation: "ECM yönetim arayüzüne erişimi kısıtlayın." },
  { path: "/ECM/Admin", title: "ECM Admin paneli dışarıya açık", severity: "critical", remediation: "Yönetim panellerine IP kısıtlaması ekleyin." },
  { path: "/.htpasswd", title: ".htpasswd dosyası dışarıya açık", severity: "critical", remediation: "Apache parolalarını ifşa eder. .htpasswd dosyasına erişimi engelleyin." },
  { path: "/.htaccess", title: ".htaccess dosyası dışarıya açık", severity: "medium", remediation: "Apache güvenlik kurallarını ifşa edebilir. Erişimi engelleyin." },

  // Yönetici ve debug arayüzleri
  { path: "/admin", title: "Admin arayüzü dışarıya açık", severity: "high", remediation: "Yönetim arayüzlerine IP kısıtlaması veya VPN zorunluluğu ekleyin." },
  { path: "/phpmyadmin", title: "phpMyAdmin arayüzü dışarıya açık", severity: "critical", remediation: "phpMyAdmin'i internete açık sunucularda kapatın veya IP kısıtlaması ekleyin." },
  { path: "/pma", title: "phpMyAdmin (pma) dışarıya açık", severity: "critical", remediation: "Veritabanı yönetim arayüzüne erişimi kısıtlayın." },
  { path: "/debug", title: "Debug endpoint dışarıya açık", severity: "high", remediation: "Debug endpoint'lerini üretimde devre dışı bırakın." },
  { path: "/telescope", title: "Laravel Telescope dışarıya açık", severity: "high", remediation: "TELESCOPE_ENABLED=false ayarlayın veya IP kısıtlaması ekleyin." },
  { path: "/telescope/requests", title: "Laravel Telescope istekleri dışarıya açık", severity: "high", remediation: "Telescope'a erişimi kısıtlayın." },
  { path: "/horizon", title: "Laravel Horizon dışarıya açık", severity: "high", remediation: "Horizon'a erişimi kimlik doğrulamayla koruyun." },
  { path: "/_debugbar", title: "PHP DebugBar dışarıya açık", severity: "high", remediation: "DebugBar'ı üretimde devre dışı bırakın." },

  // Spring Boot / Java Actuator
  { path: "/actuator", title: "Spring Actuator endpoint dışarıya açık", severity: "high", remediation: "Actuator endpoint'lerini management.endpoints.web.exposure.include ile kısıtlayın." },
  { path: "/actuator/env", title: "Spring Actuator /env dışarıya açık", severity: "critical", remediation: "Ortam değişkenlerini ifşa eder. Actuator erişimini kısıtlayın." },
  { path: "/actuator/health", title: "Spring Actuator /health dışarıya açık", severity: "medium", remediation: "Uygulama sağlık bilgisini ifşa edebilir. Gerekirse erişimi kısıtlayın." },
  { path: "/actuator/mappings", title: "Spring Actuator /mappings dışarıya açık", severity: "high", remediation: "Tüm URL eşleşmelerini ifşa eder. Actuator erişimini kısıtlayın." },

  // Sunucu durum sayfaları
  { path: "/server-status", title: "Apache server-status dışarıya açık", severity: "high", remediation: "Apache'de 'Require local' kuralıyla server-status'u yalnızca localhost'a açın." },
  { path: "/server-info", title: "Apache server-info dışarıya açık", severity: "high", remediation: "Apache yapılandırma detaylarını ifşa eder. Erişimi kısıtlayın." },
  { path: "/nginx_status", title: "Nginx durum sayfası dışarıya açık", severity: "medium", remediation: "nginx_status'u yalnızca izin verilen IP'lere açın." },

  // Log dosyaları
  { path: "/storage/logs/laravel.log", title: "Laravel log dosyası dışarıya açık", severity: "high", remediation: "storage/ dizinine web erişimini engelleyin." },
  { path: "/logs/error.log", title: "Hata log dosyası dışarıya açık", severity: "high", remediation: "Log dosyalarını web kökünün dışında tutun veya erişimi engelleyin." },
  { path: "/error.log", title: "Hata log dosyası dışarıya açık", severity: "high", remediation: "Log dosyalarına web erişimini engelleyin." },
  { path: "/access.log", title: "Erişim log dosyası dışarıya açık", severity: "medium", remediation: "Log dosyalarına web erişimini engelleyin." },

  // İşletim sistemi / sistem dosyaları
  { path: "/.DS_Store", title: ".DS_Store dosyası dışarıya açık", severity: "low", remediation: "Dizin yapısını ifşa eder. .DS_Store dosyalarını sunucudan kaldırın." },

  // Composer / npm paket dosyaları
  { path: "/composer.json", title: "Composer bağımlılık dosyası dışarıya açık", severity: "medium", remediation: "Kullanılan kütüphane sürümlerini ifşa eder. Bağımlılık dosyalarına web erişimini engelleyin." },
  { path: "/composer.lock", title: "Composer lock dosyası dışarıya açık", severity: "medium", remediation: "Kesin kütüphane sürümlerini ifşa ederek bilinen zafiyetlerin hedeflenmesini kolaylaştırır." },
  { path: "/package.json", title: "package.json dosyası dışarıya açık", severity: "medium", remediation: "Node.js bağımlılıklarını ifşa eder. Bağımlılık dosyalarına web erişimini engelleyin." },

  // ASP.NET / SQL Server — ek veritabanı ve admin yolları
  { path: "/App_Data/db.mdf", title: "SQL Server veritabanı dosyası dışarıya açık", severity: "critical", remediation: "App_Data dizinine web erişimini engelleyin." },
  { path: "/ECM/EthicsCommitteesManagement", title: "ECM yönetim modülü dışarıya açık", severity: "high", remediation: "İç yönetim URL'lerini erişime kapatın." },
  { path: "/data/backup.sql", title: "Veritabanı yedeği (data/) dışarıya açık", severity: "critical", remediation: "data/ dizinine web erişimini engelleyin." },
];
