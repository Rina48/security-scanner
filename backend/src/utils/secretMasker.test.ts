import assert from "node:assert/strict";
import test from "node:test";
import { assertUrlHasNoUserInfo, maskSecrets } from "./secretMasker.js";

test("hassas query değerleri case ve encoded anahtarlarla atlatılamaz", () => {
  const secrets = [
    "opaque-token-value-a1",
    "opaque-key-value-b2",
    "opaque-access-value-c3",
    "opaque-password-value-d4",
    "opaque-secret-value-e5",
    "opaque-session-value-f6",
  ];
  const input = [
    "https://example.test/scan?ToKeN=" + secrets[0],
    "API_KEY=" + secrets[1],
    "%61ccess%5Ftoken=" + secrets[2],
    "PaSsWoRd=" + secrets[3],
    "secret=" + secrets[4],
    "SESSION=" + secrets[5],
    "page=2",
  ].join("&");

  const masked = maskSecrets(input);

  for (const secret of secrets) assert.equal(masked.includes(secret), false);
  assert.match(masked, /ToKeN=REDACTED/);
  assert.match(masked, /API_KEY=REDACTED/);
  assert.match(masked, /%61ccess%5Ftoken=REDACTED/);
  assert.match(masked, /page=2/);
});

test("hassas olmayan URL aynı kalır", () => {
  const normalUrl = "https://example.test/search?q=security&page=2&sort=desc";
  assert.equal(maskSecrets(normalUrl), normalUrl);
});

test("opaque credential header değerleri biçimlerinden bağımsız maskelenir", () => {
  const opaqueCookie = "random-looking-cookie-value-741";
  const opaqueAuthorization = "random-looking-authorization-value-852";
  const opaqueApiKey = "random-looking-api-key-value-963";
  const input = [
    `Authorization: Bearer ${opaqueAuthorization}`,
    `Cookie: random_cookie_name=${opaqueCookie}; theme=light`,
    `X-Api-Key: ${opaqueApiKey}`,
  ].join("\n");

  const masked = maskSecrets(input);

  assert.equal(masked.includes(opaqueCookie), false);
  assert.equal(masked.includes(opaqueAuthorization), false);
  assert.equal(masked.includes(opaqueApiKey), false);
  assert.equal((masked.match(/\[REDACTED\]/g) ?? []).length, 3);
  assert.equal(maskSecrets(masked), masked);
});

test("JWT büyük bölümü korunmadan sabit işaretle değiştirilir", () => {
  const jwt = [
    "eyJhbGciOiJIUzI1NiJ9",
    "eyJzdWIiOiJzeW50aGV0aWMtdGVzdCJ9",
    "syntheticSignatureValue1234567890",
  ].join(".");
  const masked = maskSecrets(`Bearer ${jwt}`);

  assert.equal(masked.includes(jwt), false);
  assert.equal(masked.includes("eyJzdWIiOiJzeW50aGV0aWMtdGVzdCJ9"), false);
  assert.match(masked, /\[JWT-REDACTED\]/);
});

test("URL userinfo güvenli hata ile reddedilir ve rapor metninden çıkarılır", () => {
  const userInfoValue = "synthetic-userinfo-value-159";
  const url = `https://synthetic-user:${userInfoValue}@example.test/path`;

  assert.throws(() => assertUrlHasNoUserInfo(url), /URL userinfo is not allowed/);
  const masked = maskSecrets(`Endpoint: ${url}`);
  assert.equal(masked.includes(userInfoValue), false);
  assert.match(masked, /https:\/\/example\.test\/path/);
});
