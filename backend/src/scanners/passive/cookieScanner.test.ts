import assert from "node:assert/strict";
import test from "node:test";
import { Headers } from "undici";
import { runCookieScanner } from "./cookieScanner.js";

test("cookie bulgusu yalnız adı ve güvenlik bayraklarını taşır", () => {
  const cookieName = "random_cookie_name_7";
  const opaqueValue = "synthetic-opaque-cookie-value-581";
  const headers = new Headers({
    "set-cookie": `${cookieName}=${opaqueValue}; Secure; SameSite=Strict; Path=/private`,
  });

  const findings = runCookieScanner(headers, "https://example.test/path");

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.id, `cookie-without-httponly-${cookieName}`);
  assert.equal(
    findings[0]?.evidence,
    `Cookie: ${cookieName}; Secure=present; HttpOnly=missing; SameSite=Strict`,
  );
  const serialized = JSON.stringify(findings);
  assert.equal(serialized.includes(opaqueValue), false);
  assert.equal(serialized.includes("/private"), false);
});
