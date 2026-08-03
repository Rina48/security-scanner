import assert from "node:assert/strict";
import test from "node:test";
import { logRedactedError } from "./safeLogging.js";

test("backend hata logu query, authorization ve opaque cookie değerlerini yazmaz", () => {
  const querySecret = "synthetic-log-query-value-258";
  const authorizationSecret = "synthetic-log-auth-value-369";
  const cookieSecret = "synthetic-log-cookie-value-470";
  const captured: string[] = [];
  const originalConsoleError = console.error;
  console.error = (...values: unknown[]) => {
    captured.push(values.map(String).join(" "));
  };

  try {
    logRedactedError(
      "[synthetic-test] request failed:",
      new Error(
        `https://example.test/path?access_token=${querySecret}\n`
        + `Authorization: Bearer ${authorizationSecret}\n`
        + `Set-Cookie: random_cookie_name=${cookieSecret}; Secure; HttpOnly`,
      ),
    );
  } finally {
    console.error = originalConsoleError;
  }

  const output = captured.join("\n");
  assert.equal(output.includes(querySecret), false);
  assert.equal(output.includes(authorizationSecret), false);
  assert.equal(output.includes(cookieSecret), false);
  assert.match(output, /access_token=REDACTED/);
  assert.match(output, /Set-Cookie: \[REDACTED\]/);
});
