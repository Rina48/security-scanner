import assert from "node:assert/strict";
import test from "node:test";
import { authorizeScanRequest, scanRequestSchema } from "./scanRequestPolicy.js";

test("istemcinin eski demo bayrağı şema tarafından reddedilir", () => {
  assert.throws(() =>
    scanRequestSchema.parse({
      targetUrl: "https://example.com",
      mode: "active",
      demoOmuActive: true,
    }),
  );
});

test("allowlist dışı aktif tarama ağ çağrısından önce 403 kararı alır", () => {
  const denied = authorizeScanRequest(
    { targetUrl: "https://example.com", mode: "active" },
    {},
  );
  assert.deepEqual(denied, {
    allowed: false,
    status: 403,
    message: "Active scan target is not authorized.",
  });

  assert.deepEqual(
    authorizeScanRequest(
      { targetUrl: "https://example.com", mode: "active" },
      { ALLOWED_ACTIVE_HOSTS: "example.com" },
    ),
    { allowed: true },
  );
});

test("URL userinfo şema seviyesinde secret'ı hata metnine taşımadan reddedilir", () => {
  const userInfoSecret = "synthetic-schema-userinfo-value-136";
  const result = scanRequestSchema.safeParse({
    targetUrl: `https://synthetic-user:${userInfoSecret}@example.test/path`,
    mode: "passive",
  });

  assert.equal(result.success, false);
  if (result.success) return;
  const issues = JSON.stringify(result.error.issues);
  assert.match(issues, /URL userinfo is not allowed/);
  assert.equal(issues.includes(userInfoSecret), false);
});
