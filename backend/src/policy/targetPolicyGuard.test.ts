import assert from "node:assert/strict";
import test from "node:test";
import { isActiveScanAllowed } from "./targetPolicyGuard.js";

const ENV = { ALLOWED_ACTIVE_HOSTS: "Example.COM.,127.0.0.1" };

test("aktif tarama allowlist'i yalnızca exact normalized hostname kabul eder", () => {
  assert.equal(isActiveScanAllowed("https://example.com/path", "active", ENV), true);
  assert.equal(isActiveScanAllowed("http://127.0.0.1:8080", "active", ENV), true);
  assert.equal(isActiveScanAllowed("https://sub.example.com", "active", ENV), false);
  assert.equal(isActiveScanAllowed("https://example.com.evil.test", "active", ENV), false);
  assert.equal(isActiveScanAllowed("https://evil-example.com", "active", ENV), false);
  assert.equal(isActiveScanAllowed("https://user@example.com", "active", ENV), false);
  assert.equal(isActiveScanAllowed("https://example.com", "passive", ENV), false);
});
