import assert from "node:assert/strict";
import test from "node:test";
import { loadServerConfig } from "./serverConfig.js";

const VALID_ENV = { SECURITY_SCANNER_API_TOKEN: "t".repeat(32) };

test("sunucu varsayılan olarak yalnızca IPv4 loopback'e bind olur", () => {
  const config = loadServerConfig(VALID_ENV);
  assert.equal(config.bindHost, "127.0.0.1");
});

test("token eksik veya kısa olduğunda başlangıç fail-closed olur", () => {
  assert.throws(() => loadServerConfig({}), /SECURITY_SCANNER_API_TOKEN/);
  assert.throws(
    () => loadServerConfig({ SECURITY_SCANNER_API_TOKEN: "short" }),
    /en az 32/,
  );
});

test("probe varsayılan olarak kapalıdır ve yalnız açık konfigürasyonla açılır", () => {
  assert.equal(loadServerConfig(VALID_ENV).probeEnabled, false);
  assert.equal(
    loadServerConfig({ ...VALID_ENV, SECURITY_SCANNER_PROBE_ENABLED: "true" }).probeEnabled,
    true,
  );
  assert.equal(
    loadServerConfig({ ...VALID_ENV, SECURITY_SCANNER_PROBE_ENABLED: "TRUE" }).probeEnabled,
    false,
  );
});
