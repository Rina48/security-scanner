import assert from "node:assert/strict";
import test from "node:test";
import { DEFAULT_RESOURCE_LIMITS } from "./resourceLimits.js";
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

test("kaynak limitleri güvenli varsayılanlarla yüklenir ve environment ile değişir", () => {
  assert.deepEqual(loadServerConfig(VALID_ENV).resourceLimits, DEFAULT_RESOURCE_LIMITS);

  const config = loadServerConfig({
    ...VALID_ENV,
    SECURITY_SCANNER_MAX_CONCURRENT_SCANS: "3",
    SECURITY_SCANNER_MAX_QUEUED_SCANS: "4",
    SECURITY_SCANNER_MAX_ASYNC_JOBS: "5",
    SECURITY_SCANNER_RATE_LIMIT_MAX: "6",
    SECURITY_SCANNER_RATE_LIMIT_WINDOW_MS: "7000",
    SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES: "8000",
    SECURITY_SCANNER_MAX_REQUESTS_PER_SCAN: "9",
    SECURITY_SCANNER_ASYNC_JOB_TTL_MS: "10000",
  });
  assert.deepEqual(config.resourceLimits, {
    maxConcurrentScans: 3,
    maxQueuedScans: 4,
    maxAsyncJobs: 5,
    scanRateLimitMax: 6,
    scanRateLimitWindowMs: 7_000,
    maxResponseBodyBytes: 8_000,
    maxRequestsPerScan: 9,
    asyncJobTtlMs: 10_000,
  });
});

test("geçersiz kaynak limiti sunucu başlangıcını fail-closed durdurur", () => {
  for (const value of ["-1", "1.5", "unlimited", "2147483648"]) {
    assert.throws(
      () => loadServerConfig({
        ...VALID_ENV,
        SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES: value,
      }),
      /SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES/,
    );
  }
});
