import assert from "node:assert/strict";
import test from "node:test";
import { Headers } from "undici";
import { safeFetchText, type EgressResolver } from "./egressPolicy.js";
import {
  createScanResourceManager,
  DEFAULT_RESOURCE_LIMITS,
  ResourceLimitError,
  type ResourceLimitConfig,
} from "./resourceLimits.js";

function limits(
  overrides: Partial<ResourceLimitConfig> = {},
): ResourceLimitConfig {
  return { ...DEFAULT_RESOURCE_LIMITS, ...overrides };
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason?: unknown): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test("global scheduler eşzamanlı ve bekleyen tarama sayılarını kesin sınırlar", async () => {
  const resources = createScanResourceManager(limits({
    maxConcurrentScans: 1,
    maxQueuedScans: 1,
  }));
  const firstGate = deferred<string>();
  const first = resources.runScan(() => firstGate.promise);
  const second = resources.runScan(async () => "second");

  assert.equal(resources.activeScanCount, 1);
  assert.equal(resources.queuedScanCount, 1);
  assert.throws(
    () => resources.runScan(async () => "third"),
    (error) => error instanceof ResourceLimitError
      && error.code === "scan-capacity"
      && error.statusCode === 503,
  );
  assert.equal(resources.queuedScanCount, 1);

  firstGate.resolve("first");
  assert.equal(await first, "first");
  assert.equal(await second, "second");
  assert.equal(resources.activeScanCount, 0);
  assert.equal(resources.queuedScanCount, 0);
});

test("kuyrukta iptal edilen tarama çalıştırılmaz ve kapasiteyi hemen bırakır", async () => {
  const resources = createScanResourceManager(limits({
    maxConcurrentScans: 1,
    maxQueuedScans: 1,
  }));
  const firstGate = deferred<void>();
  const first = resources.runScan(() => firstGate.promise);
  const controller = new AbortController();
  let queuedStarted = false;
  const queued = resources.runScan(async () => {
    queuedStarted = true;
  }, controller.signal);

  controller.abort(new DOMException("cancelled", "AbortError"));
  await assert.rejects(queued, { name: "AbortError" });
  assert.equal(resources.queuedScanCount, 0);
  assert.equal(queuedStarted, false);

  firstGate.resolve();
  await first;
  assert.equal(resources.activeScanCount, 0);
});

test("tarama başlangıç rate limit'i 429 ve Retry-After üretir", () => {
  let now = 0;
  const resources = createScanResourceManager(limits({
    scanRateLimitMax: 2,
    scanRateLimitWindowMs: 1_000,
  }), () => now);

  resources.assertScanStartAllowed();
  resources.assertScanStartAllowed();
  assert.throws(
    () => resources.assertScanStartAllowed(),
    (error) => error instanceof ResourceLimitError
      && error.code === "scan-rate-limit"
      && error.statusCode === 429
      && error.retryAfterSeconds === 1,
  );

  now = 1_000;
  assert.doesNotThrow(() => resources.assertScanStartAllowed());
});

test("tarama başına hedef istek bütçesi ağ çağrılarını üst sınırda keser", async () => {
  const resources = createScanResourceManager(limits({ maxRequestsPerScan: 2 }));
  const resolver: EgressResolver = async () => [
    { address: "93.184.216.34", family: 4 },
  ];
  let requestCalls = 0;

  await assert.rejects(
    resources.runScan(async () => {
      for (let index = 0; index < 3; index += 1) {
        await safeFetchText("https://budget.example", {}, {
          access: "passive",
          resolver,
          request: async () => {
            requestCalls += 1;
            return {
              status: 200,
              headers: new Headers(),
              async text() {
                return "ok";
              },
            };
          },
        });
      }
    }),
    (error) => error instanceof ResourceLimitError
      && error.code === "request-budget",
  );
  assert.equal(requestCalls, 2);
});
