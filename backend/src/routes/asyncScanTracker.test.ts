import assert from "node:assert/strict";
import test from "node:test";
import {
  createScanResourceManager,
  DEFAULT_RESOURCE_LIMITS,
  ResourceLimitError,
  type ResourceLimitConfig,
} from "../security/resourceLimits.js";
import type { ScanResult } from "../types.js";
import { createAsyncScanTracker } from "./asyncScanTracker.js";

function limits(
  overrides: Partial<ResourceLimitConfig> = {},
): ResourceLimitConfig {
  return { ...DEFAULT_RESOURCE_LIMITS, ...overrides };
}

function report(scanId = "async-test"): ScanResult {
  return {
    scanId,
    targetUrl: "https://example.test",
    mode: "passive",
    isActiveAllowed: false,
    score: 0,
    findings: [],
    executiveSummary: {
      riskLevel: "clean",
      headline: "clean",
      businessRisk: "none",
      immediateActions: [],
      findingCounts: { critical: 0, high: 0, medium: 0, low: 0 },
    },
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
  };
}

async function waitUntil(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("Koşul zamanında sağlanmadı.");
    await new Promise<void>((resolve) => setTimeout(resolve, 5));
  }
}

test("asenkron iş kapasitesi aşılmaz ve tamamlanan kayıt hemen temizlenir", async () => {
  const resources = createScanResourceManager(limits({
    maxAsyncJobs: 1,
    maxConcurrentScans: 1,
    maxQueuedScans: 1,
  }));
  let complete!: (value: ScanResult) => void;
  const scanResult = new Promise<ScanResult>((resolve) => {
    complete = resolve;
  });
  const saved: ScanResult[] = [];
  const tracker = createAsyncScanTracker(resources, {
    runScan: async () => scanResult,
    saveScanResult: (value) => saved.push(value),
  });

  const first = tracker.start({ targetUrl: "https://example.test", mode: "passive" });
  assert.equal(tracker.size, 1);
  assert.ok(tracker.get(first.scanId));
  assert.throws(
    () => tracker.start({ targetUrl: "https://second.test", mode: "passive" }),
    (error) => error instanceof ResourceLimitError
      && error.code === "async-capacity"
      && error.statusCode === 503,
  );
  assert.equal(tracker.size, 1);

  complete(report(first.scanId));
  await waitUntil(() => tracker.size === 0);
  assert.equal(saved.length, 1);
  assert.equal(tracker.get(first.scanId), undefined);
  tracker.dispose();
});

test("başarısız asenkron iş kaydı kapasiteyi serbest bırakır", async () => {
  const resources = createScanResourceManager(limits({ maxAsyncJobs: 1 }));
  let loggedErrors = 0;
  const tracker = createAsyncScanTracker(resources, {
    logError: () => {
      loggedErrors += 1;
    },
    runScan: async () => {
      throw new Error("synthetic failure");
    },
    saveScanResult: () => {
      throw new Error("Başarısız tarama kaydedilmemeli.");
    },
  });

  const started = tracker.start({ targetUrl: "https://example.test", mode: "passive" });
  await waitUntil(() => tracker.size === 0);
  assert.equal(tracker.get(started.scanId), undefined);
  assert.equal(loggedErrors, 1);
  tracker.dispose();
});

test("TTL eski asenkron işi abort eder ve bellek kaydını siler", async () => {
  const resources = createScanResourceManager(limits({
    asyncJobTtlMs: 25,
    maxAsyncJobs: 1,
  }));
  let capturedSignal: AbortSignal | undefined;
  let saveCalls = 0;
  const tracker = createAsyncScanTracker(resources, {
    runScan: async (_request, options) => {
      capturedSignal = options?.signal;
      assert.ok(capturedSignal);
      return new Promise((_resolve, reject) => {
        capturedSignal?.addEventListener(
          "abort",
          () => reject(capturedSignal?.reason),
          { once: true },
        );
      });
    },
    saveScanResult: () => {
      saveCalls += 1;
    },
  });

  const started = tracker.start({ targetUrl: "https://example.test", mode: "passive" });
  await waitUntil(() => tracker.size === 0);
  assert.equal(capturedSignal?.aborted, true);
  assert.equal(tracker.get(started.scanId), undefined);
  assert.equal(saveCalls, 0);
  tracker.dispose();
});
