import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import type { Express, Request, Response } from "express";
import { Headers } from "undici";
import type { ScanResult } from "../types.js";
import { runCookieScanner } from "../scanners/passive/cookieScanner.js";
import {
  createScanResourceManager,
  DEFAULT_RESOURCE_LIMITS,
} from "../security/resourceLimits.js";
import {
  registerScanRoutes,
  type ScanRouteDependencies,
} from "./scanRoutes.js";

type ScanPostHandler = (request: Request, response: Response) => Promise<void>;

class MockRequest extends EventEmitter {
  aborted = false;
  body: unknown;

  constructor(body: unknown) {
    super();
    this.body = body;
  }
}

class MockResponse extends EventEmitter {
  body: unknown;
  destroyed = false;
  headers = new Map<string, string>();
  headersSent = false;
  statusCode = 200;
  writableEnded = false;

  status(code: number): this {
    this.statusCode = code;
    return this;
  }

  setHeader(name: string, value: string | number | readonly string[]): this {
    this.headers.set(name.toLowerCase(), String(value));
    return this;
  }

  json(body: unknown): this {
    this.body = body;
    this.headersSent = true;
    this.writableEnded = true;
    this.emit("finish");
    return this;
  }
}

function captureScanPostHandler(
  dependencies: ScanRouteDependencies,
): ScanPostHandler {
  let handler: ScanPostHandler | undefined;
  const app: Record<string, unknown> = {};
  const registerNoop = (): typeof app => app;
  app.get = registerNoop;
  app.delete = registerNoop;
  app.post = (path: string, routeHandler: ScanPostHandler): typeof app => {
    if (path === "/api/scans") handler = routeHandler;
    return app;
  };

  registerScanRoutes(app as unknown as Express, dependencies);
  assert.ok(handler);
  return handler;
}

function completedReport(): ScanResult {
  return {
    scanId: "scan-test-id",
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

function requestBody(useAsync = false): unknown {
  return {
    targetUrl: "https://example.test",
    mode: "passive",
    async: useAsync,
  };
}

test("synchronous client disconnect aborts runScan and does not save history", async () => {
  let capturedSignal: AbortSignal | undefined;
  let saveCalls = 0;
  let markStarted: (() => void) | undefined;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const handler = captureScanPostHandler({
    runScan: async (_scanRequest, options) => {
      capturedSignal = options?.signal;
      assert.ok(capturedSignal);
      markStarted?.();
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
  const request = new MockRequest(requestBody());
  const response = new MockResponse();

  const route = handler(
    request as unknown as Request,
    response as unknown as Response,
  );
  await started;
  response.destroyed = true;
  response.emit("close");
  await route;

  assert.equal(capturedSignal?.aborted, true);
  assert.equal(saveCalls, 0);
  assert.equal(request.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
});

test("already disconnected synchronous request does not start or save a scan", async () => {
  let scanStarts = 0;
  let saveCalls = 0;
  const handler = captureScanPostHandler({
    runScan: async () => {
      scanStarts += 1;
      return completedReport();
    },
    saveScanResult: () => {
      saveCalls += 1;
    },
  });
  const request = new MockRequest(requestBody());
  request.aborted = true;
  const response = new MockResponse();

  await handler(
    request as unknown as Request,
    response as unknown as Response,
  );

  assert.equal(scanStarts, 0);
  assert.equal(saveCalls, 0);
  assert.equal(response.headersSent, false);
  assert.equal(request.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
});

test("normal synchronous completion does not abort its request signal", async () => {
  const report = completedReport();
  let capturedSignal: AbortSignal | undefined;
  let savedReport: ScanResult | undefined;
  const handler = captureScanPostHandler({
    runScan: async (_scanRequest, options) => {
      capturedSignal = options?.signal;
      return report;
    },
    saveScanResult: (result) => {
      savedReport = result;
    },
  });
  const request = new MockRequest(requestBody());
  const response = new MockResponse();

  await handler(
    request as unknown as Request,
    response as unknown as Response,
  );
  response.emit("close");

  assert.equal(capturedSignal?.aborted, false);
  assert.deepEqual(savedReport, report);
  assert.equal(response.statusCode, 201);
  assert.deepEqual(response.body, report);
  assert.equal(request.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
});

test("API cevabı ve kaydedilecek geçmiş tüm rapor alanlarını redact eder", async () => {
  const cookieName = "random_api_cookie_9";
  const cookieSecret = "synthetic-api-cookie-value-814";
  const querySecret = "synthetic-api-query-value-925";
  const cookieFinding = runCookieScanner(
    new Headers({
      "set-cookie": `${cookieName}=${cookieSecret}; Secure; SameSite=None; Path=/private`,
    }),
    `https://example.test/path?token=${querySecret}`,
  )[0];
  assert.ok(cookieFinding);

  const report = completedReport();
  report.targetUrl = `https://example.test/path?token=${querySecret}&page=2`;
  report.findings = [{
    ...cookieFinding,
    title: `Finding password=${querySecret}`,
    evidence: `${cookieFinding.evidence}\nsecret=${querySecret}`,
    remediation: `Use https://example.test/help?api_key=${querySecret}`,
    endpoint: `https://example.test/path?access_token=${querySecret}`,
  }];
  report.executiveSummary = {
    ...report.executiveSummary,
    headline: `Review https://example.test/path?session=${querySecret}`,
    businessRisk: `Cookie: ${cookieName}=${cookieSecret}; Secure`,
    immediateActions: [`Authorization: Bearer ${querySecret}`],
  };

  let savedReport: ScanResult | undefined;
  const handler = captureScanPostHandler({
    runScan: async () => report,
    saveScanResult: (result) => {
      savedReport = result;
    },
  });
  const response = new MockResponse();

  await handler(
    new MockRequest(requestBody()) as unknown as Request,
    response as unknown as Response,
  );

  const apiPayload = JSON.stringify(response.body);
  const historyPayload = JSON.stringify(savedReport);
  for (const payload of [apiPayload, historyPayload]) {
    assert.equal(payload.includes(cookieSecret), false);
    assert.equal(payload.includes(querySecret), false);
    assert.match(payload, new RegExp(cookieName));
    assert.match(payload, /Secure=present/);
    assert.match(payload, /HttpOnly=missing/);
    assert.match(payload, /SameSite=None/);
    assert.match(payload, /page=2/);
  }
  assert.equal(response.statusCode, 201);
});

test("background scan is not coupled to the initiating client connection", async () => {
  let backgroundStarts = 0;
  let synchronousStarts = 0;
  const handler = captureScanPostHandler({
    runScan: async () => {
      synchronousStarts += 1;
      return completedReport();
    },
    startBackgroundScan: () => {
      backgroundStarts += 1;
      return {
        scanId: "background-scan-id",
        startedAt: "2026-01-01T00:00:00.000Z",
      };
    },
  });
  const request = new MockRequest(requestBody(true));
  const response = new MockResponse();

  await handler(
    request as unknown as Request,
    response as unknown as Response,
  );
  response.destroyed = true;
  response.emit("close");

  assert.equal(backgroundStarts, 1);
  assert.equal(synchronousStarts, 0);
  assert.equal(response.statusCode, 202);
  assert.equal(request.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
});

test("eşzamanlı tarama kapasitesi doluyken yeni tarama 503 ile reddedilir", async () => {
  const resources = createScanResourceManager({
    ...DEFAULT_RESOURCE_LIMITS,
    maxConcurrentScans: 1,
    maxQueuedScans: 0,
    scanRateLimitMax: 10,
  });
  let releaseFirst!: () => void;
  let firstStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    firstStarted = resolve;
  });
  const firstGate = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let scanStarts = 0;
  const handler = captureScanPostHandler({
    resources,
    runScan: async () => {
      scanStarts += 1;
      firstStarted();
      await firstGate;
      return completedReport();
    },
    saveScanResult: () => undefined,
  });

  const firstResponse = new MockResponse();
  const first = handler(
    new MockRequest(requestBody()) as unknown as Request,
    firstResponse as unknown as Response,
  );
  await started;

  const rejectedResponse = new MockResponse();
  await handler(
    new MockRequest(requestBody()) as unknown as Request,
    rejectedResponse as unknown as Response,
  );
  assert.equal(rejectedResponse.statusCode, 503);
  assert.deepEqual(rejectedResponse.body, {
    code: "scan-capacity",
    message: "Tarama kapasitesi dolu. Daha sonra tekrar deneyin.",
  });
  assert.equal(scanStarts, 1);

  releaseFirst();
  await first;
  assert.equal(firstResponse.statusCode, 201);
});

test("tarama başlangıç rate limit'i rota seviyesinde 429 döndürür", async () => {
  const resources = createScanResourceManager({
    ...DEFAULT_RESOURCE_LIMITS,
    scanRateLimitMax: 1,
    scanRateLimitWindowMs: 60_000,
  });
  const handler = captureScanPostHandler({
    resources,
    runScan: async () => completedReport(),
    saveScanResult: () => undefined,
  });

  const acceptedResponse = new MockResponse();
  await handler(
    new MockRequest(requestBody()) as unknown as Request,
    acceptedResponse as unknown as Response,
  );
  assert.equal(acceptedResponse.statusCode, 201);

  const limitedResponse = new MockResponse();
  await handler(
    new MockRequest(requestBody()) as unknown as Request,
    limitedResponse as unknown as Response,
  );
  assert.equal(limitedResponse.statusCode, 429);
  assert.equal(limitedResponse.headers.get("retry-after"), "60");
  assert.deepEqual(limitedResponse.body, {
    code: "scan-rate-limit",
    message: "Çok fazla tarama isteği gönderildi. Daha sonra tekrar deneyin.",
  });
});
