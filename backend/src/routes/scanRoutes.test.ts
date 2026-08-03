import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import type { Express, Request, Response } from "express";
import type { ScanResult } from "../types.js";
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
  headersSent = false;
  statusCode = 200;
  writableEnded = false;

  status(code: number): this {
    this.statusCode = code;
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
  assert.equal(savedReport, report);
  assert.equal(response.statusCode, 201);
  assert.equal(response.body, report);
  assert.equal(request.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
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
