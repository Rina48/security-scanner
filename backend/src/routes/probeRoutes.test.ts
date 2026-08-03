import assert from "node:assert/strict";
import test from "node:test";
import type { NextFunction } from "express";
import { Headers } from "undici";
import {
  createScanResourceManager,
  DEFAULT_RESOURCE_LIMITS,
} from "../security/resourceLimits.js";
import { createProbeHandler } from "./probeRoutes.js";
import { createMockRequest, createMockResponse } from "../testing/expressMocks.js";

test("sahte X-Forwarded-For loopback olmayan probe istemcisine erişim sağlamaz", async () => {
  let fetchCalls = 0;
  const handler = createProbeHandler(async () => {
    fetchCalls += 1;
    throw new Error("Fetch çağrılmamalı");
  });
  const { response, recorder } = createMockResponse();

  await handler(
    createMockRequest({
      remoteAddress: "203.0.113.10",
      forwardedFor: "127.0.0.1",
      body: { targetUrl: "https://example.com" },
    }),
    response,
    (() => undefined) as NextFunction,
  );

  assert.equal(recorder.statusCode, 403);
  assert.equal(fetchCalls, 0);
});

test("probe rotası ortak tarama rate limit'ini aşınca 429 döndürür", async () => {
  const resources = createScanResourceManager({
    ...DEFAULT_RESOURCE_LIMITS,
    scanRateLimitMax: 1,
  });
  const handler = createProbeHandler(async () => ({
    status: 200,
    headers: new Headers(),
    body: "ok",
    url: "http://127.0.0.1",
  }), resources);
  const next = (() => undefined) as NextFunction;
  const request = createMockRequest({
    remoteAddress: "127.0.0.1",
    body: { targetUrl: "http://fixture.test" },
  });

  const accepted = createMockResponse();
  await handler(request, accepted.response, next);
  assert.equal(accepted.recorder.statusCode, 200);

  const limited = createMockResponse();
  await handler(request, limited.response, next);
  assert.equal(limited.recorder.statusCode, 429);
  assert.deepEqual(limited.recorder.body, {
    code: "scan-rate-limit",
    message: "Çok fazla tarama isteği gönderildi. Daha sonra tekrar deneyin.",
  });
});

test("probe userinfo içeren URL'yi fetch çağrısından önce reddeder", async () => {
  const userInfoSecret = "synthetic-probe-userinfo-value-247";
  let fetchCalls = 0;
  const handler = createProbeHandler(async () => {
    fetchCalls += 1;
    throw new Error("Fetch çağrılmamalı");
  });
  const { response, recorder } = createMockResponse();

  await handler(
    createMockRequest({
      remoteAddress: "127.0.0.1",
      body: {
        targetUrl: `https://synthetic-user:${userInfoSecret}@example.test/path`,
      },
    }),
    response,
    (() => undefined) as NextFunction,
  );

  assert.equal(recorder.statusCode, 400);
  assert.equal(fetchCalls, 0);
  assert.equal(JSON.stringify(recorder.body).includes(userInfoSecret), false);
});
