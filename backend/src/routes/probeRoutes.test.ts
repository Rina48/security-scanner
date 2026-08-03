import assert from "node:assert/strict";
import test from "node:test";
import type { NextFunction } from "express";
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
