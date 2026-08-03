import assert from "node:assert/strict";
import test from "node:test";
import type { NextFunction } from "express";
import { createOriginGuard } from "./corsPolicy.js";
import { createMockRequest, createMockResponse } from "../testing/expressMocks.js";

test("bilinmeyen browser Origin reddedilir", () => {
  const guard = createOriginGuard(new Set(["http://localhost:5173"]));
  const { response, recorder } = createMockResponse();
  let nextCalled = false;

  guard(
    createMockRequest({ origin: "https://attacker.example" }),
    response,
    (() => {
      nextCalled = true;
    }) as NextFunction,
  );

  assert.equal(recorder.statusCode, 403);
  assert.equal(recorder.headers.has("access-control-allow-origin"), false);
  assert.equal(nextCalled, false);
});

test("allowlist Origin ve Origin başlığı olmayan CLI çağrısı kabul edilir", () => {
  const guard = createOriginGuard(new Set(["http://localhost:5173"]));
  for (const request of [
    createMockRequest({ origin: "http://localhost:5173" }),
    createMockRequest(),
  ]) {
    const { response } = createMockResponse();
    let nextCalled = false;
    guard(request, response, (() => {
      nextCalled = true;
    }) as NextFunction);
    assert.equal(nextCalled, true);
  }
});
