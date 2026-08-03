import assert from "node:assert/strict";
import test from "node:test";
import type { NextFunction } from "express";
import { createApiAuthMiddleware } from "./auth.js";
import { createMockRequest, createMockResponse } from "../testing/expressMocks.js";

const API_TOKEN = "t".repeat(32);

test("tokensız hassas API çağrısı 401 döner", () => {
  const middleware = createApiAuthMiddleware(API_TOKEN);
  const { response, recorder } = createMockResponse();
  let nextCalled = false;

  middleware(createMockRequest(), response, (() => {
    nextCalled = true;
  }) as NextFunction);

  assert.equal(recorder.statusCode, 401);
  assert.equal(recorder.headers.get("www-authenticate"), "Bearer");
  assert.equal(nextCalled, false);
});

test("geçersiz token 401, doğru token sonraki middleware'e geçer", () => {
  const middleware = createApiAuthMiddleware(API_TOKEN);
  const invalid = createMockResponse();
  middleware(
    createMockRequest({ authorization: `Bearer ${"x".repeat(32)}` }),
    invalid.response,
    (() => assert.fail("Geçersiz token next çağırmamalı")) as NextFunction,
  );
  assert.equal(invalid.recorder.statusCode, 401);

  const valid = createMockResponse();
  let nextCalled = false;
  middleware(
    createMockRequest({ authorization: `Bearer ${API_TOKEN}` }),
    valid.response,
    (() => {
      nextCalled = true;
    }) as NextFunction,
  );
  assert.equal(valid.recorder.statusCode, 200);
  assert.equal(nextCalled, true);
});
