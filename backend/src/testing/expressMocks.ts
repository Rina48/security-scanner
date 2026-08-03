import type { Request, Response } from "express";

export interface ResponseRecorder {
  statusCode: number;
  body: unknown;
  headers: Map<string, string>;
}

export function createMockResponse(): {
  response: Response;
  recorder: ResponseRecorder;
} {
  const recorder: ResponseRecorder = {
    statusCode: 200,
    body: undefined,
    headers: new Map(),
  };
  const responseObject: {
    setHeader(name: string, value: number | string | readonly string[]): unknown;
    status(code: number): unknown;
    json(body: unknown): unknown;
  } = {
    setHeader(name, value) {
      recorder.headers.set(name.toLowerCase(), String(value));
      return responseObject;
    },
    status(code) {
      recorder.statusCode = code;
      return responseObject;
    },
    json(body) {
      recorder.body = body;
      return responseObject;
    },
  };

  return { response: responseObject as unknown as Response, recorder };
}

export function createMockRequest(input?: {
  authorization?: string;
  origin?: string;
  remoteAddress?: string;
  forwardedFor?: string;
  body?: unknown;
}): Request {
  return {
    headers: {
      ...(input?.authorization ? { authorization: input.authorization } : {}),
      ...(input?.origin ? { origin: input.origin } : {}),
      ...(input?.forwardedFor ? { "x-forwarded-for": input.forwardedFor } : {}),
    },
    socket: { remoteAddress: input?.remoteAddress },
    body: input?.body,
  } as unknown as Request;
}
