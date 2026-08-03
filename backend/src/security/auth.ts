import { timingSafeEqual } from "node:crypto";
import type { RequestHandler } from "express";

function tokensEqual(actual: string, expected: string): boolean {
  const actualBuffer = Buffer.from(actual, "utf8");
  const expectedBuffer = Buffer.from(expected, "utf8");
  return (
    actualBuffer.length === expectedBuffer.length &&
    timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

export function isBearerTokenValid(
  authorizationHeader: string | undefined,
  expectedToken: string,
): boolean {
  if (!authorizationHeader?.startsWith("Bearer ")) return false;
  const suppliedToken = authorizationHeader.slice("Bearer ".length);
  return suppliedToken.length > 0 && tokensEqual(suppliedToken, expectedToken);
}

export function createApiAuthMiddleware(expectedToken: string): RequestHandler {
  return (request, response, next) => {
    const authorization = Array.isArray(request.headers.authorization)
      ? request.headers.authorization[0]
      : request.headers.authorization;

    if (!isBearerTokenValid(authorization, expectedToken)) {
      response.setHeader("WWW-Authenticate", "Bearer");
      response.status(401).json({ message: "Authentication required." });
      return;
    }

    next();
  };
}
