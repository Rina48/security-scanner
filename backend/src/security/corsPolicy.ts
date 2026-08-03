import type { RequestHandler } from "express";
import type { CorsOptions } from "cors";

function normalizeRequestOrigin(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

export function isOriginAllowed(
  origin: string | undefined,
  allowedOrigins: ReadonlySet<string>,
): boolean {
  if (origin === undefined) return true;
  const normalized = normalizeRequestOrigin(origin);
  return normalized !== null && allowedOrigins.has(normalized);
}

export function createOriginGuard(
  allowedOrigins: ReadonlySet<string>,
): RequestHandler {
  return (request, response, next) => {
    const origin = Array.isArray(request.headers.origin)
      ? request.headers.origin[0]
      : request.headers.origin;

    if (!isOriginAllowed(origin, allowedOrigins)) {
      response.status(403).json({ message: "Origin is not allowed." });
      return;
    }

    next();
  };
}

export function createCorsOptions(
  allowedOrigins: ReadonlySet<string>,
): CorsOptions {
  return {
    origin(origin, callback) {
      if (!origin) {
        callback(null, false);
        return;
      }

      const normalized = normalizeRequestOrigin(origin);
      callback(null, normalized !== null && allowedOrigins.has(normalized) ? normalized : false);
    },
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["authorization", "content-type"],
    credentials: false,
    maxAge: 600,
  };
}
