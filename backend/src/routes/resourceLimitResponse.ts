import type { Response } from "express";
import type { ResourceLimitError } from "../security/resourceLimits.js";

export function sendResourceLimitResponse(
  response: Response,
  error: ResourceLimitError,
): void {
  if (error.retryAfterSeconds !== undefined) {
    response.setHeader("retry-after", String(error.retryAfterSeconds));
  }
  response.status(error.statusCode).json({
    code: error.code,
    message: error.message,
  });
}
