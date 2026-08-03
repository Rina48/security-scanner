import type { Request, Response } from "express";

export interface ClientDisconnectScope {
  complete(): void;
  dispose(): void;
  readonly signal: AbortSignal;
}

export function createClientDisconnectScope(
  request: Request,
  response: Response,
): ClientDisconnectScope {
  const controller = new AbortController();
  let completed = false;

  const abort = (): void => {
    if (completed || controller.signal.aborted) return;
    controller.abort(new DOMException("Client disconnected", "AbortError"));
  };
  const complete = (): void => {
    completed = true;
  };
  const dispose = (): void => {
    request.removeListener("aborted", abort);
    response.removeListener("close", abort);
  };

  request.once("aborted", abort);
  response.once("close", abort);
  if (request.aborted || response.destroyed) abort();

  return { complete, dispose, signal: controller.signal };
}
