export interface TimeoutSignalScope {
  readonly signal: AbortSignal;
  dispose(): void;
}

export function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException("The operation was aborted", "AbortError");
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError(signal);
}

export function isAbortError(
  error: unknown,
  parentSignal?: AbortSignal,
): boolean {
  if (parentSignal) return parentSignal.aborted;
  return error instanceof Error && error.name === "AbortError";
}

export function createTimeoutSignal(
  parentSignal: AbortSignal | undefined,
  timeoutMs: number,
): TimeoutSignalScope {
  const controller = new AbortController();
  let disposed = false;
  let timeoutHandle: NodeJS.Timeout | undefined;

  const onParentAbort = (): void => {
    controller.abort(parentSignal ? abortError(parentSignal) : undefined);
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = undefined;
    }
    parentSignal?.removeEventListener("abort", onParentAbort);
  };

  if (parentSignal?.aborted) {
    onParentAbort();
    return { signal: controller.signal, dispose };
  }

  parentSignal?.addEventListener("abort", onParentAbort, { once: true });
  timeoutHandle = setTimeout(() => {
    controller.abort(new DOMException("The operation timed out", "TimeoutError"));
  }, timeoutMs);

  return { signal: controller.signal, dispose };
}

export async function withTimeoutSignal<T>(
  parentSignal: AbortSignal | undefined,
  timeoutMs: number,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  throwIfAborted(parentSignal);
  const scope = createTimeoutSignal(parentSignal, timeoutMs);
  try {
    const result = await operation(scope.signal);
    throwIfAborted(scope.signal);
    return result;
  } finally {
    scope.dispose();
  }
}

export function abortableDelay(
  delayMs: number,
  signal?: AbortSignal,
): Promise<void> {
  throwIfAborted(signal);

  return new Promise((resolve, reject) => {
    let settled = false;
    const timeoutHandle = setTimeout(() => settle(), delayMs);

    const cleanup = (): void => {
      clearTimeout(timeoutHandle);
      signal?.removeEventListener("abort", onAbort);
    };

    const settle = (error?: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else resolve();
    };

    const onAbort = (): void => {
      if (!signal) return;
      settle(abortError(signal));
    };

    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) onAbort();
  });
}
