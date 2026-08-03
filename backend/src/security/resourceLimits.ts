import { AsyncLocalStorage } from "node:async_hooks";
import { abortError, throwIfAborted } from "../utils/abort.js";
import type { Environment } from "./serverConfig.js";

export interface ResourceLimitConfig {
  maxConcurrentScans: number;
  maxQueuedScans: number;
  maxAsyncJobs: number;
  scanRateLimitMax: number;
  scanRateLimitWindowMs: number;
  maxResponseBodyBytes: number;
  maxRequestsPerScan: number;
  asyncJobTtlMs: number;
}

export const DEFAULT_RESOURCE_LIMITS: Readonly<ResourceLimitConfig> = Object.freeze({
  maxConcurrentScans: 2,
  maxQueuedScans: 8,
  maxAsyncJobs: 8,
  scanRateLimitMax: 20,
  scanRateLimitWindowMs: 60_000,
  maxResponseBodyBytes: 1_048_576,
  maxRequestsPerScan: 128,
  asyncJobTtlMs: 600_000,
});

const MAX_CONFIGURED_LIMIT = 2_147_483_647;

function parseIntegerLimit(
  env: Environment,
  name: string,
  fallback: number,
  minimum: number,
): number {
  const rawValue = env[name]?.trim();
  if (!rawValue) return fallback;

  const value = Number(rawValue);
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > MAX_CONFIGURED_LIMIT
  ) {
    throw new Error(
      `${name} ${minimum}-${MAX_CONFIGURED_LIMIT} arasında bir tam sayı olmalıdır.`,
    );
  }
  return value;
}

export function loadResourceLimitConfig(
  env: Environment = process.env,
): ResourceLimitConfig {
  return {
    maxConcurrentScans: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_MAX_CONCURRENT_SCANS",
      DEFAULT_RESOURCE_LIMITS.maxConcurrentScans,
      1,
    ),
    maxQueuedScans: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_MAX_QUEUED_SCANS",
      DEFAULT_RESOURCE_LIMITS.maxQueuedScans,
      0,
    ),
    maxAsyncJobs: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_MAX_ASYNC_JOBS",
      DEFAULT_RESOURCE_LIMITS.maxAsyncJobs,
      1,
    ),
    scanRateLimitMax: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_RATE_LIMIT_MAX",
      DEFAULT_RESOURCE_LIMITS.scanRateLimitMax,
      1,
    ),
    scanRateLimitWindowMs: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_RATE_LIMIT_WINDOW_MS",
      DEFAULT_RESOURCE_LIMITS.scanRateLimitWindowMs,
      1,
    ),
    maxResponseBodyBytes: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_MAX_RESPONSE_BODY_BYTES",
      DEFAULT_RESOURCE_LIMITS.maxResponseBodyBytes,
      1,
    ),
    maxRequestsPerScan: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_MAX_REQUESTS_PER_SCAN",
      DEFAULT_RESOURCE_LIMITS.maxRequestsPerScan,
      1,
    ),
    asyncJobTtlMs: parseIntegerLimit(
      env,
      "SECURITY_SCANNER_ASYNC_JOB_TTL_MS",
      DEFAULT_RESOURCE_LIMITS.asyncJobTtlMs,
      1,
    ),
  };
}

export type ResourceLimitCode =
  | "scan-capacity"
  | "async-capacity"
  | "scan-rate-limit"
  | "response-body-limit"
  | "request-budget";

export class ResourceLimitError extends Error {
  constructor(
    readonly code: ResourceLimitCode,
    readonly statusCode: 429 | 503,
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ResourceLimitError";
  }
}

export function isResourceLimitError(error: unknown): error is ResourceLimitError {
  return error instanceof ResourceLimitError;
}

interface ExecutionLimitContext {
  readonly limits: ResourceLimitConfig;
  requestCount: number;
  failure?: ResourceLimitError;
}

const executionLimits = new AsyncLocalStorage<ExecutionLimitContext>();

export function getResponseBodyByteLimit(): number {
  return executionLimits.getStore()?.limits.maxResponseBodyBytes
    ?? loadResourceLimitConfig().maxResponseBodyBytes;
}

export function consumeOutboundRequest(): void {
  const context = executionLimits.getStore();
  if (!context) return;
  if (context.failure) throw context.failure;

  if (context.requestCount >= context.limits.maxRequestsPerScan) {
    const error = new ResourceLimitError(
      "request-budget",
      503,
      "Taramanın hedef istek bütçesi aşıldı.",
    );
    context.failure = error;
    throw error;
  }
  context.requestCount += 1;
}

export function recordExecutionLimitFailure(error: ResourceLimitError): void {
  const context = executionLimits.getStore();
  if (context && !context.failure) context.failure = error;
}

async function runWithExecutionLimits<T>(
  limits: ResourceLimitConfig,
  operation: () => Promise<T>,
): Promise<T> {
  const context: ExecutionLimitContext = { limits, requestCount: 0 };
  try {
    const result = await executionLimits.run(context, operation);
    if (context.failure) throw context.failure;
    return result;
  } catch (error) {
    if (context.failure) throw context.failure;
    throw error;
  }
}

interface QueuedScan<T> {
  readonly operation: () => Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason?: unknown) => void;
  readonly signal?: AbortSignal;
  readonly onAbort: () => void;
}

class ScanScheduler {
  private activeScans = 0;
  private readonly queue: Array<QueuedScan<unknown>> = [];

  constructor(
    private readonly maxConcurrentScans: number,
    private readonly maxQueuedScans: number,
  ) {}

  schedule<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    throwIfAborted(signal);

    if (this.activeScans < this.maxConcurrentScans) {
      return this.start(operation);
    }
    if (this.queue.length >= this.maxQueuedScans) {
      throw new ResourceLimitError(
        "scan-capacity",
        503,
        "Tarama kapasitesi dolu. Daha sonra tekrar deneyin.",
      );
    }

    return new Promise<T>((resolve, reject) => {
      const entry: QueuedScan<T> = {
        operation,
        resolve,
        reject,
        signal,
        onAbort: () => {
          const index = this.queue.indexOf(entry as QueuedScan<unknown>);
          if (index >= 0) this.queue.splice(index, 1);
          reject(signal ? abortError(signal) : undefined);
        },
      };
      signal?.addEventListener("abort", entry.onAbort, { once: true });
      if (signal?.aborted) {
        entry.onAbort();
        return;
      }
      this.queue.push(entry as QueuedScan<unknown>);
    });
  }

  get activeCount(): number {
    return this.activeScans;
  }

  get queuedCount(): number {
    return this.queue.length;
  }

  private start<T>(operation: () => Promise<T>): Promise<T> {
    this.activeScans += 1;
    return Promise.resolve()
      .then(operation)
      .finally(() => {
        this.activeScans -= 1;
        this.startNext();
      });
  }

  private startNext(): void {
    while (this.activeScans < this.maxConcurrentScans) {
      const entry = this.queue.shift();
      if (!entry) return;
      entry.signal?.removeEventListener("abort", entry.onAbort);
      if (entry.signal?.aborted) {
        entry.reject(abortError(entry.signal));
        continue;
      }
      this.start(entry.operation).then(entry.resolve, entry.reject);
    }
  }
}

class ScanStartRateLimiter {
  private readonly acceptedAt: number[] = [];

  constructor(
    private readonly maximum: number,
    private readonly windowMs: number,
    private readonly now: () => number,
  ) {}

  assertAllowed(): void {
    const now = this.now();
    const cutoff = now - this.windowMs;
    while ((this.acceptedAt[0] ?? Number.POSITIVE_INFINITY) <= cutoff) {
      this.acceptedAt.shift();
    }

    if (this.acceptedAt.length >= this.maximum) {
      const oldest = this.acceptedAt[0] ?? now;
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((oldest + this.windowMs - now) / 1_000),
      );
      throw new ResourceLimitError(
        "scan-rate-limit",
        429,
        "Çok fazla tarama isteği gönderildi. Daha sonra tekrar deneyin.",
        retryAfterSeconds,
      );
    }
    this.acceptedAt.push(now);
  }
}

export interface ScanResourceManager {
  readonly limits: ResourceLimitConfig;
  assertScanStartAllowed(): void;
  runScan<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T>;
  readonly activeScanCount: number;
  readonly queuedScanCount: number;
}

export function createScanResourceManager(
  limits: ResourceLimitConfig = loadResourceLimitConfig(),
  now: () => number = Date.now,
): ScanResourceManager {
  const scheduler = new ScanScheduler(
    limits.maxConcurrentScans,
    limits.maxQueuedScans,
  );
  const rateLimiter = new ScanStartRateLimiter(
    limits.scanRateLimitMax,
    limits.scanRateLimitWindowMs,
    now,
  );

  return {
    limits,
    assertScanStartAllowed: () => rateLimiter.assertAllowed(),
    runScan: (operation, signal) => scheduler.schedule(
      () => runWithExecutionLimits(limits, operation),
      signal,
    ),
    get activeScanCount() {
      return scheduler.activeCount;
    },
    get queuedScanCount() {
      return scheduler.queuedCount;
    },
  };
}
