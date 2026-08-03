import { randomUUID } from "node:crypto";
import { runScan } from "../scanners/runScan.js";
import {
  ResourceLimitError,
  type ScanResourceManager,
} from "../security/resourceLimits.js";
import { saveScanResult } from "../storage/database.js";
import type { ScanMode, ScanRequest } from "../types.js";
import { isAbortError } from "../utils/abort.js";

export interface PendingScan {
  targetUrl: string;
  mode: ScanMode;
  startedAt: string;
  status: "queued" | "running";
}

interface TrackedScan extends PendingScan {
  readonly controller: AbortController;
  readonly expiresAt: number;
  timeoutHandle?: NodeJS.Timeout;
}

export interface AsyncScanTracker {
  get(scanId: string): PendingScan | undefined;
  start(scanRequest: ScanRequest): { scanId: string; startedAt: string };
  readonly size: number;
  dispose(): void;
}

export interface AsyncScanTrackerDependencies {
  logError?: () => void;
  now?: () => number;
  runScan?: typeof runScan;
  saveScanResult?: typeof saveScanResult;
}

export function createAsyncScanTracker(
  resources: ScanResourceManager,
  dependencies: AsyncScanTrackerDependencies = {},
): AsyncScanTracker {
  const jobs = new Map<string, TrackedScan>();
  const now = dependencies.now ?? Date.now;
  const logError = dependencies.logError
    ?? (() => console.error("[security-scanner] Async scan failed."));
  const scanRunner = dependencies.runScan ?? runScan;
  const saveResult = dependencies.saveScanResult ?? saveScanResult;

  const remove = (scanId: string, job: TrackedScan): void => {
    if (jobs.get(scanId) !== job) return;
    if (job.timeoutHandle) clearTimeout(job.timeoutHandle);
    jobs.delete(scanId);
  };

  const expire = (scanId: string, job: TrackedScan): void => {
    if (jobs.get(scanId) !== job) return;
    if (job.timeoutHandle) clearTimeout(job.timeoutHandle);
    jobs.delete(scanId);
    job.controller.abort(new DOMException("Async scan expired", "TimeoutError"));
  };

  const cleanupExpired = (): void => {
    const currentTime = now();
    for (const [scanId, job] of jobs) {
      if (job.expiresAt <= currentTime) expire(scanId, job);
    }
  };

  return {
    get(scanId) {
      cleanupExpired();
      return jobs.get(scanId);
    },

    start(scanRequest) {
      cleanupExpired();
      if (jobs.size >= resources.limits.maxAsyncJobs) {
        throw new ResourceLimitError(
          "async-capacity",
          503,
          "Asenkron tarama kapasitesi dolu. Daha sonra tekrar deneyin.",
        );
      }

      const scanId = randomUUID();
      const startedAt = new Date(now()).toISOString();
      const controller = new AbortController();
      const job: TrackedScan = {
        targetUrl: scanRequest.targetUrl,
        mode: scanRequest.mode,
        startedAt,
        status: "queued",
        controller,
        expiresAt: now() + resources.limits.asyncJobTtlMs,
      };
      const timeoutHandle = setTimeout(
        () => expire(scanId, job),
        resources.limits.asyncJobTtlMs,
      );
      timeoutHandle.unref();
      job.timeoutHandle = timeoutHandle;
      jobs.set(scanId, job);

      let scheduledScan: Promise<Awaited<ReturnType<typeof runScan>>>;
      try {
        scheduledScan = resources.runScan(async () => {
          const current = jobs.get(scanId);
          if (current === job) current.status = "running";
          return scanRunner(
            { ...scanRequest, scanId },
            { signal: controller.signal },
          );
        }, controller.signal);
      } catch (error) {
        remove(scanId, job);
        controller.abort(new DOMException("Async scan was not admitted", "AbortError"));
        throw error;
      }

      void scheduledScan
        .then((report) => {
          if (!controller.signal.aborted) saveResult(report);
        })
        .catch((error: unknown) => {
          if (!isAbortError(error, controller.signal)) {
            logError();
          }
        })
        .finally(() => remove(scanId, job));

      return { scanId, startedAt };
    },

    get size() {
      cleanupExpired();
      return jobs.size;
    },

    dispose() {
      for (const [scanId, job] of jobs) {
        if (job.timeoutHandle) clearTimeout(job.timeoutHandle);
        jobs.delete(scanId);
        job.controller.abort(new DOMException("Async scan tracker disposed", "AbortError"));
      }
    },
  };
}
