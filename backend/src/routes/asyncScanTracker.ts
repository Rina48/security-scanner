import { randomUUID } from "node:crypto";
import { runScan } from "../scanners/runScan.js";
import { saveScanResult } from "../storage/database.js";
import type { ScanMode, ScanRequest } from "../types.js";

interface PendingScan {
  targetUrl: string;
  mode: ScanMode;
  startedAt: string;
}

const pendingScans = new Map<string, PendingScan>();

export function getPendingScan(scanId: string): PendingScan | undefined {
  return pendingScans.get(scanId);
}

export function startBackgroundScan(scanRequest: ScanRequest): {
  scanId: string;
  startedAt: string;
} {
  const scanId = randomUUID();
  const startedAt = new Date().toISOString();

  pendingScans.set(scanId, {
    targetUrl: scanRequest.targetUrl,
    mode: scanRequest.mode,
    startedAt,
  });

  runScan({ ...scanRequest, scanId })
    .then((report) => {
      saveScanResult(report);
      pendingScans.delete(scanId);
    })
    .catch(() => {
      pendingScans.delete(scanId);
      console.error("[security-scanner] Async scan failed.");
    });

  return { scanId, startedAt };
}
