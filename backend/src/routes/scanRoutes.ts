import type { Express, Request, Response } from "express";
import { z } from "zod";
import { runScan } from "../scanners/runScan.js";
import { EgressPolicyError } from "../security/egressPolicy.js";
import { isAbortError, throwIfAborted } from "../utils/abort.js";
import {
  clearAllScanResults,
  getScanResultById,
  listRecentScanResults,
  saveScanResult,
} from "../storage/database.js";
import { getPendingScan, startBackgroundScan } from "./asyncScanTracker.js";
import { authorizeScanRequest, scanRequestSchema } from "./scanRequestPolicy.js";

const DEFAULT_SCAN_HISTORY_LIMIT = 30;

export interface ScanRouteDependencies {
  runScan?: typeof runScan;
  saveScanResult?: typeof saveScanResult;
  startBackgroundScan?: typeof startBackgroundScan;
}

function createClientDisconnectScope(request: Request, response: Response): {
  complete(): void;
  dispose(): void;
  signal: AbortSignal;
} {
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

async function runSynchronousScan(
  request: Request,
  response: Response,
  scanRequest: Parameters<typeof runScan>[0],
  scanRunner: typeof runScan,
  saveResult: typeof saveScanResult,
): Promise<void> {
  const disconnectScope = createClientDisconnectScope(request, response);
  try {
    throwIfAborted(disconnectScope.signal);
    const report = await scanRunner(scanRequest, {
      signal: disconnectScope.signal,
    });
    throwIfAborted(disconnectScope.signal);
    saveResult(report);
    disconnectScope.complete();
    response.status(201).json(report);
  } catch (error) {
    if (isAbortError(error, disconnectScope.signal)) return;
    throw error;
  } finally {
    disconnectScope.dispose();
  }
}

export function registerScanRoutes(
  app: Express,
  dependencies: ScanRouteDependencies = {},
): void {
  const scanRunner = dependencies.runScan ?? runScan;
  const saveResult = dependencies.saveScanResult ?? saveScanResult;
  const startAsyncScan = dependencies.startBackgroundScan ?? startBackgroundScan;

  app.get("/api/scans", (_request, response) => {
    response.json({ scans: listRecentScanResults(DEFAULT_SCAN_HISTORY_LIMIT) });
  });

  app.get("/api/scans/:id", (request, response) => {
    const { id } = request.params;
    const pending = getPendingScan(id);
    if (pending) {
      response.status(202).json({
        scanId: id,
        status: "running",
        targetUrl: pending.targetUrl,
        mode: pending.mode,
        startedAt: pending.startedAt,
        message: "Tarama devam ediyor. Tekrar isteyin.",
      });
      return;
    }

    const scan = getScanResultById(id);
    if (!scan) {
      response.status(404).json({ message: "Tarama bulunamadı." });
      return;
    }
    response.json(scan);
  });

  app.delete("/api/scans", (_request, response) => {
    clearAllScanResults();
    response.json({ message: "Tarama geçmişi temizlendi." });
  });

  app.post("/api/scans", async (request, response) => {
    try {
      const parsed = scanRequestSchema.parse(request.body);
      const { async: useAsync, ...scanRequest } = parsed;

      const authorization = authorizeScanRequest(scanRequest);
      if (!authorization.allowed) {
        response.status(authorization.status).json({ message: authorization.message });
        return;
      }

      if (useAsync) {
        const { scanId } = startAsyncScan(scanRequest);
        response.status(202).json({
          scanId,
          status: "running",
          message:
            "Tarama arka planda başlatıldı. GET /api/scans/" +
            scanId +
            " ile sonucu kontrol edin.",
          pollUrl: `/api/scans/${scanId}`,
        });
        return;
      }

      await runSynchronousScan(
        request,
        response,
        scanRequest,
        scanRunner,
        saveResult,
      );
    } catch (error) {
      if (error instanceof z.ZodError) {
        response.status(400).json({
          message: "Invalid request payload.",
          details: error.issues,
        });
        return;
      }

      if (error instanceof EgressPolicyError) {
        response.status(403).json({ message: "Target is not allowed by egress policy." });
        return;
      }

      console.error("[scanRoutes] Scan failed.");
      if (!response.headersSent && !response.destroyed) {
        response.status(500).json({ message: "Scan failed." });
      }
    }
  });
}
