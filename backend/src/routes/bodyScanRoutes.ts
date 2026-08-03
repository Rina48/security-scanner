import type { Express } from "express";
import { z } from "zod";
import { runBodyScan } from "../scanners/runBodyScan.js";
import {
  createScanResourceManager,
  isResourceLimitError,
  type ScanResourceManager,
} from "../security/resourceLimits.js";
import { saveScanResult } from "../storage/database.js";
import { isAbortError, throwIfAborted } from "../utils/abort.js";
import { createClientDisconnectScope } from "./clientDisconnect.js";
import { sendResourceLimitResponse } from "./resourceLimitResponse.js";
import { severityEnum } from "./schemas.js";

const bodyScanSchema = z.object({
  sourceLabel: z.string().min(1).max(512),
  body: z.string().min(1).max(1_500_000),
  severityOverrides: z.record(z.string(), severityEnum).optional(),
});

export interface BodyScanRouteDependencies {
  resources?: ScanResourceManager;
  runBodyScan?: typeof runBodyScan;
  saveScanResult?: typeof saveScanResult;
}

export function registerBodyScanRoutes(
  app: Express,
  dependencies: BodyScanRouteDependencies = {},
): void {
  const resources = dependencies.resources ?? createScanResourceManager();
  const bodyScanner = dependencies.runBodyScan ?? runBodyScan;
  const saveResult = dependencies.saveScanResult ?? saveScanResult;

  app.post("/api/body-scans", async (request, response) => {
    const disconnectScope = createClientDisconnectScope(request, response);
    try {
      resources.assertScanStartAllowed();
      const parsed = bodyScanSchema.parse(request.body);
      throwIfAborted(disconnectScope.signal);
      const report = await resources.runScan(
        async () => bodyScanner(parsed),
        disconnectScope.signal,
      );
      throwIfAborted(disconnectScope.signal);
      saveResult(report);
      disconnectScope.complete();
      response.status(201).json(report);
    } catch (error) {
      if (isAbortError(error, disconnectScope.signal)) return;
      if (error instanceof z.ZodError) {
        response.status(400).json({ message: "Invalid request payload.", details: error.issues });
        return;
      }
      if (isResourceLimitError(error)) {
        sendResourceLimitResponse(response, error);
        return;
      }
      console.error("[bodyScanRoutes] Body scan failed.");
      response.status(500).json({ message: "Body scan failed." });
    } finally {
      disconnectScope.dispose();
    }
  });
}
