import type { Express } from "express";
import { z } from "zod";
import { runBodyScan } from "../scanners/runBodyScan.js";
import { saveScanResult } from "../storage/database.js";
import { severityEnum } from "./schemas.js";

const bodyScanSchema = z.object({
  sourceLabel: z.string().min(1).max(512),
  body: z.string().min(1).max(1_500_000),
  severityOverrides: z.record(z.string(), severityEnum).optional(),
});

export function registerBodyScanRoutes(app: Express): void {
  app.post("/api/body-scans", (request, response) => {
    try {
      const parsed = bodyScanSchema.parse(request.body);
      const report = runBodyScan(parsed);
      saveScanResult(report);
      response.status(201).json(report);
    } catch (error) {
      if (error instanceof z.ZodError) {
        response.status(400).json({ message: "Invalid request payload.", details: error.issues });
        return;
      }
      console.error("[bodyScanRoutes] Body scan failed.");
      response.status(500).json({ message: "Body scan failed." });
    }
  });
}
