import cors from "cors";
import express, { type Express } from "express";
import helmet from "helmet";
import { registerBodyScanRoutes } from "./routes/bodyScanRoutes.js";
import { registerProbeRoutes } from "./routes/probeRoutes.js";
import { registerScanRoutes } from "./routes/scanRoutes.js";
import { createApiAuthMiddleware } from "./security/auth.js";
import { createCorsOptions, createOriginGuard } from "./security/corsPolicy.js";
import type { ServerConfig } from "./security/serverConfig.js";

export function createApp(config: ServerConfig): Express {
  const app = express();

  app.use(helmet());
  app.use(createOriginGuard(config.allowedOrigins));
  app.use(cors(createCorsOptions(config.allowedOrigins)));

  app.get("/api/health", (_request, response) => {
    response.json({ status: "ok" });
  });

  app.use("/api", createApiAuthMiddleware(config.apiToken));
  app.use(express.json({ limit: "2mb" }));

  registerScanRoutes(app);
  registerBodyScanRoutes(app);
  if (config.probeEnabled) {
    registerProbeRoutes(app);
  }

  return app;
}
