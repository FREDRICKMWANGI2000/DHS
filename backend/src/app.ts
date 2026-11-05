import express, { Express, Request, Response, NextFunction, Router } from "express";
import cors from "cors";
import { env } from "./config/env";
import { db } from "./db/client";
import { healthRouter } from "./routes/health";
import { createAuthRouter } from "./routes/auth";
import { createCsrfProtectionMiddleware } from "./middleware/csrf";
import { DbExecutor } from "./services/auth/audit.service";

export function createApp(
  executor: DbExecutor = db,
  extraApiV1Router?: Router
): Express {
  const app = express();

  app.disable("x-powered-by");

  app.use(
    cors({
      origin: env.frontendUrl,
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "X-CSRF-Token",
      ],
    })
  );

  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true }));

  // CSRF protection for browser state-changing requests (GET/HEAD/OPTIONS pass through)
  app.use("/api/v1", createCsrfProtectionMiddleware(executor));

  // API v1 Routes
  app.use("/api/v1/health", healthRouter);
  app.use("/api/v1/auth", createAuthRouter(executor));
  if (extraApiV1Router) {
    app.use("/api/v1", extraApiV1Router);
  }

  // 404 Fallback
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      status: "error",
      message: "Endpoint not found",
    });
  });

  // Global Error Handler
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error("Unhandled Express error:", err.message);
    res.status(500).json({
      status: "error",
      message: "Internal server error",
    });
  });

  return app;
}

export const app = createApp(db);
