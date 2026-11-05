import express, { Express, Request, Response, NextFunction } from "express";
import cors from "cors";
import { env } from "./config/env";
import { healthRouter } from "./routes/health";

export function createApp(): Express {
  const app = express();

  app.disable("x-powered-by");

  app.use(
    cors({
      origin: env.frontendUrl,
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
    })
  );

  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true }));

  // API v1 Routes
  app.use("/api/v1/health", healthRouter);

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

export const app = createApp();
