import { Router, Request, Response } from "express";
import { verifyDatabaseConnection } from "../db/client";

export const healthRouter = Router();

/**
 * GET /api/v1/health
 * Basic service availability health check.
 */
healthRouter.get("/", (_req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    service: "@dsh/backend",
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/v1/health/db
 * Database connectivity health check via Drizzle / PostgreSQL pool.
 */
healthRouter.get("/db", async (_req: Request, res: Response) => {
  try {
    const { connected, latencyMs } = await verifyDatabaseConnection();
    if (connected) {
      res.status(200).json({
        status: "ok",
        database: "connected",
        latencyMs,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    res.status(503).json({
      status: "error",
      database: "disconnected",
      timestamp: new Date().toISOString(),
    });
  } catch (err: unknown) {
    const error = err as Error;
    console.error("Database health check error:", error.message);
    res.status(503).json({
      status: "error",
      database: "unreachable",
      timestamp: new Date().toISOString(),
    });
  }
});
