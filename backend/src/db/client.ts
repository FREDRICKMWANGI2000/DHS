import { Pool } from "pg";
import { drizzle, NodePgDatabase } from "drizzle-orm/node-postgres";
import { env } from "../config/env";
import * as schema from "./schema";

// Global singleton to prevent duplicate pools during watch/hot-reload cycles
const globalForDb = globalThis as unknown as {
  pool: Pool | undefined;
  db: NodePgDatabase<typeof schema> | undefined;
};

export const pool: Pool =
  globalForDb.pool ??
  new Pool({
    connectionString: env.databaseUrl,
    max: env.nodeEnv === "production" ? 20 : 10,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
  });

export const db: NodePgDatabase<typeof schema> =
  globalForDb.db ??
  drizzle(pool, {
    schema,
    logger: env.nodeEnv === "development" && env.dbDebug,
  });

if (env.nodeEnv !== "production") {
  globalForDb.pool = pool;
  globalForDb.db = db;
}

export type Database = typeof db;

/**
 * Verifies database connectivity by executing SELECT 1 AS connection_test.
 */
export async function verifyDatabaseConnection(): Promise<{
  connected: boolean;
  latencyMs: number;
}> {
  const startTime = Date.now();
  const result = await pool.query<{ connection_test: number }>(
    "SELECT 1 AS connection_test;"
  );
  const latencyMs = Date.now() - startTime;
  const connected = Number(result.rows[0]?.connection_test) === 1;
  return { connected, latencyMs };
}

/**
 * Closes the connection pool gracefully.
 */
export async function closePool(): Promise<void> {
  await pool.end();
}
