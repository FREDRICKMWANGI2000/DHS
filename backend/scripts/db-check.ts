import * as dotenv from "dotenv";
import * as path from "path";

// 1. Explicitly load monorepo root .env.local relative to backend/scripts/db-check.ts
const rootEnvPath = path.resolve(__dirname, "../../.env.local");
dotenv.config({ path: rootEnvPath });

import { verifyDatabaseConnection, closePool } from "../src/db/client";

async function checkDatabaseConnection(): Promise<void> {
  console.log("==> Verifying DSH PostgreSQL connection via @dsh/backend Drizzle ORM client...");

  try {
    const { connected, latencyMs } = await verifyDatabaseConnection();

    if (connected) {
      console.log(`✓ Database connection successful! (Response time: ${latencyMs}ms)`);
      console.log("✓ 'SELECT 1 AS connection_test' verified successfully (value = 1).");
    } else {
      throw new Error("SELECT 1 did not return expected result 1.");
    }
  } catch (err: unknown) {
    const error = err as Error;
    console.error("✗ Database connectivity check failed!");
    console.error(`Reason: ${error.message}`);
    process.exitCode = 1;
  } finally {
    await closePool();
    console.log("==> Connection pool safely closed.");
  }
}

checkDatabaseConnection().catch((err) => {
  console.error("Fatal runner error:", err instanceof Error ? err.message : err);
  process.exit(1);
});
