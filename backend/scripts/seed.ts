import * as dotenv from "dotenv";
import * as path from "path";

// 1. Explicitly load monorepo root .env.local relative to backend/scripts/seed.ts
const rootEnvPath = path.resolve(__dirname, "../../.env.local");
dotenv.config({ path: rootEnvPath });

import { db, closePool } from "../src/db/client";
import { runCatalogSeed } from "../src/db/seed-catalog";

async function main(): Promise<void> {
  console.log("==================================================================");
  console.log("==> DSH Catalog Seed Runner (Idempotent / Admin-Change Preserving)");
  console.log("==================================================================");

  try {
    const summary = await db.transaction(async (tx) => {
      return runCatalogSeed(tx);
    });

    console.log("\n--- 1. Wi-Fi Packages (wifi_packages) ---");
    console.log(
      `Inserted: ${summary.wifiPackages.insertedCount} | Preserved Existing: ${summary.wifiPackages.preservedCount}`
    );
    for (const item of summary.wifiPackages.items) {
      const r = item.record;
      const customNote =
        item.customizations.length > 0
          ? ` [Admin Customizations Preserved: ${item.customizations.join("; ")}]`
          : "";
      console.log(
        `  [${item.action}] ${r.slug.padEnd(16)} | ${r.name.padEnd(16)} | ${r.currency} ${r.price.padStart(6)} | ${String(r.durationMinutes).padStart(4)} min | order=${r.displayOrder} | active=${r.isActive}${customNote}`
      );
    }

    console.log("\n--- 2. Digital Services (service_catalog) ---");
    console.log(
      `Inserted: ${summary.digitalServices.insertedCount} | Preserved Existing: ${summary.digitalServices.preservedCount}`
    );
    for (const item of summary.digitalServices.items) {
      const r = item.record;
      const customNote =
        item.customizations.length > 0
          ? ` [Admin Customizations Preserved: ${item.customizations.join("; ")}]`
          : "";
      console.log(
        `  [${item.action}] ${r.slug.padEnd(20)} | ${r.name.padEnd(20)} | ${r.currency} ${r.price.padStart(7)} | ${r.pricingUnit.padEnd(11)} | order=${String(r.displayOrder).padStart(2)} | active=${r.isActive}${customNote}`
      );
    }

    console.log("\n✓ Catalog seed completed successfully.");
  } catch (err: unknown) {
    const error = err as Error;
    console.error("\n✗ Catalog seed failed!");
    console.error(`Reason: ${error.message}`);
    process.exitCode = 1;
  } finally {
    await closePool();
    console.log("==> Database connection pool safely closed.");
  }
}

main().catch((err) => {
  console.error("Fatal seed runner error:", err instanceof Error ? err.message : err);
  process.exit(1);
});
