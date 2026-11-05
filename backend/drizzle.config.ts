import { defineConfig } from "drizzle-kit";
import * as dotenv from "dotenv";
import * as path from "path";

// Resolve the monorepo root .env.local relative to backend/drizzle.config.ts
const rootEnvPath = path.resolve(__dirname, "../.env.local");
dotenv.config({ path: rootEnvPath });

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error(
    `DATABASE_URL is not configured in ${rootEnvPath}. Drizzle CLI commands require a valid DATABASE_URL.`
  );
}

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema/index.ts",
  out: "./drizzle",
  dbCredentials: {
    url: databaseUrl,
  },
  strict: true,
  verbose: true,
});
