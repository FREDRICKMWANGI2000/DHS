import * as dotenv from "dotenv";
import * as path from "path";

// Resolve the monorepo root .env.local relative to this file (backend/src/config or backend/dist/config)
export const ROOT_ENV_LOCAL_PATH = path.resolve(__dirname, "../../../.env.local");

dotenv.config({ path: ROOT_ENV_LOCAL_PATH });

export function getRequiredEnv(key: string): string {
  const val = process.env[key];
  if (!val || val.trim() === "") {
    throw new Error(
      `Missing required environment variable '${key}'. Ensure it is configured in ${ROOT_ENV_LOCAL_PATH}.`
    );
  }
  return val;
}

export const env = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.BACKEND_PORT || process.env.PORT || 4000),
  frontendUrl: process.env.FRONTEND_URL || process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000",
  get databaseUrl(): string {
    return getRequiredEnv("DATABASE_URL");
  },
  dbDebug: process.env.DB_DEBUG === "true",
};
