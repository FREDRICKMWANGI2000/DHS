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

export const MIN_SESSION_SECRET_LENGTH = 32;
const PLACEHOLDER_SESSION_SECRET =
  "replace_with_secure_random_at_least_32_chars_secret_for_sessions";

export function validateSessionSecret(
  secret: string | undefined,
  nodeEnv: string = process.env.NODE_ENV || "development"
): string {
  if (!secret || secret.trim() === "") {
    throw new Error(
      `Missing required environment variable 'SESSION_SECRET'. Ensure it is configured in ${ROOT_ENV_LOCAL_PATH}.`
    );
  }
  const trimmed = secret.trim();
  if (trimmed.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error(
      `Invalid 'SESSION_SECRET': must be at least ${MIN_SESSION_SECRET_LENGTH} characters long.`
    );
  }
  if (nodeEnv === "production" && trimmed === PLACEHOLDER_SESSION_SECRET) {
    throw new Error(
      "Invalid 'SESSION_SECRET': placeholder secret from .env.example cannot be used in production."
    );
  }
  return trimmed;
}

export const env = {
  nodeEnv: process.env.NODE_ENV || "development",
  port: Number(process.env.BACKEND_PORT || process.env.PORT || 4000),
  frontendUrl:
    process.env.FRONTEND_URL ||
    process.env.NEXT_PUBLIC_APP_URL ||
    "http://localhost:3000",
  get databaseUrl(): string {
    return getRequiredEnv("DATABASE_URL");
  },
  get sessionSecret(): string {
    return validateSessionSecret(process.env.SESSION_SECRET, this.nodeEnv);
  },
  dbDebug: process.env.DB_DEBUG === "true",
};
