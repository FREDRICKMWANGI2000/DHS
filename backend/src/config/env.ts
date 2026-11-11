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

export const PLACEHOLDER_RESEND_API_KEY = "re_placeholder_development_api_key";
export const PLACEHOLDER_EMAIL_FROM_DOMAIN = "@yourdomain.com";

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

export interface ValidatedResendConfig {
  apiKey: string;
  emailFrom: string;
}

/**
 * Validates Resend email delivery configuration when enabled.
 * Never includes secret API key values in error messages.
 */
export function validateResendConfig(
  apiKey: string | undefined = process.env.RESEND_API_KEY,
  emailFrom: string | undefined = process.env.EMAIL_FROM,
  nodeEnv: string = process.env.NODE_ENV || "development"
): ValidatedResendConfig {
  const trimmedKey = apiKey?.trim() ?? "";
  if (!trimmedKey) {
    throw new Error(
      "Missing required environment variable 'RESEND_API_KEY' for Resend email provider."
    );
  }
  if (
    trimmedKey === PLACEHOLDER_RESEND_API_KEY ||
    trimmedKey.startsWith("re_placeholder")
  ) {
    throw new Error(
      "Invalid 'RESEND_API_KEY': placeholder value from .env.example is not a live Resend API key."
    );
  }
  if (!trimmedKey.startsWith("re_") || trimmedKey.length < 10) {
    throw new Error(
      "Invalid 'RESEND_API_KEY': must be a valid Resend API key starting with 're_'."
    );
  }

  const trimmedFrom = emailFrom?.trim() ?? "";
  if (!trimmedFrom || !trimmedFrom.includes("@")) {
    throw new Error(
      "Missing or invalid required environment variable 'EMAIL_FROM' for Resend email provider."
    );
  }
  if (
    nodeEnv === "production" &&
    trimmedFrom.toLowerCase().includes(PLACEHOLDER_EMAIL_FROM_DOMAIN)
  ) {
    throw new Error(
      "Invalid 'EMAIL_FROM': placeholder domain '@yourdomain.com' cannot be used in production."
    );
  }

  return {
    apiKey: trimmedKey,
    emailFrom: trimmedFrom,
  };
}

/**
 * Returns true only when both RESEND_API_KEY and EMAIL_FROM are configured with non-placeholder values.
 */
export function isResendConfigured(
  apiKey: string | undefined = process.env.RESEND_API_KEY,
  emailFrom: string | undefined = process.env.EMAIL_FROM,
  nodeEnv: string = process.env.NODE_ENV || "development"
): boolean {
  try {
    validateResendConfig(apiKey, emailFrom, nodeEnv);
    return true;
  } catch {
    return false;
  }
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
  get resendApiKey(): string | undefined {
    const val = process.env.RESEND_API_KEY?.trim();
    return val && val.length > 0 ? val : undefined;
  },
  get emailFrom(): string | undefined {
    const val = process.env.EMAIL_FROM?.trim();
    return val && val.length > 0 ? val : undefined;
  },
  get isEmailConfigured(): boolean {
    return isResendConfigured(
      process.env.RESEND_API_KEY,
      process.env.EMAIL_FROM,
      this.nodeEnv
    );
  },
  dbDebug: process.env.DB_DEBUG === "true",
};
