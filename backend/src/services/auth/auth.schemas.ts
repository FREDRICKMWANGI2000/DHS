import { z } from "zod";
import { normalizeEmail, normalizePhoneNumber } from "../../db/normalize";
import { validatePassword } from "./password.service";

const EMAIL_RFC_BASIC_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface ValidatedRegisterInput {
  firstName: string;
  lastName: string;
  email: string | null;
  phoneNumber: string | null;
  password: string;
  attemptedPrivilegedFields: boolean;
}

export interface ValidatedLoginInput {
  identifier: string;
  password: string;
}

/**
 * Raw Zod schema for `POST /api/v1/auth/register`.
 * Validates required fields, normalizes email and phone number using the canonical helpers,
 * enforces that at least one contact method is provided, validates password policy,
 * and never trusts client-supplied `role` or `status`.
 */
const registerRawSchema = z
  .object({
    firstName: z
      .string({ message: "First name is required." })
      .trim()
      .min(1, "First name is required.")
      .max(100, "First name must not exceed 100 characters."),
    lastName: z
      .string({ message: "Last name is required." })
      .trim()
      .min(1, "Last name is required.")
      .max(100, "Last name must not exceed 100 characters."),
    email: z
      .union([z.string(), z.null(), z.undefined()])
      .optional(),
    phoneNumber: z
      .union([z.string(), z.null(), z.undefined()])
      .optional(),
    password: z.string({ message: "Password is required." }),
  })
  .passthrough();

export function parseAndNormalizeRegisterInput(
  rawBody: unknown
):
  | { success: true; data: ValidatedRegisterInput }
  | { success: false; message: string } {
  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    return {
      success: false,
      message: "Invalid registration request payload.",
    };
  }

  const parsed = registerRawSchema.safeParse(rawBody);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    return {
      success: false,
      message: firstIssue?.message || "Invalid registration fields.",
    };
  }

  const { firstName, lastName, email, phoneNumber, password } = parsed.data;

  // Detect if caller attempted to supply role or status (which are strictly ignored/overridden)
  const rawRecord = rawBody as Record<string, unknown>;
  const attemptedPrivilegedFields =
    "role" in rawRecord || "status" in rawRecord;

  let normalizedEmail: string | null = null;
  if (typeof email === "string" && email.trim().length > 0) {
    try {
      const candidate = normalizeEmail(email);
      if (candidate.length > 255 || !EMAIL_RFC_BASIC_REGEX.test(candidate)) {
        return {
          success: false,
          message: "Please provide a valid email address.",
        };
      }
      normalizedEmail = candidate;
    } catch {
      return {
        success: false,
        message: "Please provide a valid email address.",
      };
    }
  }

  let normalizedPhone: string | null = null;
  if (typeof phoneNumber === "string" && phoneNumber.trim().length > 0) {
    try {
      normalizedPhone = normalizePhoneNumber(phoneNumber);
    } catch {
      return {
        success: false,
        message:
          "Phone number must be a valid Kenyan or E.164 number (e.g. +2547XXXXXXXX).",
      };
    }
  }

  if (!normalizedEmail && !normalizedPhone) {
    return {
      success: false,
      message: "At least one contact method (email or phone number) is required.",
    };
  }

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return {
      success: false,
      message:
        passwordValidation.errors[0] ||
        "Password does not meet security policy requirements.",
    };
  }

  return {
    success: true,
    data: {
      firstName,
      lastName,
      email: normalizedEmail,
      phoneNumber: normalizedPhone,
      password,
      attemptedPrivilegedFields,
    },
  };
}

/**
 * Zod schema for `POST /api/v1/auth/login`.
 */
const loginRawSchema = z.object({
  identifier: z
    .string({ message: "Email or phone number is required." })
    .trim()
    .min(1, "Email or phone number is required.")
    .max(255, "Identifier is too long."),
  password: z
    .string({ message: "Password is required." })
    .min(1, "Password is required.")
    .max(256, "Password is too long."),
});

export function parseLoginInput(
  rawBody: unknown
):
  | { success: true; data: ValidatedLoginInput }
  | { success: false; message: string } {
  if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
    return {
      success: false,
      message: "Invalid login request payload.",
    };
  }

  const parsed = loginRawSchema.safeParse(rawBody);
  if (!parsed.success) {
    const firstIssue = parsed.error.issues[0];
    return {
      success: false,
      message: firstIssue?.message || "Invalid login request fields.",
    };
  }

  return {
    success: true,
    data: parsed.data,
  };
}

/**
 * Normalizes a login identifier as either an email address (if it contains '@')
 * or an E.164 phone number. Returns `{ type, value }` if valid, or `{ type: 'invalid', rateLimitKey }`
 * so rate limiting and constant-time dummy verification still run without leaking format differences.
 */
export function normalizeLoginIdentifier(
  rawIdentifier: string
):
  | { valid: true; type: "EMAIL" | "PHONE"; normalized: string }
  | { valid: false; rateLimitKey: string } {
  const trimmed = rawIdentifier.trim();
  if (trimmed.includes("@")) {
    try {
      const normalized = normalizeEmail(trimmed);
      if (normalized.length <= 255 && EMAIL_RFC_BASIC_REGEX.test(normalized)) {
        return { valid: true, type: "EMAIL", normalized };
      }
    } catch {
      // fall through
    }
    return { valid: false, rateLimitKey: `invalid_email:${trimmed.toLowerCase()}` };
  }

  try {
    const normalized = normalizePhoneNumber(trimmed);
    return { valid: true, type: "PHONE", normalized };
  } catch {
    return { valid: false, rateLimitKey: `invalid_phone:${trimmed.toLowerCase()}` };
  }
}
