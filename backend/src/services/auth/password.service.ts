import * as argon2 from "argon2";

/**
 * Approved Argon2id parameters per DSH AUTH_ARCHITECTURE.md:
 * - Algorithm: Argon2id
 * - Memory cost: 65536 KiB (64 MiB)
 * - Time cost: 3 iterations
 * - Parallelism: 4 lanes
 * - Hash length: 32 bytes
 * - Salt: 16-byte CSPRNG salt automatically generated per hash by argon2
 */
export const ARGON2ID_OPTIONS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
} as const);

export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 128;

const HAS_LETTER_REGEX = /[a-zA-Z]/;
const HAS_NUMBER_OR_SYMBOL_REGEX = /[0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/;
const ARGON2ID_PHC_PREFIX = "$argon2id$";

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}

export class PasswordPolicyError extends Error {
  public readonly errors: string[];

  constructor(errors: string[]) {
    super(errors[0] || "Password does not meet security policy requirements.");
    this.name = "PasswordPolicyError";
    this.errors = errors;
  }
}

/**
 * Validates a candidate plaintext password against DSH password policy:
 * - Minimum 8 characters
 * - Maximum 128 characters
 * - Not empty or whitespace-only
 * - At least one alphabetic letter
 * - At least one number or symbol
 *
 * Never logs the candidate password.
 */
export function validatePassword(password: unknown): PasswordValidationResult {
  const errors: string[] = [];

  if (typeof password !== "string") {
    return {
      valid: false,
      errors: ["Password must be a string."],
    };
  }

  if (password.trim().length === 0) {
    errors.push("Password cannot be empty or whitespace only.");
  }

  if (password.length < MIN_PASSWORD_LENGTH) {
    errors.push(
      `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`
    );
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    errors.push(
      `Password must not exceed ${MAX_PASSWORD_LENGTH} characters.`
    );
  }

  if (!HAS_LETTER_REGEX.test(password)) {
    errors.push("Password must contain at least one letter.");
  }

  if (!HAS_NUMBER_OR_SYMBOL_REGEX.test(password)) {
    errors.push("Password must contain at least one number or symbol.");
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validates and hashes a plaintext password using Argon2id with a fresh library-generated salt.
 * Throws PasswordPolicyError if the password violates policy.
 */
export async function hashPassword(password: string): Promise<string> {
  const validation = validatePassword(password);
  if (!validation.valid) {
    throw new PasswordPolicyError(validation.errors);
  }

  return argon2.hash(password, ARGON2ID_OPTIONS);
}

/**
 * Verifies a candidate password against an Argon2id PHC hash string.
 * Safely handles malformed, empty, non-Argon2id, or unsupported hashes without throwing.
 */
export async function verifyPassword(
  passwordHash: string,
  candidatePassword: string
): Promise<boolean> {
  if (
    typeof passwordHash !== "string" ||
    typeof candidatePassword !== "string" ||
    passwordHash.length === 0 ||
    candidatePassword.length === 0 ||
    candidatePassword.length > MAX_PASSWORD_LENGTH ||
    !passwordHash.startsWith(ARGON2ID_PHC_PREFIX)
  ) {
    return false;
  }

  try {
    return await argon2.verify(passwordHash, candidatePassword);
  } catch {
    return false;
  }
}

let cachedDummyHashPromise: Promise<string> | null = null;

/**
 * Performs a constant-time dummy Argon2id verification when a login identifier does not exist,
 * preventing timing-based account enumeration.
 */
export async function verifyAgainstDummyPasswordHash(
  candidatePassword: string
): Promise<boolean> {
  if (!cachedDummyHashPromise) {
    cachedDummyHashPromise = argon2.hash(
      "DummyTimingMitigationPass!987654321",
      ARGON2ID_OPTIONS
    );
  }
  const dummyHash: string = await cachedDummyHashPromise;
  const boundedCandidate =
    typeof candidatePassword === "string" && candidatePassword.length > 0
      ? candidatePassword.slice(0, MAX_PASSWORD_LENGTH)
      : "invalid";
  await verifyPassword(dummyHash, boundedCandidate);
  return false;
}
