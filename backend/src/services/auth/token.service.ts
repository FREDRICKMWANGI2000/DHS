import * as crypto from "crypto";
import { env } from "../../config/env";

export const SECURE_TOKEN_BYTES = 32;
export const CSRF_NONCE_BYTES = 16;

export const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
export const PHONE_VERIFICATION_TTL_MS = 10 * 60 * 1000; // 10 minutes
export const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000; // 30 minutes

const BASE64URL_TOKEN_REGEX = /^[A-Za-z0-9_-]+$/;
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
const CSRF_NONCE_HEX_REGEX = /^[0-9a-f]{32}$/;
const PHONE_OTP_REGEX = /^[0-9]{6}$/;

export interface GeneratedTokenPair {
  rawToken: string;
  tokenHash: string;
  expiresAt: Date;
}

export interface GeneratedPhoneOtpPair {
  rawOtp: string;
  tokenHash: string;
  expiresAt: Date;
}

/**
 * Generates a cryptographically secure random opaque token encoded as base64url.
 * Default: 32 bytes (256 bits of entropy -> 43 base64url characters).
 */
export function generateSecureToken(
  byteLength: number = SECURE_TOKEN_BYTES
): string {
  if (!Number.isInteger(byteLength) || byteLength < 16 || byteLength > 128) {
    throw new Error(
      "Token byteLength must be an integer between 16 and 128 bytes."
    );
  }
  return crypto.randomBytes(byteLength).toString("base64url");
}

/**
 * Validates that an input is a well-formed base64url opaque token of expected length.
 */
export function isValidOpaqueToken(
  token: unknown,
  minLength: number = 43,
  maxLength: number = 128
): token is string {
  return (
    typeof token === "string" &&
    token.length >= minLength &&
    token.length <= maxLength &&
    BASE64URL_TOKEN_REGEX.test(token)
  );
}

/**
 * Computes a lowercase 64-character SHA-256 hex digest of a raw token.
 * Only this hash is persisted in PostgreSQL.
 */
export function hashToken(rawToken: string): string {
  if (typeof rawToken !== "string" || rawToken.length === 0) {
    throw new Error("Raw token must be a non-empty string.");
  }
  return crypto.createHash("sha256").update(rawToken, "utf8").digest("hex");
}

/**
 * Checks whether a value is a canonical 64-character lowercase SHA-256 hex string.
 */
export function isValidSha256Hex(hash: unknown): hash is string {
  return typeof hash === "string" && SHA256_HEX_REGEX.test(hash);
}

/**
 * Compares two 64-character hexadecimal SHA-256 digests in constant time.
 * Validates format and equal 32-byte buffer lengths before calling crypto.timingSafeEqual().
 */
export function compareTokenHashes(hashA: unknown, hashB: unknown): boolean {
  if (!isValidSha256Hex(hashA) || !isValidSha256Hex(hashB)) {
    return false;
  }

  const bufA = Buffer.from(hashA, "hex");
  const bufB = Buffer.from(hashB, "hex");

  if (bufA.byteLength !== 32 || bufA.byteLength !== bufB.byteLength) {
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Generates an email verification token pair (raw base64url token + SHA-256 hash + 24h expiry).
 */
export function generateVerificationToken(
  ttlMs: number = EMAIL_VERIFICATION_TTL_MS,
  nowMs: number = Date.now()
): GeneratedTokenPair {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("Verification token TTL must be positive.");
  }
  const rawToken = generateSecureToken(SECURE_TOKEN_BYTES);
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(nowMs + ttlMs);
  return { rawToken, tokenHash, expiresAt };
}

/**
 * Generates a password reset token pair (raw base64url token + SHA-256 hash + 30m expiry).
 */
export function generatePasswordResetToken(
  ttlMs: number = PASSWORD_RESET_TTL_MS,
  nowMs: number = Date.now()
): GeneratedTokenPair {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("Password reset token TTL must be positive.");
  }
  const rawToken = generateSecureToken(SECURE_TOKEN_BYTES);
  const tokenHash = hashToken(rawToken);
  const expiresAt = new Date(nowMs + ttlMs);
  return { rawToken, tokenHash, expiresAt };
}

/**
 * Computes a domain-separated HMAC-SHA256 hash for a 6-digit phone verification OTP
 * bound to the target userId so 6-digit codes cannot be reversed via precomputed rainbow tables.
 */
export function hashPhoneOtp(
  userId: string,
  rawOtp: string,
  secret: string = env.sessionSecret
): string {
  if (!userId || typeof userId !== "string") {
    throw new Error("userId is required to hash phone OTP.");
  }
  if (!PHONE_OTP_REGEX.test(rawOtp)) {
    throw new Error("Phone OTP must be a 6-digit numeric string.");
  }
  return crypto
    .createHmac("sha256", secret)
    .update(`${userId}:PHONE:${rawOtp}`, "utf8")
    .digest("hex");
}

/**
 * Generates a 6-digit phone verification OTP and its domain-separated HMAC-SHA256 hash (10m expiry).
 */
export function generatePhoneVerificationOtp(
  userId: string,
  ttlMs: number = PHONE_VERIFICATION_TTL_MS,
  nowMs: number = Date.now(),
  secret: string = env.sessionSecret
): GeneratedPhoneOtpPair {
  const rawOtp = crypto.randomInt(100000, 1000000).toString();
  const tokenHash = hashPhoneOtp(userId, rawOtp, secret);
  const expiresAt = new Date(nowMs + ttlMs);
  return { rawOtp, tokenHash, expiresAt };
}

/**
 * Generates a 16-byte (32 hexadecimal character) cryptographic nonce for CSRF tokens.
 */
export function generateCsrfNonce(): string {
  return crypto.randomBytes(CSRF_NONCE_BYTES).toString("hex");
}

/**
 * Validates that a value is a 32-character lowercase hexadecimal CSRF nonce.
 */
export function isValidCsrfNonce(nonce: unknown): nonce is string {
  return typeof nonce === "string" && CSRF_NONCE_HEX_REGEX.test(nonce);
}
