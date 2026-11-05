import * as crypto from "crypto";
import { Request } from "express";
import { env } from "../../config/env";
import {
  generateCsrfNonce,
  generateSecureToken,
  hashToken,
  isValidCsrfNonce,
  isValidOpaqueToken,
  isValidSha256Hex,
  SECURE_TOKEN_BYTES,
} from "./token.service";

export const CSRF_TOKEN_TTL_MS = 30 * 60 * 1000; // 30 minutes
export const CSRF_TOKEN_TTL_SECONDS = 1800;
export const CSRF_CLOCK_SKEW_TOLERANCE_MS = 60 * 1000; // 60 seconds
export const CSRF_HEADER_NAME = "x-csrf-token";

export type CsrfBindingContext =
  | {
      type: "sess";
      sessionTokenHash: string;
    }
  | {
      type: "anon";
      csrfContextId: string;
    };

export type CsrfErrorCode =
  | "CSRF_ORIGIN_MISMATCH"
  | "CSRF_TOKEN_MISSING"
  | "CSRF_TOKEN_INVALID"
  | "CSRF_TOKEN_EXPIRED";

export type CsrfVerificationResult =
  | {
      valid: true;
      issuedAtMs: number;
    }
  | {
      valid: false;
      code: CsrfErrorCode;
      message: string;
    };

/**
 * Generates a cryptographically random 32-byte base64url anonymous CSRF context identifier
 * to be stored in the `dsh_csrf_ctx` HttpOnly cookie.
 */
export function generateAnonymousCsrfContextId(): string {
  return generateSecureToken(SECURE_TOKEN_BYTES);
}

export function isValidAnonymousCsrfContextId(
  contextId: unknown
): contextId is string {
  return isValidOpaqueToken(contextId);
}

/**
 * Computes the canonical HMAC-SHA256 signature for a CSRF token:
 * - Authenticated: HMAC_SHA256(SESSION_SECRET, "sess:" + session.tokenHash + ":" + nonce + ":" + issuedAtUnixMs)
 * - Anonymous:     HMAC_SHA256(SESSION_SECRET, "anon:" + sha256(dsh_csrf_ctx) + ":" + nonce + ":" + issuedAtUnixMs)
 */
export function computeCsrfHmac(
  binding: CsrfBindingContext,
  nonce: string,
  issuedAtUnixMs: number,
  secret: string = env.sessionSecret
): string {
  let payload: string;
  if (binding.type === "sess") {
    if (!isValidSha256Hex(binding.sessionTokenHash)) {
      throw new Error(
        "Authenticated CSRF binding requires a valid 64-char SHA-256 sessionTokenHash."
      );
    }
    payload = `sess:${binding.sessionTokenHash}:${nonce}:${issuedAtUnixMs}`;
  } else {
    if (!isValidAnonymousCsrfContextId(binding.csrfContextId)) {
      throw new Error(
        "Anonymous CSRF binding requires a valid csrfContextId."
      );
    }
    const ctxHash = hashToken(binding.csrfContextId);
    payload = `anon:${ctxHash}:${nonce}:${issuedAtUnixMs}`;
  }

  return crypto
    .createHmac("sha256", secret)
    .update(payload, "utf8")
    .digest("hex");
}

/**
 * Creates a signed 3-part CSRF token (`<nonce>.<issuedAtUnixMs>.<hmacHex>`) bound to either
 * an authenticated session (`session.tokenHash`) or an anonymous browser context (`dsh_csrf_ctx`).
 */
export function createCsrfToken(
  binding: CsrfBindingContext,
  nowMs: number = Date.now(),
  secret: string = env.sessionSecret
): string {
  const nonce = generateCsrfNonce();
  const issuedAtUnixMs = Math.floor(nowMs);
  const hmacHex = computeCsrfHmac(binding, nonce, issuedAtUnixMs, secret);
  return `${nonce}.${issuedAtUnixMs}.${hmacHex}`;
}

/**
 * Verifies a submitted CSRF token against the caller's current authentication or anonymous cookie binding:
 * 1. Validates 3-part format (`<32-hex-nonce>.<timestamp-ms>.<64-hex-hmac>`).
 * 2. Recomputes expected HMAC-SHA256 for the current binding context.
 * 3. Validates equal 32-byte buffer lengths before calling `crypto.timingSafeEqual()`.
 * 4. Enforces the 30-minute CSRF token TTL (`CSRF_TOKEN_EXPIRED`).
 */
export function verifyCsrfToken(
  token: unknown,
  binding: CsrfBindingContext | null,
  nowMs: number = Date.now(),
  secret: string = env.sessionSecret
): CsrfVerificationResult {
  if (typeof token !== "string" || token.trim().length === 0) {
    return {
      valid: false,
      code: "CSRF_TOKEN_MISSING",
      message: "Missing X-CSRF-Token header.",
    };
  }

  if (!binding) {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Missing CSRF binding context.",
    };
  }

  const parts = token.split(".");
  if (parts.length !== 3) {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Invalid CSRF token format.",
    };
  }

  const [nonce, issuedAtStr, providedHmacHex] = parts;

  if (
    !isValidCsrfNonce(nonce) ||
    !/^[0-9]{10,15}$/.test(issuedAtStr) ||
    !isValidSha256Hex(providedHmacHex)
  ) {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Malformed CSRF token components.",
    };
  }

  const issuedAtMs = Number(issuedAtStr);
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0) {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Invalid CSRF token timestamp.",
    };
  }

  let expectedHmacHex: string;
  try {
    expectedHmacHex = computeCsrfHmac(binding, nonce, issuedAtMs, secret);
  } catch {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Invalid CSRF binding context.",
    };
  }

  const providedBuf = Buffer.from(providedHmacHex, "hex");
  const expectedBuf = Buffer.from(expectedHmacHex, "hex");

  if (
    providedBuf.byteLength !== 32 ||
    providedBuf.byteLength !== expectedBuf.byteLength ||
    !crypto.timingSafeEqual(providedBuf, expectedBuf)
  ) {
    return {
      valid: false,
      code: "CSRF_TOKEN_INVALID",
      message: "Invalid CSRF token signature.",
    };
  }

  const ageMs = nowMs - issuedAtMs;
  if (ageMs > CSRF_TOKEN_TTL_MS || ageMs < -CSRF_CLOCK_SKEW_TOLERANCE_MS) {
    return {
      valid: false,
      code: "CSRF_TOKEN_EXPIRED",
      message: "CSRF token has expired. Please refresh the token and try again.",
    };
  }

  return {
    valid: true,
    issuedAtMs,
  };
}

/**
 * Extracts and normalizes the request origin from `Origin` header (or `Referer` fallback)
 * and verifies that it strictly matches the configured trusted `frontendUrl`.
 */
export function validateRequestOrigin(
  req: Pick<Request, "headers">,
  allowedFrontendUrl: string = env.frontendUrl
): boolean {
  let allowedOrigin: string;
  try {
    allowedOrigin = new URL(allowedFrontendUrl).origin;
  } catch {
    return false;
  }

  const rawOrigin = req.headers.origin;
  if (typeof rawOrigin === "string" && rawOrigin.trim().length > 0) {
    try {
      return new URL(rawOrigin.trim()).origin === allowedOrigin;
    } catch {
      return false;
    }
  }

  const rawReferer = req.headers.referer;
  if (typeof rawReferer === "string" && rawReferer.trim().length > 0) {
    try {
      return new URL(rawReferer.trim()).origin === allowedOrigin;
    } catch {
      return false;
    }
  }

  return false;
}
