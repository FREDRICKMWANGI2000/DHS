import { CookieOptions, Request, Response } from "express";
import { env } from "../config/env";
import {
  getSessionDurationMs,
  UserRole,
} from "../services/auth/session.service";

export const SESSION_COOKIE_NAME = "dsh_session";
export const CSRF_CONTEXT_COOKIE_NAME = "dsh_csrf_ctx";
export const CSRF_COOKIE_MAX_AGE_MS = 30 * 60 * 1000; // 30 minutes (1800 seconds)

/**
 * Safely parses an HTTP `Cookie` request header into a key-value map.
 */
export function parseCookieHeader(
  cookieHeader: string | undefined
): Record<string, string> {
  const parsed: Record<string, string> = {};
  if (!cookieHeader || typeof cookieHeader !== "string") {
    return parsed;
  }

  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx <= 0) {
      continue;
    }
    const rawKey = pair.slice(0, eqIdx).trim();
    const rawVal = pair.slice(eqIdx + 1).trim();
    if (!rawKey) {
      continue;
    }
    try {
      parsed[rawKey] = decodeURIComponent(rawVal);
    } catch {
      parsed[rawKey] = rawVal;
    }
  }

  return parsed;
}

/**
 * Builds the canonical base security attributes for DSH authentication cookies:
 * - HttpOnly: true
 * - SameSite: "lax"
 * - Path: "/"
 * - Secure: true in production, false for local HTTP development
 * - No Domain attribute (strictly host-only)
 */
export function getBaseAuthCookieOptions(
  nodeEnv: string = env.nodeEnv
): CookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: nodeEnv === "production",
  };
}

/**
 * Sets the `dsh_session` HttpOnly cookie with a maxAge matching the user's role TTL
 * (or an explicit duration in milliseconds).
 */
export function setSessionCookie(
  res: Response,
  rawToken: string,
  roleOrMaxAgeMs: UserRole | number,
  nodeEnv: string = env.nodeEnv
): void {
  const maxAge =
    typeof roleOrMaxAgeMs === "number"
      ? roleOrMaxAgeMs
      : getSessionDurationMs(roleOrMaxAgeMs);

  res.cookie(SESSION_COOKIE_NAME, rawToken, {
    ...getBaseAuthCookieOptions(nodeEnv),
    maxAge,
  });
}

/**
 * Clears the `dsh_session` cookie using identical Path, SameSite, HttpOnly, and Secure attributes.
 */
export function clearSessionCookie(
  res: Response,
  nodeEnv: string = env.nodeEnv
): void {
  res.clearCookie(SESSION_COOKIE_NAME, getBaseAuthCookieOptions(nodeEnv));
}

/**
 * Reads the raw `dsh_session` token from the incoming request's `Cookie` header.
 */
export function getSessionCookie(req: Request): string | null {
  const cookies = parseCookieHeader(req.headers.cookie);
  const value = cookies[SESSION_COOKIE_NAME];
  return typeof value === "string" && value.length > 0 ? value : null;
}

/**
 * Sets the pre-authentication CSRF browser binding cookie `dsh_csrf_ctx` (30-minute maxAge).
 */
export function setCsrfContextCookie(
  res: Response,
  contextId: string,
  nodeEnv: string = env.nodeEnv
): void {
  res.cookie(CSRF_CONTEXT_COOKIE_NAME, contextId, {
    ...getBaseAuthCookieOptions(nodeEnv),
    maxAge: CSRF_COOKIE_MAX_AGE_MS,
  });
}

/**
 * Clears the `dsh_csrf_ctx` pre-authentication CSRF context cookie.
 */
export function clearCsrfContextCookie(
  res: Response,
  nodeEnv: string = env.nodeEnv
): void {
  res.clearCookie(CSRF_CONTEXT_COOKIE_NAME, getBaseAuthCookieOptions(nodeEnv));
}

/**
 * Reads the `dsh_csrf_ctx` pre-authentication CSRF context ID from the incoming request.
 */
export function getCsrfContextCookie(req: Request): string | null {
  const cookies = parseCookieHeader(req.headers.cookie);
  const value = cookies[CSRF_CONTEXT_COOKIE_NAME];
  return typeof value === "string" && value.length > 0 ? value : null;
}
