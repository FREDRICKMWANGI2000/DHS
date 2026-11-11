import { NextFunction, Request, RequestHandler, Response } from "express";
import { db } from "../db/client";
import { DbExecutor, recordSecurityAudit } from "../services/auth/audit.service";
import { sendError } from "../utils/api-response";

export interface RateLimitEntry {
  count: number;
  resetAtMs: number;
}

/**
 * Replaceable rate-limit store abstraction.
 * Uses an in-memory store for single-instance deployment and can be swapped with a Redis or
 * PostgreSQL store when horizontal scaling is introduced.
 */
export interface RateLimitStore {
  increment(
    key: string,
    windowMs: number,
    nowMs?: number
  ): Promise<RateLimitEntry>;
  reset(key: string): Promise<void>;
  clearAll(): Promise<void>;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly buckets = new Map<string, RateLimitEntry>();

  public async increment(
    key: string,
    windowMs: number,
    nowMs: number = Date.now()
  ): Promise<RateLimitEntry> {
    const existing = this.buckets.get(key);
    if (!existing || existing.resetAtMs <= nowMs) {
      const fresh: RateLimitEntry = {
        count: 1,
        resetAtMs: nowMs + windowMs,
      };
      this.buckets.set(key, fresh);
      return fresh;
    }

    existing.count += 1;
    return existing;
  }

  public async reset(key: string): Promise<void> {
    this.buckets.delete(key);
  }

  public async clearAll(): Promise<void> {
    this.buckets.clear();
  }
}

export const defaultRateLimitStore = new MemoryRateLimitStore();

export const DEFAULT_AUTH_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
export const DEFAULT_REGISTER_IP_MAX = 5;
export const DEFAULT_LOGIN_IP_MAX = 10;
export const DEFAULT_LOGIN_IDENTIFIER_MAX = 5;
export const DEFAULT_VERIFY_EMAIL_IP_MAX = 10;
export const DEFAULT_RESEND_VERIFICATION_IP_MAX = 10;
export const DEFAULT_RESEND_VERIFICATION_USER_MAX = 3;
export const DEFAULT_VERIFY_PHONE_IP_MAX = 10;
export const DEFAULT_FORGOT_PASSWORD_IP_MAX = 5;
export const DEFAULT_RESET_PASSWORD_IP_MAX = 5;

/**
 * Safely extracts the client IP address using Express's `req.ip` (which only honors
 * `X-Forwarded-For` when `app.set('trust proxy', ...)` is explicitly configured).
 * Never reads raw `X-Forwarded-For` directly.
 */
export function getSafeClientIp(req: Request): string {
  if (typeof req.ip === "string" && req.ip.trim().length > 0) {
    return req.ip.trim();
  }
  const remoteAddr = req.socket?.remoteAddress;
  if (typeof remoteAddr === "string" && remoteAddr.trim().length > 0) {
    return remoteAddr.trim();
  }
  return "unknown";
}

export interface IpRateLimiterOptions {
  scope: string;
  windowMs?: number;
  maxRequests: number;
  store?: RateLimitStore;
  executor?: DbExecutor;
}

/**
 * Creates an Express IP-based rate-limiting middleware that runs BEFORE expensive Argon2id work.
 */
export function createIpRateLimiter(
  options: IpRateLimiterOptions
): RequestHandler {
  const windowMs = options.windowMs ?? DEFAULT_AUTH_WINDOW_MS;
  const maxRequests = options.maxRequests;
  const store = options.store ?? defaultRateLimitStore;
  const executor = options.executor ?? db;

  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const nowMs = Date.now();
      const clientIp = getSafeClientIp(req);
      const key = `ip:${options.scope}:${clientIp}`;

      const entry = await store.increment(key, windowMs, nowMs);
      const remaining = Math.max(0, maxRequests - entry.count);
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((entry.resetAtMs - nowMs) / 1000)
      );

      res.setHeader("RateLimit-Limit", String(maxRequests));
      res.setHeader("RateLimit-Remaining", String(remaining));
      res.setHeader("RateLimit-Reset", String(retryAfterSeconds));

      if (entry.count > maxRequests) {
        res.setHeader("Retry-After", String(retryAfterSeconds));

        await recordSecurityAudit(
          {
            actorUserId: req.auth?.user.id ?? null,
            action: "auth.rate_limit.exceeded",
            entityType: "rate_limit",
            entityId: options.scope,
            ipAddress: clientIp,
            metadata: {
              scope: options.scope,
              limitType: "ip",
              maxRequests,
              windowMs,
              retryAfterSeconds,
            },
          },
          executor
        );

        sendError(
          res,
          429,
          "RATE_LIMITED",
          "Too many requests. Please wait before trying again."
        );
        return;
      }

      next();
    } catch {
      sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
    }
  };
}

export interface IdentifierRateLimitCheckParams {
  scope: string;
  normalizedIdentifier: string;
  clientIp: string;
  windowMs?: number;
  maxRequests?: number;
  store?: RateLimitStore;
  executor?: DbExecutor;
}

export interface IdentifierRateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

/**
 * Evaluates an identifier-scoped rate limit (e.g., normalized email or E.164 phone number)
 * before performing Argon2id password verification.
 */
export async function checkIdentifierRateLimit(
  params: IdentifierRateLimitCheckParams
): Promise<IdentifierRateLimitResult> {
  const windowMs = params.windowMs ?? DEFAULT_AUTH_WINDOW_MS;
  const maxRequests = params.maxRequests ?? DEFAULT_LOGIN_IDENTIFIER_MAX;
  const store = params.store ?? defaultRateLimitStore;
  const executor = params.executor ?? db;
  const nowMs = Date.now();

  const key = `id:${params.scope}:${params.normalizedIdentifier}`;
  const entry = await store.increment(key, windowMs, nowMs);
  const retryAfterSeconds = Math.max(
    1,
    Math.ceil((entry.resetAtMs - nowMs) / 1000)
  );

  if (entry.count > maxRequests) {
    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.rate_limit.exceeded",
        entityType: "rate_limit",
        entityId: params.scope,
        ipAddress: params.clientIp,
        metadata: {
          scope: params.scope,
          limitType: "identifier",
          maxRequests,
          windowMs,
          retryAfterSeconds,
        },
      },
      executor
    );

    return {
      allowed: false,
      retryAfterSeconds,
    };
  }

  return {
    allowed: true,
    retryAfterSeconds,
  };
}
