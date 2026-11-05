import { NextFunction, Request, RequestHandler, Response } from "express";
import { db } from "../db/client";
import {
  CSRF_HEADER_NAME,
  CsrfBindingContext,
  isValidAnonymousCsrfContextId,
  validateRequestOrigin,
  verifyCsrfToken,
} from "../services/auth/csrf.service";
import { hashToken, isValidOpaqueToken } from "../services/auth/token.service";
import { validateSession } from "../services/auth/session.service";
import { DbExecutor, recordSecurityAudit } from "../services/auth/audit.service";
import {
  clearSessionCookie,
  getCsrfContextCookie,
  getSessionCookie,
} from "../utils/auth-cookie";
import { sendError } from "../utils/api-response";

const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function isLogoutEndpoint(req: Request): boolean {
  const url = (req.originalUrl || req.url || "").split("?")[0];
  return url === "/api/v1/auth/logout" || url.endsWith("/auth/logout");
}

/**
 * Resolves the active CSRF binding context for an incoming request:
 * - If `req.auth` is already populated, binds to `sess:${req.auth.session.tokenHash}`.
 * - Else if a valid `dsh_session` cookie is present, validates the session, attaches `req.auth`,
 *   and binds to `sess:${session.tokenHash}`.
 * - Else if a valid `dsh_csrf_ctx` cookie is present, binds to `anon:${dsh_csrf_ctx}`.
 */
export async function resolveRequestCsrfBinding(
  req: Request,
  res: Response,
  executor: DbExecutor = db
): Promise<CsrfBindingContext | null> {
  if (req.auth) {
    return {
      type: "sess",
      sessionTokenHash: req.auth.session.tokenHash,
    };
  }

  const rawSessionToken = getSessionCookie(req);
  if (rawSessionToken) {
    const sessionResult = await validateSession(
      rawSessionToken,
      {
        ipAddress: req.ip ?? null,
        auditFailures: false,
      },
      executor
    );
    if (sessionResult.valid) {
      req.auth = sessionResult.context;
      return {
        type: "sess",
        sessionTokenHash: sessionResult.context.session.tokenHash,
      };
    }

    // For idempotent logout, allow a valid CSRF token bound to the expired/revoked session cookie
    if (isLogoutEndpoint(req) && isValidOpaqueToken(rawSessionToken)) {
      return {
        type: "sess",
        sessionTokenHash: hashToken(rawSessionToken),
      };
    }

    clearSessionCookie(res);
  }

  const csrfContextId = getCsrfContextCookie(req);
  if (csrfContextId && isValidAnonymousCsrfContextId(csrfContextId)) {
    return {
      type: "anon",
      csrfContextId,
    };
  }

  return null;
}

export function createCsrfProtectionMiddleware(
  executor: DbExecutor = db
): RequestHandler {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const method = req.method.toUpperCase();
      if (SAFE_HTTP_METHODS.has(method)) {
        next();
        return;
      }

      if (!validateRequestOrigin(req)) {
        await recordSecurityAudit(
          {
            actorUserId: req.auth?.user.id ?? null,
            action: "auth.csrf.origin_rejected",
            entityType: "route",
            entityId: `${method} ${req.originalUrl}`,
            ipAddress: req.ip ?? null,
            metadata: {
              origin: req.headers.origin ?? null,
              referer: req.headers.referer ?? null,
            },
          },
          executor
        );

        sendError(
          res,
          403,
          "CSRF_ORIGIN_MISMATCH",
          "Request origin is not permitted."
        );
        return;
      }

      const binding = await resolveRequestCsrfBinding(req, res, executor);
      const headerToken = req.headers[CSRF_HEADER_NAME];
      const tokenValue = Array.isArray(headerToken)
        ? headerToken[0]
        : headerToken;

      let verification = verifyCsrfToken(tokenValue, binding);

      // If logout was called with an expired dsh_session AND an anonymous dsh_csrf_ctx cookie,
      // also check the anonymous binding if the session-hash binding did not match.
      if (!verification.valid && isLogoutEndpoint(req)) {
        const csrfContextId = getCsrfContextCookie(req);
        if (csrfContextId && isValidAnonymousCsrfContextId(csrfContextId)) {
          const anonVerification = verifyCsrfToken(tokenValue, {
            type: "anon",
            csrfContextId,
          });
          if (anonVerification.valid) {
            verification = anonVerification;
          }
        }
      }

      if (!verification.valid) {
        await recordSecurityAudit(
          {
            actorUserId: req.auth?.user.id ?? null,
            action: "auth.csrf.token_rejected",
            entityType: "route",
            entityId: `${method} ${req.originalUrl}`,
            ipAddress: req.ip ?? null,
            metadata: {
              reasonCode: verification.code,
              bindingType: binding?.type ?? "none",
            },
          },
          executor
        );

        sendError(res, 403, verification.code, verification.message);
        return;
      }

      next();
    } catch {
      sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
    }
  };
}

/**
 * Default Express CSRF protection middleware for cookie-authenticated routes.
 */
export const csrfProtection: RequestHandler =
  createCsrfProtectionMiddleware(db);
