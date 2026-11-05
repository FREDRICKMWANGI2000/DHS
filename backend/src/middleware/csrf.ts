import { NextFunction, Request, RequestHandler, Response } from "express";
import { db } from "../db/client";
import {
  CSRF_HEADER_NAME,
  CsrfBindingContext,
  isValidAnonymousCsrfContextId,
  validateRequestOrigin,
  verifyCsrfToken,
} from "../services/auth/csrf.service";
import { validateSession } from "../services/auth/session.service";
import { DbExecutor, recordSecurityAudit } from "../services/auth/audit.service";
import {
  clearSessionCookie,
  getCsrfContextCookie,
  getSessionCookie,
} from "../utils/auth-cookie";

const SAFE_HTTP_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

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

        res.status(403).json({
          status: "error",
          code: "CSRF_ORIGIN_MISMATCH",
          message: "Request origin is not permitted.",
        });
        return;
      }

      const binding = await resolveRequestCsrfBinding(req, res, executor);
      const headerToken = req.headers[CSRF_HEADER_NAME];
      const tokenValue = Array.isArray(headerToken)
        ? headerToken[0]
        : headerToken;

      const verification = verifyCsrfToken(tokenValue, binding);
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

        res.status(403).json({
          status: "error",
          code: verification.code,
          message: verification.message,
        });
        return;
      }

      next();
    } catch {
      res.status(500).json({
        status: "error",
        code: "INTERNAL_ERROR",
        message: "Internal server error",
      });
    }
  };
}

/**
 * Default Express CSRF protection middleware for cookie-authenticated routes.
 */
export const csrfProtection: RequestHandler =
  createCsrfProtectionMiddleware(db);
