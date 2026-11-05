import { NextFunction, Request, RequestHandler, Response } from "express";
import { db } from "../db/client";
import {
  AuthenticatedSessionContext,
  UserRole,
  validateSession,
} from "../services/auth/session.service";
import { DbExecutor, recordSecurityAudit } from "../services/auth/audit.service";
import { clearSessionCookie, getSessionCookie } from "../utils/auth-cookie";
import { sendError } from "../utils/api-response";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthenticatedSessionContext;
    }
  }
}

export function createAuthenticateMiddleware(
  executor: DbExecutor = db
): RequestHandler {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const rawToken = getSessionCookie(req);
      if (!rawToken) {
        sendError(res, 401, "UNAUTHENTICATED", "Authentication required.");
        return;
      }

      const result = await validateSession(
        rawToken,
        {
          ipAddress: req.ip ?? null,
          auditFailures: true,
        },
        executor
      );

      if (!result.valid) {
        clearSessionCookie(res);

        if (result.reason === "ACCOUNT_DISABLED") {
          sendError(
            res,
            403,
            "ACCOUNT_DISABLED",
            "Account is disabled. Please contact support."
          );
          return;
        }

        sendError(res, 401, "UNAUTHENTICATED", "Invalid or expired session.");
        return;
      }

      req.auth = result.context;
      next();
    } catch {
      sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
    }
  };
}

/**
 * Primary authentication middleware (`authenticate` / `requireAuth`).
 */
export const authenticate: RequestHandler = createAuthenticateMiddleware(db);
export const requireAuth: RequestHandler = authenticate;

export function createOptionalAuthenticateMiddleware(
  executor: DbExecutor = db
): RequestHandler {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const rawToken = getSessionCookie(req);
      if (!rawToken) {
        next();
        return;
      }

      const result = await validateSession(
        rawToken,
        {
          ipAddress: req.ip ?? null,
          auditFailures: false,
        },
        executor
      );

      if (result.valid) {
        req.auth = result.context;
      } else {
        clearSessionCookie(res);
      }

      next();
    } catch {
      next();
    }
  };
}

export const optionalAuthenticate: RequestHandler =
  createOptionalAuthenticateMiddleware(db);

/**
 * Separate role-based access control (RBAC) middleware (`requireRole`).
 * Evaluates the authenticated user's database role (`req.auth.user.role`), never trusting browser claims.
 */
export function requireRole(
  ...allowedRoles: UserRole[]
): RequestHandler {
  return createRequireRoleMiddleware(allowedRoles, db);
}

export function createRequireRoleMiddleware(
  allowedRoles: ReadonlyArray<UserRole>,
  executor: DbExecutor = db
): RequestHandler {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.auth) {
        sendError(res, 401, "UNAUTHENTICATED", "Authentication required.");
        return;
      }

      const currentRole = req.auth.user.role;
      if (!allowedRoles.includes(currentRole)) {
        await recordSecurityAudit(
          {
            actorUserId: req.auth.user.id,
            action: "auth.rbac.denied",
            entityType: "route",
            entityId: `${req.method} ${req.originalUrl}`,
            ipAddress: req.ip ?? null,
            metadata: {
              userRole: currentRole,
              requiredRoles: allowedRoles,
            },
          },
          executor
        );

        sendError(
          res,
          403,
          "FORBIDDEN",
          "Insufficient permissions for this operation."
        );
        return;
      }

      next();
    } catch {
      sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
    }
  };
}
