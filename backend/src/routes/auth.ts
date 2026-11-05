import { Request, Response, Router } from "express";
import { db } from "../db/client";
import {
  createCsrfToken,
  CSRF_TOKEN_TTL_SECONDS,
  CsrfBindingContext,
  generateAnonymousCsrfContextId,
  isValidAnonymousCsrfContextId,
} from "../services/auth/csrf.service";
import { DbExecutor } from "../services/auth/audit.service";
import { validateSession } from "../services/auth/session.service";
import {
  clearCsrfContextCookie,
  clearSessionCookie,
  getCsrfContextCookie,
  getSessionCookie,
  setCsrfContextCookie,
} from "../utils/auth-cookie";

export function createAuthRouter(executor: DbExecutor = db): Router {
  const router = Router();

  /**
   * GET /api/v1/auth/csrf
   * Issues a cryptographically signed 30-minute CSRF token:
   * - Bound to `sess:${session.tokenHash}` if the caller holds an active `dsh_session` cookie.
   * - Bound to `anon:${sha256(dsh_csrf_ctx)}` (setting the HttpOnly `dsh_csrf_ctx` cookie) if unauthenticated.
   * - Sets `Cache-Control: no-store` and `Pragma: no-cache`.
   */
  router.get("/csrf", async (req: Request, res: Response): Promise<void> => {
    try {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Pragma", "no-cache");

      let binding: CsrfBindingContext | null = null;

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
          clearCsrfContextCookie(res);
          binding = {
            type: "sess",
            sessionTokenHash: sessionResult.context.session.tokenHash,
          };
        } else {
          clearSessionCookie(res);
        }
      }

      if (!binding) {
        let csrfContextId = getCsrfContextCookie(req);
        if (!csrfContextId || !isValidAnonymousCsrfContextId(csrfContextId)) {
          csrfContextId = generateAnonymousCsrfContextId();
        }
        setCsrfContextCookie(res, csrfContextId);
        binding = {
          type: "anon",
          csrfContextId,
        };
      }

      const csrfToken = createCsrfToken(binding);

      res.status(200).json({
        status: "ok",
        data: {
          csrfToken,
          expiresInSeconds: CSRF_TOKEN_TTL_SECONDS,
        },
      });
    } catch {
      res.status(500).json({
        status: "error",
        code: "INTERNAL_ERROR",
        message: "Internal server error",
      });
    }
  });

  return router;
}

export const authRouter = createAuthRouter(db);
