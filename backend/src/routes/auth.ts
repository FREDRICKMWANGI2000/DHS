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
  AuthDomainError,
  loginUser,
  logoutAllUserSessions,
  logoutCurrentSession,
  registerCustomer,
  toPublicUserDto,
} from "../services/auth/auth.service";
import {
  DEFAULT_FORGOT_PASSWORD_IDENTIFIER_MAX,
  requestPasswordReset,
  resetPasswordWithToken,
} from "../services/auth/password-recovery.service";
import {
  DEFAULT_MAX_PHONE_OTP_ATTEMPTS,
  DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS,
  resendVerificationForUser,
  verifyEmailToken,
  verifyPhoneOtp,
} from "../services/auth/verification.service";
import {
  defaultEmailDeliveryProvider,
  EmailDeliveryProvider,
} from "../services/email";
import {
  defaultSmsDeliveryProvider,
  SmsDeliveryProvider,
} from "../services/sms";
import { createAuthenticateMiddleware } from "../middleware/authenticate";
import {
  checkIdentifierRateLimit,
  createIpRateLimiter,
  DEFAULT_AUTH_WINDOW_MS,
  DEFAULT_FORGOT_PASSWORD_IP_MAX,
  DEFAULT_LOGIN_IDENTIFIER_MAX,
  DEFAULT_LOGIN_IP_MAX,
  DEFAULT_REGISTER_IP_MAX,
  DEFAULT_RESEND_VERIFICATION_IP_MAX,
  DEFAULT_RESEND_VERIFICATION_USER_MAX,
  DEFAULT_RESET_PASSWORD_IP_MAX,
  DEFAULT_VERIFY_EMAIL_IP_MAX,
  DEFAULT_VERIFY_PHONE_IP_MAX,
  defaultRateLimitStore,
  getSafeClientIp,
  RateLimitStore,
} from "../middleware/rate-limit";
import {
  clearCsrfContextCookie,
  clearSessionCookie,
  getCsrfContextCookie,
  getSessionCookie,
  setCsrfContextCookie,
  setSessionCookie,
} from "../utils/auth-cookie";
import { sendError, sendSuccess } from "../utils/api-response";

export interface AuthRouterOptions {
  executor?: DbExecutor;
  rateLimitStore?: RateLimitStore;
  emailProvider?: EmailDeliveryProvider;
  smsProvider?: SmsDeliveryProvider;
  registerIpMax?: number;
  loginIpMax?: number;
  loginIdentifierMax?: number;
  verifyEmailIpMax?: number;
  resendVerificationIpMax?: number;
  resendVerificationUserMax?: number;
  verifyPhoneIpMax?: number;
  forgotPasswordIpMax?: number;
  forgotPasswordIdentifierMax?: number;
  resetPasswordIpMax?: number;
  verificationCooldownMs?: number;
  maxPhoneOtpAttempts?: number;
  rateLimitWindowMs?: number;
}

export function createAuthRouter(
  executorOrOptions: DbExecutor | AuthRouterOptions = db
): Router {
  const isOptionsObject =
    executorOrOptions !== null &&
    typeof executorOrOptions === "object" &&
    !("select" in executorOrOptions);

  const options: AuthRouterOptions = isOptionsObject
    ? (executorOrOptions as AuthRouterOptions)
    : { executor: executorOrOptions as DbExecutor };

  const executor = options.executor ?? db;
  const rateLimitStore = options.rateLimitStore ?? defaultRateLimitStore;
  const emailProvider = options.emailProvider ?? defaultEmailDeliveryProvider;
  const smsProvider = options.smsProvider ?? defaultSmsDeliveryProvider;
  const windowMs = options.rateLimitWindowMs ?? DEFAULT_AUTH_WINDOW_MS;

  const router = Router();
  const requireAuth = createAuthenticateMiddleware(executor);

  const registerIpLimiter = createIpRateLimiter({
    scope: "auth:register:ip",
    maxRequests: options.registerIpMax ?? DEFAULT_REGISTER_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const loginIpLimiter = createIpRateLimiter({
    scope: "auth:login:ip",
    maxRequests: options.loginIpMax ?? DEFAULT_LOGIN_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const verifyEmailIpLimiter = createIpRateLimiter({
    scope: "auth:verify_email:ip",
    maxRequests: options.verifyEmailIpMax ?? DEFAULT_VERIFY_EMAIL_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const resendVerificationIpLimiter = createIpRateLimiter({
    scope: "auth:resend_verification:ip",
    maxRequests:
      options.resendVerificationIpMax ?? DEFAULT_RESEND_VERIFICATION_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const verifyPhoneIpLimiter = createIpRateLimiter({
    scope: "auth:verify_phone:ip",
    maxRequests: options.verifyPhoneIpMax ?? DEFAULT_VERIFY_PHONE_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const forgotPasswordIpLimiter = createIpRateLimiter({
    scope: "auth:forgot_password:ip",
    maxRequests: options.forgotPasswordIpMax ?? DEFAULT_FORGOT_PASSWORD_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

  const resetPasswordIpLimiter = createIpRateLimiter({
    scope: "auth:reset_password:ip",
    maxRequests: options.resetPasswordIpMax ?? DEFAULT_RESET_PASSWORD_IP_MAX,
    windowMs,
    store: rateLimitStore,
    executor,
  });

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
            ipAddress: getSafeClientIp(req),
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

      sendSuccess(res, 200, {
        csrfToken,
        expiresInSeconds: CSRF_TOKEN_TTL_SECONDS,
      });
    } catch {
      sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
    }
  });

  /**
   * POST /api/v1/auth/register
   * Public customer registration endpoint.
   * - Protected by CSRF middleware and IP rate limiting before Argon2id hashing.
   * - Always creates a CUSTOMER account with ACTIVE status inside an atomic transaction.
   * - Sets `dsh_session` HttpOnly cookie, clears `dsh_csrf_ctx`, and instructs frontend
   *   to obtain a session-bound CSRF token via `GET /api/v1/auth/csrf`.
   */
  router.post(
    "/register",
    registerIpLimiter,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await registerCustomer(
          req.body,
          {
            ipAddress: getSafeClientIp(req),
            userAgent: req.headers["user-agent"] ?? null,
            priorRawSessionToken: getSessionCookie(req),
          },
          executor
        );

        setSessionCookie(res, result.rawSessionToken, result.role);
        clearCsrfContextCookie(res);

        sendSuccess(res, 201, {
          user: result.user,
          csrfRefreshRequired: true,
          csrfEndpoint: "/api/v1/auth/csrf",
        });
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/login
   * Public customer/staff/admin login endpoint.
   * - Protected by CSRF middleware, IP rate limiter, and normalized identifier rate limiter.
   * - Supports normalized email or Kenyan E.164 phone number.
   * - Uses constant-time dummy Argon2id verification when user does not exist.
   * - Rotates session (revoking any presented prior session cookie), updates `last_login_at`,
   *   sets `dsh_session` HttpOnly cookie, and clears `dsh_csrf_ctx`.
   */
  router.post(
    "/login",
    loginIpLimiter,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await loginUser(
          req.body,
          {
            ipAddress: getSafeClientIp(req),
            userAgent: req.headers["user-agent"] ?? null,
            priorRawSessionToken: getSessionCookie(req),
            rateLimitStore,
            identifierMaxRequests:
              options.loginIdentifierMax ?? DEFAULT_LOGIN_IDENTIFIER_MAX,
            identifierWindowMs: windowMs,
          },
          executor
        );

        setSessionCookie(res, result.rawSessionToken, result.role);
        clearCsrfContextCookie(res);

        sendSuccess(res, 200, {
          user: result.user,
          csrfRefreshRequired: true,
          csrfEndpoint: "/api/v1/auth/csrf",
        });
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/logout
   * Idempotent single-session logout endpoint.
   * - Protected by CSRF middleware.
   * - Revokes the current database session if active.
   * - Always clears `dsh_session` and `dsh_csrf_ctx` cookies, even if the session had already expired.
   */
  router.post(
    "/logout",
    async (req: Request, res: Response): Promise<void> => {
      try {
        const rawSessionToken = getSessionCookie(req);
        await logoutCurrentSession(
          rawSessionToken,
          getSafeClientIp(req),
          executor
        );

        clearSessionCookie(res);
        clearCsrfContextCookie(res);

        sendSuccess(res, 200, {
          loggedOut: true,
          csrfRefreshRequired: true,
          csrfEndpoint: "/api/v1/auth/csrf",
        });
      } catch {
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/logout-all
   * Authenticated global session revocation endpoint.
   * - Requires active session (`requireAuth`) and valid CSRF token.
   * - Revokes all active sessions for the current authenticated user inside a DB transaction.
   * - Clears `dsh_session` and `dsh_csrf_ctx` cookies.
   */
  router.post(
    "/logout-all",
    requireAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const userId = req.auth!.user.id;
        await logoutAllUserSessions(
          userId,
          getSafeClientIp(req),
          executor
        );

        clearSessionCookie(res);
        clearCsrfContextCookie(res);

        sendSuccess(res, 200, {
          loggedOut: true,
          csrfRefreshRequired: true,
          csrfEndpoint: "/api/v1/auth/csrf",
        });
      } catch {
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * GET /api/v1/auth/me
   * Returns the current authenticated user's safe profile representation.
   */
  router.get(
    "/me",
    requireAuth,
    (req: Request, res: Response): void => {
      const safeUser = toPublicUserDto(req.auth!.user);
      sendSuccess(res, 200, {
        user: safeUser,
      });
    }
  );

  /**
   * POST /api/v1/auth/verify-email
   * Consumes a single-use 32-byte email verification token (`verification_type = 'EMAIL'`)
   * and marks `users.email_verified_at` atomically.
   */
  router.post(
    "/verify-email",
    verifyEmailIpLimiter,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await verifyEmailToken(
          req.body,
          {
            ipAddress: getSafeClientIp(req),
          },
          executor
        );

        sendSuccess(res, 200, result);
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/resend-verification
   * Authenticated endpoint to request a fresh email verification link or phone verification OTP.
   * - Enforces that customers can only request verification for their own account.
   * - Applies per-IP and per-user rate limits plus per-user resend cooldown.
   * - Invalidates prior unused tokens when issuing a new token.
   */
  router.post(
    "/resend-verification",
    resendVerificationIpLimiter,
    requireAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const actorUser = req.auth!.user;
        const clientIp = getSafeClientIp(req);

        const userLimit = await checkIdentifierRateLimit({
          scope: "auth:resend_verification:user",
          normalizedIdentifier: actorUser.id,
          clientIp,
          maxRequests:
            options.resendVerificationUserMax ??
            DEFAULT_RESEND_VERIFICATION_USER_MAX,
          windowMs,
          store: rateLimitStore,
          executor,
        });

        if (!userLimit.allowed) {
          res.setHeader("Retry-After", String(userLimit.retryAfterSeconds));
          sendError(
            res,
            429,
            "RATE_LIMITED",
            "Too many verification requests. Please wait before trying again."
          );
          return;
        }

        const result = await resendVerificationForUser(
          actorUser,
          req.body,
          {
            ipAddress: clientIp,
            emailProvider,
            smsProvider,
            cooldownMs:
              options.verificationCooldownMs ??
              DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS,
          },
          executor
        );

        sendSuccess(res, 200, result);
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/verify-phone
   * Authenticated endpoint to verify a 6-digit phone OTP (`verification_type = 'PHONE'`).
   * - Enforces per-token attempt limits and 10-minute expiry.
   */
  router.post(
    "/verify-phone",
    verifyPhoneIpLimiter,
    requireAuth,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await verifyPhoneOtp(
          req.auth!.user,
          req.body,
          {
            ipAddress: getSafeClientIp(req),
            maxOtpAttempts:
              options.maxPhoneOtpAttempts ?? DEFAULT_MAX_PHONE_OTP_ATTEMPTS,
          },
          executor
        );

        sendSuccess(res, 200, result);
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/forgot-password
   * Public password recovery request endpoint.
   * - Applies IP and normalized-identifier rate limiting before database lookup.
   * - Always returns HTTP 200 with a generic response to prevent account enumeration.
   */
  router.post(
    "/forgot-password",
    forgotPasswordIpLimiter,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await requestPasswordReset(
          req.body,
          {
            ipAddress: getSafeClientIp(req),
            emailProvider,
            smsProvider,
            rateLimitStore,
            identifierMaxRequests:
              options.forgotPasswordIdentifierMax ??
              DEFAULT_FORGOT_PASSWORD_IDENTIFIER_MAX,
            identifierWindowMs: windowMs,
          },
          executor
        );

        sendSuccess(res, 200, result);
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  /**
   * POST /api/v1/auth/reset-password
   * Public password reset completion endpoint.
   * - Validates new password policy, hashes with Argon2id, consumes single-use reset token
   *   atomically (`FOR UPDATE`), updates `users.password_hash`, and revokes all active user sessions.
   * - Does not create a new authenticated session automatically.
   */
  router.post(
    "/reset-password",
    resetPasswordIpLimiter,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const result = await resetPasswordWithToken(
          req.body,
          {
            ipAddress: getSafeClientIp(req),
          },
          executor
        );

        clearSessionCookie(res);

        sendSuccess(res, 200, result);
      } catch (err: unknown) {
        if (err instanceof AuthDomainError) {
          if (err.retryAfterSeconds) {
            res.setHeader("Retry-After", String(err.retryAfterSeconds));
          }
          sendError(res, err.statusCode, err.code, err.message);
          return;
        }
        sendError(res, 500, "INTERNAL_ERROR", "Internal server error");
      }
    }
  );

  return router;
}

export const authRouter = createAuthRouter(db);
