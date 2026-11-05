import { eq, or } from "drizzle-orm";
import { db } from "../../db/client";
import { users, User } from "../../db/schema";
import {
  hashPassword,
  verifyAgainstDummyPasswordHash,
  verifyPassword,
} from "./password.service";
import {
  createSession,
  CreatedSessionResult,
  invalidateAllSessionsOnLogoutAll,
  invalidateSessionOnLogout,
  SafeAuthenticatedUser,
  UserRole,
} from "./session.service";
import { DbExecutor, recordSecurityAudit } from "./audit.service";
import {
  normalizeLoginIdentifier,
  parseAndNormalizeRegisterInput,
  parseLoginInput,
} from "./auth.schemas";
import {
  checkIdentifierRateLimit,
  RateLimitStore,
} from "../../middleware/rate-limit";

export const GENERIC_REGISTRATION_REJECTED_MESSAGE =
  "Unable to complete registration with the provided details. If you already have an account, please sign in or use password recovery.";

export const GENERIC_INVALID_CREDENTIALS_MESSAGE =
  "Unable to sign in with the provided credentials.";

/**
 * Safe public user representation returned by `/register`, `/login`, and `/me`.
 * Never includes `passwordHash`, raw tokens, token hashes, or secrets.
 */
export interface PublicUserDto {
  id: string;
  firstName: string;
  lastName: string;
  email: string | null;
  phoneNumber: string | null;
  role: UserRole;
  status: User["status"];
  emailVerifiedAt: string | null;
  phoneVerifiedAt: string | null;
  createdAt: string;
}

export function toPublicUserDto(
  user: SafeAuthenticatedUser | User
): PublicUserDto {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email ?? null,
    phoneNumber: user.phoneNumber ?? null,
    role: user.role,
    status: user.status,
    emailVerifiedAt: user.emailVerifiedAt
      ? user.emailVerifiedAt.toISOString()
      : null,
    phoneVerifiedAt: user.phoneVerifiedAt
      ? user.phoneVerifiedAt.toISOString()
      : null,
    createdAt: user.createdAt.toISOString(),
  };
}

export class AuthDomainError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly retryAfterSeconds?: number;

  constructor(
    statusCode: number,
    code: string,
    message: string,
    retryAfterSeconds?: number
  ) {
    super(message);
    this.name = "AuthDomainError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

function isPgUniqueViolation(err: unknown): boolean {
  if (!err || typeof err !== "object") {
    return false;
  }
  const pgErr = err as { code?: unknown; cause?: { code?: unknown } };
  return pgErr.code === "23505" || pgErr.cause?.code === "23505";
}

export interface RegisterRequestContext {
  ipAddress: string;
  userAgent?: string | null;
  priorRawSessionToken?: string | null;
  /**
   * Optional test hook allowing integration tests to simulate a failure inside the
   * registration transaction after user insert to verify atomic transaction rollback.
   */
  beforeSessionCommitHook?: (tx: DbExecutor, userId: string) => Promise<void>;
}

export interface RegisterSuccessResult {
  user: PublicUserDto;
  rawSessionToken: string;
  role: UserRole;
}

/**
 * Registers a new CUSTOMER account and creates an authenticated session atomically.
 * - Validates & normalizes email and E.164 phone number via Zod + canonical normalizers.
 * - Hashes password with Argon2id BEFORE duplicate branching to prevent timing enumeration.
 * - Strictly creates `role = 'CUSTOMER'` and `status = 'ACTIVE'`, ignoring any client role input.
 * - Wraps user creation and session creation in a single PostgreSQL transaction (or SAVEPOINT).
 * - Handles duplicate email/phone or concurrent `23505` unique conflicts with a uniform generic response.
 */
export async function registerCustomer(
  rawBody: unknown,
  context: RegisterRequestContext,
  executor: DbExecutor = db
): Promise<RegisterSuccessResult> {
  const parsed = parseAndNormalizeRegisterInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const {
    firstName,
    lastName,
    email,
    phoneNumber,
    password,
    attemptedPrivilegedFields,
  } = parsed.data;

  // Compute Argon2id password hash before duplicate checks so response timing is uniform
  const passwordHash = await hashPassword(password);

  // Check for existing duplicate email or phone number
  const duplicateConditions = [];
  if (email) {
    duplicateConditions.push(eq(users.email, email));
  }
  if (phoneNumber) {
    duplicateConditions.push(eq(users.phoneNumber, phoneNumber));
  }

  const existingUsers = await executor
    .select({
      id: users.id,
      email: users.email,
      phoneNumber: users.phoneNumber,
    })
    .from(users)
    .where(
      duplicateConditions.length === 1
        ? duplicateConditions[0]
        : or(...duplicateConditions)
    )
    .limit(1);

  if (existingUsers.length > 0) {
    const existing = existingUsers[0];
    const conflictField =
      email && existing.email === email ? "email" : "phoneNumber";

    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.register.conflict",
        entityType: "user",
        entityId: existing.id,
        ipAddress: context.ipAddress,
        metadata: {
          conflictField,
          attemptedPrivilegedFields,
        },
      },
      executor
    );

    throw new AuthDomainError(
      400,
      "REGISTRATION_REJECTED",
      GENERIC_REGISTRATION_REJECTED_MESSAGE
    );
  }

  try {
    const { createdUser, createdSession } = await executor.transaction(
      async (tx) => {
        const txExecutor = tx as unknown as DbExecutor;

        const [insertedUser] = await txExecutor
          .insert(users)
          .values({
            firstName,
            lastName,
            email,
            phoneNumber,
            passwordHash,
            role: "CUSTOMER",
            status: "ACTIVE",
            emailVerifiedAt: null,
            phoneVerifiedAt: null,
            lastLoginAt: new Date(),
          })
          .returning();

        if (context.beforeSessionCommitHook) {
          await context.beforeSessionCommitHook(txExecutor, insertedUser.id);
        }

        const sessionResult: CreatedSessionResult = await createSession(
          {
            userId: insertedUser.id,
            ipAddress: context.ipAddress,
            userAgent: context.userAgent ?? null,
            priorRawToken: context.priorRawSessionToken ?? null,
          },
          txExecutor
        );

        await recordSecurityAudit(
          {
            actorUserId: insertedUser.id,
            action: "auth.register.success",
            entityType: "user",
            entityId: insertedUser.id,
            ipAddress: context.ipAddress,
            metadata: {
              role: insertedUser.role,
              hasEmail: Boolean(email),
              hasPhone: Boolean(phoneNumber),
              attemptedPrivilegedFields,
              sessionId: sessionResult.session.id,
            },
          },
          txExecutor
        );

        return {
          createdUser: insertedUser,
          createdSession: sessionResult,
        };
      }
    );

    return {
      user: toPublicUserDto(createdUser),
      rawSessionToken: createdSession.rawToken,
      role: createdUser.role,
    };
  } catch (err: unknown) {
    if (err instanceof AuthDomainError) {
      throw err;
    }

    if (isPgUniqueViolation(err)) {
      await recordSecurityAudit(
        {
          actorUserId: null,
          action: "auth.register.conflict",
          entityType: "user",
          entityId: null,
          ipAddress: context.ipAddress,
          metadata: {
            conflictReason: "unique_constraint_violation",
            attemptedPrivilegedFields,
          },
        },
        executor
      );

      throw new AuthDomainError(
        400,
        "REGISTRATION_REJECTED",
        GENERIC_REGISTRATION_REJECTED_MESSAGE
      );
    }

    throw err;
  }
}

export interface LoginRequestContext {
  ipAddress: string;
  userAgent?: string | null;
  priorRawSessionToken?: string | null;
  rateLimitStore?: RateLimitStore;
  identifierMaxRequests?: number;
  identifierWindowMs?: number;
}

export interface LoginSuccessResult {
  user: PublicUserDto;
  rawSessionToken: string;
  role: UserRole;
}

/**
 * Authenticates a user by normalized email or normalized Kenyan E.164 phone number:
 * 1. Validates input via Zod.
 * 2. Normalizes identifier before rate-limit check and database lookup.
 * 3. Enforces identifier-scoped rate limit BEFORE Argon2id verification.
 * 4. Uses `verifyAgainstDummyPasswordHash()` when user does not exist to prevent timing enumeration.
 * 5. Rejects wrong passwords and DISABLED accounts with a uniform generic credential error.
 * 6. Rotates session (revoking any presented prior session cookie), updates `last_login_at`, and audits.
 */
export async function loginUser(
  rawBody: unknown,
  context: LoginRequestContext,
  executor: DbExecutor = db
): Promise<LoginSuccessResult> {
  const parsed = parseLoginInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const { identifier, password } = parsed.data;
  const norm = normalizeLoginIdentifier(identifier);
  const identifierKey = norm.valid ? norm.normalized : norm.rateLimitKey;

  // Enforce identifier rate limit BEFORE running expensive Argon2id verification
  const idRateLimit = await checkIdentifierRateLimit({
    scope: "auth:login:identifier",
    normalizedIdentifier: identifierKey,
    clientIp: context.ipAddress,
    maxRequests: context.identifierMaxRequests,
    windowMs: context.identifierWindowMs,
    store: context.rateLimitStore,
    executor,
  });

  if (!idRateLimit.allowed) {
    throw new AuthDomainError(
      429,
      "RATE_LIMITED",
      "Too many sign-in attempts for this account. Please wait before trying again.",
      idRateLimit.retryAfterSeconds
    );
  }

  if (!norm.valid) {
    await verifyAgainstDummyPasswordHash(password);
    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.login.failed",
        entityType: "auth",
        entityId: null,
        ipAddress: context.ipAddress,
        metadata: {
          reason: "malformed_identifier",
        },
      },
      executor
    );
    throw new AuthDomainError(
      401,
      "INVALID_CREDENTIALS",
      GENERIC_INVALID_CREDENTIALS_MESSAGE
    );
  }

  const lookupCondition =
    norm.type === "EMAIL"
      ? eq(users.email, norm.normalized)
      : eq(users.phoneNumber, norm.normalized);

  const [user] = await executor
    .select()
    .from(users)
    .where(lookupCondition)
    .limit(1);

  if (!user) {
    await verifyAgainstDummyPasswordHash(password);
    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.login.failed",
        entityType: "auth",
        entityId: null,
        ipAddress: context.ipAddress,
        metadata: {
          reason: "user_not_found",
          identifierType: norm.type,
        },
      },
      executor
    );
    throw new AuthDomainError(
      401,
      "INVALID_CREDENTIALS",
      GENERIC_INVALID_CREDENTIALS_MESSAGE
    );
  }

  const passwordValid = await verifyPassword(user.passwordHash, password);
  if (!passwordValid) {
    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.login.failed",
        entityType: "user",
        entityId: user.id,
        ipAddress: context.ipAddress,
        metadata: {
          reason: "invalid_password",
          identifierType: norm.type,
        },
      },
      executor
    );
    throw new AuthDomainError(
      401,
      "INVALID_CREDENTIALS",
      GENERIC_INVALID_CREDENTIALS_MESSAGE
    );
  }

  if (user.status !== "ACTIVE") {
    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.login.disabled_account",
        entityType: "user",
        entityId: user.id,
        ipAddress: context.ipAddress,
        metadata: {
          status: user.status,
          identifierType: norm.type,
        },
      },
      executor
    );
    throw new AuthDomainError(
      401,
      "INVALID_CREDENTIALS",
      GENERIC_INVALID_CREDENTIALS_MESSAGE
    );
  }

  const nowDate = new Date();
  const { updatedUser, sessionResult } = await executor.transaction(
    async (tx) => {
      const txExecutor = tx as unknown as DbExecutor;

      const [updated] = await txExecutor
        .update(users)
        .set({
          lastLoginAt: nowDate,
          updatedAt: nowDate,
        })
        .where(eq(users.id, user.id))
        .returning();

      const createdSess = await createSession(
        {
          userId: user.id,
          ipAddress: context.ipAddress,
          userAgent: context.userAgent ?? null,
          priorRawToken: context.priorRawSessionToken ?? null,
          nowMs: nowDate.getTime(),
        },
        txExecutor
      );

      await recordSecurityAudit(
        {
          actorUserId: user.id,
          action: "auth.login.success",
          entityType: "user",
          entityId: user.id,
          ipAddress: context.ipAddress,
          metadata: {
            role: user.role,
            identifierType: norm.type,
            sessionId: createdSess.session.id,
            rotatedPriorSession: Boolean(context.priorRawSessionToken),
          },
        },
        txExecutor
      );

      return {
        updatedUser: updated,
        sessionResult: createdSess,
      };
    }
  );

  return {
    user: toPublicUserDto(updatedUser),
    rawSessionToken: sessionResult.rawToken,
    role: updatedUser.role,
  };
}

/**
 * Revokes the current session if active and records a safe logout audit event.
 * Idempotent: succeeds even if the session has already expired or been revoked.
 */
export async function logoutCurrentSession(
  rawSessionToken: string | null,
  ipAddress: string,
  executor: DbExecutor = db
): Promise<void> {
  if (rawSessionToken) {
    const revoked = await invalidateSessionOnLogout(
      rawSessionToken,
      ipAddress,
      executor
    );
    if (revoked) {
      return;
    }
  }

  await recordSecurityAudit(
    {
      actorUserId: null,
      action: "auth.logout.idempotent",
      entityType: "session",
      entityId: null,
      ipAddress,
      metadata: {
        hadSessionCookie: Boolean(rawSessionToken),
      },
    },
    executor
  );
}

/**
 * Revokes all active sessions for the specified authenticated user inside a database transaction.
 */
export async function logoutAllUserSessions(
  userId: string,
  ipAddress: string,
  executor: DbExecutor = db
): Promise<number> {
  return executor.transaction(async (tx) => {
    const txExecutor = tx as unknown as DbExecutor;
    return invalidateAllSessionsOnLogoutAll(userId, ipAddress, txExecutor);
  });
}
