import { and, eq, isNull, lte, ne, or, sql } from "drizzle-orm";
import { db } from "../../db/client";
import { sessions, users, User, Session } from "../../db/schema";
import {
  generateSecureToken,
  hashToken,
  isValidOpaqueToken,
  SECURE_TOKEN_BYTES,
} from "./token.service";
import { DbExecutor, recordSecurityAudit } from "./audit.service";

export type UserRole = User["role"];
export type AccountStatus = User["status"];

/**
 * Approved role-tiered session durations per DSH AUTH_ARCHITECTURE.md:
 * - CUSTOMER: 7 days (168 hours)
 * - STAFF: 12 hours
 * - ADMIN: 8 hours
 * - SUPER_ADMIN: 8 hours
 */
export const SESSION_DURATION_MS_BY_ROLE: Readonly<Record<UserRole, number>> =
  Object.freeze({
    CUSTOMER: 7 * 24 * 60 * 60 * 1000, // 7 days
    STAFF: 12 * 60 * 60 * 1000, // 12 hours
    ADMIN: 8 * 60 * 60 * 1000, // 8 hours
    SUPER_ADMIN: 8 * 60 * 60 * 1000, // 8 hours
  });

/**
 * Safe authenticated user projection that strictly omits `passwordHash`.
 */
export interface SafeAuthenticatedUser {
  id: string;
  firstName: string;
  lastName: string;
  email: string | null;
  phoneNumber: string | null;
  role: UserRole;
  status: AccountStatus;
  emailVerifiedAt: Date | null;
  phoneVerifiedAt: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Safe session metadata projection (contains SHA-256 `tokenHash` for CSRF binding, never raw tokens).
 */
export interface SafeSessionInfo {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
}

export interface AuthenticatedSessionContext {
  user: SafeAuthenticatedUser;
  session: SafeSessionInfo;
}

export interface CreatedSessionResult {
  rawToken: string;
  session: SafeSessionInfo;
  user: SafeAuthenticatedUser;
}

export type SessionRejectionReason =
  | "MALFORMED_TOKEN"
  | "NOT_FOUND"
  | "REVOKED"
  | "EXPIRED"
  | "ACCOUNT_DISABLED";

export type SessionValidationResult =
  | {
      valid: true;
      context: AuthenticatedSessionContext;
    }
  | {
      valid: false;
      reason: SessionRejectionReason;
      sessionId?: string;
      userId?: string;
    };

export class SessionSecurityError extends Error {
  public readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "SessionSecurityError";
    this.code = code;
  }
}

export function toSafeAuthenticatedUser(user: User): SafeAuthenticatedUser {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phoneNumber: user.phoneNumber,
    role: user.role,
    status: user.status,
    emailVerifiedAt: user.emailVerifiedAt,
    phoneVerifiedAt: user.phoneVerifiedAt,
    lastLoginAt: user.lastLoginAt,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

export function toSafeSessionInfo(session: Session): SafeSessionInfo {
  return {
    id: session.id,
    userId: session.userId,
    tokenHash: session.tokenHash,
    expiresAt: session.expiresAt,
    revokedAt: session.revokedAt,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    createdAt: session.createdAt,
  };
}

export function getSessionDurationMs(role: UserRole): number {
  const duration = SESSION_DURATION_MS_BY_ROLE[role];
  if (!duration) {
    throw new Error(`Unsupported user role for session duration: ${String(role)}`);
  }
  return duration;
}

async function runInTransactionIfPossible<T>(
  executor: DbExecutor,
  fn: (tx: DbExecutor) => Promise<T>
): Promise<T> {
  if (executor === db) {
    return db.transaction(async (tx) => fn(tx as unknown as DbExecutor));
  }
  return fn(executor);
}

export interface CreateSessionParams {
  userId: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  priorRawToken?: string | null;
  nowMs?: number;
}

/**
 * Creates a new server-side session for an ACTIVE user, revoking any prior session token if provided
 * (session rotation on login or privilege change). Persists only the SHA-256 hash in PostgreSQL.
 */
export async function createSession(
  params: CreateSessionParams,
  executor: DbExecutor = db
): Promise<CreatedSessionResult> {
  return runInTransactionIfPossible(executor, async (tx) => {
    const [user] = await tx
      .select()
      .from(users)
      .where(eq(users.id, params.userId))
      .limit(1);

    if (!user) {
      throw new SessionSecurityError("USER_NOT_FOUND", "User account not found.");
    }

    if (user.status !== "ACTIVE") {
      await recordSecurityAudit(
        {
          actorUserId: user.id,
          action: "auth.session.create_rejected_disabled",
          entityType: "user",
          entityId: user.id,
          ipAddress: params.ipAddress ?? null,
          metadata: { status: user.status },
        },
        tx
      );
      throw new SessionSecurityError(
        "ACCOUNT_DISABLED",
        "Cannot create session for a disabled account."
      );
    }

    const nowMs = params.nowMs ?? Date.now();
    const nowDate = new Date(nowMs);

    // If a prior session cookie existed, revoke it atomically to prevent session fixation
    if (params.priorRawToken && isValidOpaqueToken(params.priorRawToken)) {
      const priorTokenHash = hashToken(params.priorRawToken);
      await tx
        .update(sessions)
        .set({ revokedAt: nowDate })
        .where(
          and(
            eq(sessions.tokenHash, priorTokenHash),
            isNull(sessions.revokedAt)
          )
        );
    }

    const rawToken = generateSecureToken(SECURE_TOKEN_BYTES);
    const tokenHash = hashToken(rawToken);
    const durationMs = getSessionDurationMs(user.role);
    const expiresAt = new Date(nowMs + durationMs);

    const [insertedSession] = await tx
      .insert(sessions)
      .values({
        userId: user.id,
        tokenHash,
        expiresAt,
        ipAddress: params.ipAddress ?? null,
        userAgent: params.userAgent ?? null,
        createdAt: nowDate,
      })
      .returning();

    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.session.created",
        entityType: "session",
        entityId: insertedSession.id,
        ipAddress: params.ipAddress ?? null,
        metadata: {
          role: user.role,
          expiresAt: expiresAt.toISOString(),
          rotatedPriorSession: Boolean(params.priorRawToken),
        },
      },
      tx
    );

    return {
      rawToken,
      session: toSafeSessionInfo(insertedSession),
      user: toSafeAuthenticatedUser(user),
    };
  });
}

export interface ValidateSessionOptions {
  ipAddress?: string | null;
  nowMs?: number;
  auditFailures?: boolean;
}

/**
 * Validates a raw session token against PostgreSQL `sessions` and `users`:
 * - Checks token format and computes SHA-256 hash
 * - Rejects unknown, revoked, or expired sessions
 * - Rejects sessions belonging to DISABLED users (and marks the session revoked)
 * - Loads current database role and profile (never trusting browser role claims)
 */
export async function validateSession(
  rawToken: unknown,
  options: ValidateSessionOptions = {},
  executor: DbExecutor = db
): Promise<SessionValidationResult> {
  if (!isValidOpaqueToken(rawToken)) {
    return { valid: false, reason: "MALFORMED_TOKEN" };
  }

  const tokenHash = hashToken(rawToken);
  const nowDate = new Date(options.nowMs ?? Date.now());

  const rows = await executor
    .select({
      session: sessions,
      user: users,
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(eq(sessions.tokenHash, tokenHash))
    .limit(1);

  const row = rows[0];
  if (!row) {
    return { valid: false, reason: "NOT_FOUND" };
  }

  const { session, user } = row;

  if (session.revokedAt !== null) {
    return {
      valid: false,
      reason: "REVOKED",
      sessionId: session.id,
      userId: user.id,
    };
  }

  if (session.expiresAt.getTime() <= nowDate.getTime()) {
    if (options.auditFailures) {
      await recordSecurityAudit(
        {
          actorUserId: user.id,
          action: "auth.session.expired_rejected",
          entityType: "session",
          entityId: session.id,
          ipAddress: options.ipAddress ?? null,
          metadata: { expiresAt: session.expiresAt.toISOString() },
        },
        executor
      );
    }
    return {
      valid: false,
      reason: "EXPIRED",
      sessionId: session.id,
      userId: user.id,
    };
  }

  if (user.status !== "ACTIVE") {
    await executor
      .update(sessions)
      .set({ revokedAt: nowDate })
      .where(and(eq(sessions.id, session.id), isNull(sessions.revokedAt)));

    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.session.disabled_account_rejected",
        entityType: "session",
        entityId: session.id,
        ipAddress: options.ipAddress ?? null,
        metadata: { userStatus: user.status },
      },
      executor
    );

    return {
      valid: false,
      reason: "ACCOUNT_DISABLED",
      sessionId: session.id,
      userId: user.id,
    };
  }

  return {
    valid: true,
    context: {
      user: toSafeAuthenticatedUser(user),
      session: toSafeSessionInfo(session),
    },
  };
}

/**
 * Convenience wrapper around `validateSession` that returns the authenticated session context or null.
 */
export async function getCurrentSession(
  rawToken: unknown,
  executor: DbExecutor = db
): Promise<AuthenticatedSessionContext | null> {
  const result = await validateSession(rawToken, {}, executor);
  return result.valid ? result.context : null;
}

export interface RevokeSessionParams {
  sessionId?: string;
  rawToken?: string;
  actorUserId?: string | null;
  reason?: string;
  ipAddress?: string | null;
  nowMs?: number;
}

/**
 * Revokes a single active session by `sessionId` or `rawToken` and writes a security audit log.
 */
export async function revokeSession(
  params: RevokeSessionParams,
  executor: DbExecutor = db
): Promise<boolean> {
  const nowDate = new Date(params.nowMs ?? Date.now());

  let condition;
  if (params.sessionId) {
    condition = and(
      eq(sessions.id, params.sessionId),
      isNull(sessions.revokedAt)
    );
  } else if (params.rawToken && isValidOpaqueToken(params.rawToken)) {
    const tokenHash = hashToken(params.rawToken);
    condition = and(
      eq(sessions.tokenHash, tokenHash),
      isNull(sessions.revokedAt)
    );
  } else {
    return false;
  }

  const revokedRows = await executor
    .update(sessions)
    .set({ revokedAt: nowDate })
    .where(condition)
    .returning({ id: sessions.id, userId: sessions.userId });

  if (revokedRows.length === 0) {
    return false;
  }

  const revoked = revokedRows[0];
  await recordSecurityAudit(
    {
      actorUserId: params.actorUserId ?? revoked.userId,
      action: "auth.session.revoked",
      entityType: "session",
      entityId: revoked.id,
      ipAddress: params.ipAddress ?? null,
      metadata: {
        reason: params.reason ?? "manual_revocation",
      },
    },
    executor
  );

  return true;
}

export interface RevokeAllSessionsParams {
  userId: string;
  exceptSessionId?: string;
  actorUserId?: string | null;
  reason?: string;
  ipAddress?: string | null;
  nowMs?: number;
}

/**
 * Revokes all active sessions for a user (optionally keeping a single session ID active)
 * and records an immutable security audit event.
 */
export async function revokeAllSessions(
  params: RevokeAllSessionsParams,
  executor: DbExecutor = db
): Promise<number> {
  const nowDate = new Date(params.nowMs ?? Date.now());

  const baseCondition = and(
    eq(sessions.userId, params.userId),
    isNull(sessions.revokedAt)
  );

  const condition = params.exceptSessionId
    ? and(baseCondition, ne(sessions.id, params.exceptSessionId))
    : baseCondition;

  const revokedRows = await executor
    .update(sessions)
    .set({ revokedAt: nowDate })
    .where(condition)
    .returning({ id: sessions.id });

  await recordSecurityAudit(
    {
      actorUserId: params.actorUserId ?? params.userId,
      action: "auth.session.revoked_all",
      entityType: "user",
      entityId: params.userId,
      ipAddress: params.ipAddress ?? null,
      metadata: {
        reason: params.reason ?? "logout_all",
        revokedCount: revokedRows.length,
        keptSessionId: params.exceptSessionId ?? null,
      },
    },
    executor
  );

  return revokedRows.length;
}

/**
 * Cleans up expired or revoked sessions whose expiry/revocation is older than the retention window.
 */
export async function cleanupExpiredSessions(
  retentionMs: number = 30 * 24 * 60 * 60 * 1000,
  nowMs: number = Date.now(),
  executor: DbExecutor = db
): Promise<number> {
  const cutoffDate = new Date(nowMs - retentionMs);
  const deleted = await executor
    .delete(sessions)
    .where(
      or(
        lte(sessions.expiresAt, cutoffDate),
        lte(sessions.revokedAt, cutoffDate)
      )
    )
    .returning({ id: sessions.id });

  return deleted.length;
}

// ============================================================================
// SECTION 8: REUSABLE SESSION INVALIDATION RULES
// ============================================================================

/**
 * 1. Single-session logout invalidation.
 */
export async function invalidateSessionOnLogout(
  rawToken: string,
  ipAddress?: string | null,
  executor: DbExecutor = db
): Promise<boolean> {
  return revokeSession(
    {
      rawToken,
      reason: "user_logout",
      ipAddress,
    },
    executor
  );
}

/**
 * 2. Logout-all sessions invalidation.
 */
export async function invalidateAllSessionsOnLogoutAll(
  userId: string,
  ipAddress?: string | null,
  executor: DbExecutor = db
): Promise<number> {
  return revokeAllSessions(
    {
      userId,
      actorUserId: userId,
      reason: "user_logout_all",
      ipAddress,
    },
    executor
  );
}

/**
 * 3. Password-change invalidation: revokes all existing sessions for the user and issues
 * a rotated session for the active device inside a single transaction.
 */
export async function invalidateSessionsOnPasswordChange(
  params: {
    userId: string;
    ipAddress?: string | null;
    userAgent?: string | null;
  },
  executor: DbExecutor = db
): Promise<CreatedSessionResult> {
  return runInTransactionIfPossible(executor, async (tx) => {
    await revokeAllSessions(
      {
        userId: params.userId,
        actorUserId: params.userId,
        reason: "password_changed",
        ipAddress: params.ipAddress,
      },
      tx
    );

    return createSession(
      {
        userId: params.userId,
        ipAddress: params.ipAddress,
        userAgent: params.userAgent,
      },
      tx
    );
  });
}

/**
 * 4. Password-reset invalidation: revokes all active sessions for the user so they must sign in fresh.
 */
export async function invalidateSessionsOnPasswordReset(
  userId: string,
  ipAddress?: string | null,
  executor: DbExecutor = db
): Promise<number> {
  return revokeAllSessions(
    {
      userId,
      actorUserId: userId,
      reason: "password_reset",
      ipAddress,
    },
    executor
  );
}

/**
 * 5. Role-change invalidation: revokes all active sessions when an administrator changes a user's role.
 */
export async function invalidateSessionsOnRoleChange(
  params: {
    targetUserId: string;
    actorUserId: string;
    previousRole: UserRole;
    newRole: UserRole;
    ipAddress?: string | null;
  },
  executor: DbExecutor = db
): Promise<number> {
  return revokeAllSessions(
    {
      userId: params.targetUserId,
      actorUserId: params.actorUserId,
      reason: `role_changed:${params.previousRole}->${params.newRole}`,
      ipAddress: params.ipAddress,
    },
    executor
  );
}

/**
 * 6. Account-disable invalidation: revokes all active sessions when a user account is disabled.
 */
export async function invalidateSessionsOnAccountDisable(
  params: {
    targetUserId: string;
    actorUserId: string;
    ipAddress?: string | null;
  },
  executor: DbExecutor = db
): Promise<number> {
  return revokeAllSessions(
    {
      userId: params.targetUserId,
      actorUserId: params.actorUserId,
      reason: "account_disabled",
      ipAddress: params.ipAddress,
    },
    executor
  );
}

/**
 * Reusable transaction-level serialization helper for privileged SUPER_ADMIN role/status mutations.
 * Acquires `pg_advisory_xact_lock(hashtextextended('dsh_super_admin_role_guard', 0))` and locks
 * all active SUPER_ADMIN rows in deterministic primary-key order (`ORDER BY id ASC FOR UPDATE`).
 */
export async function withSuperAdminRoleGuardLock<T>(
  fn: (
    tx: DbExecutor,
    activeSuperAdminIds: ReadonlyArray<string>
  ) => Promise<T>,
  executor: DbExecutor = db
): Promise<T> {
  return runInTransactionIfPossible(executor, async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended('dsh_super_admin_role_guard', 0));`
    );

    const lockedResult = await tx.execute<{ id: string }>(
      sql`SELECT id FROM users WHERE role = 'SUPER_ADMIN' AND status = 'ACTIVE' ORDER BY id ASC FOR UPDATE;`
    );

    const activeSuperAdminIds = lockedResult.rows.map((r) => r.id);
    return fn(tx, activeSuperAdminIds);
  });
}
