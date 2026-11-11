import { and, eq, isNull, sql } from "drizzle-orm";
import { env } from "../../config/env";
import { db } from "../../db/client";
import { passwordResetTokens, users } from "../../db/schema";
import {
  checkIdentifierRateLimit,
  DEFAULT_AUTH_WINDOW_MS,
  RateLimitStore,
} from "../../middleware/rate-limit";
import {
  buildPasswordResetUrl,
  defaultEmailDeliveryProvider,
  EmailDeliveryProvider,
} from "../email";
import { defaultSmsDeliveryProvider, SmsDeliveryProvider } from "../sms";
import { DbExecutor, recordSecurityAudit } from "./audit.service";
import {
  normalizeLoginIdentifier,
  parseForgotPasswordInput,
  parseResetPasswordInput,
} from "./auth.schemas";
import { AuthDomainError } from "./auth.service";
import { hashPassword } from "./password.service";
import { invalidateSessionsOnPasswordReset } from "./session.service";
import {
  compareTokenHashes,
  generatePasswordResetToken,
  hashToken,
  isValidOpaqueToken,
  PASSWORD_RESET_TTL_MS,
} from "./token.service";
import { runAtomicTransaction } from "./verification.service";

export const DEFAULT_FORGOT_PASSWORD_IDENTIFIER_MAX = 3;

export const GENERIC_FORGOT_PASSWORD_MESSAGE =
  "If an eligible account matches the provided identifier, password recovery instructions have been dispatched.";

export const GENERIC_INVALID_RESET_TOKEN_MESSAGE =
  "Invalid or expired password reset token.";

export interface ForgotPasswordRequestContext {
  ipAddress: string;
  emailProvider?: EmailDeliveryProvider;
  smsProvider?: SmsDeliveryProvider;
  rateLimitStore?: RateLimitStore;
  identifierMaxRequests?: number;
  identifierWindowMs?: number;
  nowMs?: number;
  frontendUrl?: string;
}

export interface ForgotPasswordSuccessResult {
  message: string;
}

/**
 * Handles `POST /api/v1/auth/forgot-password`:
 * - Normalizes email or Kenyan/E.164 phone identifier.
 * - Enforces identifier-scoped rate limiting BEFORE database lookup or token generation.
 * - Always returns a uniform HTTP 200 generic message to prevent account enumeration.
 * - For accounts with a verified email and configured `EmailDeliveryProvider`:
 *   - Invalidates previous unused reset tokens for that user.
 *   - Generates a 32-byte CSPRNG reset token and stores only its SHA-256 hash (30-minute expiry).
 *   - Sends the fragment reset link (`/reset-password#token=...`) via the email provider.
 * - For unverified email addresses:
 *   - Does not send a password reset link and preserves the generic public response.
 * - For phone-only accounts / phone identifiers:
 *   - Until a live SMS provider is integrated, does not claim an SMS was sent, records a safe
 *     internal audit event, and preserves the generic public response.
 * - If email delivery fails:
 *   - Revokes/invalidates the undelivered reset token, records a safe internal audit event,
 *     and returns the generic public response without exposing provider errors.
 */
export async function requestPasswordReset(
  rawBody: unknown,
  context: ForgotPasswordRequestContext,
  executor: DbExecutor = db
): Promise<ForgotPasswordSuccessResult> {
  const parsed = parseForgotPasswordInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const norm = normalizeLoginIdentifier(parsed.data.rawIdentifier);
  const identifierKey = norm.valid ? norm.normalized : norm.rateLimitKey;

  const idRateLimit = await checkIdentifierRateLimit({
    scope: "auth:forgot_password:identifier",
    normalizedIdentifier: identifierKey,
    clientIp: context.ipAddress,
    maxRequests:
      context.identifierMaxRequests ?? DEFAULT_FORGOT_PASSWORD_IDENTIFIER_MAX,
    windowMs: context.identifierWindowMs ?? DEFAULT_AUTH_WINDOW_MS,
    store: context.rateLimitStore,
    executor,
  });

  if (!idRateLimit.allowed) {
    throw new AuthDomainError(
      429,
      "RATE_LIMITED",
      "Too many password recovery requests. Please wait before trying again.",
      idRateLimit.retryAfterSeconds
    );
  }

  if (!norm.valid) {
    throw new AuthDomainError(
      400,
      "VALIDATION_ERROR",
      "Please provide a valid email address or Kenyan/E.164 phone number."
    );
  }

  const emailProvider = context.emailProvider ?? defaultEmailDeliveryProvider;
  const smsProvider = context.smsProvider ?? defaultSmsDeliveryProvider;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);
  const frontendUrl = context.frontendUrl ?? env.frontendUrl;

  const lookupCondition =
    norm.type === "EMAIL"
      ? eq(users.email, norm.normalized)
      : eq(users.phoneNumber, norm.normalized);

  const [user] = await executor
    .select()
    .from(users)
    .where(lookupCondition)
    .limit(1);

  if (!user || user.status !== "ACTIVE") {
    await recordSecurityAudit(
      {
        actorUserId: user?.id ?? null,
        action: "auth.password_reset.ignored",
        entityType: "auth",
        entityId: user?.id ?? null,
        ipAddress: context.ipAddress,
        metadata: {
          reason: !user ? "user_not_found" : "account_disabled",
          identifierType: norm.type,
        },
      },
      executor
    );

    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  // Phone-identified or phone-only account handling:
  // Until a live SMS provider is integrated, phone-based recovery is unavailable.
  // Never claim an SMS was sent; preserve the generic public response.
  if (norm.type === "PHONE" && (!user.email || !user.emailVerifiedAt)) {
    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.password_reset.sms_unavailable",
        entityType: "user",
        entityId: user.id,
        ipAddress: context.ipAddress,
        metadata: {
          identifierType: "PHONE",
          smsProviderConfigured: smsProvider.isConfigured(),
          reason:
            "Phone-based password recovery is unavailable until a live SMS provider is integrated.",
        },
      },
      executor
    );

    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  // Unverified email handling: never send password reset links to unverified email addresses
  if (!user.email || user.emailVerifiedAt === null) {
    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.password_reset.ignored",
        entityType: "user",
        entityId: user.id,
        ipAddress: context.ipAddress,
        metadata: {
          reason: "email_unverified",
          identifierType: norm.type,
        },
      },
      executor
    );

    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  // Verified email requires a configured EmailDeliveryProvider
  if (!emailProvider.isConfigured()) {
    await recordSecurityAudit(
      {
        actorUserId: user.id,
        action: "auth.password_reset.delivery_failed",
        entityType: "user",
        entityId: user.id,
        ipAddress: context.ipAddress,
        metadata: {
          provider: emailProvider.providerName,
          errorCode: "EMAIL_PROVIDER_NOT_CONFIGURED",
          errorReason:
            "Email delivery provider is not configured. Set RESEND_API_KEY and EMAIL_FROM.",
        },
      },
      executor
    );

    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  const txResult = await runAtomicTransaction(executor, async (tx) => {
    const lockedUsers = await tx.execute<{
      id: string;
      first_name: string;
      email: string | null;
      status: "ACTIVE" | "DISABLED";
      email_verified_at: Date | string | null;
    }>(
      sql`SELECT id, first_name, email, status, email_verified_at
          FROM users
          WHERE id = ${user.id}
          FOR UPDATE`
    );

    const lockedUser = lockedUsers.rows[0];
    if (
      !lockedUser ||
      lockedUser.status !== "ACTIVE" ||
      !lockedUser.email ||
      lockedUser.email_verified_at === null
    ) {
      return { status: "ineligible" as const };
    }

    // Invalidate all previous unused password reset tokens for this account
    await tx
      .update(passwordResetTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(passwordResetTokens.userId, lockedUser.id),
          isNull(passwordResetTokens.usedAt)
        )
      );

    const { rawToken, tokenHash, expiresAt } = generatePasswordResetToken(
      PASSWORD_RESET_TTL_MS,
      nowMs
    );

    const [insertedReset] = await tx
      .insert(passwordResetTokens)
      .values({
        userId: lockedUser.id,
        tokenHash,
        expiresAt,
        createdAt: nowDate,
      })
      .returning({ id: passwordResetTokens.id });

    await recordSecurityAudit(
      {
        actorUserId: lockedUser.id,
        action: "auth.password_reset.requested",
        entityType: "password_reset_token",
        entityId: insertedReset.id,
        ipAddress: context.ipAddress,
        metadata: {
          identifierType: norm.type,
          expiresAt: expiresAt.toISOString(),
        },
      },
      tx
    );

    return {
      status: "created" as const,
      userId: lockedUser.id,
      firstName: lockedUser.first_name,
      toEmail: lockedUser.email,
      resetTokenId: insertedReset.id,
      rawToken,
    };
  });

  if (txResult.status !== "created") {
    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  const resetUrl = buildPasswordResetUrl(txResult.rawToken, frontendUrl);

  const deliveryResult = await emailProvider.sendPasswordResetEmail({
    toEmail: txResult.toEmail,
    firstName: txResult.firstName,
    resetUrl,
    expiresInMinutes: 30,
  });

  if (!deliveryResult.delivered) {
    // Invalidate the reset token immediately so an undelivered token cannot remain usable
    await runAtomicTransaction(executor, async (tx) => {
      await tx
        .update(passwordResetTokens)
        .set({ usedAt: nowDate })
        .where(eq(passwordResetTokens.id, txResult.resetTokenId));

      await recordSecurityAudit(
        {
          actorUserId: txResult.userId,
          action: "auth.password_reset.delivery_failed",
          entityType: "password_reset_token",
          entityId: txResult.resetTokenId,
          ipAddress: context.ipAddress,
          metadata: {
            provider: deliveryResult.provider,
            errorCode: deliveryResult.errorCode ?? "EMAIL_PROVIDER_REJECTED",
            errorReason:
              deliveryResult.errorReason ??
              "Failed to deliver password reset email.",
          },
        },
        tx
      );
    });

    return {
      message: GENERIC_FORGOT_PASSWORD_MESSAGE,
    };
  }

  await recordSecurityAudit(
    {
      actorUserId: txResult.userId,
      action: "auth.password_reset.email_sent",
      entityType: "password_reset_token",
      entityId: txResult.resetTokenId,
      ipAddress: context.ipAddress,
      metadata: {
        provider: deliveryResult.provider,
        providerMessageId: deliveryResult.providerMessageId ?? null,
      },
    },
    executor
  );

  return {
    message: GENERIC_FORGOT_PASSWORD_MESSAGE,
  };
}

export interface ResetPasswordRequestContext {
  ipAddress: string;
  nowMs?: number;
}

export interface ResetPasswordSuccessResult {
  passwordReset: true;
  message: string;
}

/**
 * Handles `POST /api/v1/auth/reset-password`:
 * 1. Validates `newPassword` using `validatePassword()`.
 * 2. Hashes `newPassword` using Argon2id (`hashPassword()`).
 * 3. Hashes the supplied `token` using SHA-256 (`hashToken()`).
 * 4. Locks the matching `password_reset_tokens` row with `FOR UPDATE` inside a PostgreSQL transaction.
 * 5. Verifies `used_at IS NULL`, `expires_at > now()`, and `users.status === 'ACTIVE'`.
 * 6. Marks the token used (`used_at = now()`).
 * 7. Updates `users.password_hash`.
 * 8. Revokes all active sessions for that user (`invalidateSessionsOnPasswordReset()`).
 * 9. Writes a safe security audit event (`auth.password_reset.completed`).
 * 10. Commits atomically without creating a new authenticated session.
 */
export async function resetPasswordWithToken(
  rawBody: unknown,
  context: ResetPasswordRequestContext,
  executor: DbExecutor = db
): Promise<ResetPasswordSuccessResult> {
  const parsed = parseResetPasswordInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const { token: rawToken, newPassword } = parsed.data;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);

  // Hash new password with Argon2id before entering the DB row-lock transaction
  const newPasswordHash = await hashPassword(newPassword);

  if (!isValidOpaqueToken(rawToken)) {
    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.password_reset.invalid_token",
        entityType: "password_reset_token",
        entityId: null,
        ipAddress: context.ipAddress,
        metadata: {
          reason: "malformed_token",
        },
      },
      executor
    );

    throw new AuthDomainError(
      400,
      "INVALID_OR_EXPIRED_TOKEN",
      GENERIC_INVALID_RESET_TOKEN_MESSAGE
    );
  }

  const tokenHash = hashToken(rawToken);

  const outcome = await runAtomicTransaction(executor, async (tx) => {
    const lockedResetRows = await tx.execute<{
      id: string;
      user_id: string;
      token_hash: string;
      expires_at: Date | string;
      used_at: Date | string | null;
    }>(
      sql`SELECT id, user_id, token_hash, expires_at, used_at
          FROM password_reset_tokens
          WHERE token_hash = ${tokenHash}
          FOR UPDATE`
    );

    const resetRow = lockedResetRows.rows[0];
    if (!resetRow || !compareTokenHashes(resetRow.token_hash, tokenHash)) {
      await recordSecurityAudit(
        {
          actorUserId: null,
          action: "auth.password_reset.invalid_token",
          entityType: "password_reset_token",
          entityId: null,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_not_found",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    if (resetRow.used_at !== null) {
      await recordSecurityAudit(
        {
          actorUserId: resetRow.user_id,
          action: "auth.password_reset.invalid_token",
          entityType: "password_reset_token",
          entityId: resetRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_already_used",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    const expiresAtMs = new Date(resetRow.expires_at).getTime();
    if (expiresAtMs <= nowMs) {
      await recordSecurityAudit(
        {
          actorUserId: resetRow.user_id,
          action: "auth.password_reset.invalid_token",
          entityType: "password_reset_token",
          entityId: resetRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_expired",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    const lockedUsers = await tx.execute<{
      id: string;
      status: "ACTIVE" | "DISABLED";
    }>(
      sql`SELECT id, status
          FROM users
          WHERE id = ${resetRow.user_id}
          FOR UPDATE`
    );

    const userRow = lockedUsers.rows[0];
    if (!userRow || userRow.status !== "ACTIVE") {
      await recordSecurityAudit(
        {
          actorUserId: resetRow.user_id,
          action: "auth.password_reset.invalid_token",
          entityType: "password_reset_token",
          entityId: resetRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "user_inactive_or_missing",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    // Mark the consumed reset token and any other unused reset tokens for this user as used
    await tx
      .update(passwordResetTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(passwordResetTokens.userId, userRow.id),
          isNull(passwordResetTokens.usedAt)
        )
      );

    // Update the user's Argon2id password_hash
    await tx
      .update(users)
      .set({
        passwordHash: newPasswordHash,
        updatedAt: nowDate,
      })
      .where(eq(users.id, userRow.id));

    // Revoke all active sessions for that user
    const revokedSessionsCount = await invalidateSessionsOnPasswordReset(
      userRow.id,
      context.ipAddress,
      tx
    );

    await recordSecurityAudit(
      {
        actorUserId: userRow.id,
        action: "auth.password_reset.completed",
        entityType: "user",
        entityId: userRow.id,
        ipAddress: context.ipAddress,
        metadata: {
          resetTokenId: resetRow.id,
          revokedSessionsCount,
        },
      },
      tx
    );

    return { ok: true as const };
  });

  if (!outcome.ok) {
    throw new AuthDomainError(
      400,
      "INVALID_OR_EXPIRED_TOKEN",
      GENERIC_INVALID_RESET_TOKEN_MESSAGE
    );
  }

  return {
    passwordReset: true,
    message:
      "Your password has been reset successfully. Please sign in with your new password.",
  };
}
