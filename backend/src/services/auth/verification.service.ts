import { and, eq, isNull, sql } from "drizzle-orm";
import { env } from "../../config/env";
import { db } from "../../db/client";
import { normalizePhoneNumber } from "../../db/normalize";
import { users, verificationTokens } from "../../db/schema";
import {
  buildEmailVerificationUrl,
  defaultEmailDeliveryProvider,
  EmailDeliveryProvider,
} from "../email";
import { defaultSmsDeliveryProvider, SmsDeliveryProvider } from "../sms";
import { DbExecutor, recordSecurityAudit } from "./audit.service";
import {
  parseResendVerificationInput,
  parseVerifyEmailInput,
  parseVerifyPhoneInput,
} from "./auth.schemas";
import { AuthDomainError } from "./auth.service";
import { SafeAuthenticatedUser } from "./session.service";
import {
  compareTokenHashes,
  EMAIL_VERIFICATION_TTL_MS,
  generatePhoneVerificationOtp,
  generateVerificationToken,
  hashPhoneOtp,
  hashToken,
  isValidOpaqueToken,
  PHONE_VERIFICATION_TTL_MS,
} from "./token.service";

export const DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS = 60 * 1000; // 60 seconds
export const DEFAULT_MAX_PHONE_OTP_ATTEMPTS = 5;

export const GENERIC_EMAIL_VERIFICATION_RESEND_MESSAGE =
  "If your account requires email verification, a verification link has been sent.";

export const GENERIC_PHONE_VERIFICATION_RESEND_MESSAGE =
  "If your phone number requires verification, a verification code has been dispatched.";

export const GENERIC_INVALID_VERIFICATION_TOKEN_MESSAGE =
  "Invalid or expired verification token.";

export const GENERIC_INVALID_PHONE_OTP_MESSAGE =
  "Invalid or expired verification code.";

/**
 * Per-executor queue used when `executor` is already a single-connection test transaction (`tx`)
 * so concurrent `Promise.all` calls in tests do not interleave PostgreSQL `SAVEPOINT` names
 * on the same `pg.Client` socket. When `executor === db`, each transaction checks out its own
 * connection from the pool and relies on PostgreSQL `SELECT ... FOR UPDATE` row-level locking.
 */
const singleTxQueues = new WeakMap<object, Promise<unknown>>();

export async function runAtomicTransaction<T>(
  executor: DbExecutor,
  fn: (tx: DbExecutor) => Promise<T>
): Promise<T> {
  if (executor === db) {
    return db.transaction(async (tx) => fn(tx as unknown as DbExecutor));
  }

  const prev = singleTxQueues.get(executor) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  singleTxQueues.set(
    executor,
    prev.then(
      () => gate,
      () => gate
    )
  );

  await prev.catch(() => undefined);
  try {
    return await executor.transaction(async (subTx) =>
      fn(subTx as unknown as DbExecutor)
    );
  } finally {
    release();
  }
}

export interface VerifyEmailRequestContext {
  ipAddress: string;
  nowMs?: number;
}

export interface VerifyEmailSuccessResult {
  emailVerified: true;
  message: string;
}

/**
 * Consumes a single-use email verification token (`POST /api/v1/auth/verify-email`):
 * 1. Validates and hashes the raw token using SHA-256.
 * 2. Locks the matching `verification_tokens` row with `FOR UPDATE` inside a PostgreSQL transaction.
 * 3. Verifies `verification_type === 'EMAIL'`, `used_at IS NULL`, and `expires_at > now()`.
 * 4. Marks the token used (`used_at = now()`) and updates `users.email_verified_at` atomically.
 * 5. Writes a safe security audit log without exposing raw tokens or hashes.
 */
export async function verifyEmailToken(
  rawBody: unknown,
  context: VerifyEmailRequestContext,
  executor: DbExecutor = db
): Promise<VerifyEmailSuccessResult> {
  const parsed = parseVerifyEmailInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const rawToken = parsed.data.token;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);

  if (!isValidOpaqueToken(rawToken)) {
    await recordSecurityAudit(
      {
        actorUserId: null,
        action: "auth.email_verification.failed",
        entityType: "verification_token",
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
      GENERIC_INVALID_VERIFICATION_TOKEN_MESSAGE
    );
  }

  const tokenHash = hashToken(rawToken);

  const outcome = await runAtomicTransaction(executor, async (tx) => {
    const lockedTokens = await tx.execute<{
      id: string;
      user_id: string;
      token_hash: string;
      verification_type: "EMAIL" | "PHONE";
      expires_at: Date | string;
      used_at: Date | string | null;
    }>(
      sql`SELECT id, user_id, token_hash, verification_type, expires_at, used_at
          FROM verification_tokens
          WHERE token_hash = ${tokenHash}
          FOR UPDATE`
    );

    const tokenRow = lockedTokens.rows[0];
    if (!tokenRow || !compareTokenHashes(tokenRow.token_hash, tokenHash)) {
      await recordSecurityAudit(
        {
          actorUserId: null,
          action: "auth.email_verification.failed",
          entityType: "verification_token",
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

    if (tokenRow.verification_type !== "EMAIL") {
      await recordSecurityAudit(
        {
          actorUserId: tokenRow.user_id,
          action: "auth.email_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "wrong_verification_type",
            actualType: tokenRow.verification_type,
          },
        },
        tx
      );
      return { ok: false as const };
    }

    if (tokenRow.used_at !== null) {
      await recordSecurityAudit(
        {
          actorUserId: tokenRow.user_id,
          action: "auth.email_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_already_used",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    const expiresAtMs = new Date(tokenRow.expires_at).getTime();
    if (expiresAtMs <= nowMs) {
      await recordSecurityAudit(
        {
          actorUserId: tokenRow.user_id,
          action: "auth.email_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
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
      email_verified_at: Date | string | null;
    }>(
      sql`SELECT id, status, email_verified_at
          FROM users
          WHERE id = ${tokenRow.user_id}
          FOR UPDATE`
    );

    const userRow = lockedUsers.rows[0];
    if (!userRow || userRow.status !== "ACTIVE") {
      await recordSecurityAudit(
        {
          actorUserId: tokenRow.user_id,
          action: "auth.email_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "user_inactive_or_missing",
          },
        },
        tx
      );
      return { ok: false as const };
    }

    // Mark the consumed token and any other unused EMAIL tokens for this user as used
    await tx
      .update(verificationTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(verificationTokens.userId, userRow.id),
          eq(verificationTokens.verificationType, "EMAIL"),
          isNull(verificationTokens.usedAt)
        )
      );

    const verifiedAt = userRow.email_verified_at
      ? new Date(userRow.email_verified_at)
      : nowDate;

    await tx
      .update(users)
      .set({
        emailVerifiedAt: verifiedAt,
        updatedAt: nowDate,
      })
      .where(eq(users.id, userRow.id));

    await recordSecurityAudit(
      {
        actorUserId: userRow.id,
        action: "auth.email_verification.verified",
        entityType: "user",
        entityId: userRow.id,
        ipAddress: context.ipAddress,
        metadata: {
          verificationTokenId: tokenRow.id,
          verificationType: "EMAIL",
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
      GENERIC_INVALID_VERIFICATION_TOKEN_MESSAGE
    );
  }

  return {
    emailVerified: true,
    message: "Email address has been verified.",
  };
}

export interface ResendVerificationContext {
  ipAddress: string;
  emailProvider?: EmailDeliveryProvider;
  smsProvider?: SmsDeliveryProvider;
  cooldownMs?: number;
  nowMs?: number;
  frontendUrl?: string;
}

export interface ResendVerificationSuccessResult {
  message: string;
  type: "EMAIL" | "PHONE";
}

/**
 * Handles `POST /api/v1/auth/resend-verification` for an authenticated user:
 * - Enforces that authenticated customers may only request verification for their own account.
 * - Supports `EMAIL` and `PHONE` channels.
 * - For `EMAIL`:
 *   - Locks the user row (`FOR UPDATE`) to serialize concurrent requests and prevent duplicate emails.
 *   - If already verified, returns the generic public response without creating new tokens.
 *   - Enforces the per-user resend cooldown (`DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS`).
 *   - If no email provider is configured, records an internal delivery failure event and returns
 *     the generic public response without marking verified or pretending delivery succeeded.
 *   - Invalidates prior unused `EMAIL` tokens, stores SHA-256 hash of a new 32-byte token (24h TTL),
 *     and dispatches the fragment verification link via `EmailDeliveryProvider`.
 * - For `PHONE`:
 *   - Delegates to `dispatchPhoneVerificationOtp()`.
 */
export async function resendVerificationForUser(
  actorUser: SafeAuthenticatedUser,
  rawBody: unknown,
  context: ResendVerificationContext,
  executor: DbExecutor = db
): Promise<ResendVerificationSuccessResult> {
  const parsed = parseResendVerificationInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const { type, requestedEmail, requestedPhoneNumber, requestedUserId } =
    parsed.data;

  // Enforce that authenticated callers can only request verification for their own account.
  // Never query other users' emails/phones so account existence is never revealed.
  if (
    (requestedUserId && requestedUserId !== actorUser.id) ||
    (requestedEmail && requestedEmail !== actorUser.email) ||
    (requestedPhoneNumber && requestedPhoneNumber !== actorUser.phoneNumber)
  ) {
    await recordSecurityAudit(
      {
        actorUserId: actorUser.id,
        action: "auth.verification.resend_forbidden_target",
        entityType: "user",
        entityId: actorUser.id,
        ipAddress: context.ipAddress,
        metadata: {
          requestedType: type,
          mismatchedUserId: Boolean(
            requestedUserId && requestedUserId !== actorUser.id
          ),
          mismatchedEmail: Boolean(
            requestedEmail && requestedEmail !== actorUser.email
          ),
          mismatchedPhone: Boolean(
            requestedPhoneNumber &&
              requestedPhoneNumber !== actorUser.phoneNumber
          ),
        },
      },
      executor
    );

    throw new AuthDomainError(
      403,
      "FORBIDDEN",
      "You can only request verification for your own account."
    );
  }

  if (type === "PHONE") {
    return dispatchPhoneVerificationOtp(actorUser, context, executor);
  }

  return issueAndSendEmailVerification(actorUser.id, context, executor);
}

/**
 * Issues a fresh 24-hour email verification token for `userId` and sends it via `EmailDeliveryProvider`.
 * Concurrency-safe via `SELECT ... FOR UPDATE` on the `users` row.
 */
export async function issueAndSendEmailVerification(
  userId: string,
  context: ResendVerificationContext,
  executor: DbExecutor = db
): Promise<ResendVerificationSuccessResult> {
  const emailProvider = context.emailProvider ?? defaultEmailDeliveryProvider;
  const cooldownMs =
    context.cooldownMs ?? DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);
  const frontendUrl = context.frontendUrl ?? env.frontendUrl;

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
          WHERE id = ${userId}
          FOR UPDATE`
    );

    const userRow = lockedUsers.rows[0];
    if (!userRow || userRow.status !== "ACTIVE") {
      return { status: "inactive" as const };
    }

    if (!userRow.email) {
      return { status: "missing_email" as const };
    }

    if (userRow.email_verified_at !== null) {
      await recordSecurityAudit(
        {
          actorUserId: userRow.id,
          action: "auth.email_verification.already_verified",
          entityType: "user",
          entityId: userRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            verificationType: "EMAIL",
          },
        },
        tx
      );
      return { status: "already_verified" as const };
    }

    // Check cooldown against the latest EMAIL verification token for this user
    if (cooldownMs > 0) {
      const recentTokens = await tx.execute<{
        id: string;
        created_at: Date | string;
        used_at: Date | string | null;
      }>(
        sql`SELECT id, created_at, used_at
            FROM verification_tokens
            WHERE user_id = ${userRow.id} AND verification_type = 'EMAIL'
            ORDER BY created_at DESC
            LIMIT 1`
      );

      const latest = recentTokens.rows[0];
      if (latest) {
        const createdAtMs = new Date(latest.created_at).getTime();
        const elapsedMs = nowMs - createdAtMs;
        if (elapsedMs < cooldownMs) {
          const retryAfterSeconds = Math.max(
            1,
            Math.ceil((cooldownMs - elapsedMs) / 1000)
          );
          await recordSecurityAudit(
            {
              actorUserId: userRow.id,
              action: "auth.email_verification.cooldown_blocked",
              entityType: "user",
              entityId: userRow.id,
              ipAddress: context.ipAddress,
              metadata: {
                cooldownMs,
                retryAfterSeconds,
              },
            },
            tx
          );
          return {
            status: "cooldown" as const,
            retryAfterSeconds,
          };
        }
      }
    }

    if (!emailProvider.isConfigured()) {
      await recordSecurityAudit(
        {
          actorUserId: userRow.id,
          action: "auth.email_verification.delivery_failed",
          entityType: "user",
          entityId: userRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            provider: emailProvider.providerName,
            errorCode: "EMAIL_PROVIDER_NOT_CONFIGURED",
            errorReason:
              "Email delivery provider is not configured. Set RESEND_API_KEY and EMAIL_FROM.",
          },
        },
        tx
      );
      return { status: "provider_unconfigured" as const };
    }

    // Invalidate all prior unused EMAIL verification tokens for this user
    await tx
      .update(verificationTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(verificationTokens.userId, userRow.id),
          eq(verificationTokens.verificationType, "EMAIL"),
          isNull(verificationTokens.usedAt)
        )
      );

    const { rawToken, tokenHash, expiresAt } = generateVerificationToken(
      EMAIL_VERIFICATION_TTL_MS,
      nowMs
    );

    const [insertedToken] = await tx
      .insert(verificationTokens)
      .values({
        userId: userRow.id,
        tokenHash,
        verificationType: "EMAIL",
        expiresAt,
        createdAt: nowDate,
      })
      .returning({ id: verificationTokens.id });

    return {
      status: "created" as const,
      userId: userRow.id,
      firstName: userRow.first_name,
      toEmail: userRow.email,
      tokenId: insertedToken.id,
      rawToken,
      expiresAt,
    };
  });

  if (txResult.status === "missing_email") {
    throw new AuthDomainError(
      400,
      "MISSING_CONTACT_CHANNEL",
      "No email address is associated with this account."
    );
  }

  if (txResult.status === "cooldown") {
    throw new AuthDomainError(
      429,
      "RATE_LIMITED",
      "Please wait before requesting another verification email.",
      txResult.retryAfterSeconds
    );
  }

  if (
    txResult.status === "inactive" ||
    txResult.status === "already_verified" ||
    txResult.status === "provider_unconfigured"
  ) {
    return {
      message: GENERIC_EMAIL_VERIFICATION_RESEND_MESSAGE,
      type: "EMAIL",
    };
  }

  const verificationUrl = buildEmailVerificationUrl(
    txResult.rawToken,
    frontendUrl
  );

  const deliveryResult = await emailProvider.sendVerificationEmail({
    toEmail: txResult.toEmail,
    firstName: txResult.firstName,
    verificationUrl,
    expiresInHours: 24,
  });

  if (!deliveryResult.delivered) {
    // Delete the undelivered token so no unusable token stays active and record internal failure
    await runAtomicTransaction(executor, async (tx) => {
      await tx
        .delete(verificationTokens)
        .where(eq(verificationTokens.id, txResult.tokenId));

      await recordSecurityAudit(
        {
          actorUserId: txResult.userId,
          action: "auth.email_verification.delivery_failed",
          entityType: "verification_token",
          entityId: txResult.tokenId,
          ipAddress: context.ipAddress,
          metadata: {
            provider: deliveryResult.provider,
            errorCode: deliveryResult.errorCode ?? "EMAIL_PROVIDER_REJECTED",
            errorReason:
              deliveryResult.errorReason ??
              "Email provider failed to deliver verification message.",
          },
        },
        tx
      );
    });

    return {
      message: GENERIC_EMAIL_VERIFICATION_RESEND_MESSAGE,
      type: "EMAIL",
    };
  }

  await recordSecurityAudit(
    {
      actorUserId: txResult.userId,
      action: "auth.email_verification.sent",
      entityType: "verification_token",
      entityId: txResult.tokenId,
      ipAddress: context.ipAddress,
      metadata: {
        provider: deliveryResult.provider,
        providerMessageId: deliveryResult.providerMessageId ?? null,
        expiresAt: txResult.expiresAt.toISOString(),
      },
    },
    executor
  );

  return {
    message: GENERIC_EMAIL_VERIFICATION_RESEND_MESSAGE,
    type: "EMAIL",
  };
}

/**
 * Dispatches a 6-digit phone verification OTP (`verification_type = 'PHONE'`).
 * - Until a live SMS provider is configured (`!smsProvider.isConfigured()`), returns HTTP 503
 *   with code `SMS_VERIFICATION_UNAVAILABLE` without creating a token or marking phone verified.
 * - When a configured/mock provider is present:
 *   - Normalizes phone number using `normalizePhoneNumber()`.
 *   - Enforces resend cooldown and invalidates previous unused `PHONE` tokens.
 *   - Generates a 6-digit CSPRNG OTP and stores only its domain-separated HMAC-SHA256 digest (10m TTL).
 *   - If SMS dispatch fails, does not persist the token or mark phone verified, and returns HTTP 503.
 */
export async function dispatchPhoneVerificationOtp(
  actorUser: SafeAuthenticatedUser,
  context: ResendVerificationContext,
  executor: DbExecutor = db
): Promise<ResendVerificationSuccessResult> {
  const smsProvider = context.smsProvider ?? defaultSmsDeliveryProvider;
  const cooldownMs =
    context.cooldownMs ?? DEFAULT_VERIFICATION_RESEND_COOLDOWN_MS;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);

  if (!actorUser.phoneNumber) {
    throw new AuthDomainError(
      400,
      "MISSING_CONTACT_CHANNEL",
      "No phone number is associated with this account."
    );
  }

  const normalizedPhone = normalizePhoneNumber(actorUser.phoneNumber);

  if (!smsProvider.isConfigured()) {
    await recordSecurityAudit(
      {
        actorUserId: actorUser.id,
        action: "auth.phone_verification.unavailable",
        entityType: "user",
        entityId: actorUser.id,
        ipAddress: context.ipAddress,
        metadata: {
          provider: smsProvider.providerName,
          errorCode: "SMS_VERIFICATION_UNAVAILABLE",
        },
      },
      executor
    );

    throw new AuthDomainError(
      503,
      "SMS_VERIFICATION_UNAVAILABLE",
      "Phone verification via SMS is currently unavailable because no live SMS provider is configured."
    );
  }

  const txResult = await runAtomicTransaction(executor, async (tx) => {
    const lockedUsers = await tx.execute<{
      id: string;
      phone_number: string | null;
      status: "ACTIVE" | "DISABLED";
      phone_verified_at: Date | string | null;
    }>(
      sql`SELECT id, phone_number, status, phone_verified_at
          FROM users
          WHERE id = ${actorUser.id}
          FOR UPDATE`
    );

    const userRow = lockedUsers.rows[0];
    if (!userRow || userRow.status !== "ACTIVE" || !userRow.phone_number) {
      return { status: "inactive" as const };
    }

    if (userRow.phone_verified_at !== null) {
      await recordSecurityAudit(
        {
          actorUserId: userRow.id,
          action: "auth.phone_verification.already_verified",
          entityType: "user",
          entityId: userRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            verificationType: "PHONE",
          },
        },
        tx
      );
      return { status: "already_verified" as const };
    }

    if (cooldownMs > 0) {
      const recentTokens = await tx.execute<{
        id: string;
        created_at: Date | string;
      }>(
        sql`SELECT id, created_at
            FROM verification_tokens
            WHERE user_id = ${userRow.id} AND verification_type = 'PHONE'
            ORDER BY created_at DESC
            LIMIT 1`
      );

      const latest = recentTokens.rows[0];
      if (latest) {
        const createdAtMs = new Date(latest.created_at).getTime();
        const elapsedMs = nowMs - createdAtMs;
        if (elapsedMs < cooldownMs) {
          const retryAfterSeconds = Math.max(
            1,
            Math.ceil((cooldownMs - elapsedMs) / 1000)
          );
          await recordSecurityAudit(
            {
              actorUserId: userRow.id,
              action: "auth.phone_verification.cooldown_blocked",
              entityType: "user",
              entityId: userRow.id,
              ipAddress: context.ipAddress,
              metadata: {
                cooldownMs,
                retryAfterSeconds,
              },
            },
            tx
          );
          return {
            status: "cooldown" as const,
            retryAfterSeconds,
          };
        }
      }
    }

    const { rawOtp, tokenHash, expiresAt } = generatePhoneVerificationOtp(
      userRow.id,
      PHONE_VERIFICATION_TTL_MS,
      nowMs
    );

    const smsResult = await smsProvider.sendVerificationOtp(
      normalizedPhone,
      rawOtp
    );

    if (!smsResult.delivered) {
      // Do NOT create a verification_tokens row or mark phone_verified_at when SMS dispatch fails
      await recordSecurityAudit(
        {
          actorUserId: userRow.id,
          action: "auth.phone_verification.delivery_failed",
          entityType: "user",
          entityId: userRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            provider: smsResult.provider,
            errorCode: smsResult.errorCode ?? "SMS_VERIFICATION_UNAVAILABLE",
            errorReason:
              smsResult.errorReason ?? "Failed to dispatch verification SMS.",
          },
        },
        tx
      );
      return {
        status: "delivery_failed" as const,
      };
    }

    // Invalidate previous unused PHONE tokens for this user
    await tx
      .update(verificationTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(verificationTokens.userId, userRow.id),
          eq(verificationTokens.verificationType, "PHONE"),
          isNull(verificationTokens.usedAt)
        )
      );

    const [insertedToken] = await tx
      .insert(verificationTokens)
      .values({
        userId: userRow.id,
        tokenHash,
        verificationType: "PHONE",
        attemptCount: 0,
        expiresAt,
        createdAt: nowDate,
      })
      .returning({ id: verificationTokens.id });

    await recordSecurityAudit(
      {
        actorUserId: userRow.id,
        action: "auth.phone_verification.otp_sent",
        entityType: "verification_token",
        entityId: insertedToken.id,
        ipAddress: context.ipAddress,
        metadata: {
          provider: smsResult.provider,
          providerMessageId: smsResult.providerMessageId ?? null,
          expiresAt: expiresAt.toISOString(),
        },
      },
      tx
    );

    return {
      status: "sent" as const,
    };
  });

  if (txResult.status === "cooldown") {
    throw new AuthDomainError(
      429,
      "RATE_LIMITED",
      "Please wait before requesting another verification code.",
      txResult.retryAfterSeconds
    );
  }

  if (txResult.status === "delivery_failed") {
    throw new AuthDomainError(
      503,
      "SMS_VERIFICATION_UNAVAILABLE",
      "Phone verification via SMS is currently unavailable."
    );
  }

  return {
    message: GENERIC_PHONE_VERIFICATION_RESEND_MESSAGE,
    type: "PHONE",
  };
}

export interface VerifyPhoneOtpContext {
  ipAddress: string;
  nowMs?: number;
  maxOtpAttempts?: number;
}

export interface VerifyPhoneOtpSuccessResult {
  phoneVerified: true;
  message: string;
}

/**
 * Verifies a 6-digit phone OTP (`POST /api/v1/auth/verify-phone`):
 * - Computes domain-separated HMAC-SHA256 digest (`${userId}:PHONE:${code}`).
 * - Enforces single-use consumption (`used_at IS NULL`), 10-minute expiry, and row-level locking (`FOR UPDATE`).
 * - Persists failed attempt counts on `verification_tokens.attempt_count` in PostgreSQL (`DEFAULT_MAX_PHONE_OTP_ATTEMPTS = 5`),
 *   automatically invalidating the token (`used_at = now()`) on the fifth failed attempt inside the same transaction.
 * - Updates `users.phone_verified_at` and marks the token used atomically.
 */
export async function verifyPhoneOtp(
  actorUser: SafeAuthenticatedUser,
  rawBody: unknown,
  context: VerifyPhoneOtpContext,
  executor: DbExecutor = db
): Promise<VerifyPhoneOtpSuccessResult> {
  const parsed = parseVerifyPhoneInput(rawBody);
  if (!parsed.success) {
    throw new AuthDomainError(400, "VALIDATION_ERROR", parsed.message);
  }

  const code = parsed.data.code;
  const nowMs = context.nowMs ?? Date.now();
  const nowDate = new Date(nowMs);
  const maxAttempts = context.maxOtpAttempts ?? DEFAULT_MAX_PHONE_OTP_ATTEMPTS;

  const expectedHash = hashPhoneOtp(actorUser.id, code);

  const outcome = await runAtomicTransaction(executor, async (tx) => {
    const lockedUsers = await tx.execute<{
      id: string;
      status: "ACTIVE" | "DISABLED";
      phone_verified_at: Date | string | null;
    }>(
      sql`SELECT id, status, phone_verified_at
          FROM users
          WHERE id = ${actorUser.id}
          FOR UPDATE`
    );

    const userRow = lockedUsers.rows[0];
    if (!userRow || userRow.status !== "ACTIVE") {
      return { ok: false as const, reason: "inactive" as const };
    }

    const lockedTokens = await tx.execute<{
      id: string;
      user_id: string;
      token_hash: string;
      verification_type: "EMAIL" | "PHONE";
      attempt_count: number;
      expires_at: Date | string;
      used_at: Date | string | null;
    }>(
      sql`SELECT id, user_id, token_hash, verification_type, attempt_count, expires_at, used_at
          FROM verification_tokens
          WHERE user_id = ${actorUser.id} AND verification_type = 'PHONE'
          ORDER BY created_at DESC
          LIMIT 1
          FOR UPDATE`
    );

    const tokenRow = lockedTokens.rows[0];
    if (!tokenRow) {
      await recordSecurityAudit(
        {
          actorUserId: actorUser.id,
          action: "auth.phone_verification.failed",
          entityType: "user",
          entityId: actorUser.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "no_token_found",
          },
        },
        tx
      );
      return { ok: false as const, reason: "invalid" as const };
    }

    if (tokenRow.used_at !== null) {
      await recordSecurityAudit(
        {
          actorUserId: actorUser.id,
          action: "auth.phone_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_already_used",
          },
        },
        tx
      );
      return { ok: false as const, reason: "replayed" as const };
    }

    const expiresAtMs = new Date(tokenRow.expires_at).getTime();
    if (expiresAtMs <= nowMs) {
      await recordSecurityAudit(
        {
          actorUserId: actorUser.id,
          action: "auth.phone_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "token_expired",
          },
        },
        tx
      );
      return { ok: false as const, reason: "expired" as const };
    }

    const currentAttempts = Number(tokenRow.attempt_count);
    if (currentAttempts >= maxAttempts) {
      await tx
        .update(verificationTokens)
        .set({ usedAt: nowDate })
        .where(eq(verificationTokens.id, tokenRow.id));

      await recordSecurityAudit(
        {
          actorUserId: actorUser.id,
          action: "auth.phone_verification.max_attempts_exceeded",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            attempts: currentAttempts,
            maxAttempts,
          },
        },
        tx
      );

      return { ok: false as const, reason: "max_attempts" as const };
    }

    if (!compareTokenHashes(tokenRow.token_hash, expectedHash)) {
      const nextAttemptCount = currentAttempts + 1;
      const reachedMaxAttempts = nextAttemptCount >= maxAttempts;

      await tx
        .update(verificationTokens)
        .set({
          attemptCount: nextAttemptCount,
          ...(reachedMaxAttempts ? { usedAt: nowDate } : {}),
        })
        .where(eq(verificationTokens.id, tokenRow.id));

      if (reachedMaxAttempts) {
        await recordSecurityAudit(
          {
            actorUserId: actorUser.id,
            action: "auth.phone_verification.max_attempts_exceeded",
            entityType: "verification_token",
            entityId: tokenRow.id,
            ipAddress: context.ipAddress,
            metadata: {
              attempts: nextAttemptCount,
              maxAttempts,
            },
          },
          tx
        );

        return { ok: false as const, reason: "max_attempts" as const };
      }

      await recordSecurityAudit(
        {
          actorUserId: actorUser.id,
          action: "auth.phone_verification.failed",
          entityType: "verification_token",
          entityId: tokenRow.id,
          ipAddress: context.ipAddress,
          metadata: {
            reason: "incorrect_otp",
            attemptNumber: nextAttemptCount,
            maxAttempts,
          },
        },
        tx
      );

      return { ok: false as const, reason: "incorrect" as const };
    }

    // OTP matched: mark token used and update phone_verified_at atomically
    await tx
      .update(verificationTokens)
      .set({ usedAt: nowDate })
      .where(
        and(
          eq(verificationTokens.userId, actorUser.id),
          eq(verificationTokens.verificationType, "PHONE"),
          isNull(verificationTokens.usedAt)
        )
      );

    const verifiedAt = userRow.phone_verified_at
      ? new Date(userRow.phone_verified_at)
      : nowDate;

    await tx
      .update(users)
      .set({
        phoneVerifiedAt: verifiedAt,
        updatedAt: nowDate,
      })
      .where(eq(users.id, actorUser.id));

    await recordSecurityAudit(
      {
        actorUserId: actorUser.id,
        action: "auth.phone_verification.verified",
        entityType: "user",
        entityId: actorUser.id,
        ipAddress: context.ipAddress,
        metadata: {
          verificationTokenId: tokenRow.id,
          verificationType: "PHONE",
          attemptCount: currentAttempts,
        },
      },
      tx
    );

    return { ok: true as const };
  });

  if (!outcome.ok) {
    if (outcome.reason === "max_attempts") {
      throw new AuthDomainError(
        429,
        "RATE_LIMITED",
        "Too many failed verification attempts. Please request a new verification code."
      );
    }

    throw new AuthDomainError(
      400,
      "INVALID_OR_EXPIRED_TOKEN",
      GENERIC_INVALID_PHONE_OTP_MESSAGE
    );
  }

  return {
    phoneVerified: true,
    message: "Phone number has been verified.",
  };
}
