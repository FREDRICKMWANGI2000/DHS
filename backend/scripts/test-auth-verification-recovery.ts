import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import { and, eq, isNull } from "drizzle-orm";
import {
  env,
  isResendConfigured,
  PLACEHOLDER_RESEND_API_KEY,
  validateResendConfig,
} from "../src/config/env";
import { db, pool } from "../src/db/client";
import {
  auditLogs,
  passwordResetTokens,
  sessions,
  users,
  verificationTokens,
} from "../src/db/schema";
import { createApp } from "../src/app";
import { MemoryRateLimitStore } from "../src/middleware/rate-limit";
import { DbExecutor } from "../src/services/auth/audit.service";
import {
  EMAIL_VERIFICATION_TTL_MS,
  generateSecureToken,
  hashPhoneOtp,
  hashToken,
  PASSWORD_RESET_TTL_MS,
  PHONE_VERIFICATION_TTL_MS,
} from "../src/services/auth/token.service";
import {
  verifyEmailToken,
  verifyPhoneOtp,
} from "../src/services/auth/verification.service";
import { resetPasswordWithToken } from "../src/services/auth/password-recovery.service";
import { toSafeAuthenticatedUser } from "../src/services/auth/session.service";
import {
  extractTokenFromFragmentUrl,
  MockEmailDeliveryProvider,
  ResendEmailDeliveryProvider,
} from "../src/services/email";
import {
  MockSmsDeliveryProvider,
  UnconfiguredSmsDeliveryProvider,
} from "../src/services/sms";
import {
  CSRF_CONTEXT_COOKIE_NAME,
  SESSION_COOKIE_NAME,
} from "../src/utils/auth-cookie";

const ROLLBACK_SENTINEL = Symbol("ROLLBACK_SENTINEL");

async function withRolledBackTransaction(
  fn: (tx: DbExecutor) => Promise<void>
): Promise<void> {
  try {
    await db.transaction(async (tx) => {
      await fn(tx as unknown as DbExecutor);
      throw ROLLBACK_SENTINEL;
    });
  } catch (err) {
    if (err !== ROLLBACK_SENTINEL) {
      throw err;
    }
  }
}

function extractCookieValue(
  setCookieHeaders: string[],
  cookieName: string
): string | null {
  for (const header of setCookieHeaders) {
    const firstPart = header.split(";")[0]?.trim() ?? "";
    if (firstPart.startsWith(`${cookieName}=`)) {
      return firstPart.slice(cookieName.length + 1);
    }
  }
  return null;
}

async function fetchCsrfTokenAndCookie(
  baseUrl: string,
  sessionCookieValue?: string
): Promise<{ csrfToken: string; csrfCtxCookie: string | null }> {
  const headers: Record<string, string> = {};
  if (sessionCookieValue) {
    headers.Cookie = `${SESSION_COOKIE_NAME}=${sessionCookieValue}`;
  }
  const res = await fetch(`${baseUrl}/api/v1/auth/csrf`, { headers });
  assert.equal(res.status, 200);
  const setCookies = res.headers.getSetCookie();
  const csrfCtxVal = extractCookieValue(setCookies, CSRF_CONTEXT_COOKIE_NAME);
  const body = (await res.json()) as {
    status: string;
    data: { csrfToken: string };
  };
  return {
    csrfToken: body.data.csrfToken,
    csrfCtxCookie: csrfCtxVal,
  };
}

test("1. Email Delivery Architecture & Resend Provider Configuration Validation", async () => {
  // 1.1 Placeholder or missing RESEND_API_KEY is detected as unconfigured without leaking secrets
  assert.equal(isResendConfigured(undefined, "noreply@dsh.co.ke"), false);
  assert.equal(
    isResendConfigured(PLACEHOLDER_RESEND_API_KEY, "noreply@dsh.co.ke"),
    false
  );
  assert.equal(isResendConfigured("re_valid_key_123456", ""), false);
  assert.equal(
    isResendConfigured(
      "re_valid_key_123456",
      "Digital Services Hub <noreply@yourdomain.com>",
      "production"
    ),
    false
  );
  assert.equal(
    isResendConfigured(
      "re_valid_key_123456",
      "Digital Services Hub <noreply@dsh.co.ke>",
      "production"
    ),
    true
  );

  assert.throws(
    () => validateResendConfig("invalid_prefix_secret_xyz", "noreply@dsh.co.ke"),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal(
        err.message.includes("invalid_prefix_secret_xyz"),
        false,
        "Secret key value must never appear in validation error messages"
      );
      return true;
    }
  );

  // 1.2 Unconfigured ResendEmailDeliveryProvider reports delivered=false without network calls
  const unconfiguredResend = new ResendEmailDeliveryProvider({
    apiKey: PLACEHOLDER_RESEND_API_KEY,
    emailFrom: "Digital Services Hub <noreply@yourdomain.com>",
  });
  assert.equal(unconfiguredResend.isConfigured(), false);
  const unconfResult = await unconfiguredResend.sendVerificationEmail({
    toEmail: "user@example.com",
    firstName: "Amina",
    verificationUrl: "http://localhost:3000/verify-email#token=test_token",
    expiresInHours: 24,
  });
  assert.equal(unconfResult.delivered, false);
  assert.equal(unconfResult.errorCode, "EMAIL_PROVIDER_NOT_CONFIGURED");

  // 1.3 Configured ResendEmailDeliveryProvider dispatches via injected fetchFn and handles 200 & 500 safely
  let capturedAuthHeader = "";
  let capturedBody = "";
  const configuredResend = new ResendEmailDeliveryProvider({
    apiKey: "re_test_live_adapter_key_99999",
    emailFrom: "Digital Services Hub <noreply@dsh.co.ke>",
    nodeEnv: "production",
    fetchFn: async (_url, init) => {
      const headers = init?.headers as Record<string, string>;
      capturedAuthHeader = headers.Authorization;
      capturedBody = String(init?.body ?? "");
      return new Response(JSON.stringify({ id: "resend_msg_001" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    },
  });
  assert.equal(configuredResend.isConfigured(), true);
  const sendOk = await configuredResend.sendPasswordResetEmail({
    toEmail: "amina@example.com",
    firstName: "Amina",
    resetUrl: "http://localhost:3000/reset-password#token=reset_tok_abc",
    expiresInMinutes: 30,
  });
  assert.equal(sendOk.delivered, true);
  assert.equal(sendOk.providerMessageId, "resend_msg_001");
  assert.equal(capturedAuthHeader, "Bearer re_test_live_adapter_key_99999");
  assert.match(capturedBody, /Digital Services Hub/);
  assert.match(capturedBody, /#token=reset_tok_abc/);

  const failingResend = new ResendEmailDeliveryProvider({
    apiKey: "re_test_live_adapter_key_99999",
    emailFrom: "Digital Services Hub <noreply@dsh.co.ke>",
    fetchFn: async () => new Response("Bad Gateway", { status: 502 }),
  });
  const sendFail = await failingResend.sendVerificationEmail({
    toEmail: "amina@example.com",
    firstName: "Amina",
    verificationUrl: "http://localhost:3000/verify-email#token=verify_tok_abc",
    expiresInHours: 24,
  });
  assert.equal(sendFail.delivered, false);
  assert.equal(sendFail.errorCode, "EMAIL_PROVIDER_REJECTED");
  assert.equal(
    (sendFail.errorReason ?? "").includes("re_test_live_adapter_key_99999"),
    false
  );
});

test("2. Email Verification & Resend Protection (POST /api/v1/auth/resend-verification & POST /api/v1/auth/verify-email)", async () => {
  await withRolledBackTransaction(async (tx) => {
    const rateLimitStore = new MemoryRateLimitStore();
    const mockEmailProvider = new MockEmailDeliveryProvider();
    const app = createApp(tx, undefined, {
      rateLimitStore,
      emailProvider: mockEmailProvider,
      registerIpMax: 50,
      loginIpMax: 50,
      verifyEmailIpMax: 50,
      resendVerificationIpMax: 50,
      resendVerificationUserMax: 20,
      verificationCooldownMs: 60_000,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Register Customer A
      const anonCsrf = await fetchCsrfTokenAndCookie(baseUrl);
      const regRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonCsrf.csrfToken,
        },
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina.verify@example.com",
          phoneNumber: "0711222333",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(regRes.status, 201);
      const aminaSessionCookie = extractCookieValue(
        regRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      const regJson = (await regRes.json()) as {
        data: { user: { id: string; emailVerifiedAt: string | null } };
      };
      const aminaId = regJson.data.user.id;
      assert.equal(regJson.data.user.emailVerifiedAt, null);

      const aminaCsrf = await fetchCsrfTokenAndCookie(
        baseUrl,
        aminaSessionCookie
      );
      const aminaAuthHeaders = {
        "Content-Type": "application/json",
        Origin: env.frontendUrl,
        Cookie: `${SESSION_COOKIE_NAME}=${aminaSessionCookie}`,
        "X-CSRF-Token": aminaCsrf.csrfToken,
      };

      // 2.1 Authenticated customer cannot request verification for another account
      const otherAccountResendRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({
            type: "EMAIL",
            email: "someone.else@example.com",
          }),
        }
      );
      assert.equal(otherAccountResendRes.status, 403);
      assert.equal(mockEmailProvider.sentVerificationEmails.length, 0);

      // 2.2 Provider unavailable: when email provider is unconfigured, user is NOT marked verified,
      // no fake delivery is claimed, generic 200 is returned, and internal failure audit event is recorded
      mockEmailProvider.setConfigured(false);
      const unconfResendRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }
      );
      assert.equal(unconfResendRes.status, 200);
      assert.equal(mockEmailProvider.sentVerificationEmails.length, 0);

      const [userAfterUnconf] = await tx
        .select()
        .from(users)
        .where(eq(users.id, aminaId));
      assert.equal(
        userAfterUnconf.emailVerifiedAt,
        null,
        "User must not be marked verified when email provider is unavailable"
      );

      // Re-enable mock email provider
      mockEmailProvider.setConfigured(true);

      // 2.3 Email verification delivery through mock provider + concurrent resend protection
      const [concurrentRes1, concurrentRes2] = await Promise.all([
        fetch(`${baseUrl}/api/v1/auth/resend-verification`, {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }),
        fetch(`${baseUrl}/api/v1/auth/resend-verification`, {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }),
      ]);

      const statuses = [concurrentRes1.status, concurrentRes2.status].sort();
      assert.deepEqual(
        statuses,
        [200, 429],
        "Concurrent resend requests must allow one and block the duplicate with 429 cooldown"
      );
      assert.equal(
        mockEmailProvider.sentVerificationEmails.length,
        1,
        "Exactly one verification email must be sent on concurrent requests"
      );

      const sentEmail1 = mockEmailProvider.sentVerificationEmails[0];
      assert.equal(sentEmail1.toEmail, "amina.verify@example.com");
      assert.match(
        sentEmail1.verificationUrl,
        /^http:\/\/localhost:3000\/verify-email#token=[A-Za-z0-9_-]{43}$/,
        "Verification link must carry the 32-byte token in the URL fragment (#token=...)"
      );
      const rawToken1 = extractTokenFromFragmentUrl(sentEmail1.verificationUrl)!;
      assert.ok(rawToken1);

      // Verify SHA-256 hash stored in PostgreSQL (never raw token) and 24-hour expiry
      const storedTokens1 = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.userId, aminaId));
      assert.equal(storedTokens1.length, 1);
      assert.equal(storedTokens1[0].tokenHash, hashToken(rawToken1));
      assert.notEqual(storedTokens1[0].tokenHash, rawToken1);
      const ttlDiffMs =
        storedTokens1[0].expiresAt.getTime() -
        storedTokens1[0].createdAt.getTime();
      assert.equal(ttlDiffMs, EMAIL_VERIFICATION_TTL_MS);

      // 2.4 Resend cooldown blocks immediate sequential resend
      const cooldownBlockedRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }
      );
      assert.equal(cooldownBlockedRes.status, 429);
      assert.ok(Number(cooldownBlockedRes.headers.get("retry-after")) >= 1);
      assert.equal(mockEmailProvider.sentVerificationEmails.length, 1);

      // Backdate the first token's created_at by 61 seconds so cooldown expires, then resend:
      // Prior unused token must be invalidated (used_at IS NOT NULL) when new token is issued!
      const pastCreatedAt = new Date(Date.now() - 61_000);
      await tx
        .update(verificationTokens)
        .set({ createdAt: pastCreatedAt })
        .where(eq(verificationTokens.id, storedTokens1[0].id));

      const resendAfterCooldownRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }
      );
      assert.equal(resendAfterCooldownRes.status, 200);
      assert.equal(mockEmailProvider.sentVerificationEmails.length, 2);

      const rawToken2 = extractTokenFromFragmentUrl(
        mockEmailProvider.sentVerificationEmails[1].verificationUrl
      )!;
      assert.notEqual(rawToken2, rawToken1);

      // Verify rawToken1 was invalidated when rawToken2 was issued
      const oldTokenVerifyRes = await fetch(
        `${baseUrl}/api/v1/auth/verify-email`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ token: rawToken1 }),
        }
      );
      assert.equal(oldTokenVerifyRes.status, 400);
      const oldTokenVerifyBody = (await oldTokenVerifyRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(oldTokenVerifyBody.error.code, "INVALID_OR_EXPIRED_TOKEN");

      // 2.5 Invalid token & Expired token return identical generic error
      const invalidTokenRes = await fetch(
        `${baseUrl}/api/v1/auth/verify-email`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ token: generateSecureToken() }),
        }
      );
      assert.equal(invalidTokenRes.status, 400);
      const invalidTokenBody = (await invalidTokenRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(invalidTokenBody.error.code, "INVALID_OR_EXPIRED_TOKEN");
      assert.equal(
        invalidTokenBody.error.message,
        oldTokenVerifyBody.error.message
      );

      // Test expired token by checking at nowMs + 24h + 1ms via service
      await assert.rejects(
        async () =>
          verifyEmailToken(
            { token: rawToken2 },
            {
              ipAddress: "127.0.0.1",
              nowMs: Date.now() + EMAIL_VERIFICATION_TTL_MS + 1000,
            },
            tx
          ),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, invalidTokenBody.error.message);
          return true;
        }
      );

      // 2.6 Concurrent token consumption: two simultaneous requests with rawToken2 -> only ONE succeeds!
      const [verifyConc1, verifyConc2] = await Promise.all([
        fetch(`${baseUrl}/api/v1/auth/verify-email`, {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ token: rawToken2 }),
        }),
        fetch(`${baseUrl}/api/v1/auth/verify-email`, {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ token: rawToken2 }),
        }),
      ]);

      const verifyStatuses = [verifyConc1.status, verifyConc2.status].sort();
      assert.deepEqual(
        verifyStatuses,
        [200, 400],
        "Concurrent consumption of the same email verification token must succeed once (200) and reject the second (400)"
      );

      // 2.7 Verified timestamp update & Replayed token rejection
      const [verifiedUser] = await tx
        .select()
        .from(users)
        .where(eq(users.id, aminaId));
      assert.ok(
        verifiedUser.emailVerifiedAt instanceof Date,
        "users.email_verified_at must be populated after successful verification"
      );

      const replayRes = await fetch(`${baseUrl}/api/v1/auth/verify-email`, {
        method: "POST",
        headers: aminaAuthHeaders,
        body: JSON.stringify({ token: rawToken2 }),
      });
      assert.equal(replayRes.status, 400);
      const replayBody = (await replayRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(replayBody.error.code, "INVALID_OR_EXPIRED_TOKEN");
      assert.equal(replayBody.error.message, invalidTokenBody.error.message);

      // 2.8 Already verified account: resend-verification returns generic 200 without generating new tokens
      const tokensBeforeAlreadyVerified = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.userId, aminaId));

      const alreadyVerifiedResend = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: aminaAuthHeaders,
          body: JSON.stringify({ type: "EMAIL" }),
        }
      );
      assert.equal(alreadyVerifiedResend.status, 200);
      assert.equal(
        mockEmailProvider.sentVerificationEmails.length,
        2,
        "No new email should be sent when account is already verified"
      );

      const tokensAfterAlreadyVerified = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.userId, aminaId));
      assert.equal(
        tokensAfterAlreadyVerified.length,
        tokensBeforeAlreadyVerified.length,
        "No new verification_tokens row should be created when account is already verified"
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test("3. Phone OTP Verification & SMS Provider Limitations (503 when unconfigured, Mock SMS success, HMAC storage, expiry, replay & attempt limits)", async () => {
  await withRolledBackTransaction(async (tx) => {
    const rateLimitStore = new MemoryRateLimitStore();
    const unconfiguredSms = new UnconfiguredSmsDeliveryProvider();
    const mockSms = new MockSmsDeliveryProvider({ configured: false });

    const app = createApp(tx, undefined, {
      rateLimitStore,
      smsProvider: mockSms,
      registerIpMax: 50,
      resendVerificationIpMax: 50,
      resendVerificationUserMax: 20,
      verifyPhoneIpMax: 50,
      verificationCooldownMs: 60_000,
      maxPhoneOtpAttempts: 5,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Verify default UnconfiguredSmsDeliveryProvider returns SMS_VERIFICATION_UNAVAILABLE
      assert.equal(unconfiguredSms.isConfigured(), false);
      const defaultSmsRes = await unconfiguredSms.sendVerificationOtp(
        "0722333444",
        "123456"
      );
      assert.equal(defaultSmsRes.delivered, false);
      assert.equal(defaultSmsRes.errorCode, "SMS_VERIFICATION_UNAVAILABLE");

      // Register Customer with phone number
      const anonCsrf = await fetchCsrfTokenAndCookie(baseUrl);
      const regRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonCsrf.csrfToken,
        },
        body: JSON.stringify({
          firstName: "Brian",
          lastName: "Ochieng",
          phoneNumber: "0722 333 444",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(regRes.status, 201);
      const brianCookie = extractCookieValue(
        regRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      const regBody = (await regRes.json()) as {
        data: { user: { id: string; phoneNumber: string } };
      };
      const brianId = regBody.data.user.id;
      assert.equal(regBody.data.user.phoneNumber, "+254722333444");

      const brianCsrf = await fetchCsrfTokenAndCookie(baseUrl, brianCookie);
      const brianHeaders = {
        "Content-Type": "application/json",
        Origin: env.frontendUrl,
        Cookie: `${SESSION_COOKIE_NAME}=${brianCookie}`,
        "X-CSRF-Token": brianCsrf.csrfToken,
      };

      // 3.1 SMS provider unavailable -> HTTP 503 SMS_VERIFICATION_UNAVAILABLE, no token created, no phone_verified_at
      const unavRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(unavRes.status, 503);
      const unavBody = (await unavRes.json()) as {
        error: { code: string };
      };
      assert.equal(unavBody.error.code, "SMS_VERIFICATION_UNAVAILABLE");

      const tokensAfterUnav = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.userId, brianId));
      assert.equal(
        tokensAfterUnav.length,
        0,
        "No verification token may be created when SMS provider is unavailable"
      );

      const [userAfterUnav] = await tx
        .select()
        .from(users)
        .where(eq(users.id, brianId));
      assert.equal(userAfterUnav.phoneVerifiedAt, null);

      // 3.2 When SMS provider is configured but dispatch fails -> HTTP 503, no token created, no verification timestamp
      mockSms.setConfigured(true);
      mockSms.setSimulateFailure("SMS_PROVIDER_NETWORK_ERROR");
      const failDispatchRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(failDispatchRes.status, 503);
      assert.equal(
        (
          await tx
            .select()
            .from(verificationTokens)
            .where(eq(verificationTokens.userId, brianId))
        ).length,
        0,
        "No token may be persisted when SMS dispatch fails"
      );

      // 3.3 Mock SMS provider success: 6-digit OTP generated, HMAC-SHA256 stored, 10m expiry, attempt_count = 0
      mockSms.setSimulateFailure(null);
      const otpSendRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(otpSendRes.status, 200);
      assert.equal(mockSms.sentOtpMessages.length, 1);

      const sentSms1 = mockSms.sentOtpMessages[0];
      assert.equal(sentSms1.phoneNumber, "+254722333444");
      assert.match(sentSms1.code, /^[0-9]{6}$/);

      const [storedOtpRow1] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.userId, brianId));
      assert.ok(storedOtpRow1);
      assert.equal(
        storedOtpRow1.attemptCount,
        0,
        "Initial verification_tokens.attempt_count must be 0"
      );
      assert.equal(storedOtpRow1.usedAt, null);
      assert.notEqual(
        storedOtpRow1.tokenHash,
        sentSms1.code,
        "Raw 6-digit OTP must never be stored in PostgreSQL"
      );
      assert.equal(
        storedOtpRow1.tokenHash,
        hashPhoneOtp(brianId, sentSms1.code),
        "Stored token_hash must match domain-separated HMAC-SHA256 digest"
      );
      assert.equal(
        storedOtpRow1.expiresAt.getTime() - storedOtpRow1.createdAt.getTime(),
        PHONE_VERIFICATION_TTL_MS
      );

      // 3.4 (A) Attempt progression: 0 -> 1 -> 2 -> 3 -> 4 -> 5 in PostgreSQL, 5th sets used_at, subsequent rejected
      const wrongCode1 = sentSms1.code === "000000" ? "999999" : "000000";
      for (let expectedAttempt = 1; expectedAttempt <= 4; expectedAttempt++) {
        const wrongRes = await fetch(`${baseUrl}/api/v1/auth/verify-phone`, {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ code: wrongCode1 }),
        });
        assert.equal(wrongRes.status, 400);

        const [rowAfterAttempt] = await tx
          .select()
          .from(verificationTokens)
          .where(eq(verificationTokens.id, storedOtpRow1.id));
        assert.equal(
          rowAfterAttempt.attemptCount,
          expectedAttempt,
          `PostgreSQL attempt_count must equal ${expectedAttempt} after attempt ${expectedAttempt}`
        );
        assert.equal(
          rowAfterAttempt.usedAt,
          null,
          `used_at must remain NULL before the 5th failed attempt (attempt ${expectedAttempt})`
        );
      }

      // 5th wrong attempt reaches maxOtpAttempts (5), returns 429, sets attempt_count = 5 and used_at IS NOT NULL
      const attempt5Res = await fetch(`${baseUrl}/api/v1/auth/verify-phone`, {
        method: "POST",
        headers: brianHeaders,
        body: JSON.stringify({ code: wrongCode1 }),
      });
      assert.equal(attempt5Res.status, 429);

      const [rowAfterAttempt5] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.id, storedOtpRow1.id));
      assert.equal(rowAfterAttempt5.attemptCount, 5);
      assert.ok(
        rowAfterAttempt5.usedAt instanceof Date,
        "used_at must be set on the 5th failed OTP attempt"
      );

      // Even submitting the correct code now must fail because the token was invalidated after 5 failed attempts!
      const afterMaxAttemptsRes = await fetch(
        `${baseUrl}/api/v1/auth/verify-phone`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ code: sentSms1.code }),
        }
      );
      assert.equal(afterMaxAttemptsRes.status, 400);

      const [rowAfterPostInvalidation] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.id, storedOtpRow1.id));
      assert.equal(
        rowAfterPostInvalidation.attemptCount,
        5,
        "attempt_count must not increment past 5 once invalidated"
      );

      // 3.5 (B) Backend restart simulation:
      // Create a test OTP, perform 3 incorrect attempts, verify PostgreSQL stores attempt_count = 3,
      // then spin up a fresh Express app + fresh MemoryRateLimitStore and submit 2 more incorrect attempts.
      await tx
        .update(verificationTokens)
        .set({ createdAt: new Date(Date.now() - 61_000) })
        .where(eq(verificationTokens.id, storedOtpRow1.id));

      const otpRestartSendRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(otpRestartSendRes.status, 200);
      assert.equal(mockSms.sentOtpMessages.length, 2);
      const sentSmsRestart = mockSms.sentOtpMessages[1];
      const wrongCodeRestart =
        sentSmsRestart.code === "111111" ? "888888" : "111111";

      const restartTokens = await tx
        .select()
        .from(verificationTokens)
        .where(
          and(
            eq(verificationTokens.userId, brianId),
            isNull(verificationTokens.usedAt)
          )
        );
      assert.equal(restartTokens.length, 1);
      const restartTokenId = restartTokens[0].id;
      assert.equal(restartTokens[0].attemptCount, 0);

      for (let i = 1; i <= 3; i++) {
        const res = await fetch(`${baseUrl}/api/v1/auth/verify-phone`, {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ code: wrongCodeRestart }),
        });
        assert.equal(res.status, 400);
      }

      const [tokenBeforeRestart] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.id, restartTokenId));
      assert.equal(
        tokenBeforeRestart.attemptCount,
        3,
        "PostgreSQL must persist attempt_count = 3 prior to simulated backend restart"
      );
      assert.equal(tokenBeforeRestart.usedAt, null);

      // Simulate backend restart: brand-new MemoryRateLimitStore + brand-new Express application instance
      const freshRateLimitStore = new MemoryRateLimitStore();
      const restartedApp = createApp(tx, undefined, {
        rateLimitStore: freshRateLimitStore,
        smsProvider: mockSms,
        registerIpMax: 50,
        resendVerificationIpMax: 50,
        resendVerificationUserMax: 20,
        verifyPhoneIpMax: 50,
        verificationCooldownMs: 60_000,
        maxPhoneOtpAttempts: 5,
      });
      const restartServer = http.createServer(restartedApp);
      await new Promise<void>((resolve) =>
        restartServer.listen(0, "127.0.0.1", resolve)
      );
      const restartPort = (restartServer.address() as AddressInfo).port;
      const restartBaseUrl = `http://127.0.0.1:${restartPort}`;

      try {
        // Attempt 4 on restarted backend -> HTTP 400, attempt_count = 4
        const restartAttempt4Res = await fetch(
          `${restartBaseUrl}/api/v1/auth/verify-phone`,
          {
            method: "POST",
            headers: brianHeaders,
            body: JSON.stringify({ code: wrongCodeRestart }),
          }
        );
        assert.equal(restartAttempt4Res.status, 400);

        const [tokenAfterRestart4] = await tx
          .select()
          .from(verificationTokens)
          .where(eq(verificationTokens.id, restartTokenId));
        assert.equal(tokenAfterRestart4.attemptCount, 4);
        assert.equal(tokenAfterRestart4.usedAt, null);

        // Attempt 5 on restarted backend -> HTTP 429, attempt_count = 5, used_at IS NOT NULL
        const restartAttempt5Res = await fetch(
          `${restartBaseUrl}/api/v1/auth/verify-phone`,
          {
            method: "POST",
            headers: brianHeaders,
            body: JSON.stringify({ code: wrongCodeRestart }),
          }
        );
        assert.equal(restartAttempt5Res.status, 429);

        const [tokenAfterRestart5] = await tx
          .select()
          .from(verificationTokens)
          .where(eq(verificationTokens.id, restartTokenId));
        assert.equal(
          tokenAfterRestart5.attemptCount,
          5,
          "New in-memory store must not reset PostgreSQL attempt_count; 2 more attempts after 3 must reach 5"
        );
        assert.ok(tokenAfterRestart5.usedAt instanceof Date);

        // Correct code after 5th attempt on restarted backend -> rejected with 400
        const restartCorrectAfterInvalidRes = await fetch(
          `${restartBaseUrl}/api/v1/auth/verify-phone`,
          {
            method: "POST",
            headers: brianHeaders,
            body: JSON.stringify({ code: sentSmsRestart.code }),
          }
        );
        assert.equal(restartCorrectAfterInvalidRes.status, 400);
      } finally {
        await new Promise<void>((resolve) =>
          restartServer.close(() => resolve())
        );
      }

      // 3.6 (C) Concurrent requests:
      // Submit 8 concurrent incorrect OTP requests against the same token.
      // Verify row locking ensures attempt_count never exceeds 5, used_at is set, and correct OTP fails afterward.
      await tx
        .update(verificationTokens)
        .set({ createdAt: new Date(Date.now() - 61_000) })
        .where(eq(verificationTokens.id, restartTokenId));

      const otpConcSendRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(otpConcSendRes.status, 200);
      assert.equal(mockSms.sentOtpMessages.length, 3);
      const sentSmsConc = mockSms.sentOtpMessages[2];
      const wrongCodeConc =
        sentSmsConc.code === "222222" ? "777777" : "222222";

      const concTokens = await tx
        .select()
        .from(verificationTokens)
        .where(
          and(
            eq(verificationTokens.userId, brianId),
            isNull(verificationTokens.usedAt)
          )
        );
      assert.equal(concTokens.length, 1);
      const concTokenId = concTokens[0].id;
      assert.equal(concTokens[0].attemptCount, 0);

      const [brianForConc] = await tx
        .select()
        .from(users)
        .where(eq(users.id, brianId));
      const safeBrianForConc = toSafeAuthenticatedUser(brianForConc);

      const concurrentOutcomes = await Promise.all(
        Array.from({ length: 8 }, async () => {
          try {
            await verifyPhoneOtp(
              safeBrianForConc,
              { code: wrongCodeConc },
              { ipAddress: "127.0.0.1", maxOtpAttempts: 5 },
              tx
            );
            return 200;
          } catch (err: unknown) {
            if (
              err !== null &&
              typeof err === "object" &&
              "statusCode" in err &&
              typeof (err as { statusCode: unknown }).statusCode === "number"
            ) {
              return (err as { statusCode: number }).statusCode;
            }
            throw err;
          }
        })
      );

      const concStatuses = [...concurrentOutcomes].sort();
      // 4 attempts before threshold (400) + 1 attempt hitting threshold (429) + 3 attempts after invalidation (400)
      assert.deepEqual(
        concStatuses,
        [400, 400, 400, 400, 400, 400, 400, 429],
        "8 concurrent wrong OTP attempts must produce exactly one 429 on the 5th attempt and 400 for the rest"
      );

      const [concTokenAfter] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.id, concTokenId));
      assert.equal(
        concTokenAfter.attemptCount,
        5,
        "Database row locking must ensure attempt_count never exceeds 5 under concurrent load"
      );
      assert.ok(
        concTokenAfter.usedAt instanceof Date,
        "used_at must be set after concurrent attempts reach 5"
      );

      const concCorrectAfterRes = await fetch(
        `${baseUrl}/api/v1/auth/verify-phone`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ code: sentSmsConc.code }),
        }
      );
      assert.equal(concCorrectAfterRes.status, 400);

      // 3.7 (D) Successful verification:
      // Issue a fresh OTP after backdating cooldown, test expired OTP rejection, then valid OTP consumption & replay rejection
      await tx
        .update(verificationTokens)
        .set({ createdAt: new Date(Date.now() - 61_000) })
        .where(eq(verificationTokens.id, concTokenId));

      const otpSendFinalRes = await fetch(
        `${baseUrl}/api/v1/auth/resend-verification`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ type: "PHONE" }),
        }
      );
      assert.equal(otpSendFinalRes.status, 200);
      assert.equal(mockSms.sentOtpMessages.length, 4);
      const sentSmsFinal = mockSms.sentOtpMessages[3];

      const activeFinalTokens = await tx
        .select()
        .from(verificationTokens)
        .where(
          and(
            eq(verificationTokens.userId, brianId),
            isNull(verificationTokens.usedAt)
          )
        );
      assert.equal(activeFinalTokens.length, 1);
      const finalTokenId = activeFinalTokens[0].id;

      const [brianUserRow] = await tx
        .select()
        .from(users)
        .where(eq(users.id, brianId));

      // Expired OTP check (+10m + 1s)
      await assert.rejects(
        async () =>
          verifyPhoneOtp(
            toSafeAuthenticatedUser(brianUserRow),
            { code: sentSmsFinal.code },
            {
              ipAddress: "127.0.0.1",
              nowMs: Date.now() + PHONE_VERIFICATION_TTL_MS + 1000,
            },
            tx
          ),
        /Invalid or expired verification code/
      );

      // Valid OTP verification
      const validPhoneRes = await fetch(`${baseUrl}/api/v1/auth/verify-phone`, {
        method: "POST",
        headers: brianHeaders,
        body: JSON.stringify({ code: sentSmsFinal.code }),
      });
      assert.equal(validPhoneRes.status, 200);

      const [verifiedBrian] = await tx
        .select()
        .from(users)
        .where(eq(users.id, brianId));
      assert.ok(verifiedBrian.phoneVerifiedAt instanceof Date);

      const [consumedFinalToken] = await tx
        .select()
        .from(verificationTokens)
        .where(eq(verificationTokens.id, finalTokenId));
      assert.ok(
        consumedFinalToken.usedAt instanceof Date,
        "Successful verification must atomically set verification_tokens.used_at"
      );
      assert.equal(
        consumedFinalToken.attemptCount,
        0,
        "attempt_count must remain a valid non-negative integer (0) upon first-try successful verification"
      );

      // Replayed OTP rejection
      const replayPhoneRes = await fetch(
        `${baseUrl}/api/v1/auth/verify-phone`,
        {
          method: "POST",
          headers: brianHeaders,
          body: JSON.stringify({ code: sentSmsFinal.code }),
        }
      );
      assert.equal(replayPhoneRes.status, 400);

      // Verify no raw OTP codes or token hashes appear in audit_logs
      const phoneAuditLogs = await tx.select().from(auditLogs);
      const serializedPhoneAuditLogs = JSON.stringify(phoneAuditLogs);
      for (const msg of mockSms.sentOtpMessages) {
        assert.equal(
          serializedPhoneAuditLogs.includes(msg.code),
          false,
          "Raw OTP code must never appear in audit_logs"
        );
        assert.equal(
          serializedPhoneAuditLogs.includes(hashPhoneOtp(brianId, msg.code)),
          false,
          "OTP token_hash must never appear in audit_logs"
        );
      }
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test("4. Password Recovery & Reset (POST /api/v1/auth/forgot-password & POST /api/v1/auth/reset-password)", async () => {
  await withRolledBackTransaction(async (tx) => {
    const rateLimitStore = new MemoryRateLimitStore();
    const mockEmailProvider = new MockEmailDeliveryProvider();

    const app = createApp(tx, undefined, {
      rateLimitStore,
      emailProvider: mockEmailProvider,
      registerIpMax: 50,
      loginIpMax: 50,
      forgotPasswordIpMax: 50,
      forgotPasswordIdentifierMax: 10,
      resetPasswordIpMax: 50,
    });

    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const anonCsrf = await fetchCsrfTokenAndCookie(baseUrl);
      const anonHeaders = {
        "Content-Type": "application/json",
        Origin: env.frontendUrl,
        Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonCsrf.csrfCtxCookie}`,
        "X-CSRF-Token": anonCsrf.csrfToken,
      };

      // Register User 1 (Email + Phone, initially unverified email)
      const oldPassword = "OldSecurePassword123!";
      const newPassword = "NewSecurePassword456!";
      const reg1Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Wanjiku",
          lastName: "Njoroge",
          email: "wanjiku@example.com",
          phoneNumber: "0744555666",
          password: oldPassword,
        }),
      });
      assert.equal(reg1Res.status, 201);
      const wanjikuSession1 = extractCookieValue(
        reg1Res.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      const wanjikuBody = (await reg1Res.json()) as {
        data: { user: { id: string } };
      };
      const wanjikuId = wanjikuBody.data.user.id;

      // Create a second active session for Wanjiku via POST /login to verify multi-session revocation on reset
      const loginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          identifier: "wanjiku@example.com",
          password: oldPassword,
        }),
      });
      assert.equal(loginRes.status, 200);
      const wanjikuSession2 = extractCookieValue(
        loginRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;

      // Register User 2 (Phone-only account)
      const reg2Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Kiprop",
          lastName: "Koech",
          phoneNumber: "0755666777",
          password: "KipropPassword123!",
        }),
      });
      assert.equal(reg2Res.status, 201);

      // 4.1 Unknown identifier handling -> returns generic 200 OK, sends no email
      const unknownForgotRes = await fetch(
        `${baseUrl}/api/v1/auth/forgot-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({ email: "nonexistent.person@example.com" }),
        }
      );
      assert.equal(unknownForgotRes.status, 200);
      const unknownForgotBody = (await unknownForgotRes.json()) as {
        status: string;
        data: { message: string };
      };
      assert.equal(unknownForgotBody.status, "ok");
      assert.equal(mockEmailProvider.sentPasswordResetEmails.length, 0);

      // 4.2 Unverified-email handling -> does NOT send reset link to unverified email, returns identical generic 200 OK
      const unverifiedForgotRes = await fetch(
        `${baseUrl}/api/v1/auth/forgot-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({ email: "wanjiku@example.com" }),
        }
      );
      assert.equal(unverifiedForgotRes.status, 200);
      const unverifiedForgotBody = (await unverifiedForgotRes.json()) as {
        data: { message: string };
      };
      assert.equal(
        unverifiedForgotBody.data.message,
        unknownForgotBody.data.message,
        "Unverified email forgot-password response must match unknown identifier response"
      );
      assert.equal(
        mockEmailProvider.sentPasswordResetEmails.length,
        0,
        "Password reset link must never be sent to an unverified email address"
      );

      // 4.3 Phone-only account handling -> preserves generic 200 OK without claiming SMS was sent
      const phoneOnlyForgotRes = await fetch(
        `${baseUrl}/api/v1/auth/forgot-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({ identifier: "0755 666 777" }),
        }
      );
      assert.equal(phoneOnlyForgotRes.status, 200);
      const phoneOnlyForgotBody = (await phoneOnlyForgotRes.json()) as {
        data: { message: string };
      };
      assert.equal(
        phoneOnlyForgotBody.data.message,
        unknownForgotBody.data.message
      );

      // Now mark Wanjiku's email as verified in PostgreSQL
      await tx
        .update(users)
        .set({ emailVerifiedAt: new Date() })
        .where(eq(users.id, wanjikuId));

      // 4.4 Verified-email delivery & prior reset token invalidation
      const verifiedForgotRes1 = await fetch(
        `${baseUrl}/api/v1/auth/forgot-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({ email: "  WANJIKU@EXAMPLE.COM " }),
        }
      );
      assert.equal(verifiedForgotRes1.status, 200);
      const verifiedForgotBody1 = (await verifiedForgotRes1.json()) as {
        data: { message: string };
      };
      assert.equal(
        verifiedForgotBody1.data.message,
        unknownForgotBody.data.message,
        "Verified email forgot-password response must be identical to unknown identifier response"
      );
      assert.equal(mockEmailProvider.sentPasswordResetEmails.length, 1);

      const firstResetEmail = mockEmailProvider.sentPasswordResetEmails[0];
      assert.equal(firstResetEmail.toEmail, "wanjiku@example.com");
      assert.match(firstResetEmail.rendered.html, /Digital Services Hub/);
      assert.match(firstResetEmail.rendered.html, /30 minutes/);
      assert.match(firstResetEmail.rendered.html, /ignore this email/i);
      assert.equal(firstResetEmail.rendered.html.includes(oldPassword), false);

      const rawResetToken1 = extractTokenFromFragmentUrl(
        firstResetEmail.resetUrl
      )!;
      assert.ok(rawResetToken1);

      // Request a second password reset -> invalidates rawResetToken1 and issues rawResetToken2
      const verifiedForgotRes2 = await fetch(
        `${baseUrl}/api/v1/auth/forgot-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({ email: "wanjiku@example.com" }),
        }
      );
      assert.equal(verifiedForgotRes2.status, 200);
      assert.equal(mockEmailProvider.sentPasswordResetEmails.length, 2);
      const rawResetToken2 = extractTokenFromFragmentUrl(
        mockEmailProvider.sentPasswordResetEmails[1].resetUrl
      )!;
      assert.notEqual(rawResetToken2, rawResetToken1);

      // Verify SHA-256 token hashing in PostgreSQL & 30-minute expiry
      const resetRows = await tx
        .select()
        .from(passwordResetTokens)
        .where(eq(passwordResetTokens.userId, wanjikuId));
      assert.equal(resetRows.length, 2);
      const activeResetRow = resetRows.find((r) => r.usedAt === null)!;
      assert.ok(activeResetRow);
      assert.equal(activeResetRow.tokenHash, hashToken(rawResetToken2));
      assert.notEqual(activeResetRow.tokenHash, rawResetToken2);
      assert.equal(
        activeResetRow.expiresAt.getTime() - activeResetRow.createdAt.getTime(),
        PASSWORD_RESET_TTL_MS
      );

      // Verify replaced token (rawResetToken1) is rejected
      const replacedTokenRes = await fetch(
        `${baseUrl}/api/v1/auth/reset-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({
            token: rawResetToken1,
            newPassword,
          }),
        }
      );
      assert.equal(replacedTokenRes.status, 400);
      const replacedTokenBody = (await replacedTokenRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(replacedTokenBody.error.code, "INVALID_OR_EXPIRED_TOKEN");

      // 4.5 Invalid password rejection on reset-password (does not consume the valid token!)
      const weakPwRes = await fetch(`${baseUrl}/api/v1/auth/reset-password`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          token: rawResetToken2,
          newPassword: "short",
        }),
      });
      assert.equal(weakPwRes.status, 400);
      const weakPwBody = (await weakPwRes.json()) as {
        error: { code: string };
      };
      assert.equal(weakPwBody.error.code, "VALIDATION_ERROR");

      // 4.6 Expired reset token rejection (+30m + 1s)
      await assert.rejects(
        async () =>
          resetPasswordWithToken(
            { token: rawResetToken2, newPassword },
            {
              ipAddress: "127.0.0.1",
              nowMs: Date.now() + PASSWORD_RESET_TTL_MS + 1000,
            },
            tx
          ),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, replacedTokenBody.error.message);
          return true;
        }
      );

      // 4.7 Concurrent reset requests with rawResetToken2 -> only ONE succeeds (200), the other fails (400)!
      const [resetConc1, resetConc2] = await Promise.all([
        fetch(`${baseUrl}/api/v1/auth/reset-password`, {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({
            token: rawResetToken2,
            newPassword,
          }),
        }),
        fetch(`${baseUrl}/api/v1/auth/reset-password`, {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({
            token: rawResetToken2,
            newPassword,
          }),
        }),
      ]);

      const resetStatuses = [resetConc1.status, resetConc2.status].sort();
      assert.deepEqual(
        resetStatuses,
        [200, 400],
        "Two simultaneous password reset requests with the same token must succeed once (200) and reject the second (400)"
      );

      const winningRes = resetConc1.status === 200 ? resetConc1 : resetConc2;
      assert.equal(
        extractCookieValue(
          winningRes.headers.getSetCookie(),
          SESSION_COOKIE_NAME
        ),
        "",
        "Password reset must not create a new authenticated session and must clear any existing session cookie"
      );

      // 4.8 Replay of consumed reset token fails with 400 INVALID_OR_EXPIRED_TOKEN
      const replayResetRes = await fetch(
        `${baseUrl}/api/v1/auth/reset-password`,
        {
          method: "POST",
          headers: anonHeaders,
          body: JSON.stringify({
            token: rawResetToken2,
            newPassword: "AnotherValidPassword789!",
          }),
        }
      );
      assert.equal(replayResetRes.status, 400);

      // 4.9 All previous sessions for Wanjiku are immediately revoked and stop working on GET /api/v1/auth/me
      const activeSessionsAfterReset = await tx
        .select()
        .from(sessions)
        .where(and(eq(sessions.userId, wanjikuId), isNull(sessions.revokedAt)));
      assert.equal(
        activeSessionsAfterReset.length,
        0,
        "All active sessions for the user must be revoked upon password reset"
      );

      const meSess1Res = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${wanjikuSession1}` },
      });
      assert.equal(meSess1Res.status, 401);

      const meSess2Res = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: { Cookie: `${SESSION_COOKIE_NAME}=${wanjikuSession2}` },
      });
      assert.equal(meSess2Res.status, 401);

      // 4.10 Previous password no longer works on POST /api/v1/auth/login
      const oldPwLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          identifier: "wanjiku@example.com",
          password: oldPassword,
        }),
      });
      assert.equal(oldPwLoginRes.status, 401);

      // 4.11 New password works on POST /api/v1/auth/login
      const newPwLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          identifier: "wanjiku@example.com",
          password: newPassword,
        }),
      });
      assert.equal(newPwLoginRes.status, 200);
      const freshSessionCookie = extractCookieValue(
        newPwLoginRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      );
      assert.ok(freshSessionCookie);

      // 4.12 Audit log verification: zero raw tokens, OTPs, or password hashes in audit_logs
      const logs = await tx.select().from(auditLogs);
      const serializedLogs = JSON.stringify(logs);
      assert.equal(serializedLogs.includes(rawResetToken1), false);
      assert.equal(serializedLogs.includes(rawResetToken2), false);
      assert.equal(serializedLogs.includes(oldPassword), false);
      assert.equal(serializedLogs.includes(newPassword), false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test.after(async () => {
  await pool.end();
});
