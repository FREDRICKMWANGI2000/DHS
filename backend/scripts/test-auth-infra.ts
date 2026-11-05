import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import { drizzle } from "drizzle-orm/node-postgres";
import { eq } from "drizzle-orm";
import { env, validateSessionSecret } from "../src/config/env";
import { pool } from "../src/db/client";
import * as schema from "../src/db/schema";
import { users, sessions, auditLogs } from "../src/db/schema";
import {
  hashPassword,
  verifyPassword,
  validatePassword,
  PasswordPolicyError,
  verifyAgainstDummyPasswordHash,
} from "../src/services/auth/password.service";
import {
  generateSecureToken,
  isValidOpaqueToken,
  hashToken,
  isValidSha256Hex,
  compareTokenHashes,
  generateVerificationToken,
  generatePasswordResetToken,
  generatePhoneVerificationOtp,
  hashPhoneOtp,
  generateCsrfNonce,
  isValidCsrfNonce,
} from "../src/services/auth/token.service";
import {
  createSession,
  validateSession,
  getCurrentSession,
  revokeSession,
  revokeAllSessions,
  getSessionDurationMs,
  invalidateSessionOnLogout,
  invalidateAllSessionsOnLogoutAll,
  invalidateSessionsOnPasswordChange,
  invalidateSessionsOnPasswordReset,
  invalidateSessionsOnRoleChange,
  invalidateSessionsOnAccountDisable,
  SessionSecurityError,
  withSuperAdminRoleGuardLock,
} from "../src/services/auth/session.service";
import {
  sanitizeAuditMetadata,
  DbExecutor,
} from "../src/services/auth/audit.service";
import {
  createCsrfToken,
  verifyCsrfToken,
  validateRequestOrigin,
  generateAnonymousCsrfContextId,
  CSRF_TOKEN_TTL_MS,
} from "../src/services/auth/csrf.service";
import {
  setSessionCookie,
  clearSessionCookie,
  getSessionCookie,
  setCsrfContextCookie,
  clearCsrfContextCookie,
  parseCookieHeader,
  SESSION_COOKIE_NAME,
  CSRF_CONTEXT_COOKIE_NAME,
} from "../src/utils/auth-cookie";
import { createApp } from "../src/app";
import {
  createAuthenticateMiddleware,
  createRequireRoleMiddleware,
} from "../src/middleware/authenticate";
import { Request, Response, Router } from "express";

/**
 * Helper to execute a database test inside a PostgreSQL transaction that ALWAYS rolls back,
 * ensuring zero test data or audit_logs rows are ever left behind in `dsh_db`.
 */
async function withRolledBackTransaction(
  fn: (tx: DbExecutor) => Promise<void>
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const txDb = drizzle(client, { schema }) as unknown as DbExecutor;
    await fn(txDb);
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
}

test("1. Environment & SESSION_SECRET validation", () => {
  assert.throws(
    () => validateSessionSecret(undefined),
    /Missing required environment variable 'SESSION_SECRET'/
  );
  assert.throws(
    () => validateSessionSecret("   "),
    /Missing required environment variable 'SESSION_SECRET'/
  );
  assert.throws(
    () => validateSessionSecret("short_secret_under_32_chars"),
    /must be at least 32 characters long/
  );
  assert.throws(
    () =>
      validateSessionSecret(
        "replace_with_secure_random_at_least_32_chars_secret_for_sessions",
        "production"
      ),
    /placeholder secret from \.env\.example cannot be used in production/
  );

  const valid = validateSessionSecret(
    "a_very_strong_and_valid_32_plus_char_secret_key_for_test"
  );
  assert.equal(
    valid,
    "a_very_strong_and_valid_32_plus_char_secret_key_for_test"
  );
  assert.ok(env.sessionSecret.length >= 32);
});

test("2. Argon2id Password Engine — policy validation, hashing, salting & malformed hash handling", async () => {
  // Policy boundary checks (8–128 chars, at least one letter, at least one number or symbol)
  assert.equal(validatePassword(null).valid, false);
  assert.equal(validatePassword("       ").valid, false);
  assert.equal(validatePassword("Ab1!567").valid, false); // 7 chars (< 8 invalid)
  assert.equal(validatePassword("Ab1!5678").valid, true); // 8 chars exact (valid)
  assert.equal(validatePassword("Abcdefg1").valid, true); // 8 chars with letter + number (valid)
  assert.equal(validatePassword("Abcdefg!").valid, true); // 8 chars with letter + symbol (valid)
  assert.equal(validatePassword("a".repeat(127) + "1").valid, true); // 128 chars exact with letter + number (valid)
  assert.equal(validatePassword("a".repeat(127) + "!").valid, true); // 128 chars exact with letter + symbol (valid)
  assert.equal(validatePassword("a".repeat(128) + "1").valid, false); // 129 chars (> 128 invalid)
  assert.equal(validatePassword("onlylettersinpassword").valid, false); // missing number or symbol (invalid)
  assert.equal(validatePassword("1234567890!@#").valid, false); // missing letter (invalid)

  await assert.rejects(
    async () => hashPassword("short1"),
    (err: unknown) => err instanceof PasswordPolicyError
  );

  const plain = "CorrectHorseBatteryStaple99!";
  const hash1 = await hashPassword(plain);
  const hash2 = await hashPassword(plain);

  // Verify Argon2id PHC header with approved parameters (m=65536, t=3, p=4) and unique salts
  assert.match(hash1, /^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
  assert.match(hash2, /^\$argon2id\$v=19\$m=65536,t=3,p=4\$/);
  assert.notEqual(hash1, hash2, "Each Argon2id hash must use a unique random salt");

  // Correct vs incorrect password verification
  assert.equal(await verifyPassword(hash1, plain), true);
  assert.equal(await verifyPassword(hash1, "WrongPassword99!"), false);

  // Safe handling of malformed or unsupported hashes
  assert.equal(await verifyPassword("", plain), false);
  assert.equal(await verifyPassword("not_a_hash", plain), false);
  assert.equal(await verifyPassword("$2b$12$bcryptHashNotSupported", plain), false);
  assert.equal(await verifyPassword("$argon2id$v=19$m=65536,t=3,p=4$corrupted", plain), false);
  assert.equal(await verifyPassword(hash1, ""), false);
  assert.equal(await verifyPassword(hash1, "x".repeat(200)), false);

  // Dummy verification for timing-attack mitigation
  assert.equal(await verifyAgainstDummyPasswordHash("AnyCandidate123!"), false);
});

test("3. Cryptographic Token Service — CSPRNG uniqueness, SHA-256 stability & timing-safe comparison", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 100; i++) {
    const tok = generateSecureToken();
    assert.equal(tok.length, 43);
    assert.equal(isValidOpaqueToken(tok), true);
    assert.equal(seen.has(tok), false);
    seen.add(tok);
  }

  const sampleToken = generateSecureToken();
  const h1 = hashToken(sampleToken);
  const h2 = hashToken(sampleToken);
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);
  assert.equal(isValidSha256Hex(h1), true);
  assert.notEqual(h1, sampleToken);

  const otherHash = hashToken(generateSecureToken());
  assert.equal(compareTokenHashes(h1, h2), true);
  assert.equal(compareTokenHashes(h1, otherHash), false);
  assert.equal(compareTokenHashes(h1, "short"), false);
  assert.equal(compareTokenHashes(h1, "Z".repeat(64)), false);
  assert.equal(compareTokenHashes(null, h1), false);

  const nowMs = 1_700_000_000_000;
  const emailVer = generateVerificationToken(undefined, nowMs);
  assert.equal(hashToken(emailVer.rawToken), emailVer.tokenHash);
  assert.equal(emailVer.expiresAt.getTime(), nowMs + 24 * 60 * 60 * 1000);

  const resetTok = generatePasswordResetToken(undefined, nowMs);
  assert.equal(hashToken(resetTok.rawToken), resetTok.tokenHash);
  assert.equal(resetTok.expiresAt.getTime(), nowMs + 30 * 60 * 1000);

  const phoneOtp = generatePhoneVerificationOtp(
    "00000000-0000-0000-0000-000000000001",
    undefined,
    nowMs
  );
  assert.match(phoneOtp.rawOtp, /^[0-9]{6}$/);
  assert.equal(
    phoneOtp.tokenHash,
    hashPhoneOtp("00000000-0000-0000-0000-000000000001", phoneOtp.rawOtp)
  );
  assert.equal(phoneOtp.expiresAt.getTime(), nowMs + 10 * 60 * 1000);

  const nonce = generateCsrfNonce();
  assert.equal(isValidCsrfNonce(nonce), true);
  assert.equal(nonce.length, 32);
});

test("4. Audit Metadata Sanitization — strips passwords, hashes, tokens, and secrets", () => {
  const dirty = {
    role: "CUSTOMER",
    password: "PlaintextPassword123!",
    newPassword: "NewPassword123!",
    passwordHash: "$argon2id$v=19$m=65536,t=3,p=4$salt$hash",
    rawToken: "secret_raw_token",
    tokenHash: "a".repeat(64),
    csrfToken: "nonce.123.hmac",
    nested: {
      safeField: "allowed",
      sessionSecret: "top_secret",
       leakedArgon: "$argon2id$v=19$m=65536,t=3,p=4$abc",
    },
  };

  const clean = sanitizeAuditMetadata(dirty);
  assert.equal(clean.role, "CUSTOMER");
  assert.equal("password" in clean, false);
  assert.equal("newPassword" in clean, false);
  assert.equal("passwordHash" in clean, false);
  assert.equal("rawToken" in clean, false);
  assert.equal("tokenHash" in clean, false);
  assert.equal("csrfToken" in clean, false);
  assert.deepEqual(clean.nested, { safeField: "allowed" });
});

test("5. Session Management & Invalidation Rules (PostgreSQL rolled-back transaction)", async () => {
  await withRolledBackTransaction(async (tx) => {
    const pwHash = await hashPassword("ValidTestPass123!");

    // Insert test users for CUSTOMER, STAFF, ADMIN, SUPER_ADMIN, and a DISABLED user
    const [customerUser, staffUser, adminUser, superAdminUser, disabledUser] =
      await tx
        .insert(users)
        .values([
          {
            firstName: "Test",
            lastName: "Customer",
            email: "test.customer@example.com",
            phoneNumber: "+254700000001",
            passwordHash: pwHash,
            role: "CUSTOMER",
            status: "ACTIVE",
          },
          {
            firstName: "Test",
            lastName: "Staff",
            email: "test.staff@example.com",
            passwordHash: pwHash,
            role: "STAFF",
            status: "ACTIVE",
          },
          {
            firstName: "Test",
            lastName: "Admin",
            email: "test.admin@example.com",
            passwordHash: pwHash,
            role: "ADMIN",
            status: "ACTIVE",
          },
          {
            firstName: "Test",
            lastName: "SuperAdmin",
            email: "test.superadmin@example.com",
            passwordHash: pwHash,
            role: "SUPER_ADMIN",
            status: "ACTIVE",
          },
          {
            firstName: "Test",
            lastName: "Disabled",
            email: "test.disabled@example.com",
            passwordHash: pwHash,
            role: "CUSTOMER",
            status: "DISABLED",
          },
        ])
        .returning();

    const baseNowMs = Date.now();

    // 5.1 Role-specific session TTL verification
    const custSess = await createSession(
      { userId: customerUser.id, ipAddress: "127.0.0.1", nowMs: baseNowMs },
      tx
    );
    const staffSess = await createSession(
      { userId: staffUser.id, nowMs: baseNowMs },
      tx
    );
    const adminSess = await createSession(
      { userId: adminUser.id, nowMs: baseNowMs },
      tx
    );
    const superSess = await createSession(
      { userId: superAdminUser.id, nowMs: baseNowMs },
      tx
    );

    assert.equal(
      custSess.session.expiresAt.getTime() - baseNowMs,
      7 * 24 * 60 * 60 * 1000
    );
    assert.equal(
      staffSess.session.expiresAt.getTime() - baseNowMs,
      12 * 60 * 60 * 1000
    );
    assert.equal(
      adminSess.session.expiresAt.getTime() - baseNowMs,
      8 * 60 * 60 * 1000
    );
    assert.equal(
      superSess.session.expiresAt.getTime() - baseNowMs,
      8 * 60 * 60 * 1000
    );

    // 5.2 Raw token is NEVER stored in PostgreSQL; only SHA-256 hash is stored
    const [dbSessionRow] = await tx
      .select()
      .from(sessions)
      .where(eq(sessions.id, custSess.session.id));
    assert.notEqual(dbSessionRow.tokenHash, custSess.rawToken);
    assert.equal(dbSessionRow.tokenHash, hashToken(custSess.rawToken));

    // 5.3 Valid session verification & safe user projection (no passwordHash)
    const validated = await validateSession(
      custSess.rawToken,
      { nowMs: baseNowMs + 1000 },
      tx
    );
    assert.equal(validated.valid, true);
    if (validated.valid) {
      assert.equal(validated.context.user.id, customerUser.id);
      assert.equal(validated.context.user.role, "CUSTOMER");
      assert.equal("passwordHash" in validated.context.user, false);
    }

    // 5.4 Passing the database tokenHash instead of rawToken must be rejected
    const hashAsTokenAttempt = await validateSession(
      dbSessionRow.tokenHash,
      { nowMs: baseNowMs + 1000 },
      tx
    );
    assert.equal(hashAsTokenAttempt.valid, false);

    // 5.5 Expiry rejection
    const expiredCheck = await validateSession(
      custSess.rawToken,
      { nowMs: baseNowMs + 7 * 24 * 60 * 60 * 1000 + 1 },
      tx
    );
    assert.equal(expiredCheck.valid, false);
    if (!expiredCheck.valid) {
      assert.equal(expiredCheck.reason, "EXPIRED");
    }

    // 5.6 Session rotation revokes prior session token
    const rotatedSess = await createSession(
      {
        userId: customerUser.id,
        priorRawToken: custSess.rawToken,
        nowMs: baseNowMs + 2000,
      },
      tx
    );
    assert.notEqual(rotatedSess.rawToken, custSess.rawToken);
    const oldSessionCheck = await validateSession(
      custSess.rawToken,
      { nowMs: baseNowMs + 3000 },
      tx
    );
    assert.equal(oldSessionCheck.valid, false);
    if (!oldSessionCheck.valid) {
      assert.equal(oldSessionCheck.reason, "REVOKED");
    }

    // 5.7 Single-session logout revocation (by rawToken and by sessionId)
    const revokedSingle = await invalidateSessionOnLogout(
      rotatedSess.rawToken,
      "127.0.0.1",
      tx
    );
    assert.equal(revokedSingle, true);
    assert.equal(await getCurrentSession(rotatedSess.rawToken, tx), null);

    const byIdSess = await createSession({ userId: customerUser.id }, tx);
    assert.equal(
      await revokeSession({ sessionId: byIdSess.session.id, reason: "test_by_id" }, tx),
      true
    );
    assert.equal(await getCurrentSession(byIdSess.rawToken, tx), null);

    // Test revokeAllSessions with exceptSessionId
    const keepSess = await createSession({ userId: customerUser.id }, tx);
    const dropSess = await createSession({ userId: customerUser.id }, tx);
    const partialRevoked = await revokeAllSessions(
      { userId: customerUser.id, exceptSessionId: keepSess.session.id },
      tx
    );
    assert.equal(partialRevoked, 1);
    assert.equal((await validateSession(keepSess.rawToken, {}, tx)).valid, true);
    assert.equal((await validateSession(dropSess.rawToken, {}, tx)).valid, false);
    await revokeSession({ sessionId: keepSess.session.id }, tx);

    // 5.8 Disabled account cannot create session
    await assert.rejects(
      async () => createSession({ userId: disabledUser.id }, tx),
      (err: unknown) =>
        err instanceof SessionSecurityError && err.code === "ACCOUNT_DISABLED"
    );

    // 5.9 Password-change invalidation revokes all prior sessions and issues a new one
    const s1 = await createSession({ userId: customerUser.id }, tx);
    const s2 = await createSession({ userId: customerUser.id }, tx);
    const afterPwChange = await invalidateSessionsOnPasswordChange(
      { userId: customerUser.id, ipAddress: "127.0.0.1" },
      tx
    );
    assert.equal((await validateSession(s1.rawToken, {}, tx)).valid, false);
    assert.equal((await validateSession(s2.rawToken, {}, tx)).valid, false);
    assert.equal(
      (await validateSession(afterPwChange.rawToken, {}, tx)).valid,
      true
    );

    // 5.10 Logout-all, password-reset, role-change, and account-disable invalidations
    const s3 = await createSession({ userId: customerUser.id }, tx);
    const revokedAllCount = await invalidateAllSessionsOnLogoutAll(
      customerUser.id,
      "127.0.0.1",
      tx
    );
    assert.equal(revokedAllCount, 2); // afterPwChange + s3
    assert.equal((await validateSession(s3.rawToken, {}, tx)).valid, false);

    const s4 = await createSession({ userId: customerUser.id }, tx);
    await invalidateSessionsOnPasswordReset(customerUser.id, "127.0.0.1", tx);
    assert.equal((await validateSession(s4.rawToken, {}, tx)).valid, false);

    const s5 = await createSession({ userId: staffUser.id }, tx);
    await invalidateSessionsOnRoleChange(
      {
        targetUserId: staffUser.id,
        actorUserId: adminUser.id,
        previousRole: "STAFF",
        newRole: "ADMIN",
      },
      tx
    );
    assert.equal((await validateSession(s5.rawToken, {}, tx)).valid, false);

    // 5.11 Active session for a user who becomes DISABLED is rejected and auto-revoked
    const s6 = await createSession({ userId: staffUser.id }, tx);
    await tx
      .update(users)
      .set({ status: "DISABLED" })
      .where(eq(users.id, staffUser.id));

    const disabledValidation = await validateSession(s6.rawToken, {}, tx);
    assert.equal(disabledValidation.valid, false);
    if (!disabledValidation.valid) {
      assert.equal(disabledValidation.reason, "ACCOUNT_DISABLED");
    }

    await invalidateSessionsOnAccountDisable(
      { targetUserId: customerUser.id, actorUserId: adminUser.id },
      tx
    );

    // 5.12 Verify SUPER_ADMIN advisory + FOR UPDATE serialization lock helper works
    await withSuperAdminRoleGuardLock(async (_lockTx, activeSuperAdminIds) => {
      assert.ok(activeSuperAdminIds.includes(superAdminUser.id));
    }, tx);

    // 5.13 Verify audit_logs recorded events without leaking any secrets
    const logs = await tx.select().from(auditLogs);
    assert.ok(logs.length > 0);
    for (const log of logs) {
      const serialized = JSON.stringify(log.metadata);
      assert.equal(serialized.includes(pwHash), false);
      assert.equal(serialized.includes(custSess.rawToken), false);
    }
  });
});

test("6. Session & CSRF Cookie Utilities — HttpOnly, SameSite=Lax, Path=/, Secure in production & clear matching", () => {
  const capturedHeaders: string[] = [];
  const mockRes = {
    cookie(name: string, val: string, opts: Record<string, unknown>) {
      const parts = [`${name}=${encodeURIComponent(val)}`];
      if (opts.path) parts.push(`Path=${opts.path}`);
      if (opts.httpOnly) parts.push("HttpOnly");
      if (opts.secure) parts.push("Secure");
      if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
      if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(Number(opts.maxAge) / 1000)}`);
      if (opts.domain) parts.push(`Domain=${opts.domain}`);
      capturedHeaders.push(parts.join("; "));
      return this;
    },
    clearCookie(name: string, opts: Record<string, unknown>) {
      const parts = [`${name}=`];
      if (opts.path) parts.push(`Path=${opts.path}`);
      if (opts.httpOnly) parts.push("HttpOnly");
      if (opts.secure) parts.push("Secure");
      if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
      if (opts.domain) parts.push(`Domain=${opts.domain}`);
      capturedHeaders.push(parts.join("; "));
      return this;
    },
  } as unknown as Response;

  // Development cookie (Secure omitted)
  setSessionCookie(mockRes, "raw_token_dev", "CUSTOMER", "development");
  assert.match(capturedHeaders[0], /^dsh_session=raw_token_dev; Path=\/; HttpOnly; SameSite=lax; Max-Age=604800$/);
  assert.equal(capturedHeaders[0].includes("Secure"), false);
  assert.equal(capturedHeaders[0].includes("Domain"), false);

  // Production cookie (Secure included)
  setSessionCookie(mockRes, "raw_token_prod", "ADMIN", "production");
  assert.match(capturedHeaders[1], /^dsh_session=raw_token_prod; Path=\/; HttpOnly; Secure; SameSite=lax; Max-Age=28800$/);

  // Clear cookie uses matching attributes
  clearSessionCookie(mockRes, "production");
  assert.equal(capturedHeaders[2], "dsh_session=; Path=/; HttpOnly; Secure; SameSite=lax");

  // CSRF context cookie (30 min = 1800s)
  setCsrfContextCookie(mockRes, "ctx_123", "production");
  assert.match(capturedHeaders[3], /^dsh_csrf_ctx=ctx_123; Path=\/; HttpOnly; Secure; SameSite=lax; Max-Age=1800$/);

  clearCsrfContextCookie(mockRes, "development");
  assert.equal(capturedHeaders[4], "dsh_csrf_ctx=; Path=/; HttpOnly; SameSite=lax");

  // Cookie parsing
  const mockReq = {
    headers: {
      cookie: `${SESSION_COOKIE_NAME}=tok_abc; ${CSRF_CONTEXT_COOKIE_NAME}=ctx_xyz`,
    },
  } as unknown as Request;
  assert.equal(getSessionCookie(mockReq), "tok_abc");
  assert.deepEqual(parseCookieHeader(mockReq.headers.cookie), {
    dsh_session: "tok_abc",
    dsh_csrf_ctx: "ctx_xyz",
  });
  assert.equal(getSessionDurationMs("STAFF"), 12 * 60 * 60 * 1000);
});

test("7. CSRF Unit Verification — authenticated binding, anonymous binding, HMAC tampering, expiry, Origin & rotation", () => {
  const nowMs = 1_700_000_000_000;
  const anonCtxId = generateAnonymousCsrfContextId();
  const anonBinding = { type: "anon" as const, csrfContextId: anonCtxId };

  const anonToken = createCsrfToken(anonBinding, nowMs);
  assert.deepEqual(verifyCsrfToken(anonToken, anonBinding, nowMs + 5000), {
    valid: true,
    issuedAtMs: nowMs,
  });

  // Expired token (> 30 minutes)
  const expiredResult = verifyCsrfToken(
    anonToken,
    anonBinding,
    nowMs + CSRF_TOKEN_TTL_MS + 1
  );
  assert.equal(expiredResult.valid, false);
  if (!expiredResult.valid) {
    assert.equal(expiredResult.code, "CSRF_TOKEN_EXPIRED");
  }

  // Wrong anonymous context rejected
  const otherAnonBinding = {
    type: "anon" as const,
    csrfContextId: generateAnonymousCsrfContextId(),
  };
  const wrongCtxResult = verifyCsrfToken(anonToken, otherAnonBinding, nowMs);
  assert.equal(wrongCtxResult.valid, false);
  if (!wrongCtxResult.valid) {
    assert.equal(wrongCtxResult.code, "CSRF_TOKEN_INVALID");
  }

  // Authenticated session binding & rotation
  const sessionTokenHash = hashToken(generateSecureToken());
  const sessBinding = { type: "sess" as const, sessionTokenHash };

  // Pre-auth token must fail once user is in authenticated session binding
  const preAuthOnSessResult = verifyCsrfToken(anonToken, sessBinding, nowMs);
  assert.equal(preAuthOnSessResult.valid, false);

  const sessCsrfToken = createCsrfToken(sessBinding, nowMs);
  assert.equal(verifyCsrfToken(sessCsrfToken, sessBinding, nowMs).valid, true);

  // Tampered HMAC and malformed lengths handled safely without RangeError
  const tamperedToken = sessCsrfToken.slice(0, -2) + (sessCsrfToken.endsWith("aa") ? "bb" : "aa");
  assert.equal(verifyCsrfToken(tamperedToken, sessBinding, nowMs).valid, false);
  assert.equal(verifyCsrfToken("bad.token", sessBinding, nowMs).valid, false);
  assert.equal(verifyCsrfToken("", sessBinding, nowMs).valid, false);

  // Origin validation
  assert.equal(
    validateRequestOrigin(
      { headers: { origin: "http://localhost:3000" } },
      "http://localhost:3000"
    ),
    true
  );
  assert.equal(
    validateRequestOrigin(
      { headers: { origin: "https://evil.example.com" } },
      "http://localhost:3000"
    ),
    false
  );
  assert.equal(
    validateRequestOrigin({ headers: {} }, "http://localhost:3000"),
    false
  );
});

test("8. Express HTTP Integration — GET /api/v1/auth/csrf, CSRF middleware & authenticate/requireRole", async () => {
  await withRolledBackTransaction(async (tx) => {
    const testRouter = Router();
    const authMw = createAuthenticateMiddleware(tx);
    const adminRoleMw = createRequireRoleMiddleware(
      ["ADMIN", "SUPER_ADMIN"],
      tx
    );

    testRouter.post(
      "/test-csrf-mutation",
      (_req: Request, res: Response) => {
        res.status(200).json({ status: "ok", mutated: true });
      }
    );

    testRouter.get(
      "/test-protected-me",
      authMw,
      (req: Request, res: Response) => {
        res.status(200).json({ status: "ok", user: req.auth?.user });
      }
    );

    testRouter.get(
      "/test-protected-admin",
      authMw,
      adminRoleMw,
      (req: Request, res: Response) => {
        res.status(200).json({ status: "ok", userId: req.auth?.user.id });
      }
    );

    const app = createApp(tx, testRouter);

    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 8.1 GET /api/v1/auth/csrf (anonymous) returns Cache-Control: no-store, Pragma: no-cache, sets dsh_csrf_ctx, and returns csrfToken
      const csrfRes = await fetch(`${baseUrl}/api/v1/auth/csrf`);
      assert.equal(csrfRes.status, 200);
      assert.equal(csrfRes.headers.get("cache-control"), "no-store");
      assert.equal(csrfRes.headers.get("pragma"), "no-cache");

      const setCookieHeader = csrfRes.headers.get("set-cookie") ?? "";
      assert.match(setCookieHeader, /dsh_csrf_ctx=[^;]+/);
      assert.match(setCookieHeader, /HttpOnly/i);
      assert.match(setCookieHeader, /SameSite=Lax/i);
      assert.match(setCookieHeader, /Path=\//i);
      assert.match(setCookieHeader, /Max-Age=1800/i);

      const anonCookiePair = setCookieHeader.split(";")[0];
      const csrfBody = (await csrfRes.json()) as {
        status: string;
        data: { csrfToken: string; expiresInSeconds: number };
      };
      assert.equal(csrfBody.status, "ok");
      assert.equal(csrfBody.data.expiresInSeconds, 1800);
      const anonCsrfToken = csrfBody.data.csrfToken;

      // 8.2 POST without Origin header -> 403 CSRF_ORIGIN_MISMATCH
      const noOriginRes = await fetch(`${baseUrl}/api/v1/test-csrf-mutation`, {
        method: "POST",
        headers: {
          Cookie: anonCookiePair,
          "X-CSRF-Token": anonCsrfToken,
        },
      });
      assert.equal(noOriginRes.status, 403);
      const noOriginBody = (await noOriginRes.json()) as { code: string };
      assert.equal(noOriginBody.code, "CSRF_ORIGIN_MISMATCH");

      // 8.3 POST with valid Origin but missing X-CSRF-Token -> 403 CSRF_TOKEN_MISSING
      const noTokenRes = await fetch(`${baseUrl}/api/v1/test-csrf-mutation`, {
        method: "POST",
        headers: {
          Origin: env.frontendUrl,
          Cookie: anonCookiePair,
        },
      });
      assert.equal(noTokenRes.status, 403);
      const noTokenBody = (await noTokenRes.json()) as { code: string };
      assert.equal(noTokenBody.code, "CSRF_TOKEN_MISSING");

      // 8.4 POST with valid Origin, dsh_csrf_ctx cookie, and matching X-CSRF-Token -> 200 OK
      const validPostRes = await fetch(`${baseUrl}/api/v1/test-csrf-mutation`, {
        method: "POST",
        headers: {
          Origin: env.frontendUrl,
          Cookie: anonCookiePair,
          "X-CSRF-Token": anonCsrfToken,
        },
      });
      assert.equal(validPostRes.status, 200);

      // 8.5 Create authenticated CUSTOMER and ADMIN sessions in tx and verify HTTP auth & RBAC
      const pwHash = await hashPassword("HttpIntegrationPass123!");
      const [custUser, admUser] = await tx
        .insert(users)
        .values([
          {
            firstName: "Http",
            lastName: "Customer",
            email: "http.customer@example.com",
            passwordHash: pwHash,
            role: "CUSTOMER",
            status: "ACTIVE",
          },
          {
            firstName: "Http",
            lastName: "Admin",
            email: "http.admin@example.com",
            passwordHash: pwHash,
            role: "ADMIN",
            status: "ACTIVE",
          },
        ])
        .returning();

      const custSession = await createSession({ userId: custUser.id }, tx);
      const admSession = await createSession({ userId: admUser.id }, tx);
      const custCookie = `${SESSION_COOKIE_NAME}=${custSession.rawToken}`;
      const admCookie = `${SESSION_COOKIE_NAME}=${admSession.rawToken}`;

      // Unauthenticated request -> 401
      const unauthRes = await fetch(`${baseUrl}/api/v1/test-protected-me`);
      assert.equal(unauthRes.status, 401);

      // Authenticated CUSTOMER -> 200 on /test-protected-me (no passwordHash leaked)
      const meRes = await fetch(`${baseUrl}/api/v1/test-protected-me`, {
        headers: { Cookie: custCookie },
      });
      assert.equal(meRes.status, 200);
      const meJson = (await meRes.json()) as {
        user: Record<string, unknown>;
      };
      assert.equal(meJson.user.id, custUser.id);
      assert.equal("passwordHash" in meJson.user, false);

      // Authenticated CUSTOMER -> 403 FORBIDDEN on admin route
      const custAdminRes = await fetch(
        `${baseUrl}/api/v1/test-protected-admin`,
        {
          headers: { Cookie: custCookie },
        }
      );
      assert.equal(custAdminRes.status, 403);

      // Authenticated ADMIN -> 200 OK on admin route
      const admAdminRes = await fetch(
        `${baseUrl}/api/v1/test-protected-admin`,
        {
          headers: { Cookie: admCookie },
        }
      );
      assert.equal(admAdminRes.status, 200);

      // 8.6 Authenticated CSRF binding: pre-auth anonCsrfToken is rejected when dsh_session is present
      const preAuthWithSessionRes = await fetch(
        `${baseUrl}/api/v1/test-csrf-mutation`,
        {
          method: "POST",
          headers: {
            Origin: env.frontendUrl,
            Cookie: `${custCookie}; ${anonCookiePair}`,
            "X-CSRF-Token": anonCsrfToken,
          },
        }
      );
      assert.equal(preAuthWithSessionRes.status, 403);

      // Fetching GET /api/v1/auth/csrf with dsh_session issues a session-bound CSRF token and clears dsh_csrf_ctx
      const sessCsrfRes = await fetch(`${baseUrl}/api/v1/auth/csrf`, {
        headers: { Cookie: custCookie },
      });
      assert.equal(sessCsrfRes.status, 200);
      const sessCsrfBody = (await sessCsrfRes.json()) as {
        data: { csrfToken: string };
      };

      const validSessPostRes = await fetch(
        `${baseUrl}/api/v1/test-csrf-mutation`,
        {
          method: "POST",
          headers: {
            Origin: env.frontendUrl,
            Cookie: custCookie,
            "X-CSRF-Token": sessCsrfBody.data.csrfToken,
          },
        }
      );
      assert.equal(validSessPostRes.status, 200);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test.after(async () => {
  await pool.end();
});
