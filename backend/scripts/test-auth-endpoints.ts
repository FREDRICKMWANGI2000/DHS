import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "node:net";
import { and, eq, isNull } from "drizzle-orm";
import { env } from "../src/config/env";
import { db, pool } from "../src/db/client";
import { auditLogs, sessions, users } from "../src/db/schema";
import { createApp } from "../src/app";
import { DbExecutor } from "../src/services/auth/audit.service";
import { parseAndNormalizeRegisterInput } from "../src/services/auth/auth.schemas";
import { registerCustomer } from "../src/services/auth/auth.service";
import { hashToken } from "../src/services/auth/token.service";
import { MemoryRateLimitStore } from "../src/middleware/rate-limit";
import {
  CSRF_CONTEXT_COOKIE_NAME,
  SESSION_COOKIE_NAME,
} from "../src/utils/auth-cookie";

const ROLLBACK_SENTINEL = Symbol("ROLLBACK_SENTINEL");

/**
 * Runs a test callback inside a Drizzle PostgreSQL transaction that ALWAYS rolls back.
 * Because `tx` is a Drizzle `NodePgTransaction`, any nested `executor.transaction(...)` calls
 * inside `registerCustomer` or `loginUser` automatically use PostgreSQL `SAVEPOINT`s and roll back
 * completely when the outer transaction throws `ROLLBACK_SENTINEL`, leaving zero rows in `dsh_db`.
 */
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

test("1. Registration Endpoint (POST /api/v1/auth/register) — validation, normalization, anti-enumeration, role safety, session & rollback", async () => {
  await withRolledBackTransaction(async (tx) => {
    const rateLimitStore = new MemoryRateLimitStore();
    const app = createApp(tx, undefined, {
      rateLimitStore,
      registerIpMax: 50,
      loginIpMax: 50,
    });
    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const { csrfToken, csrfCtxCookie } = await fetchCsrfTokenAndCookie(baseUrl);
      assert.ok(csrfCtxCookie);
      const anonHeaders = {
        "Content-Type": "application/json",
        Origin: env.frontendUrl,
        Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${csrfCtxCookie}`,
        "X-CSRF-Token": csrfToken,
      };

      // 1.1 Missing contact details (neither email nor phoneNumber) -> 400 VALIDATION_ERROR
      const noContactRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(noContactRes.status, 400);
      const noContactBody = (await noContactRes.json()) as {
        error: { code: string };
      };
      assert.equal(noContactBody.error.code, "VALIDATION_ERROR");

      // 1.2 Invalid email -> 400 VALIDATION_ERROR
      const badEmailRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "not-an-email",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(badEmailRes.status, 400);

      // 1.3 Invalid phone number -> 400 VALIDATION_ERROR
      const badPhoneRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          phoneNumber: "12345",
          password: "StrongPassword123!",
        }),
      });
      assert.equal(badPhoneRes.status, 400);

      // 1.4 Password policy consistency checks (8–128 chars, at least one letter, at least one number or symbol)
      // Verify registration schema uses validatePassword() as the single source of truth:
      // - 7-character invalid password -> 400 VALIDATION_ERROR
      const pw7Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina@example.com",
          password: "Abcde1!", // 7 chars
        }),
      });
      assert.equal(pw7Res.status, 400);

      // - 129-character invalid password -> 400 VALIDATION_ERROR
      const pw129Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina@example.com",
          password: "a".repeat(128) + "1", // 129 chars
        }),
      });
      assert.equal(pw129Res.status, 400);

      // - Password missing a letter -> 400 VALIDATION_ERROR
      const pwNoLetterRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina@example.com",
          password: "1234567890!@#",
        }),
      });
      assert.equal(pwNoLetterRes.status, 400);

      // - Password missing both number and symbol -> 400 VALIDATION_ERROR
      const pwOnlyLettersRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina@example.com",
          password: "OnlyLettersPassword",
        }),
      });
      assert.equal(pwOnlyLettersRes.status, 400);

      // - 8-character valid password (letter + number, and letter + symbol) & 128-character valid password
      assert.equal(
        parseAndNormalizeRegisterInput({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina8num@example.com",
          password: "Abcdefg1", // 8 chars, letter + number
        }).success,
        true
      );
      assert.equal(
        parseAndNormalizeRegisterInput({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina8sym@example.com",
          password: "Abcdefg!", // 8 chars, letter + symbol
        }).success,
        true
      );
      assert.equal(
        parseAndNormalizeRegisterInput({
          firstName: "Amina",
          lastName: "Mwangi",
          email: "amina128@example.com",
          password: "a".repeat(127) + "1", // 128 chars, letter + number
        }).success,
        true
      );

      // Also verify an 8-character password with letter + symbol succeeds end-to-end on POST /api/v1/auth/register
      const reg8CharRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Eight",
          lastName: "CharUser",
          email: "eight.char@example.com",
          password: "Abcdefg!", // 8 chars exact, letter + symbol
        }),
      });
      assert.equal(reg8CharRes.status, 201);

      // And verify a 128-character password with letter + number succeeds end-to-end on POST /api/v1/auth/register
      const reg128CharRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "MaxLen",
          lastName: "CharUser",
          email: "maxlen.char@example.com",
          password: "a".repeat(127) + "1", // 128 chars exact, letter + number
        }),
      });
      assert.equal(reg128CharRes.status, 201);

      // 1.5 Valid customer registration + client attempting to submit role="ADMIN"
      const regRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "  Amina  ",
          lastName: "  Mwangi ",
          email: "  Amina.Mwangi@Example.COM ",
          phoneNumber: "0712 345 678",
          password: "StrongPassword123!",
          role: "ADMIN",
          status: "DISABLED",
        }),
      });
      assert.equal(regRes.status, 201);

      const regCookies = regRes.headers.getSetCookie();
      const sessionCookie = extractCookieValue(regCookies, SESSION_COOKIE_NAME);
      const clearedCsrfCtx = extractCookieValue(
        regCookies,
        CSRF_CONTEXT_COOKIE_NAME
      );
      assert.ok(sessionCookie, "dsh_session HttpOnly cookie must be set on 201");
      assert.equal(
        clearedCsrfCtx,
        "",
        "dsh_csrf_ctx pre-auth cookie must be cleared on registration"
      );

      const regJson = (await regRes.json()) as {
        status: string;
        data: {
          user: Record<string, unknown>;
          csrfRefreshRequired: boolean;
          csrfEndpoint: string;
        };
      };
      assert.equal(regJson.status, "ok");
      assert.equal(regJson.data.csrfRefreshRequired, true);
      assert.equal(regJson.data.csrfEndpoint, "/api/v1/auth/csrf");
      assert.equal(regJson.data.user.firstName, "Amina");
      assert.equal(regJson.data.user.lastName, "Mwangi");
      assert.equal(regJson.data.user.email, "amina.mwangi@example.com");
      assert.equal(regJson.data.user.phoneNumber, "+254712345678");
      assert.equal(
        regJson.data.user.role,
        "CUSTOMER",
        "Client-supplied ADMIN role must be ignored; role must be CUSTOMER"
      );
      assert.equal(regJson.data.user.status, "ACTIVE");
      assert.equal(regJson.data.user.emailVerifiedAt, null);
      assert.equal(regJson.data.user.phoneVerifiedAt, null);
      assert.equal("passwordHash" in regJson.data.user, false);
      assert.equal("password_hash" in regJson.data.user, false);

      // Verify session exists in PostgreSQL with SHA-256 hash only
      const [dbSession] = await tx
        .select()
        .from(sessions)
        .where(eq(sessions.userId, String(regJson.data.user.id)));
      assert.ok(dbSession);
      assert.equal(dbSession.tokenHash, hashToken(sessionCookie));
      assert.notEqual(dbSession.tokenHash, sessionCookie);

      // 1.6 Duplicate email & duplicate phone return identical generic non-enumerating response
      const dupEmailRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Other",
          lastName: "User",
          email: "AMINA.MWANGI@EXAMPLE.COM",
          password: "AnotherStrongPassword123!",
        }),
      });
      assert.equal(dupEmailRes.status, 400);
      const dupEmailBody = (await dupEmailRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(dupEmailBody.error.code, "REGISTRATION_REJECTED");

      const dupPhoneRes = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders,
        body: JSON.stringify({
          firstName: "Other",
          lastName: "User",
          phoneNumber: "+254712345678",
          password: "AnotherStrongPassword123!",
        }),
      });
      assert.equal(dupPhoneRes.status, 400);
      const dupPhoneBody = (await dupPhoneRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(dupPhoneBody.error.code, "REGISTRATION_REJECTED");
      assert.equal(
        dupEmailBody.error.message,
        dupPhoneBody.error.message,
        "Duplicate email and duplicate phone must return identical generic message"
      );
      assert.equal(
        extractCookieValue(dupPhoneRes.headers.getSetCookie(), SESSION_COOKIE_NAME),
        null,
        "Rejected registration must not set dsh_session cookie"
      );

      // 1.7 Registration transaction rollback on session creation failure
      await assert.rejects(
        async () =>
          registerCustomer(
            {
              firstName: "Rollback",
              lastName: "Test",
              email: "rollback.user@example.com",
              password: "StrongPassword123!",
            },
            {
              ipAddress: "127.0.0.1",
              beforeSessionCommitHook: async () => {
                throw new Error("Simulated failure before session commit");
              },
            },
            tx
          ),
        /Simulated failure before session commit/
      );

      const orphanUsers = await tx
        .select()
        .from(users)
        .where(eq(users.email, "rollback.user@example.com"));
      assert.equal(
        orphanUsers.length,
        0,
        "Failed session creation must roll back the user insert atomically"
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test("2. Login, Logout, Logout-All, Current User (/me) & Rate Limiting", async () => {
  await withRolledBackTransaction(async (tx) => {
    const rateLimitStore = new MemoryRateLimitStore();
    const app = createApp(tx, undefined, {
      rateLimitStore,
      registerIpMax: 10,
      loginIpMax: 10,
      loginIdentifierMax: 4,
    });
    const server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve)
    );
    const { port } = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Seed Customer 1 and Customer 2 via POST /register
      const csrf1 = await fetchCsrfTokenAndCookie(baseUrl);
      const anonHeaders1 = {
        "Content-Type": "application/json",
        Origin: env.frontendUrl,
        Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${csrf1.csrfCtxCookie}`,
        "X-CSRF-Token": csrf1.csrfToken,
      };

      const reg1Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders1,
        body: JSON.stringify({
          firstName: "David",
          lastName: "Kamau",
          email: "david.kamau@example.com",
          phoneNumber: "0722111222",
          password: "DavidStrongPassword1!",
        }),
      });
      assert.equal(reg1Res.status, 201);
      const davidRegSessionCookie = extractCookieValue(
        reg1Res.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      const davidBody = (await reg1Res.json()) as {
        data: { user: { id: string } };
      };
      const davidUserId = davidBody.data.user.id;

      const reg2Res = await fetch(`${baseUrl}/api/v1/auth/register`, {
        method: "POST",
        headers: anonHeaders1,
        body: JSON.stringify({
          firstName: "Grace",
          lastName: "Otieno",
          email: "grace.otieno@example.com",
          phoneNumber: "0733444555",
          password: "GraceStrongPassword2!",
        }),
      });
      assert.equal(reg2Res.status, 201);
      const graceSessionCookie = extractCookieValue(
        reg2Res.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      const graceBody = (await reg2Res.json()) as {
        data: { user: { id: string } };
      };
      const graceUserId = graceBody.data.user.id;

      // 2.1 Login with email & session rotation (passing davidRegSessionCookie revokes it and issues a new token)
      const loginCsrf = await fetchCsrfTokenAndCookie(baseUrl);
      const loginEmailRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${loginCsrf.csrfCtxCookie}; ${SESSION_COOKIE_NAME}=${davidRegSessionCookie}`,
          "X-CSRF-Token": loginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "  DAVID.KAMAU@EXAMPLE.COM ",
          password: "DavidStrongPassword1!",
        }),
      });
      // Wait: when davidRegSessionCookie is sent in Cookie, CSRF middleware binds to sess:${davidRegSessionCookie}
      // because davidRegSessionCookie is an active session! So anon loginCsrf.csrfToken was rejected with 403!
      assert.equal(
        loginEmailRes.status,
        403,
        "Presenting an anonymous CSRF token when an active session cookie is present must be rejected"
      );

      // Fetch a session-bound CSRF token for davidRegSessionCookie and then log in to verify session rotation
      const davidSessCsrf = await fetchCsrfTokenAndCookie(
        baseUrl,
        davidRegSessionCookie
      );
      const rotatedLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${SESSION_COOKIE_NAME}=${davidRegSessionCookie}`,
          "X-CSRF-Token": davidSessCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "  DAVID.KAMAU@EXAMPLE.COM ",
          password: "DavidStrongPassword1!",
        }),
      });
      assert.equal(rotatedLoginRes.status, 200);
      const davidRotatedSessionCookie = extractCookieValue(
        rotatedLoginRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      assert.ok(davidRotatedSessionCookie);
      assert.notEqual(
        davidRotatedSessionCookie,
        davidRegSessionCookie,
        "Login must rotate the session token"
      );

      // Verify old session was revoked in PostgreSQL
      const [oldSessRow] = await tx
        .select()
        .from(sessions)
        .where(eq(sessions.tokenHash, hashToken(davidRegSessionCookie)));
      assert.ok(oldSessRow.revokedAt !== null, "Prior session must be revoked on login rotation");

      // 2.2 Login with Kenyan phone number (0722111222 -> +254722111222)
      const anonLoginCsrf = await fetchCsrfTokenAndCookie(baseUrl);
      const phoneLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonLoginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "0722 111 222",
          password: "DavidStrongPassword1!",
        }),
      });
      assert.equal(phoneLoginRes.status, 200);
      const davidPhoneSessionCookie = extractCookieValue(
        phoneLoginRes.headers.getSetCookie(),
        SESSION_COOKIE_NAME
      )!;
      assert.ok(davidPhoneSessionCookie);

      // 2.3 Wrong password & unknown identifier return identical 401 INVALID_CREDENTIALS
      const wrongPwRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonLoginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "david.kamau@example.com",
          password: "WrongPassword999!",
        }),
      });
      assert.equal(wrongPwRes.status, 401);
      const wrongPwBody = (await wrongPwRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(wrongPwBody.error.code, "INVALID_CREDENTIALS");

      const unknownIdRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonLoginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "nobody.exists@example.com",
          password: "WrongPassword999!",
        }),
      });
      assert.equal(unknownIdRes.status, 401);
      const unknownIdBody = (await unknownIdRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(unknownIdBody.error.code, "INVALID_CREDENTIALS");
      assert.equal(wrongPwBody.error.message, unknownIdBody.error.message);

      // 2.4 Identifier rate limiting on login (loginIdentifierMax = 4)
      // Normalized email "david.kamau@example.com" has already used 2 attempts
      // (rotatedLoginRes and wrongPwRes; phoneLoginRes used normalized phone "+254744112233").
      // Attempts 3 and 4 on "david.kamau@example.com" are allowed (wrong password -> 401),
      // and Attempt 5 must be blocked with 429 RATE_LIMITED even with the valid password!
      for (const attemptNum of [3, 4]) {
        const allowedAttemptRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Origin: env.frontendUrl,
            Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
            "X-CSRF-Token": anonLoginCsrf.csrfToken,
          },
          body: JSON.stringify({
            identifier: "david.kamau@example.com",
            password: "WrongPassword999!",
          }),
        });
        assert.equal(
          allowedAttemptRes.status,
          401,
          `Expected attempt ${attemptNum} on david.kamau@example.com to reach auth check (401)`
        );
      }

      const attempt5Res = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonLoginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "david.kamau@example.com",
          password: "DavidStrongPassword1!",
        }),
      });
      assert.equal(attempt5Res.status, 429);
      const attempt5Body = (await attempt5Res.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(attempt5Body.error.code, "RATE_LIMITED");
      assert.ok(
        Number(attempt5Res.headers.get("retry-after")) >= 1,
        "429 response must include Retry-After header"
      );

      // Reset rateLimitStore for remaining functional tests
      await rateLimitStore.clearAll();

      // 2.5 GET /api/v1/auth/me — authenticated, missing cookie, revoked session
      const meOkRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Cookie: `${SESSION_COOKIE_NAME}=${davidRotatedSessionCookie}`,
        },
      });
      assert.equal(meOkRes.status, 200);
      const meOkBody = (await meOkRes.json()) as {
        status: string;
        data: { user: Record<string, unknown> };
      };
      assert.equal(meOkBody.data.user.id, davidUserId);
      assert.equal(meOkBody.data.user.email, "david.kamau@example.com");
      assert.equal("passwordHash" in meOkBody.data.user, false);

      const meMissingRes = await fetch(`${baseUrl}/api/v1/auth/me`);
      assert.equal(meMissingRes.status, 401);

      const meRevokedRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Cookie: `${SESSION_COOKIE_NAME}=${davidRegSessionCookie}`,
        },
      });
      assert.equal(meRevokedRes.status, 401);

      // 2.6 Single-session Logout (POST /api/v1/auth/logout) & expired session logout handling
      const davidPhoneCsrf = await fetchCsrfTokenAndCookie(
        baseUrl,
        davidPhoneSessionCookie
      );
      const logoutRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
        method: "POST",
        headers: {
          Origin: env.frontendUrl,
          Cookie: `${SESSION_COOKIE_NAME}=${davidPhoneSessionCookie}`,
          "X-CSRF-Token": davidPhoneCsrf.csrfToken,
        },
      });
      assert.equal(logoutRes.status, 200);
      assert.equal(
        extractCookieValue(logoutRes.headers.getSetCookie(), SESSION_COOKIE_NAME),
        "",
        "Logout must clear dsh_session cookie"
      );

      // Calling logout AGAIN with the already-revoked/expired session cookie and its CSRF token
      // must still succeed idempotently (200 OK) and clear cookies
      const expiredLogoutRes = await fetch(`${baseUrl}/api/v1/auth/logout`, {
        method: "POST",
        headers: {
          Origin: env.frontendUrl,
          Cookie: `${SESSION_COOKIE_NAME}=${davidPhoneSessionCookie}`,
          "X-CSRF-Token": davidPhoneCsrf.csrfToken,
        },
      });
      assert.equal(expiredLogoutRes.status, 200);
      assert.equal(
        extractCookieValue(
          expiredLogoutRes.headers.getSetCookie(),
          SESSION_COOKIE_NAME
        ),
        ""
      );

      // 2.7 Logout-All (POST /api/v1/auth/logout-all) revokes all of David's sessions while preserving Grace's session
      const davidActiveCsrf = await fetchCsrfTokenAndCookie(
        baseUrl,
        davidRotatedSessionCookie
      );
      const logoutAllRes = await fetch(`${baseUrl}/api/v1/auth/logout-all`, {
        method: "POST",
        headers: {
          Origin: env.frontendUrl,
          Cookie: `${SESSION_COOKIE_NAME}=${davidRotatedSessionCookie}`,
          "X-CSRF-Token": davidActiveCsrf.csrfToken,
        },
      });
      assert.equal(logoutAllRes.status, 200);

      // David's active session is now revoked
      const davidActiveSessions = await tx
        .select()
        .from(sessions)
        .where(
          and(eq(sessions.userId, davidUserId), isNull(sessions.revokedAt))
        );
      assert.equal(davidActiveSessions.length, 0);

      // Grace's session remains active and works on GET /api/v1/auth/me
      const graceMeRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Cookie: `${SESSION_COOKIE_NAME}=${graceSessionCookie}`,
        },
      });
      assert.equal(graceMeRes.status, 200);

      // 2.8 Disabled account rejection on login and on GET /api/v1/auth/me
      await tx
        .update(users)
        .set({ status: "DISABLED" })
        .where(eq(users.id, graceUserId));

      const graceDisabledMeRes = await fetch(`${baseUrl}/api/v1/auth/me`, {
        headers: {
          Cookie: `${SESSION_COOKIE_NAME}=${graceSessionCookie}`,
        },
      });
      assert.equal(graceDisabledMeRes.status, 403);

      const disabledLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Origin: env.frontendUrl,
          Cookie: `${CSRF_CONTEXT_COOKIE_NAME}=${anonLoginCsrf.csrfCtxCookie}`,
          "X-CSRF-Token": anonLoginCsrf.csrfToken,
        },
        body: JSON.stringify({
          identifier: "grace.otieno@example.com",
          password: "GraceStrongPassword2!",
        }),
      });
      assert.equal(disabledLoginRes.status, 401);
      const disabledLoginBody = (await disabledLoginRes.json()) as {
        error: { code: string; message: string };
      };
      assert.equal(
        disabledLoginBody.error.code,
        "INVALID_CREDENTIALS",
        "Disabled account login must not disclose account details"
      );
      assert.equal(
        disabledLoginBody.error.message,
        wrongPwBody.error.message,
        "Disabled account login must return the identical generic error message"
      );

      // 2.9 Verify audit logs recorded registration, login, logout, logout-all, and rate-limit events without secrets
      const recordedAudits = await tx.select().from(auditLogs);
      const actions = new Set(recordedAudits.map((a) => a.action));
      assert.ok(actions.has("auth.register.success"));
      assert.ok(actions.has("auth.login.success"));
      assert.ok(actions.has("auth.login.failed"));
      assert.ok(actions.has("auth.login.disabled_account"));
      assert.ok(actions.has("auth.rate_limit.exceeded"));
      assert.ok(actions.has("auth.session.revoked"));
      assert.ok(actions.has("auth.session.revoked_all"));
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

test.after(async () => {
  await pool.end();
});
