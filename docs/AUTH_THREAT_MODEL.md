# Digital Services Hub (DSH) — Authentication & Authorization Threat Model

This document analyzes the 15 primary authentication, session management, and access-control threats facing the DSH platform (`@dsh/frontend` + `@dsh/backend` + PostgreSQL 18), along with concrete technical mitigations and verification tests.

---

## 1. Threat Matrix Summary

| # | Threat | Severity | Primary Defense Layer |
| :---: | :--- | :---: | :--- |
| 1 | Brute-Force Login Attacks | High | Dual IP + Identifier Rate Limiting & Argon2id Memory-Hard Hashing |
| 2 | Credential Stuffing | High | Rate Limiting, Normalized Identifier Throttling & Audit Anomaly Logging |
| 3 | Session Theft (Network / DB Leak) | Critical | `HttpOnly` + `Secure` Cookies & SHA-256 Hashed `sessions.token_hash` in PostgreSQL |
| 4 | Session Fixation | High | Mandatory Session Rotation on Login, Password Change & Privilege Change |
| 5 | Cross-Site Request Forgery (CSRF) | High | `SameSite=Lax`, Strict `Origin` Validation & Session-Bound `X-CSRF-Token` |
| 6 | XSS-Related Token Theft | Critical | `HttpOnly` Cookie Storage (Zero `localStorage` / `sessionStorage` Tokens) |
| 7 | Account Enumeration | Medium | Generic Error Messages, Constant-Time Dummy Argon2id Verification & Uniform Reset Responses |
| 8 | Password Reset Abuse | High | Rate Limiting, 32-Byte CSPRNG Tokens, SHA-256 Storage, 30-Min Expiry & Single-Use (`used_at`) |
| 9 | Privilege Escalation (Vertical) | Critical | Server-Side `requireRole` Middleware & Hardcoded `role = 'CUSTOMER'` on Public Registration |
| 10 | Insecure Direct Object Reference (IDOR) | Critical | Mandatory SQL Ownership (`customer_id`) & Assignment (`staff_assignments`) Predicates |
| 11 | Unauthorized Role Changes | Critical | Anti-Escalation Rules (`ADMIN` Cannot Touch `SUPER_ADMIN`) & Last `SUPER_ADMIN` Guard |
| 12 | Verification Token Replay | Medium | Single-Use `used_at` Timestamp, Short Expiry & Prior-Token Invalidation on Resend |
| 13 | Concurrent Login & Stale Session Persistence | High | Immediate Session Revocation (`revoked_at = now()`) on Logout-All, Password Reset & Account Disable |
| 14 | Audit-Log Manipulation | High | Append-Only PostgreSQL Trigger (`audit_logs_prevent_mutation_trg`) & Insert-Only Repository |
| 15 | Sensitive Information Leakage | Critical | Redacted Logs, Generic 500 Handler, Zero Plaintext Secrets in DB Metadata |

---

## 2. Detailed Threat Analysis, Mitigations & Verification Tests

### Threat 1: Brute-Force Login Attacks
- **Risk**: High — An attacker systematically guesses passwords for a known customer, staff, or admin email/phone number.
- **Attack Scenario**: Automated script sends hundreds of `POST /api/v1/auth/login` requests per minute targeting an admin email or a Kenyan mobile number (`+2547...`).
- **Mitigation**:
  1. Enforce dual sliding-window rate limits on `POST /api/v1/auth/login`: max **10 attempts per 15 minutes per IP** and **5 failed attempts per 15 minutes per normalized identifier** (temporary cooldown without permanent account lockout DoS).
  2. Hash passwords with **Argon2id** (`memoryCost: 64 MiB`, `timeCost: 3`), making offline and online guessing computationally expensive.
  3. Record every failed login attempt in `audit_logs` (`action = 'auth.login.failed'`).
- **Verification Test**: Send 6 consecutive failed `POST /api/v1/auth/login` requests for the same email; verify the 6th request returns `429 Too Many Requests` with a `Retry-After` header and does not execute password verification.

---

### Threat 2: Credential Stuffing
- **Risk**: High — Attackers replay breached email/password pairs from external websites against DSH `/api/v1/auth/login`.
- **Attack Scenario**: Botnet distributes login attempts across multiple accounts from rotating or single IPs.
- **Mitigation**:
  1. IP-based rate limiting (10 attempts / 15 min) throttles multi-account stuffing from a single source.
  2. Password policy enforces 8–128 characters with letter + number/symbol requirements.
  3. On password change or reset, all existing sessions are revoked.
  4. Failed login spikes are logged with IP and User-Agent metadata in `audit_logs`.
- **Verification Test**: Submit 11 rapid login attempts across distinct email addresses from the same IP; confirm the 11th request is blocked with `429 Too Many Requests`.

---

### Threat 3: Session Theft (Network Interception or Database Leak)
- **Risk**: Critical — An attacker obtains a valid session identifier to impersonate an authenticated user or administrator.
- **Attack Scenario**:
  - *Scenario A*: Attacker reads `sessions` rows via a leaked database backup or SQL injection.
  - *Scenario B*: Attacker sniffs unencrypted traffic in production.
- **Mitigation**:
  1. PostgreSQL [`sessions`](file:///home/codewithfred/Projects/DHS/backend/src/db/schema/sessions.ts#L15-L39) stores only `token_hash = SHA256(rawToken)` (`varchar(128)`). The raw 256-bit token exists only in the client's `HttpOnly` cookie and cannot be reconstructed from `sessions.token_hash`.
  2. Production cookies enforce `Secure` (HTTPS-only) and host-only scope (no `Domain` attribute).
  3. Role-tiered TTLs limit session lifetime (8h for `ADMIN`/`SUPER_ADMIN`, 12h for `STAFF`, 7d for `CUSTOMER`).
- **Verification Test**: Query `SELECT token_hash FROM sessions` after logging in; verify the stored value is a 64-character hex SHA-256 digest that does not match the raw `dsh_session` cookie value, and verify passing `token_hash` as the cookie value returns `401 Unauthorized`.

---

### Threat 4: Session Fixation
- **Risk**: High — An attacker tricks a victim into authenticating using a session token known to the attacker.
- **Attack Scenario**: A shared cyber-café workstation browser already holds a pre-existing `dsh_session` cookie before a staff member or customer logs in.
- **Mitigation**:
  1. `POST /api/v1/auth/login` explicitly revokes any pre-existing session carried in the request cookie (`UPDATE sessions SET revoked_at = now()`) and always generates a brand-new 256-bit token and `sessions` row.
  2. `POST /api/v1/auth/change-password` revokes all prior sessions and issues a new session token.
- **Verification Test**: Authenticate as User A (capturing Cookie 1), then call `POST /api/v1/auth/login` as User B while sending Cookie 1; verify Cookie 1 is marked `revoked_at IS NOT NULL` in PostgreSQL and a distinct Cookie 2 is issued.

---

### Threat 5: Cross-Site Request Forgery (CSRF)
- **Risk**: High — A malicious third-party website triggers unauthorized state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) using the victim's browser cookies.
- **Attack Scenario**: An authenticated `ADMIN` visits an external page that submits a hidden form or `fetch` request to `POST http://localhost:4000/api/v1/auth/change-password` or modifies catalog prices, or an attacker triggers a cross-site login CSRF attack.
- **Mitigation**:
  1. `dsh_session` and `dsh_csrf_ctx` cookies use `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` in production, and no `Domain` attribute (`dsh_csrf_ctx` has `Max-Age=1800`).
  2. Strict CORS configuration in [`backend/src/app.ts`](file:///home/codewithfred/Projects/DHS/backend/src/app.ts#L11-L18) allows only `env.frontendUrl`.
  3. `GET /api/v1/auth/csrf` sets `Cache-Control: no-store` and issues a signed CSRF token (`<nonce>.<issuedAtUnixMs>.<hmacHex>`) with an explicit **30-minute TTL**, bound either to `session.tokenHash` (when authenticated) or to the `dsh_csrf_ctx` `HttpOnly` cookie (pre-authentication), held strictly in frontend memory (never in `localStorage` or `sessionStorage`).
  4. CSRF middleware validates **both** the request `Origin` header against `env.frontendUrl` **and** the `X-CSRF-Token` header on all `POST`, `PUT`, `PATCH`, and `DELETE` requests, checking token format, equal `Buffer` byte lengths (`32` bytes) before invoking `crypto.timingSafeEqual()`, and the 30-minute TTL (`403 CSRF_TOKEN_EXPIRED` triggers frontend token reacquisition via `GET /api/v1/auth/csrf`).
  5. CSRF tokens rotate automatically whenever an authenticated session is created or rotated (`/login`, successful `/register`, `/change-password`) — while rejected `/register` or `/login` attempts do not rotate `dsh_csrf_ctx` — and are invalidated immediately upon logout or session revocation.
- **Verification Test**: Issue a `POST /api/v1/auth/logout`, `POST /api/v1/auth/login`, or `POST /api/v1/auth/change-password` with a missing, malformed, wrong-length, expired (>30 min), or pre-auth `X-CSRF-Token` header, or a forged `Origin: https://evil.example.com`; verify `403 Forbidden` without unhandled `RangeError` exceptions, and verify `GET /api/v1/auth/csrf` returns `Cache-Control: no-store`.

---

### Threat 6: XSS-Related Token Theft
- **Risk**: Critical — Injected client-side JavaScript attempts to read session or CSRF tokens from web storage and exfiltrate them to an external server.
- **Attack Scenario**: An attacker attempts `document.cookie`, `localStorage.getItem(...)`, or `sessionStorage.getItem(...)` via an XSS vector.
- **Mitigation**:
  1. `dsh_session` and `dsh_csrf_ctx` are set exclusively as `HttpOnly` cookies, making them completely inaccessible to `document.cookie` or client-side JavaScript.
  2. Storing session tokens or CSRF tokens in `localStorage` or `sessionStorage` is strictly prohibited across `@dsh/frontend`.
  3. React 19 automatic output escaping and strict input validation prevent stored XSS in order messages and profile fields.
- **Verification Test**: Inspect the `Set-Cookie` headers from `GET /api/v1/auth/csrf` and `POST /api/v1/auth/login` and verify the `HttpOnly` directive is present on `dsh_session` and `dsh_csrf_ctx`; grep `frontend/src/` to confirm zero references to `localStorage` or `sessionStorage` for auth or CSRF tokens.

---

### Threat 7: Account Enumeration
- **Risk**: Medium — An attacker probes `/login`, `/register`, `/forgot-password`, or verification endpoints to discover which email addresses or Kenyan phone numbers have registered DSH accounts.
- **Attack Scenario**: Attacker measures response status codes, field-specific duplicate messages, or Argon2id response timing differences between existing and non-existing users.
- **Mitigation**:
  1. `POST /api/v1/auth/login` returns the identical `401 Unauthorized` message (`"Invalid credentials."`) whether the identifier was not found or the password was wrong, executing a dummy `argon2.verify()` when the user is not found to equalize latency.
  2. `POST /api/v1/auth/register` hashes the password with Argon2id before checking duplicates and returns a uniform, generic non-enumerating error (`"Unable to complete registration with the provided details. If you already have an account, please sign in or use password recovery."`) without disclosing whether `email` or `phoneNumber` matched an existing account, while recording the detailed collision internally in `audit_logs` (`auth.register.conflict`).
  3. `POST /api/v1/auth/forgot-password` and `POST /api/v1/auth/resend-verification` always return generic `200 OK` responses, and `/verify-email` / `/verify-phone` return uniform `400 INVALID_OR_EXPIRED_TOKEN` errors.
- **Verification Test**: Submit `POST /api/v1/auth/register` with an existing email vs. an existing phone number; verify both return the identical generic error without revealing which field matched, while `audit_logs` records `auth.register.conflict`. Call `POST /api/v1/auth/login` and `POST /api/v1/auth/forgot-password` with unknown vs. known identifiers and verify uniform public responses.

---

### Threat 8: Password Reset Abuse
- **Risk**: High — An attacker attempts to predict reset tokens, reuse an old reset link, or flood a user with reset emails.
- **Attack Scenario**: Attacker intercepts an already-used reset link from browser history or requests multiple reset tokens and attempts to use an older one.
- **Mitigation**:
  1. Reset tokens are 32-byte (256-bit) CSPRNG values hashed with SHA-256 in [`password_reset_tokens.token_hash`](file:///home/codewithfred/Projects/DHS/backend/src/db/schema/sessions.ts#L48).
  2. Short TTL (**30 minutes**) enforced via `expires_at > now()`.
  3. Issuing a new reset token invalidates all prior unused reset tokens for that user (`UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL`).
  4. Consuming a reset token locks the row (`SELECT ... FOR UPDATE`), sets `used_at = now()`, updates `users.password_hash`, and revokes all active user sessions in a single transaction.
- **Verification Test**: Complete a password reset with a valid token, then replay the exact same token a second time; verify the second request fails with `400 Bad Request` (`INVALID_OR_EXPIRED_TOKEN`) and verify all prior sessions for that user have `revoked_at IS NOT NULL`.

---

### Threat 9: Privilege Escalation (Vertical)
- **Risk**: Critical — A public user or lower-privileged role (`CUSTOMER` or `STAFF`) gains `ADMIN` or `SUPER_ADMIN` privileges.
- **Attack Scenario**:
  - *Scenario A*: Attacker sends `{"role": "SUPER_ADMIN"}` in `POST /api/v1/auth/register` or profile update.
  - *Scenario B*: `STAFF` user calls an admin-only endpoint to view financial reports or modify catalog prices.
- **Mitigation**:
  1. Public registration schema rejects or ignores any client-supplied `role` field and hardcodes `role = 'CUSTOMER'` in the Drizzle `INSERT`.
  2. Every administrative and staff route is protected by server-side `requireAuth` + `requireRole(...)` middleware.
  3. Unauthorized role access attempts are logged in `audit_logs` (`auth.rbac.denied`) and rejected with `403 Forbidden`.
- **Verification Test**: Call `POST /api/v1/auth/register` with `"role": "ADMIN"`; verify either `400 Bad Request` or created user has `role = 'CUSTOMER'`. Call an admin endpoint with a `CUSTOMER` or `STAFF` session cookie and verify `403 Forbidden`.

---

### Threat 10: Insecure Direct Object Reference (IDOR / Horizontal Escalation)
- **Risk**: Critical — Customer A accesses or modifies Customer B's orders, uploaded files, messages, Wi-Fi sessions, or payment receipts by substituting UUIDs in API paths.
- **Attack Scenario**: Authenticated `CUSTOMER` requests `GET /api/v1/orders/<customer_b_order_uuid>` or `STAFF` user requests an order not assigned to them in `staff_assignments`.
- **Mitigation**:
  1. Every `CUSTOMER` data query scopes the SQL `WHERE` clause by `customer_id = req.auth.user.id`.
  2. Every `STAFF` order query verifies an active assignment in [`staff_assignments`](file:///home/codewithfred/Projects/DHS/backend/src/db/schema/orders.ts#L80-L110) (`staff_user_id = req.auth.user.id AND unassigned_at IS NULL`).
  3. Order message queries for `CUSTOMER` strictly filter `visibility = 'CUSTOMER'`, preventing leakage of `INTERNAL` staff notes.
- **Verification Test**: Create an order as Customer B, then request that order's details, files, and messages using Customer A's session; verify `404 Not Found` / `403 Forbidden`. Verify `INTERNAL` messages are never returned to Customer B.

---

### Threat 11: Unauthorized Role Changes & `SUPER_ADMIN` Takeover / Write-Skew Lockout
- **Risk**: Critical — An `ADMIN` attempts to promote themselves or another user to `SUPER_ADMIN`, or two concurrent requests demote/disable two different `SUPER_ADMIN` accounts simultaneously, leaving zero active `SUPER_ADMIN` accounts.
- **Attack Scenario**: Compromised `ADMIN` account calls user-management APIs to grant `SUPER_ADMIN`, or two concurrent `SUPER_ADMIN` sessions simultaneously demote each other when `count = 2`.
- **Mitigation**:
  1. `ADMIN` role is restricted to managing `CUSTOMER`, `STAFF`, and non-super `ADMIN` accounts. Any attempt by an `ADMIN` to create, promote, demote, or disable a `SUPER_ADMIN` is rejected with `403 Forbidden`.
  2. Modifying any user's `role` or `status` immediately revokes all active sessions for that target user (`UPDATE sessions SET revoked_at = now()`) so the new role/status takes effect on the very next request.
  3. **Atomic Concurrency Guard for Last Active `SUPER_ADMIN`**: All application paths (REST endpoints, CLI scripts, and internal services) that modify a `SUPER_ADMIN` account's `role` or `status` run inside a PostgreSQL transaction that (1) acquires `SELECT pg_advisory_xact_lock(hashtextextended('dsh_super_admin_role_guard', 0))`, (2) locks all active `SUPER_ADMIN` rows in deterministic PK order (`SELECT id FROM users WHERE role = 'SUPER_ADMIN' AND status = 'ACTIVE' ORDER BY id ASC FOR UPDATE`), (3) rechecks `activeSuperAdminCount`, (4) rejects with `409 Conflict` (`LAST_SUPER_ADMIN_PROTECTED`) if removing/demoting the last active `SUPER_ADMIN`, (5) performs the update and session revocation atomically, and (6) records an immutable event in `audit_logs`.
- **Verification Test**: Attempt to promote a user to `SUPER_ADMIN` using an `ADMIN` session (`403 Forbidden`). Attempt to disable or demote the only active `SUPER_ADMIN` (`409 Conflict`). Execute two concurrent requests to demote the last two active `SUPER_ADMIN` accounts (`Admin A` and `Admin B`); verify the serialization lock causes the first to succeed and the second to fail with `409 Conflict` (`LAST_SUPER_ADMIN_PROTECTED`), preserving exactly one active `SUPER_ADMIN`.

---

### Threat 12: Verification Token Replay & Brute-Force
- **Risk**: Medium — An attacker replays a consumed verification token or brute-forces a 6-digit phone OTP.
- **Attack Scenario**: Attacker submits all 1,000,000 6-digit codes to `POST /api/v1/auth/verify-phone` or replays a used email verification link.
- **Mitigation**:
  1. [`verification_tokens`](file:///home/codewithfred/Projects/DHS/backend/src/db/schema/sessions.ts#L65-L91) enforces `used_at IS NULL` and `expires_at > now()`.
  2. Phone OTPs expire in **10 minutes** and `POST /api/v1/auth/verify-phone` is strictly rate-limited (5 attempts per 15 minutes per user/IP). After 5 failed attempts, the active `PHONE` verification token is automatically invalidated (`used_at = now()`).
  3. Calling `POST /api/v1/auth/resend-verification` invalidates all prior unused tokens of that type for the user.
- **Verification Test**: Verify an email or phone token once (`200 OK`), then submit the same token again and verify `400 Bad Request`. Submit 6 wrong phone OTPs and verify rate limiting / token invalidation.

---

### Threat 13: Concurrent Login & Stale Session Persistence
- **Risk**: High — A user who changes their password on one device or has their account disabled by an admin remains logged in on a cyber-café computer or stolen phone.
- **Attack Scenario**: Customer forgets to log out on a shared computer and later resets their password or clicks "Log out of all devices", or an admin disables a terminated staff member's account.
- **Mitigation**:
  1. `requireAuth` checks `sessions.revoked_at IS NULL`, `sessions.expires_at > now()`, **and** joins `users` to verify `users.status = 'ACTIVE'` on every protected request.
  2. Password change, password reset, `POST /api/v1/auth/logout-all`, role change, and account deactivation (`status = 'DISABLED'`) all execute `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`.
- **Verification Test**: Create 2 concurrent sessions for a user; call `POST /api/v1/auth/logout-all` (or disable the user in `users`); verify both sessions immediately receive `401 Unauthorized` on `GET /api/v1/auth/me`.

---

### Threat 14: Audit-Log Manipulation
- **Risk**: High — A compromised application process or rogue insider attempts to erase or alter security events in `audit_logs` to cover tracks.
- **Attack Scenario**: Execution of `UPDATE audit_logs` or `DELETE FROM audit_logs` after unauthorized actions.
- **Mitigation**:
  1. Database-level enforcement: PostgreSQL trigger `audit_logs_prevent_mutation_trg` (`BEFORE UPDATE OR DELETE ON audit_logs EXECUTE FUNCTION prevent_append_only_mutation()`) raises an exception on any update or delete attempt.
  2. Application-level enforcement: The audit service exposes only `insert` and authorized `select` functions.
- **Verification Test**: Execute `UPDATE audit_logs` and `DELETE FROM audit_logs` in PostgreSQL; verify both fail with `ERROR: Table "audit_logs" is append-only; UPDATE/DELETE operations are prohibited.`

---

### Threat 15: Sensitive Information Leakage
- **Risk**: Critical — Passwords, Argon2id hashes, raw session tokens, reset tokens, or database connection strings leak via API responses, error stack traces, or audit log metadata.
- **Attack Scenario**: An unhandled exception or verbose serializer returns the full `users` row (including `password_hash`) in `GET /api/v1/auth/me` or writes `req.body.password` into `audit_logs.metadata`.
- **Mitigation**:
  1. Dedicated DTO mappers (`toPublicUserDto(user)`) explicitly pick safe fields (`id`, `firstName`, `lastName`, `email`, `phoneNumber`, `role`, `status`, `emailVerifiedAt`, `phoneVerifiedAt`, `lastLoginAt`, `createdAt`) and never include `passwordHash`.
  2. Audit logging helpers sanitize metadata objects, stripping keys matching `password`, `passwordHash`, `token`, `secret`, `authorization`, or `cookie`.
  3. Global Express error handler in [`backend/src/app.ts`](file:///home/codewithfred/Projects/DHS/backend/src/app.ts#L35-L41) returns generic error messages without stack traces.
- **Verification Test**: Inspect responses from `/register`, `/login`, and `/me` to verify `passwordHash` and `tokenHash` are never present; inspect `audit_logs.metadata` after auth operations to confirm zero plaintext secrets or hashes.
