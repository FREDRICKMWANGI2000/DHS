# Digital Services Hub (DSH) — Role-Based Access Control (RBAC) Matrix

## 1. Core RBAC Security Invariants

1. **Server-Side Enforcement Only**:
   - Every permission check and resource ownership rule is enforced inside `@dsh/backend` Express middleware and service-layer queries.
   - Frontend navigation menus, sidebars, and route guards in `@dsh/frontend` exist purely for user experience and **must never be treated as a security boundary**.
2. **Four Canonical Roles ([`user_role`](file:///home/codewithfred/Projects/DHS/backend/src/db/schema/enums.ts#L3-L8))**:
   - `CUSTOMER` — Default role assigned to all self-registered public users.
   - `STAFF` — Operational staff who process assigned digital service orders and customer deliverables.
   - `ADMIN` — Hub managers who manage catalog items, orders, staff assignments, customer accounts, and operational finances.
   - `SUPER_ADMIN` — System owners with full administrative authority, privileged role management, and system-level configuration access.
3. **Active Account Requirement**:
   - An authenticated user must have `users.status = 'ACTIVE'` on every request. Transitioning an account to `DISABLED` immediately invalidates all access regardless of role.
4. **Strict Anti-Escalation Rule**:
   - No user may assign or promote any account to a role higher than their own, and **`ADMIN` accounts can never create, promote, demote, or disable a `SUPER_ADMIN` account**.

---

## 2. Role Hierarchy & Scope Summary

| Role | Primary Scope | Prohibited Actions |
| :--- | :--- | :--- |
| **`CUSTOMER`** | Own profile, own devices, own Wi-Fi sessions, own digital service orders, own order files/messages (`CUSTOMER` visibility only), and own payments. | Cannot view or mutate any other customer's records (IDOR protection), cannot view `INTERNAL` order notes, cannot modify catalog prices or order statuses beyond customer cancellation/submission rules. |
| **`STAFF`** | Assigned digital service orders (`staff_assignments`), operational order processing, uploading deliverables, customer communication (`CUSTOMER` and `INTERNAL` messages), and viewing operational payment status (`PAID`/`PENDING`) for assigned orders. | Cannot access aggregate revenue, financial reports, unassigned customer orders (unless operational queue policy explicitly grants read-only queue view), cannot manage other staff, cannot edit catalog pricing, and cannot modify `business_settings`. |
| **`ADMIN`** | Full management of customers, `STAFF` and `ADMIN` accounts, `wifi_packages`, `service_catalog`, all `service_orders`, `staff_assignments`, operational `payments`, and authorized financial/revenue reports. | Cannot create, promote, demote, or disable `SUPER_ADMIN` accounts; cannot modify system-level security settings reserved for `SUPER_ADMIN`. |
| **`SUPER_ADMIN`** | Full administrative permissions across all domains, including `SUPER_ADMIN` lifecycle management, `business_settings`, and full `audit_logs` inspection. | Cannot disable or demote the **last active `SUPER_ADMIN`** account (`LAST_SUPER_ADMIN_PROTECTED`). |

---

## 3. Comprehensive Permission Matrix by Domain

Legend:
- **ALLOW (All)**: Permitted across all records in this resource domain.
- **ALLOW (Own)**: Permitted **only** where `record.user_id = req.auth.user.id` (or `customer_id = req.auth.user.id`).
- **ALLOW (Assigned)**: Permitted **only** where an active row exists in `staff_assignments` (`staff_user_id = req.auth.user.id AND unassigned_at IS NULL`).
- **DENY**: Strictly forbidden (`403 Forbidden`).

### 3.1 Authentication & Self-Profile (`users`, `sessions`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| View & update own profile (`/auth/me`) | ALLOW (Own) | ALLOW (Own) | ALLOW (Own) | ALLOW (Own) | Cannot self-mutate `role` or `status` |
| Change own password & revoke own sessions | ALLOW (Own) | ALLOW (Own) | ALLOW (Own) | ALLOW (Own) | Requires current password verification |
| Register account via public `/auth/register` | Public -> `CUSTOMER` | N/A | N/A | N/A | Always forces `role = 'CUSTOMER'` |

### 3.2 User & Role Management (`users`, `sessions`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| List / search `CUSTOMER` accounts | DENY | DENY | ALLOW (All) | ALLOW (All) | Server-side role check `>= ADMIN` |
| View `CUSTOMER` contact details for assigned order | DENY | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Staff scoped to active `staff_assignments` |
| Create `STAFF` or `ADMIN` account | DENY | DENY | ALLOW | ALLOW | Logged in `audit_logs` |
| Create or promote `SUPER_ADMIN` account | DENY | DENY | **DENY** | ALLOW | Exclusive to `SUPER_ADMIN` |
| Disable/enable `CUSTOMER` or `STAFF` account | DENY | DENY | ALLOW | ALLOW | Revokes target user's active sessions |
| Disable/enable `ADMIN` account | DENY | DENY | ALLOW (Other) | ALLOW | Admin cannot disable `SUPER_ADMIN` |
| Disable/demote `SUPER_ADMIN` account | DENY | DENY | **DENY** | ALLOW* | *Forbidden if target is the last active `SUPER_ADMIN` |

### 3.3 Wi-Fi Packages & Sessions (`wifi_packages`, `wifi_sessions`, `customer_devices`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| View active `wifi_packages` catalog | ALLOW (Public) | ALLOW (Public) | ALLOW (All) | ALLOW (All) | Public sees `is_active = true`; Admin sees all |
| Create / edit / toggle `wifi_packages` | DENY | DENY | ALLOW (All) | ALLOW (All) | Server-authoritative pricing; audited |
| Purchase Wi-Fi session | ALLOW (Public/Own) | ALLOW (Own) | ALLOW (All) | ALLOW (All) | Snapshots price & duration from DB |
| View `wifi_sessions` history | ALLOW (Own) | DENY* | ALLOW (All) | ALLOW (All) | Customer scoped to `customer_id = user.id` |
| Authorize / revoke active Wi-Fi session | DENY | DENY | ALLOW (All) | ALLOW (All) | Audited in `audit_logs` |
| Manage `customer_devices` (MAC addresses) | ALLOW (Own) | DENY | ALLOW (All) | ALLOW (All) | Normalized via `normalizeMacAddress()` |

### 3.4 Digital Service Catalog & Orders (`service_catalog`, `service_orders`, `staff_assignments`, `service_order_status_history`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| View active `service_catalog` | ALLOW (Public) | ALLOW (Public) | ALLOW (All) | ALLOW (All) | Public sees `is_active = true`; Admin sees all |
| Create / update / toggle `service_catalog` | DENY | DENY | ALLOW (All) | ALLOW (All) | Preserves historical order snapshots |
| Create `service_orders` | ALLOW (Own) | ALLOW (Own) | ALLOW (All) | ALLOW (All) | `total_amount = unit_price_snapshot * quantity` |
| View `service_orders` | ALLOW (Own) | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Enforced in SQL `WHERE` clause |
| Assign / unassign staff (`staff_assignments`) | DENY | DENY | ALLOW (All) | ALLOW (All) | Records `assigned_by = req.auth.user.id` |
| Update order workflow status (`IN_PROGRESS`, `WAITING_FOR_CUSTOMER`, `READY`, `COMPLETED`) | DENY | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Appends immutable row to `service_order_status_history` |
| Cancel own `DRAFT` / `PAYMENT_PENDING` order | ALLOW (Own) | DENY | ALLOW (All) | ALLOW (All) | Appends row to `service_order_status_history` |

### 3.5 Order Files & Messages (`service_order_files`, `service_order_messages`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Upload customer input file (`CUSTOMER_UPLOAD`) | ALLOW (Own Order) | DENY | ALLOW (All) | ALLOW (All) | Verified order ownership |
| Upload staff deliverable (`STAFF_DELIVERABLE`) | DENY | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Verified active `staff_assignments` |
| Download order files | ALLOW (Own Order) | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Signed/authorized backend stream |
| Read/send `CUSTOMER` visibility messages | ALLOW (Own Order) | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | `visibility = 'CUSTOMER'` |
| Read/send `INTERNAL` staff notes | **DENY** | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | `visibility = 'INTERNAL'` stripped from customer queries |

### 3.6 Payments & Financial Reporting (`payments`, `payment_attempts`, `payment_callback_events`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Initiate M-Pesa STK Push for own order/session | ALLOW (Own) | ALLOW (Own) | ALLOW (All) | ALLOW (All) | Enforces `payments_target_xor_chk` |
| View own payment receipts & status | ALLOW (Own) | ALLOW (Own) | ALLOW (All) | ALLOW (All) | Scoped to own orders/sessions |
| View payment status (`PAID`/`PENDING`) on assigned order | N/A | ALLOW (Assigned) | ALLOW (All) | ALLOW (All) | Staff sees operational payment state only |
| View aggregate revenue & financial analytics | **DENY** | **DENY** | ALLOW (All) | ALLOW (All) | Restricted to `ADMIN` and `SUPER_ADMIN` |
| Inspect raw `payment_callback_events` / reconcile | **DENY** | **DENY** | ALLOW (All) | ALLOW (All) | Restricted to `ADMIN` and `SUPER_ADMIN` |

### 3.7 System Configuration & Security Audit (`business_settings`, `audit_logs`)
| Operation | `CUSTOMER` | `STAFF` | `ADMIN` | `SUPER_ADMIN` | Ownership / Enforcement Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| Read public operational settings (e.g. support contact) | ALLOW (Public) | ALLOW (Public) | ALLOW (All) | ALLOW (All) | Whitelisted public keys only |
| Modify operational `business_settings` | DENY | DENY | ALLOW (Operational) | ALLOW (All) | System security keys require `SUPER_ADMIN` |
| Modify system-wide security settings | DENY | DENY | **DENY** | ALLOW (All) | Exclusive to `SUPER_ADMIN` |
| Query `audit_logs` | DENY | DENY | ALLOW (Operational) | ALLOW (All) | Append-only (`audit_logs_prevent_mutation_trg`) |

---

## 4. Backend Middleware Enforcement Architecture

RBAC will be enforced in `@dsh/backend` through composable Express middleware:

1. **`requireAuth`**:
   - Validates `dsh_session` cookie, checks `sessions.revoked_at IS NULL` and `sessions.expires_at > now()`, verifies `users.status = 'ACTIVE'`, and populates `req.auth`.
2. **`requireRole(...allowedRoles: UserRole[])`**:
   - Verifies `allowedRoles.includes(req.auth.user.role)`.
   - If unauthorized, writes an `auth.rbac.denied` entry to `audit_logs` and returns `403 Forbidden`.
3. **Resource Ownership / Assignment Guards**:
   - **Customer Ownership**: Queries include `WHERE customer_id = req.auth.user.id` when `req.auth.user.role === 'CUSTOMER'`.
   - **Staff Assignment**: Queries join or check `EXISTS (SELECT 1 FROM staff_assignments sa WHERE sa.order_id = service_orders.id AND sa.staff_user_id = req.auth.user.id AND sa.unassigned_at IS NULL)` when `req.auth.user.role === 'STAFF'`.
   - Returning `404 Not Found` or `403 Forbidden` prevents Insecure Direct Object Reference (IDOR) probing across UUIDs.

---

## 5. Atomic Concurrency Protection for the Last Active `SUPER_ADMIN`

An independent row lock on only the target account (`SELECT ... WHERE id = $target FOR UPDATE`) is insufficient when two `SUPER_ADMIN` accounts exist and two concurrent requests simultaneously attempt to demote or disable each other (write-skew race condition).

**All application paths** that create, promote, demote, disable, or modify a `SUPER_ADMIN` account's `role` or `status` (including administrative REST endpoints, CLI scripts, and internal service helpers) must execute the following 6-step serialized transaction:

1. **Start Transaction**: `BEGIN` a PostgreSQL transaction.
2. **Acquire Serialization Locks**:
   - Acquire a 64-bit transaction-level PostgreSQL advisory lock:
     `SELECT pg_advisory_xact_lock(hashtextextended('dsh_super_admin_role_guard', 0));`
   - Lock all active `SUPER_ADMIN` rows in deterministic primary-key order:
     `SELECT id FROM users WHERE role = 'SUPER_ADMIN' AND status = 'ACTIVE' ORDER BY id ASC FOR UPDATE;`
3. **Recheck Active `SUPER_ADMIN` Count**:
   - Count the locked active `SUPER_ADMIN` rows returned after acquiring the serialization locks.
4. **Prevent Removal or Demotion of the Last Active `SUPER_ADMIN`**:
   - If the target user is currently an active `SUPER_ADMIN` and `activeSuperAdminCount <= 1`, `ROLLBACK` the transaction, log `auth.super_admin.last_admin_blocked` in `audit_logs`, and return `409 Conflict` (`LAST_SUPER_ADMIN_PROTECTED`).
5. **Perform the Change Atomically**:
   - Update the target user's `role` or `status` (`UPDATE users ...`) and immediately revoke all active sessions for the target user (`UPDATE sessions SET revoked_at = now() WHERE user_id = $target AND revoked_at IS NULL`).
6. **Record Audit Event & Commit**:
   - Insert an immutable audit event (`users.privileged_role.changed` or `users.privileged_status.changed`) into `audit_logs` and `COMMIT`.
