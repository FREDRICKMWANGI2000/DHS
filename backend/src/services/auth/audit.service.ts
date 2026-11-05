import { NodePgDatabase } from "drizzle-orm/node-postgres";
import { db } from "../../db/client";
import * as schema from "../../db/schema";
import { auditLogs, AuditLog } from "../../db/schema";

export type DbExecutor = NodePgDatabase<typeof schema>;

/**
 * Keys that must NEVER be persisted in audit_logs.metadata under any circumstances.
 */
const FORBIDDEN_METADATA_KEY_REGEX =
  /^(password|new_?password|current_?password|old_?password|password_?hash|token|raw_?token|session_?token|token_?hash|csrf_?token|reset_?token|verification_?token|otp|raw_?otp|code|secret|session_?secret|api_?key|consumer_?key|consumer_?secret|passkey|authorization|cookie|set_?cookie)$/i;

const SENSITIVE_VALUE_PATTERNS = [
  /^\$argon2(id|i|d)\$/i,
  /^Bearer\s+/i,
  /^postgresql:\/\//i,
];

function isSensitiveValue(val: unknown): boolean {
  if (typeof val !== "string") {
    return false;
  }
  return SENSITIVE_VALUE_PATTERNS.some((pattern) => pattern.test(val.trim()));
}

/**
 * Deeply sanitizes an audit metadata object by removing any forbidden secret/credential keys
 * and stripping values that match password hash or connection string patterns.
 */
export function sanitizeAuditMetadata(
  metadata: Record<string, unknown> | undefined
): Record<string, unknown> {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return {};
  }

  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    if (FORBIDDEN_METADATA_KEY_REGEX.test(key)) {
      continue;
    }

    if (isSensitiveValue(value)) {
      continue;
    }

    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      if (value instanceof Date) {
        sanitized[key] = value.toISOString();
      } else {
        sanitized[key] = sanitizeAuditMetadata(
          value as Record<string, unknown>
        );
      }
    } else if (Array.isArray(value)) {
      sanitized[key] = value
        .filter((item) => !isSensitiveValue(item))
        .map((item) =>
          item !== null && typeof item === "object" && !Array.isArray(item)
            ? sanitizeAuditMetadata(item as Record<string, unknown>)
            : item
        );
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

export interface RecordSecurityAuditParams {
  actorUserId?: string | null;
  action: string;
  entityType: string;
  entityId?: string | null;
  metadata?: Record<string, unknown>;
  ipAddress?: string | null;
}

/**
 * Appends an immutable security or operational audit event to PostgreSQL `audit_logs`.
 * Respects the append-only database trigger (`audit_logs_prevent_mutation_trg`) and strips all secrets.
 */
export async function recordSecurityAudit(
  params: RecordSecurityAuditParams,
  executor: DbExecutor = db
): Promise<AuditLog> {
  const safeMetadata = sanitizeAuditMetadata(params.metadata);
  const [inserted] = await executor
    .insert(auditLogs)
    .values({
      actorUserId: params.actorUserId ?? null,
      action: params.action,
      entityType: params.entityType,
      entityId: params.entityId ?? null,
      metadata: safeMetadata,
      ipAddress: params.ipAddress ?? null,
    })
    .returning();

  return inserted;
}
