import {
  pgTable,
  uuid,
  varchar,
  jsonb,
  timestamp,
  index,
} from "drizzle-orm/pg-core";
import { users } from "./users";

/**
 * Immutable operational and security audit log table.
 *
 * APPEND-ONLY IMMUTABILITY RULES:
 * 1. Application Level: Only INSERT and SELECT operations are permitted. No UPDATE or DELETE
 *    helpers are exposed by the repository/service layer.
 * 2. Database Migration Level: Protected by a PostgreSQL BEFORE UPDATE OR DELETE trigger
 *    (prevent_append_only_mutation) that raises an exception on any mutation attempt.
 * 3. Secret Prohibition: Never store passwords, raw session/reset tokens, or API keys in metadata.
 */
export const auditLogs = pgTable(
  "audit_logs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    actorUserId: uuid("actor_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    action: varchar("action", { length: 120 }).notNull(),
    entityType: varchar("entity_type", { length: 80 }).notNull(),
    entityId: varchar("entity_id", { length: 128 }),
    metadata: jsonb("metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    ipAddress: varchar("ip_address", { length: 64 }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("audit_logs_actor_user_id_idx").on(table.actorUserId),
    index("audit_logs_entity_idx").on(table.entityType, table.entityId),
    index("audit_logs_created_at_idx").on(table.createdAt),
  ]
);
