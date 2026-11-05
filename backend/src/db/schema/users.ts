import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  text,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { userRoleEnum, accountStatusEnum } from "./enums";

export const users = pgTable(
  "users",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    firstName: varchar("first_name", { length: 100 }).notNull(),
    lastName: varchar("last_name", { length: 100 }).notNull(),
    email: varchar("email", { length: 255 }),
    phoneNumber: varchar("phone_number", { length: 32 }),
    passwordHash: text("password_hash").notNull(),
    role: userRoleEnum("role").notNull().default("CUSTOMER"),
    status: accountStatusEnum("status").notNull().default("ACTIVE"),
    emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),
    phoneVerifiedAt: timestamp("phone_verified_at", { withTimezone: true }),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    uniqueIndex("users_email_unique").on(table.email),
    uniqueIndex("users_phone_number_unique").on(table.phoneNumber),
    index("users_role_status_idx").on(table.role, table.status),
    check(
      "users_contact_required_chk",
      sql`${table.email} IS NOT NULL OR ${table.phoneNumber} IS NOT NULL`
    ),
    check(
      "users_email_normalized_chk",
      sql`${table.email} IS NULL OR (${table.email} = lower(trim(${table.email})) AND char_length(${table.email}) >= 3)`
    ),
    check(
      "users_phone_normalized_chk",
      sql`${table.phoneNumber} IS NULL OR (${table.phoneNumber} = trim(${table.phoneNumber}) AND ${table.phoneNumber} ~ '^\\+[1-9][0-9]{7,14}$')`
    ),
  ]
);
