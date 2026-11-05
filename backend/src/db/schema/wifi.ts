import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  text,
  numeric,
  integer,
  boolean,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { users } from "./users";
import { wifiSessionStatusEnum } from "./enums";

export const wifiPackages = pgTable(
  "wifi_packages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: varchar("name", { length: 100 }).notNull(),
    slug: varchar("slug", { length: 100 }).notNull(),
    description: text("description"),
    price: numeric("price", { precision: 10, scale: 2 }).notNull(),
    currency: varchar("currency", { length: 3 }).notNull().default("KES"),
    durationMinutes: integer("duration_minutes").notNull(),
    isActive: boolean("is_active").notNull().default(true),
    displayOrder: integer("display_order").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    uniqueIndex("wifi_packages_slug_unique").on(table.slug),
    index("wifi_packages_active_order_idx").on(
      table.isActive,
      table.displayOrder
    ),
    check("wifi_packages_price_positive_chk", sql`${table.price} > 0`),
    check(
      "wifi_packages_duration_positive_chk",
      sql`${table.durationMinutes} > 0`
    ),
    check(
      "wifi_packages_currency_len_chk",
      sql`char_length(${table.currency}) = 3`
    ),
  ]
);

export const wifiSessions = pgTable(
  "wifi_sessions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    customerId: uuid("customer_id").references(() => users.id, {
      onDelete: "set null",
    }),
    packageId: uuid("package_id")
      .notNull()
      .references(() => wifiPackages.id, { onDelete: "restrict" }),
    packageNameSnapshot: varchar("package_name_snapshot", {
      length: 100,
    }).notNull(),
    amountSnapshot: numeric("amount_snapshot", {
      precision: 10,
      scale: 2,
    }).notNull(),
    currency: varchar("currency", { length: 3 }).notNull().default("KES"),
    durationMinutesSnapshot: integer("duration_minutes_snapshot").notNull(),
    phoneNumber: varchar("phone_number", { length: 32 }).notNull(),
    clientMac: varchar("client_mac", { length: 32 }),
    clientIp: varchar("client_ip", { length: 64 }),
    status: wifiSessionStatusEnum("status")
      .notNull()
      .default("PENDING_PAYMENT"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    gatewayReference: varchar("gateway_reference", { length: 128 }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("wifi_sessions_customer_id_idx").on(table.customerId),
    index("wifi_sessions_package_id_idx").on(table.packageId),
    index("wifi_sessions_status_expires_idx").on(table.status, table.expiresAt),
    index("wifi_sessions_phone_number_idx").on(table.phoneNumber),
    index("wifi_sessions_client_mac_idx").on(table.clientMac),
    check(
      "wifi_sessions_amount_positive_chk",
      sql`${table.amountSnapshot} > 0`
    ),
    check(
      "wifi_sessions_duration_positive_chk",
      sql`${table.durationMinutesSnapshot} > 0`
    ),
    check(
      "wifi_sessions_expiry_after_start_chk",
      sql`${table.expiresAt} IS NULL OR ${table.startedAt} IS NULL OR ${table.expiresAt} > ${table.startedAt}`
    ),
    check(
      "wifi_sessions_phone_normalized_chk",
      sql`${table.phoneNumber} = trim(${table.phoneNumber}) AND ${table.phoneNumber} ~ '^\\+[1-9][0-9]{7,14}$'`
    ),
    check(
      "wifi_sessions_mac_normalized_chk",
      sql`${table.clientMac} IS NULL OR (${table.clientMac} = upper(trim(${table.clientMac})) AND ${table.clientMac} ~ '^([0-9A-F]{2}:){5}[0-9A-F]{2}$')`
    ),
  ]
);

export const customerDevices = pgTable(
  "customer_devices",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    customerId: uuid("customer_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    deviceName: varchar("device_name", { length: 100 }).notNull(),
    macAddress: varchar("mac_address", { length: 32 }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    isActive: boolean("is_active").notNull().default(true),
  },
  (table) => [
    uniqueIndex("customer_devices_customer_mac_unique").on(
      table.customerId,
      table.macAddress
    ),
    index("customer_devices_mac_idx").on(table.macAddress),
    check(
      "customer_devices_mac_normalized_chk",
      sql`${table.macAddress} = upper(trim(${table.macAddress})) AND ${table.macAddress} ~ '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'`
    ),
  ]
);
