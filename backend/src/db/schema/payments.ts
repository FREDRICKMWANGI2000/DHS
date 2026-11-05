import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  text,
  numeric,
  integer,
  jsonb,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { wifiSessions } from "./wifi";
import { serviceOrders } from "./orders";
import { paymentProviderEnum, paymentStatusEnum } from "./enums";

export const payments = pgTable(
  "payments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    reference: varchar("reference", { length: 64 }).notNull(),
    wifiSessionId: uuid("wifi_session_id").references(() => wifiSessions.id, {
      onDelete: "restrict",
    }),
    serviceOrderId: uuid("service_order_id").references(
      () => serviceOrders.id,
      { onDelete: "restrict" }
    ),
    provider: paymentProviderEnum("provider").notNull().default("MPESA"),
    amount: numeric("amount", { precision: 10, scale: 2 }).notNull(),
    currency: varchar("currency", { length: 3 }).notNull().default("KES"),
    status: paymentStatusEnum("status").notNull().default("PENDING"),
    paidAt: timestamp("paid_at", { withTimezone: true }),
    reversedAt: timestamp("reversed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    uniqueIndex("payments_reference_unique").on(table.reference),
    uniqueIndex("payments_wifi_session_id_unique").on(table.wifiSessionId),
    uniqueIndex("payments_service_order_id_unique").on(table.serviceOrderId),
    index("payments_status_created_idx").on(table.status, table.createdAt),
    check(
      "payments_target_xor_chk",
      sql`(${table.wifiSessionId} IS NOT NULL AND ${table.serviceOrderId} IS NULL) OR (${table.wifiSessionId} IS NULL AND ${table.serviceOrderId} IS NOT NULL)`
    ),
    check("payments_amount_positive_chk", sql`${table.amount} > 0`),
    check(
      "payments_currency_len_chk",
      sql`char_length(${table.currency}) = 3`
    ),
  ]
);

export const paymentAttempts = pgTable(
  "payment_attempts",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    paymentId: uuid("payment_id")
      .notNull()
      .references(() => payments.id, { onDelete: "restrict" }),
    attemptNumber: integer("attempt_number").notNull(),
    merchantRequestId: varchar("merchant_request_id", { length: 128 }),
    checkoutRequestId: varchar("checkout_request_id", { length: 128 }),
    mpesaReceiptNumber: varchar("mpesa_receipt_number", { length: 64 }),
    resultCode: varchar("result_code", { length: 32 }),
    resultDescription: text("result_description"),
    status: paymentStatusEnum("status").notNull().default("PENDING"),
    initiatedAt: timestamp("initiated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    uniqueIndex("payment_attempts_payment_attempt_num_unique").on(
      table.paymentId,
      table.attemptNumber
    ),
    uniqueIndex("payment_attempts_merchant_request_id_unique").on(
      table.merchantRequestId
    ),
    uniqueIndex("payment_attempts_checkout_request_id_unique").on(
      table.checkoutRequestId
    ),
    uniqueIndex("payment_attempts_mpesa_receipt_unique").on(
      table.mpesaReceiptNumber
    ),
    index("payment_attempts_payment_id_idx").on(table.paymentId),
    check(
      "payment_attempts_attempt_num_positive_chk",
      sql`${table.attemptNumber} >= 1`
    ),
  ]
);

export const paymentCallbackEvents = pgTable(
  "payment_callback_events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    paymentAttemptId: uuid("payment_attempt_id")
      .notNull()
      .references(() => paymentAttempts.id, { onDelete: "restrict" }),
    idempotencyKey: varchar("idempotency_key", { length: 160 }).notNull(),
    providerEventId: varchar("provider_event_id", { length: 128 }),
    outcome: varchar("outcome", { length: 64 }).notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    processedAt: timestamp("processed_at", { withTimezone: true }),
    safeMetadata: jsonb("safe_metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
  },
  (table) => [
    uniqueIndex("payment_callback_events_idempotency_key_unique").on(
      table.idempotencyKey
    ),
    uniqueIndex("payment_callback_events_provider_event_id_unique").on(
      table.providerEventId
    ),
    index("payment_callback_events_attempt_id_idx").on(table.paymentAttemptId),
  ]
);
