import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  text,
  integer,
  numeric,
  jsonb,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { users } from "./users";
import { serviceCatalog } from "./services";
import { servicePricingUnitEnum, serviceOrderStatusEnum } from "./enums";

export const serviceOrders = pgTable(
  "service_orders",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderNumber: varchar("order_number", { length: 40 }).notNull(),
    customerId: uuid("customer_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    serviceId: uuid("service_id")
      .notNull()
      .references(() => serviceCatalog.id, { onDelete: "restrict" }),
    serviceNameSnapshot: varchar("service_name_snapshot", {
      length: 150,
    }).notNull(),
    quantity: integer("quantity").notNull().default(1),
    unitPriceSnapshot: numeric("unit_price_snapshot", {
      precision: 10,
      scale: 2,
    }).notNull(),
    totalAmount: numeric("total_amount", {
      precision: 10,
      scale: 2,
    }).notNull(),
    currency: varchar("currency", { length: 3 }).notNull().default("KES"),
    pricingUnitSnapshot: servicePricingUnitEnum(
      "pricing_unit_snapshot"
    ).notNull(),
    status: serviceOrderStatusEnum("status").notNull().default("DRAFT"),
    customerRequirements: text("customer_requirements"),
    formData: jsonb("form_data")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("service_orders_order_number_unique").on(table.orderNumber),
    index("service_orders_customer_id_idx").on(table.customerId),
    index("service_orders_service_id_idx").on(table.serviceId),
    index("service_orders_status_created_idx").on(
      table.status,
      table.createdAt
    ),
    check("service_orders_quantity_positive_chk", sql`${table.quantity} >= 1`),
    check(
      "service_orders_unit_price_positive_chk",
      sql`${table.unitPriceSnapshot} > 0`
    ),
    check(
      "service_orders_total_amount_chk",
      sql`${table.totalAmount} = ${table.unitPriceSnapshot} * ${table.quantity}`
    ),
  ]
);

export const staffAssignments = pgTable(
  "staff_assignments",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => serviceOrders.id, { onDelete: "cascade" }),
    staffUserId: uuid("staff_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    assignedBy: uuid("assigned_by")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    assignedAt: timestamp("assigned_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    unassignedAt: timestamp("unassigned_at", { withTimezone: true }),
    notes: text("notes"),
  },
  (table) => [
    index("staff_assignments_order_id_idx").on(table.orderId),
    index("staff_assignments_staff_active_idx").on(
      table.staffUserId,
      table.unassignedAt
    ),
    check(
      "staff_assignments_unassigned_after_assigned_chk",
      sql`${table.unassignedAt} IS NULL OR ${table.unassignedAt} >= ${table.assignedAt}`
    ),
  ]
);

export const serviceOrderStatusHistory = pgTable(
  "service_order_status_history",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => serviceOrders.id, { onDelete: "restrict" }),
    previousStatus: serviceOrderStatusEnum("previous_status"),
    newStatus: serviceOrderStatusEnum("new_status").notNull(),
    changedBy: uuid("changed_by").references(() => users.id, {
      onDelete: "set null",
    }),
    note: text("note"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("service_order_status_history_order_created_idx").on(
      table.orderId,
      table.createdAt
    ),
  ]
);
