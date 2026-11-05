import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  text,
  timestamp,
  index,
  check,
} from "drizzle-orm/pg-core";
import { users } from "./users";
import { serviceOrders } from "./orders";
import { messageVisibilityEnum } from "./enums";

export const serviceOrderMessages = pgTable(
  "service_order_messages",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => serviceOrders.id, { onDelete: "cascade" }),
    senderUserId: uuid("sender_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    body: text("body").notNull(),
    visibility: messageVisibilityEnum("visibility")
      .notNull()
      .default("CUSTOMER"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    index("service_order_messages_order_visibility_idx").on(
      table.orderId,
      table.visibility,
      table.createdAt
    ),
    index("service_order_messages_sender_idx").on(table.senderUserId),
    check(
      "service_order_messages_body_nonempty_chk",
      sql`char_length(trim(${table.body})) > 0`
    ),
  ]
);
