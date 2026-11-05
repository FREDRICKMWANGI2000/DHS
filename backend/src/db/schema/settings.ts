import {
  pgTable,
  uuid,
  varchar,
  jsonb,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { users } from "./users";

export const businessSettings = pgTable(
  "business_settings",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    key: varchar("key", { length: 120 }).notNull(),
    value: jsonb("value").$type<unknown>().notNull(),
    description: text("description"),
    updatedBy: uuid("updated_by").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [uniqueIndex("business_settings_key_unique").on(table.key)]
);
