import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  text,
  numeric,
  boolean,
  integer,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { servicePricingUnitEnum } from "./enums";

export const serviceCatalog = pgTable(
  "service_catalog",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: varchar("name", { length: 150 }).notNull(),
    slug: varchar("slug", { length: 150 }).notNull(),
    description: text("description"),
    price: numeric("price", { precision: 10, scale: 2 }).notNull(),
    currency: varchar("currency", { length: 3 }).notNull().default("KES"),
    pricingUnit: servicePricingUnitEnum("pricing_unit")
      .notNull()
      .default("FIXED"),
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
    uniqueIndex("service_catalog_slug_unique").on(table.slug),
    index("service_catalog_active_order_idx").on(
      table.isActive,
      table.displayOrder
    ),
    check("service_catalog_price_positive_chk", sql`${table.price} > 0`),
    check(
      "service_catalog_currency_len_chk",
      sql`char_length(${table.currency}) = 3`
    ),
  ]
);
