import { sql } from "drizzle-orm";
import {
  pgTable,
  uuid,
  varchar,
  integer,
  boolean,
  timestamp,
  uniqueIndex,
  index,
  check,
} from "drizzle-orm/pg-core";
import { users } from "./users";
import { serviceOrders } from "./orders";

export const serviceOrderFiles = pgTable(
  "service_order_files",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    orderId: uuid("order_id")
      .notNull()
      .references(() => serviceOrders.id, { onDelete: "restrict" }),
    uploadedBy: uuid("uploaded_by")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    originalFilename: varchar("original_filename", { length: 255 }).notNull(),
    storageKey: varchar("storage_key", { length: 512 }).notNull(),
    mimeType: varchar("mime_type", { length: 128 }).notNull(),
    fileSize: integer("file_size").notNull(),
    checksum: varchar("checksum", { length: 128 }).notNull(),
    isDeliverable: boolean("is_deliverable").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => [
    uniqueIndex("service_order_files_storage_key_unique").on(table.storageKey),
    index("service_order_files_order_id_idx").on(table.orderId),
    index("service_order_files_uploaded_by_idx").on(table.uploadedBy),
    check("service_order_files_size_positive_chk", sql`${table.fileSize} > 0`),
  ]
);
