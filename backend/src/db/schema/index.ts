export * from "./enums";
export * from "./users";
export * from "./sessions";
export * from "./audit";
export * from "./wifi";
export * from "./services";
export * from "./orders";
export * from "./payments";
export * from "./files";
export * from "./messages";
export * from "./settings";
export * from "./relations";

import { users } from "./users";
import {
  sessions,
  passwordResetTokens,
  verificationTokens,
} from "./sessions";
import { auditLogs } from "./audit";
import { wifiPackages, wifiSessions, customerDevices } from "./wifi";
import { serviceCatalog } from "./services";
import {
  serviceOrders,
  staffAssignments,
  serviceOrderStatusHistory,
} from "./orders";
import {
  payments,
  paymentAttempts,
  paymentCallbackEvents,
} from "./payments";
import { serviceOrderFiles } from "./files";
import { serviceOrderMessages } from "./messages";
import { businessSettings } from "./settings";

// Inferred Select & Insert Entity Types (Backend-Only)
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type NewPasswordResetToken = typeof passwordResetTokens.$inferInsert;

export type VerificationToken = typeof verificationTokens.$inferSelect;
export type NewVerificationToken = typeof verificationTokens.$inferInsert;

export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;

export type WifiPackage = typeof wifiPackages.$inferSelect;
export type NewWifiPackage = typeof wifiPackages.$inferInsert;

export type WifiSession = typeof wifiSessions.$inferSelect;
export type NewWifiSession = typeof wifiSessions.$inferInsert;

export type CustomerDevice = typeof customerDevices.$inferSelect;
export type NewCustomerDevice = typeof customerDevices.$inferInsert;

export type ServiceCatalogItem = typeof serviceCatalog.$inferSelect;
export type NewServiceCatalogItem = typeof serviceCatalog.$inferInsert;

export type ServiceOrder = typeof serviceOrders.$inferSelect;
export type NewServiceOrder = typeof serviceOrders.$inferInsert;

export type StaffAssignment = typeof staffAssignments.$inferSelect;
export type NewStaffAssignment = typeof staffAssignments.$inferInsert;

export type ServiceOrderStatusHistoryItem =
  typeof serviceOrderStatusHistory.$inferSelect;
export type NewServiceOrderStatusHistoryItem =
  typeof serviceOrderStatusHistory.$inferInsert;

export type Payment = typeof payments.$inferSelect;
export type NewPayment = typeof payments.$inferInsert;

export type PaymentAttempt = typeof paymentAttempts.$inferSelect;
export type NewPaymentAttempt = typeof paymentAttempts.$inferInsert;

export type PaymentCallbackEvent = typeof paymentCallbackEvents.$inferSelect;
export type NewPaymentCallbackEvent = typeof paymentCallbackEvents.$inferInsert;

export type ServiceOrderFile = typeof serviceOrderFiles.$inferSelect;
export type NewServiceOrderFile = typeof serviceOrderFiles.$inferInsert;

export type ServiceOrderMessage = typeof serviceOrderMessages.$inferSelect;
export type NewServiceOrderMessage = typeof serviceOrderMessages.$inferInsert;

export type BusinessSetting = typeof businessSettings.$inferSelect;
export type NewBusinessSetting = typeof businessSettings.$inferInsert;
