import { pgEnum } from "drizzle-orm/pg-core";

export const userRoleEnum = pgEnum("user_role", [
  "CUSTOMER",
  "STAFF",
  "ADMIN",
  "SUPER_ADMIN",
]);

export const accountStatusEnum = pgEnum("account_status", [
  "ACTIVE",
  "DISABLED",
]);

export const verificationTypeEnum = pgEnum("verification_type", [
  "EMAIL",
  "PHONE",
]);

export const wifiSessionStatusEnum = pgEnum("wifi_session_status", [
  "PENDING_PAYMENT",
  "PENDING_AUTHORIZATION",
  "ACTIVE",
  "EXPIRED",
  "REVOKED",
  "FAILED",
]);

export const paymentStatusEnum = pgEnum("payment_status", [
  "PENDING",
  "SUCCESS",
  "FAILED",
  "CANCELLED",
  "REVERSED",
]);

export const paymentProviderEnum = pgEnum("payment_provider", ["MPESA"]);

export const servicePricingUnitEnum = pgEnum("service_pricing_unit", [
  "FIXED",
  "PER_PAGE",
  "PER_HOUR",
  "PER_SESSION",
  "PER_SET",
]);

export const serviceOrderStatusEnum = pgEnum("service_order_status", [
  "DRAFT",
  "PAYMENT_PENDING",
  "PAID",
  "QUEUED",
  "IN_PROGRESS",
  "WAITING_FOR_CUSTOMER",
  "READY",
  "COMPLETED",
  "CANCELLED",
  "REFUNDED",
]);

export const messageVisibilityEnum = pgEnum("message_visibility", [
  "CUSTOMER",
  "INTERNAL",
]);
