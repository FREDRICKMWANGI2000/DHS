import { relations } from "drizzle-orm";
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

export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  passwordResetTokens: many(passwordResetTokens),
  verificationTokens: many(verificationTokens),
  auditLogs: many(auditLogs),
  wifiSessions: many(wifiSessions),
  customerDevices: many(customerDevices),
  serviceOrders: many(serviceOrders),
  staffAssignmentsReceived: many(staffAssignments, {
    relationName: "staffUserAssignments",
  }),
  staffAssignmentsCreated: many(staffAssignments, {
    relationName: "assignedByUserAssignments",
  }),
  orderStatusChanges: many(serviceOrderStatusHistory),
  uploadedFiles: many(serviceOrderFiles),
  sentMessages: many(serviceOrderMessages),
  updatedSettings: many(businessSettings),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));

export const passwordResetTokensRelations = relations(
  passwordResetTokens,
  ({ one }) => ({
    user: one(users, {
      fields: [passwordResetTokens.userId],
      references: [users.id],
    }),
  })
);

export const verificationTokensRelations = relations(
  verificationTokens,
  ({ one }) => ({
    user: one(users, {
      fields: [verificationTokens.userId],
      references: [users.id],
    }),
  })
);

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  actor: one(users, {
    fields: [auditLogs.actorUserId],
    references: [users.id],
  }),
}));

export const wifiPackagesRelations = relations(wifiPackages, ({ many }) => ({
  wifiSessions: many(wifiSessions),
}));

export const wifiSessionsRelations = relations(
  wifiSessions,
  ({ one }) => ({
    customer: one(users, {
      fields: [wifiSessions.customerId],
      references: [users.id],
    }),
    package: one(wifiPackages, {
      fields: [wifiSessions.packageId],
      references: [wifiPackages.id],
    }),
    payment: one(payments, {
      fields: [wifiSessions.id],
      references: [payments.wifiSessionId],
    }),
  })
);

export const customerDevicesRelations = relations(
  customerDevices,
  ({ one }) => ({
    customer: one(users, {
      fields: [customerDevices.customerId],
      references: [users.id],
    }),
  })
);

export const serviceCatalogRelations = relations(
  serviceCatalog,
  ({ many }) => ({
    orders: many(serviceOrders),
  })
);

export const serviceOrdersRelations = relations(
  serviceOrders,
  ({ one, many }) => ({
    customer: one(users, {
      fields: [serviceOrders.customerId],
      references: [users.id],
    }),
    service: one(serviceCatalog, {
      fields: [serviceOrders.serviceId],
      references: [serviceCatalog.id],
    }),
    payment: one(payments, {
      fields: [serviceOrders.id],
      references: [payments.serviceOrderId],
    }),
    staffAssignments: many(staffAssignments),
    statusHistory: many(serviceOrderStatusHistory),
    files: many(serviceOrderFiles),
    messages: many(serviceOrderMessages),
  })
);

export const staffAssignmentsRelations = relations(
  staffAssignments,
  ({ one }) => ({
    order: one(serviceOrders, {
      fields: [staffAssignments.orderId],
      references: [serviceOrders.id],
    }),
    staffUser: one(users, {
      fields: [staffAssignments.staffUserId],
      references: [users.id],
      relationName: "staffUserAssignments",
    }),
    assignedByUser: one(users, {
      fields: [staffAssignments.assignedBy],
      references: [users.id],
      relationName: "assignedByUserAssignments",
    }),
  })
);

export const serviceOrderStatusHistoryRelations = relations(
  serviceOrderStatusHistory,
  ({ one }) => ({
    order: one(serviceOrders, {
      fields: [serviceOrderStatusHistory.orderId],
      references: [serviceOrders.id],
    }),
    changedByUser: one(users, {
      fields: [serviceOrderStatusHistory.changedBy],
      references: [users.id],
    }),
  })
);

export const paymentsRelations = relations(payments, ({ one, many }) => ({
  wifiSession: one(wifiSessions, {
    fields: [payments.wifiSessionId],
    references: [wifiSessions.id],
  }),
  serviceOrder: one(serviceOrders, {
    fields: [payments.serviceOrderId],
    references: [serviceOrders.id],
  }),
  attempts: many(paymentAttempts),
}));

export const paymentAttemptsRelations = relations(
  paymentAttempts,
  ({ one, many }) => ({
    payment: one(payments, {
      fields: [paymentAttempts.paymentId],
      references: [payments.id],
    }),
    callbackEvents: many(paymentCallbackEvents),
  })
);

export const paymentCallbackEventsRelations = relations(
  paymentCallbackEvents,
  ({ one }) => ({
    paymentAttempt: one(paymentAttempts, {
      fields: [paymentCallbackEvents.paymentAttemptId],
      references: [paymentAttempts.id],
    }),
  })
);

export const serviceOrderFilesRelations = relations(
  serviceOrderFiles,
  ({ one }) => ({
    order: one(serviceOrders, {
      fields: [serviceOrderFiles.orderId],
      references: [serviceOrders.id],
    }),
    uploadedByUser: one(users, {
      fields: [serviceOrderFiles.uploadedBy],
      references: [users.id],
    }),
  })
);

export const serviceOrderMessagesRelations = relations(
  serviceOrderMessages,
  ({ one }) => ({
    order: one(serviceOrders, {
      fields: [serviceOrderMessages.orderId],
      references: [serviceOrders.id],
    }),
    sender: one(users, {
      fields: [serviceOrderMessages.senderUserId],
      references: [users.id],
    }),
  })
);

export const businessSettingsRelations = relations(
  businessSettings,
  ({ one }) => ({
    updatedByUser: one(users, {
      fields: [businessSettings.updatedBy],
      references: [users.id],
    }),
  })
);
