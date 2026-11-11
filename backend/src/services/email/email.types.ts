export type EmailDeliveryErrorCode =
  | "EMAIL_PROVIDER_NOT_CONFIGURED"
  | "EMAIL_INVALID_CONFIGURATION"
  | "EMAIL_PROVIDER_REJECTED"
  | "EMAIL_PROVIDER_NETWORK_ERROR";

export interface EmailDeliveryResult {
  delivered: boolean;
  provider: string;
  providerMessageId?: string | null;
  errorCode?: EmailDeliveryErrorCode;
  errorReason?: string;
}

export interface SendVerificationEmailParams {
  toEmail: string;
  firstName: string;
  verificationUrl: string;
  expiresInHours: number;
}

export interface SendPasswordResetEmailParams {
  toEmail: string;
  firstName: string;
  resetUrl: string;
  expiresInMinutes: number;
}

/**
 * Provider-independent email delivery abstraction for DSH transactional security emails.
 * Implementations must never log raw verification/reset tokens, URLs containing tokens, or API keys.
 */
export interface EmailDeliveryProvider {
  readonly providerName: string;
  isConfigured(): boolean;
  sendVerificationEmail(
    params: SendVerificationEmailParams
  ): Promise<EmailDeliveryResult>;
  sendPasswordResetEmail(
    params: SendPasswordResetEmailParams
  ): Promise<EmailDeliveryResult>;
}
