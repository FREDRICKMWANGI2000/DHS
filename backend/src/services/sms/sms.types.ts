export type SmsDeliveryErrorCode =
  | "SMS_VERIFICATION_UNAVAILABLE"
  | "SMS_INVALID_PHONE_NUMBER"
  | "SMS_PROVIDER_REJECTED"
  | "SMS_PROVIDER_NETWORK_ERROR";

export interface SmsDeliveryResult {
  delivered: boolean;
  provider: string;
  providerMessageId?: string | null;
  errorCode?: SmsDeliveryErrorCode;
  errorReason?: string;
}

/**
 * Provider-independent SMS delivery abstraction for DSH phone OTP verification.
 * Note: No live SMS provider has been selected yet. Until a real SMS gateway is integrated
 * and tested, the default runtime adapter reports `isConfigured() === false` and returns
 * `SMS_VERIFICATION_UNAVAILABLE`.
 */
export interface SmsDeliveryProvider {
  readonly providerName: string;
  isConfigured(): boolean;
  sendVerificationOtp(
    phoneNumber: string,
    code: string
  ): Promise<SmsDeliveryResult>;
}
