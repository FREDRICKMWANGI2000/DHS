import { normalizePhoneNumber } from "../../db/normalize";
import { SmsDeliveryProvider, SmsDeliveryResult } from "./sms.types";

/**
 * Default non-operational SMS provider adapter used until a live SMS gateway is selected and integrated.
 * - Never invents credentials or fakes successful SMS delivery.
 * - Never logs raw OTP codes.
 * - Always returns `{ delivered: false, errorCode: "SMS_VERIFICATION_UNAVAILABLE" }`.
 */
export class UnconfiguredSmsDeliveryProvider implements SmsDeliveryProvider {
  public readonly providerName = "unconfigured-sms";

  public isConfigured(): boolean {
    return false;
  }

  public async sendVerificationOtp(
    phoneNumber: string,
    _code: string
  ): Promise<SmsDeliveryResult> {
    try {
      normalizePhoneNumber(phoneNumber);
    } catch {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "SMS_INVALID_PHONE_NUMBER",
        errorReason: "Phone number must be a valid Kenyan or E.164 phone number.",
      };
    }

    return {
      delivered: false,
      provider: this.providerName,
      errorCode: "SMS_VERIFICATION_UNAVAILABLE",
      errorReason:
        "No live SMS delivery provider is configured. Real phone OTP verification requires an SMS provider integration.",
    };
  }
}

export const defaultSmsDeliveryProvider: SmsDeliveryProvider =
  new UnconfiguredSmsDeliveryProvider();
