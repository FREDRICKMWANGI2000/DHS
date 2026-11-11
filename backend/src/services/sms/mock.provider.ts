import { normalizePhoneNumber } from "../../db/normalize";
import {
  SmsDeliveryErrorCode,
  SmsDeliveryProvider,
  SmsDeliveryResult,
} from "./sms.types";

export interface RecordedSmsOtpMessage {
  phoneNumber: string;
  code: string;
  sentAtMs: number;
  messageId: string;
}

/**
 * In-memory mock SMS delivery provider for automated testing only.
 * Normalizes phone numbers using `normalizePhoneNumber()` and never sends external messages
 * or writes raw OTPs to console logs.
 */
export class MockSmsDeliveryProvider implements SmsDeliveryProvider {
  public readonly providerName = "mock-sms";

  public readonly sentOtpMessages: RecordedSmsOtpMessage[] = [];

  private configured: boolean;
  private simulateFailureCode: SmsDeliveryErrorCode | null = null;
  private messageCounter = 0;

  constructor(options: { configured?: boolean } = {}) {
    this.configured = options.configured ?? true;
  }

  public isConfigured(): boolean {
    return this.configured;
  }

  public setConfigured(configured: boolean): void {
    this.configured = configured;
  }

  public setSimulateFailure(code: SmsDeliveryErrorCode | null): void {
    this.simulateFailureCode = code;
  }

  public clear(): void {
    this.sentOtpMessages.length = 0;
    this.simulateFailureCode = null;
  }

  public async sendVerificationOtp(
    phoneNumber: string,
    code: string
  ): Promise<SmsDeliveryResult> {
    let normalizedPhone: string;
    try {
      normalizedPhone = normalizePhoneNumber(phoneNumber);
    } catch {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "SMS_INVALID_PHONE_NUMBER",
        errorReason: "Invalid E.164 phone number format.",
      };
    }

    if (!this.configured) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "SMS_VERIFICATION_UNAVAILABLE",
        errorReason: "Mock SMS provider is marked unconfigured.",
      };
    }

    if (this.simulateFailureCode) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: this.simulateFailureCode,
        errorReason: `Simulated SMS delivery failure (${this.simulateFailureCode}).`,
      };
    }

    if (!/^[0-9]{6}$/.test(code)) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "SMS_PROVIDER_REJECTED",
        errorReason: "OTP code must be a 6-digit string.",
      };
    }

    this.messageCounter += 1;
    const messageId = `mock_sms_${this.messageCounter}`;

    this.sentOtpMessages.push({
      phoneNumber: normalizedPhone,
      code,
      sentAtMs: Date.now(),
      messageId,
    });

    return {
      delivered: true,
      provider: this.providerName,
      providerMessageId: messageId,
    };
  }
}
