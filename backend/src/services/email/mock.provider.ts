import {
  renderPasswordResetEmailTemplate,
  renderVerificationEmailTemplate,
  RenderedEmailMessage,
} from "./email.templates";
import {
  EmailDeliveryErrorCode,
  EmailDeliveryProvider,
  EmailDeliveryResult,
  SendPasswordResetEmailParams,
  SendVerificationEmailParams,
} from "./email.types";

export interface RecordedVerificationEmail extends SendVerificationEmailParams {
  rendered: RenderedEmailMessage;
  sentAtMs: number;
  messageId: string;
}

export interface RecordedPasswordResetEmail
  extends SendPasswordResetEmailParams {
  rendered: RenderedEmailMessage;
  sentAtMs: number;
  messageId: string;
}

/**
 * In-memory mock email delivery provider exclusively for automated security tests.
 * Never sends real network requests and never logs raw tokens to console.
 */
export class MockEmailDeliveryProvider implements EmailDeliveryProvider {
  public readonly providerName = "mock-email";

  public readonly sentVerificationEmails: RecordedVerificationEmail[] = [];
  public readonly sentPasswordResetEmails: RecordedPasswordResetEmail[] = [];

  private configured: boolean;
  private simulateFailureCode: EmailDeliveryErrorCode | null = null;
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

  public setSimulateFailure(code: EmailDeliveryErrorCode | null): void {
    this.simulateFailureCode = code;
  }

  public clear(): void {
    this.sentVerificationEmails.length = 0;
    this.sentPasswordResetEmails.length = 0;
    this.simulateFailureCode = null;
  }

  public async sendVerificationEmail(
    params: SendVerificationEmailParams
  ): Promise<EmailDeliveryResult> {
    if (!this.configured) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "EMAIL_PROVIDER_NOT_CONFIGURED",
        errorReason: "Mock email provider is marked unconfigured.",
      };
    }

    if (this.simulateFailureCode) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: this.simulateFailureCode,
        errorReason: `Simulated email delivery failure (${this.simulateFailureCode}).`,
      };
    }

    this.messageCounter += 1;
    const messageId = `mock_verify_${this.messageCounter}`;
    const rendered = renderVerificationEmailTemplate(params);

    this.sentVerificationEmails.push({
      ...params,
      rendered,
      sentAtMs: Date.now(),
      messageId,
    });

    return {
      delivered: true,
      provider: this.providerName,
      providerMessageId: messageId,
    };
  }

  public async sendPasswordResetEmail(
    params: SendPasswordResetEmailParams
  ): Promise<EmailDeliveryResult> {
    if (!this.configured) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "EMAIL_PROVIDER_NOT_CONFIGURED",
        errorReason: "Mock email provider is marked unconfigured.",
      };
    }

    if (this.simulateFailureCode) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: this.simulateFailureCode,
        errorReason: `Simulated email delivery failure (${this.simulateFailureCode}).`,
      };
    }

    this.messageCounter += 1;
    const messageId = `mock_reset_${this.messageCounter}`;
    const rendered = renderPasswordResetEmailTemplate(params);

    this.sentPasswordResetEmails.push({
      ...params,
      rendered,
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

/**
 * Helper to extract the `#token=...` value from a fragment verification/reset URL inside automated tests.
 */
export function extractTokenFromFragmentUrl(url: string): string | null {
  const hashIndex = url.indexOf("#");
  if (hashIndex === -1) {
    return null;
  }
  const fragment = url.slice(hashIndex + 1);
  const params = new URLSearchParams(fragment);
  return params.get("token");
}
