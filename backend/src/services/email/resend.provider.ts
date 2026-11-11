import { env, validateResendConfig } from "../../config/env";
import {
  renderPasswordResetEmailTemplate,
  renderVerificationEmailTemplate,
} from "./email.templates";
import {
  EmailDeliveryProvider,
  EmailDeliveryResult,
  SendPasswordResetEmailParams,
  SendVerificationEmailParams,
} from "./email.types";

const RESEND_EMAILS_ENDPOINT = "https://api.resend.com/emails";
const DEFAULT_RESEND_TIMEOUT_MS = 10_000;

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit
) => Promise<Response>;

export interface ResendProviderOptions {
  apiKey?: string;
  emailFrom?: string;
  nodeEnv?: string;
  apiUrl?: string;
  timeoutMs?: number;
  fetchFn?: FetchLike;
}

interface ResendSendPayload {
  toEmail: string;
  subject: string;
  html: string;
  text: string;
}

/**
 * Resend HTTPS email delivery adapter implementing `EmailDeliveryProvider`.
 * - Reads `RESEND_API_KEY` and `EMAIL_FROM` from environment or explicit options.
 * - Treats missing or `.env.example` placeholder credentials as unconfigured (`isConfigured() === false`)
 *   and never pretends messages were delivered or prints raw tokens to logs.
 * - Never includes `RESEND_API_KEY` or raw verification/reset tokens in error messages or logs.
 */
export class ResendEmailDeliveryProvider implements EmailDeliveryProvider {
  public readonly providerName = "resend";

  private readonly rawApiKey: string | undefined;
  private readonly rawEmailFrom: string | undefined;
  private readonly nodeEnv: string;
  private readonly apiUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchFn: FetchLike;

  constructor(options: ResendProviderOptions = {}) {
    this.rawApiKey =
      options.apiKey !== undefined ? options.apiKey : process.env.RESEND_API_KEY;
    this.rawEmailFrom =
      options.emailFrom !== undefined
        ? options.emailFrom
        : process.env.EMAIL_FROM;
    this.nodeEnv = options.nodeEnv ?? env.nodeEnv;
    this.apiUrl = options.apiUrl ?? RESEND_EMAILS_ENDPOINT;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_RESEND_TIMEOUT_MS;
    this.fetchFn = options.fetchFn ?? fetch;
  }

  public isConfigured(): boolean {
    try {
      validateResendConfig(this.rawApiKey, this.rawEmailFrom, this.nodeEnv);
      return true;
    } catch {
      return false;
    }
  }

  public async sendVerificationEmail(
    params: SendVerificationEmailParams
  ): Promise<EmailDeliveryResult> {
    const rendered = renderVerificationEmailTemplate(params);
    return this.dispatchEmail({
      toEmail: params.toEmail,
      subject: rendered.subject,
      html: rendered.html,
      text: rendered.text,
    });
  }

  public async sendPasswordResetEmail(
    params: SendPasswordResetEmailParams
  ): Promise<EmailDeliveryResult> {
    const rendered = renderPasswordResetEmailTemplate(params);
    return this.dispatchEmail({
      toEmail: params.toEmail,
      subject: rendered.subject,
      html: rendered.html,
      text: rendered.text,
    });
  }

  private async dispatchEmail(
    payload: ResendSendPayload
  ): Promise<EmailDeliveryResult> {
    let validatedConfig: { apiKey: string; emailFrom: string };
    try {
      validatedConfig = validateResendConfig(
        this.rawApiKey,
        this.rawEmailFrom,
        this.nodeEnv
      );
    } catch (err: unknown) {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "EMAIL_PROVIDER_NOT_CONFIGURED",
        errorReason:
          err instanceof Error
            ? err.message
            : "Resend email provider is not configured.",
      };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchFn(this.apiUrl, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${validatedConfig.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          from: validatedConfig.emailFrom,
          to: [payload.toEmail],
          subject: payload.subject,
          html: payload.html,
          text: payload.text,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        return {
          delivered: false,
          provider: this.providerName,
          errorCode: "EMAIL_PROVIDER_REJECTED",
          errorReason: `Resend API rejected delivery with HTTP ${response.status}.`,
        };
      }

      let messageId: string | null = null;
      try {
        const body = (await response.json()) as { id?: unknown };
        if (typeof body?.id === "string" && body.id.trim().length > 0) {
          messageId = body.id.trim();
        }
      } catch {
        // Ignore non-JSON body on 2xx
      }

      return {
        delivered: true,
        provider: this.providerName,
        providerMessageId: messageId,
      };
    } catch {
      return {
        delivered: false,
        provider: this.providerName,
        errorCode: "EMAIL_PROVIDER_NETWORK_ERROR",
        errorReason: "Network or timeout error while communicating with Resend API.",
      };
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

export function createConfiguredEmailDeliveryProvider(
  options?: ResendProviderOptions
): EmailDeliveryProvider {
  return new ResendEmailDeliveryProvider(options);
}

export const defaultEmailDeliveryProvider: EmailDeliveryProvider =
  createConfiguredEmailDeliveryProvider();
