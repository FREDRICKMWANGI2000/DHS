import { env } from "../../config/env";
import {
  SendPasswordResetEmailParams,
  SendVerificationEmailParams,
} from "./email.types";

export interface RenderedEmailMessage {
  subject: string;
  html: string;
  text: string;
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function normalizeFrontendBaseUrl(frontendUrl: string = env.frontendUrl): string {
  return frontendUrl.trim().replace(/\/+$/, "");
}

/**
 * Builds a frontend email verification URL carrying the raw token in the URL fragment (`#token=...`)
 * so browsers never transmit the secret token in HTTP `Referer` headers or server access logs.
 */
export function buildEmailVerificationUrl(
  rawToken: string,
  frontendUrl: string = env.frontendUrl
): string {
  const base = normalizeFrontendBaseUrl(frontendUrl);
  return `${base}/verify-email#token=${encodeURIComponent(rawToken)}`;
}

/**
 * Builds a frontend password reset URL carrying the raw token in the URL fragment (`#token=...`)
 * so browsers never transmit the secret token in HTTP `Referer` headers or server access logs.
 */
export function buildPasswordResetUrl(
  rawToken: string,
  frontendUrl: string = env.frontendUrl
): string {
  const base = normalizeFrontendBaseUrl(frontendUrl);
  return `${base}/reset-password#token=${encodeURIComponent(rawToken)}`;
}

/**
 * Renders the Digital Services Hub email verification message (HTML and plain text).
 * Never includes passwords or secrets other than the provided fragment verification URL.
 */
export function renderVerificationEmailTemplate(
  params: SendVerificationEmailParams
): RenderedEmailMessage {
  const safeName = escapeHtml(params.firstName.trim() || "Customer");
  const safeUrl = escapeHtml(params.verificationUrl);
  const hours = params.expiresInHours;

  const subject = "Verify your email address — Digital Services Hub";

  const text = [
    "Digital Services Hub",
    "====================",
    "",
    `Hello ${params.firstName.trim() || "Customer"},`,
    "",
    "Please verify your email address for your Digital Services Hub account by opening the secure link below:",
    "",
    params.verificationUrl,
    "",
    `This verification link will expire in ${hours} hours and can only be used once.`,
    "",
    "If you did not create a Digital Services Hub account or did not request this verification email, you can safely ignore this message.",
  ].join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(subject)}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 24px;">
  <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; background-color: #ffffff;">
    <p style="margin: 0 0 8px 0; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #0284c7;">
      Digital Services Hub
    </p>
    <h1 style="margin: 0 0 16px 0; font-size: 20px; color: #0f172a;">
      Verify your email address
    </h1>
    <p style="margin: 0 0 16px 0;">
      Hello ${safeName},
    </p>
    <p style="margin: 0 0 20px 0;">
      We received a request to verify the email address associated with your <strong>Digital Services Hub</strong> account. Click the button below to confirm your email address:
    </p>
    <p style="margin: 0 0 20px 0;">
      <a href="${safeUrl}" style="display: inline-block; background-color: #0284c7; color: #ffffff; text-decoration: none; font-weight: 600; padding: 12px 20px; border-radius: 6px;">
        Verify Email Address
      </a>
    </p>
    <p style="margin: 0 0 16px 0; font-size: 14px; color: #475569;">
      This verification link will expire in <strong>${hours} hours</strong> and can only be used once.
    </p>
    <p style="margin: 0; font-size: 13px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 16px;">
      If you did not request this email verification, please ignore this email. Your account will remain unchanged.
    </p>
  </div>
</body>
</html>`;

  return { subject, html, text };
}

/**
 * Renders the Digital Services Hub password reset email (HTML and plain text):
 * - Identifies Digital Services Hub.
 * - Clearly explains the password-reset request.
 * - Includes the secure fragment reset link.
 * - Explains token expiry (e.g. 30 minutes).
 * - Advises ignoring the email when the request was not made by the recipient.
 * - Never includes old or new passwords.
 */
export function renderPasswordResetEmailTemplate(
  params: SendPasswordResetEmailParams
): RenderedEmailMessage {
  const safeName = escapeHtml(params.firstName.trim() || "Customer");
  const safeUrl = escapeHtml(params.resetUrl);
  const minutes = params.expiresInMinutes;

  const subject = "Password reset request — Digital Services Hub";

  const text = [
    "Digital Services Hub",
    "====================",
    "",
    `Hello ${params.firstName.trim() || "Customer"},`,
    "",
    "We received a request to reset the password for your Digital Services Hub account.",
    "Use the secure link below to choose a new password:",
    "",
    params.resetUrl,
    "",
    `This password reset link will expire in ${minutes} minutes and can only be used once.`,
    "",
    "If you did not request a password reset, please ignore this email. Your current password and account remain secure.",
  ].join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${escapeHtml(subject)}</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 24px;">
  <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; background-color: #ffffff;">
    <p style="margin: 0 0 8px 0; font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: #0284c7;">
      Digital Services Hub
    </p>
    <h1 style="margin: 0 0 16px 0; font-size: 20px; color: #0f172a;">
      Reset your password
    </h1>
    <p style="margin: 0 0 16px 0;">
      Hello ${safeName},
    </p>
    <p style="margin: 0 0 20px 0;">
      We received a password-reset request for your <strong>Digital Services Hub</strong> account. Click the button below to set a new password:
    </p>
    <p style="margin: 0 0 20px 0;">
      <a href="${safeUrl}" style="display: inline-block; background-color: #0284c7; color: #ffffff; text-decoration: none; font-weight: 600; padding: 12px 20px; border-radius: 6px;">
        Reset Password
      </a>
    </p>
    <p style="margin: 0 0 16px 0; font-size: 14px; color: #475569;">
      This password reset link will expire in <strong>${minutes} minutes</strong> and can only be used once.
    </p>
    <p style="margin: 0; font-size: 13px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 16px;">
      If you did not make this password-reset request, please ignore this email. No changes have been made to your account.
    </p>
  </div>
</body>
</html>`;

  return { subject, html, text };
}
