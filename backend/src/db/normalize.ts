/**
 * Canonical data normalization helpers for contact and device identifiers.
 * Matches PostgreSQL CHECK constraints enforced on users, wifi_sessions, and customer_devices.
 */

const E164_REGEX = /^\+[1-9][0-9]{7,14}$/;
const MAC_COLON_UPPER_REGEX = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;

/**
 * Normalizes an email address to trimmed lowercase.
 */
export function normalizeEmail(rawEmail: string): string {
  const normalized = rawEmail.trim().toLowerCase();
  if (normalized.length < 3 || !normalized.includes("@")) {
    throw new Error("Invalid email format.");
  }
  return normalized;
}

/**
 * Normalizes Kenyan and E.164 phone numbers to canonical E.164 format (+2547XXXXXXXX / +2541XXXXXXXX).
 * Accepts inputs such as:
 * - "0712345678" -> "+254712345678"
 * - "0112345678" -> "+254112345678"
 * - "254712345678" -> "+254712345678"
 * - "+254712345678" -> "+254712345678"
 */
export function normalizePhoneNumber(rawPhone: string): string {
  const cleaned = rawPhone.replace(/[\s\-()]/g, "");

  let normalized = cleaned;
  if (/^0[17][0-9]{8}$/.test(cleaned)) {
    normalized = `+254${cleaned.slice(1)}`;
  } else if (/^254[17][0-9]{8}$/.test(cleaned)) {
    normalized = `+${cleaned}`;
  }

  if (!E164_REGEX.test(normalized)) {
    throw new Error(
      "Phone number must be a valid Kenyan or E.164 number (e.g. +2547XXXXXXXX)."
    );
  }
  return normalized;
}

/**
 * Normalizes a MAC address to uppercase colon-separated format (AA:BB:CC:DD:EE:FF).
 * Accepts colon-separated, hyphen-separated, or raw 12-hex-character strings.
 */
export function normalizeMacAddress(rawMac: string): string {
  const hexOnly = rawMac.trim().replace(/[:-]/g, "").toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(hexOnly)) {
    throw new Error("Invalid MAC address format.");
  }

  const pairs = hexOnly.match(/.{1,2}/g);
  const formatted = pairs ? pairs.join(":") : "";

  if (!MAC_COLON_UPPER_REGEX.test(formatted)) {
    throw new Error("Invalid normalized MAC address.");
  }
  return formatted;
}
