/**
 * Digital Services Hub (DSH) — Brand Design Tokens
 * Tagline: "Connect • Create • Get Things Done"
 */

export const DSH_COLORS = {
  black: '#0A0A0A',
  warmWhite: '#FAFAF7',
  gold: '#C9A227',
  goldBright: '#FFD700',
  white: '#FFFFFF',
  surfaceDark: '#141414',
  borderDark: '#262626',
  textMuted: '#A1A1AA',
  whatsappGreen: '#25D366',
} as const;

export const DSH_BRAND = {
  name: 'Digital Services Hub',
  shortName: 'DSH',
  tagline: 'Connect • Create • Get Things Done',
  description: 'High-speed Wi-Fi, professional document creation, and digital cyber services.',
  location: 'Kenya',
  currency: 'KES',
} as const;

export type DshColorKey = keyof typeof DSH_COLORS;
