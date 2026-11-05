# Digital Services Hub (DSH) — Architecture & Standards

## 1. System Philosophy: Modular Monolith
DSH is structured as a **single Next.js application** with cohesive, modular server-side domains.
- **Do not split into microservices** at this stage. All public web pages, captive portal, customer portal, staff/admin operations, background integrations (M-Pesa Daraja, MikroTik/Omada), and database operations live within this application repository.
- Keeps deployment, atomic transactions, database migrations, and operational debugging simple and reliable.

## 2. Server Authority & Security Rules
- **Backend-Authoritative**: The client is never trusted for pricing, payment status, role assignment, file permissions, or network access entitlement.
- **Payment vs. Gateway Decoupling**: Payment completion (`PAID`) and HotSpot internet activation (`AUTHORIZED`) are distinct states. The application never signals "Internet active" to the user until the router/gateway explicitly verifies authorization.
- **Anonymous Wi-Fi Checkout**: Wi-Fi buyers on `/connect` do not require account registration or authentication.
- **Role-Based Access Control (RBAC)**:
  - `CUSTOMER`: Access to own orders, Wi-Fi sessions, profile, and invoices.
  - `STAFF`: Day-to-day operations, task queue, order status changes, and customer support. **Strictly restricted from viewing financial reports or revenue totals.**
  - `ADMIN`: Full operational and catalog management, package pricing, staff assignments, and audit views.
  - `SUPER_ADMIN`: System-level configuration, credentials, database backups, and bootstrap controls.

## 3. Directory Layout Conventions
```
/
├── .env.example            # Canonical environment variable template (no real secrets)
├── docs/                   # Engineering documentation and architecture notes
├── public/                 # Static public assets (logos, icons, placeholders)
├── src/
│   ├── app/                # Next.js App Router (pages, layouts, route handlers)
│   │   ├── (public)/       # Marketing, catalog, about, contact pages
│   │   ├── connect/        # Anonymous captive portal & Wi-Fi checkout
│   │   ├── account/        # Customer portal (authenticated)
│   │   ├── admin/          # Staff and Admin dashboards
│   │   └── api/            # Server Route Handlers (Daraja callbacks, webhooks, auth)
│   ├── components/         # Shared React components
│   │   ├── layout/         # Header, Footer, Sidebar, Navigation
│   │   └── ui/             # Reusable design primitives (Buttons, Cards, Dialogs)
│   ├── lib/                # Core business logic and shared modules
│   │   ├── auth/           # Sessions, Argon2id hashing, role guards
│   │   ├── constants/      # Brand tokens, roles, packages, statuses
│   │   ├── db/             # Drizzle ORM schema, connection, migrations
│   │   ├── services/       # Domain services (M-Pesa, Wi-Fi session engine, email)
│   │   ├── validation/     # Zod input validation schemas
│   │   └── utils.ts        # Helper functions
│   └── types/              # Domain TypeScript types and interfaces
└── tests/                  # Integration and unit tests
```

## 4. Brand Design Tokens
- Deep Black: `#0A0A0A`
- Warm White: `#FAFAF7`
- Gold Accent: `#C9A227`
- Bright Gold: `#FFD700`
- Dark Surface: `#141414`
- Dark Border: `#262626`
- WhatsApp Green: `#25D366` (official communication links only)

Avoid random mint/green or purple hues.
