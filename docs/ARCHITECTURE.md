# Digital Services Hub (DSH) — Architecture & Standards

## 1. System Philosophy: npm Workspaces Monorepo
DSH is structured as an **npm Workspaces monorepo** separating presentation from server-authoritative data and domain logic:
- **`frontend/` (`@dsh/frontend`)**: Next.js 16 (App Router, React 19, Tailwind CSS v4) web application. Communicates with the backend strictly over HTTP REST APIs (`/api/v1/*`). Never holds database credentials or direct database connections.
- **`backend/` (`@dsh/backend`)**: Express API server, Drizzle ORM data layer, PostgreSQL connection pool, domain services (M-Pesa Daraja, Wi-Fi session engine, MikroTik HotSpot gateway, authentication, and RBAC).

## 2. Server Authority & Security Rules
- **Backend-Authoritative**: `@dsh/backend` is the single source of truth for pricing, payment verification, role enforcement, file permissions, and network access entitlement.
- **Payment vs. Gateway Decoupling**: Payment completion (`PAID`) and HotSpot internet activation (`AUTHORIZED`) are distinct states. The application never signals "Internet active" to the user until the router/gateway explicitly verifies authorization.
- **Anonymous Wi-Fi Checkout**: Wi-Fi buyers on `/connect` do not require account registration or authentication.
- **Role-Based Access Control (RBAC)**:
  - `CUSTOMER`: Access to own orders, Wi-Fi sessions, profile, and invoices.
  - `STAFF`: Day-to-day operations, task queue, order status changes, and customer support. **Strictly restricted from viewing financial reports or revenue totals.**
  - `ADMIN`: Full operational and catalog management, package pricing, staff assignments, and audit views.
  - `SUPER_ADMIN`: System-level configuration, credentials, database backups, and bootstrap controls.

## 3. Monorepo Directory Layout
```
/
├── .env.example                # Canonical environment variable template (no real secrets)
├── docker-compose.yml          # PostgreSQL 18 container & persistent volume config
├── package.json                # Root npm Workspaces configuration (@dsh/frontend, @dsh/backend)
├── docs/                       # Engineering documentation and architecture notes
├── frontend/                   # @dsh/frontend (Next.js 16 Application)
│   ├── package.json
│   ├── next.config.ts
│   ├── public/                 # Static public assets
│   └── src/
│       ├── app/                # Next.js App Router pages & layouts
│       ├── components/         # Shared React UI and layout components
│       ├── lib/                # Frontend utilities, brand tokens, HTTP API client
│       └── types/              # Frontend TypeScript types
├── backend/                    # @dsh/backend (Express API & Drizzle ORM)
│   ├── package.json
│   ├── tsconfig.json
│   ├── drizzle.config.ts       # Drizzle Kit configuration (loads root .env.local)
│   ├── drizzle/                # Generated SQL migrations
│   ├── scripts/
│   │   └── db-check.ts         # Database connectivity verification script
│   └── src/
│       ├── index.ts            # Express server entry point
│       ├── app.ts              # Express app, CORS, middleware & route mounting
│       ├── config/
│       │   └── env.ts          # Reliable root .env.local loader & env validation
│       ├── db/
│       │   ├── client.ts       # Drizzle ORM & pg.Pool connection singleton
│       │   └── schema/         # Drizzle PostgreSQL schema definitions
│       └── routes/
│           └── health.ts       # GET /api/v1/health & GET /api/v1/health/db
└── tests/                      # Cross-workspace & integration tests
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
