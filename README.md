# Digital Services Hub (DSH)

> **Connect • Create • Get Things Done**  
> High-speed Wi-Fi, captive portal, and full-service digital agency platform for Kenya.

---

## 1. Monorepo Architecture (npm Workspaces)

DSH is organized as an npm Workspaces monorepo:

- **`frontend/` (`@dsh/frontend`)**: Next.js 16 web application (App Router, React 19, Tailwind CSS v4). Communicates with the backend via HTTP REST APIs.
- **`backend/` (`@dsh/backend`)**: Express API server, Drizzle ORM data layer, and PostgreSQL connection pool.

---

## 2. Quick Start

### Prerequisites
- Node.js LTS (v20+ or v26+)
- npm (v10+)
- Docker & Docker Compose (for PostgreSQL 18)
- Git

### Installation
```bash
# Clone the repository
git clone <repository_url>
cd DHS

# Install all workspace dependencies
npm install

# Setup environment variables at repository root
cp .env.example .env.local
```

### Database (PostgreSQL 18 & Drizzle ORM)
The database runs via Docker Compose using the official `postgres:18` image and a persistent named volume (`dsh_postgres_data`). Database modeling, migrations, and typed queries live exclusively in `@dsh/backend`.

* **Client Initialization**: `backend/src/db/client.ts` initializes a `node-postgres` connection pool with connection timeouts, idle timeouts, and hot-reload singleton protection.
* **Environment Resolution**: `backend/src/config/env.ts`, `backend/drizzle.config.ts`, and `backend/scripts/db-check.ts` resolve the monorepo root `.env.local` relative to their own file locations (`__dirname`), ensuring reliability regardless of working directory.
* **Schema & Migrations Location**:
  * Schema Entry Point: `backend/src/db/schema/index.ts` (18 tables, 9 enums, Drizzle relations)
  * Migrations Directory: `backend/drizzle/` (`0000_bored_electro.sql` and `meta/_journal.json`)
  * Migration Journal Table: `drizzle.__drizzle_migrations` in PostgreSQL
  * Append-Only Protection: Database triggers (`prevent_append_only_mutation()`) enforce strict immutability on `audit_logs` and `service_order_status_history`.

```bash
# Start PostgreSQL container in background (uses local secrets from .env.local)
docker compose --env-file .env.local up -d

# Verify database connection via @dsh/backend Drizzle ORM
npm run db:check

# Check container health and status
docker ps --filter "name=dsh_postgres"
docker inspect --format='{{.State.Health.Status}}' dsh_postgres

# View PostgreSQL logs
docker compose --env-file .env.local logs -f postgres

# Stop the database container (preserves all data in persistent volume)
docker compose --env-file .env.local stop

# Restart PostgreSQL container
docker compose --env-file .env.local restart postgres

# Connect to database via psql inside the container
docker exec -it dsh_postgres psql -U dsh_user -d dsh_db

# Drizzle Kit & Seed CLI commands (delegated to @dsh/backend)
npm run db:generate   # Generate SQL migrations from schema
npm run db:migrate    # Apply migrations to database
npm run db:seed       # Seed default Wi-Fi packages and digital services (idempotent)
npm run db:studio     # Launch Drizzle Studio browser GUI
```
> **Warning**: Never execute `docker compose down -v` as that deletes the persistent volume and destroys database data.

### Database Seeding & Administrator Price Protection
The catalog seed system (`backend/scripts/seed.ts` & `backend/src/db/seed-catalog.ts`) populates the initial 5 Wi-Fi packages and 11 digital services:

- **Idempotency Mechanism**: Uses `INSERT ... ON CONFLICT (slug) DO NOTHING` inside a database transaction.
- **Administrator Change Protection**: The seed script **never overwrites** existing records. If an administrator edits a package or service's price, description, duration, display order, or active status, re-running `npm run db:seed` preserves the administrator's customizations untouched and reports any differences from the initial defaults.
- **Strict Scope**: Only inserts missing catalog records (`wifi_packages` and `service_catalog`). Never creates fake customers, orders, sessions, or payments.

#### Default Wi-Fi Packages (`wifi_packages`)
| Order | Name | Slug | Default Price | Duration |
| :--- | :--- | :--- | :--- | :--- |
| 1 | Quick Connect | `quick-connect` | KES 20.00 | 60 minutes (1h) |
| 2 | Standard | `standard` | KES 30.00 | 120 minutes (2h) |
| 3 | Extended | `extended` | KES 50.00 | 240 minutes (4h) |
| 4 | Day Pass | `day-pass` | KES 80.00 | 480 minutes (8h) |
| 5 | Full Day | `full-day` | KES 100.00 | 1440 minutes (24h) |

#### Default Digital Services (`service_catalog`)
| Order | Service | Slug | Default Price | Pricing Unit |
| :--- | :--- | :--- | :--- | :--- |
| 1 | CV & Resume | `cv-resume` | KES 1,200.00 | `FIXED` |
| 2 | Job Applications | `job-applications` | KES 800.00 | `FIXED` |
| 3 | Cover Letters | `cover-letters` | KES 600.00 | `FIXED` |
| 4 | Typing | `typing` | KES 200.00 | `FIXED` |
| 5 | Document Formatting | `document-formatting` | KES 150.00 | `FIXED` |
| 6 | PDF Services | `pdf-services` | KES 100.00 | `FIXED` |
| 7 | Printing | `printing` | KES 15.00 | `PER_PAGE` |
| 8 | Scanning | `scanning` | KES 25.00 | `PER_PAGE` |
| 9 | Passport Photos | `passport-photos` | KES 250.00 | `PER_SET` |
| 10 | Cyber Café | `cyber-cafe` | KES 50.00 | `PER_HOUR` |
| 11 | Internet Access | `internet-access` | KES 100.00 | `PER_SESSION` |

```bash
# Run catalog seed
npm run db:seed

# Verify seeded records directly in PostgreSQL
docker exec dsh_postgres psql -U dsh_user -d dsh_db -c "SELECT display_order, slug, name, price, duration_minutes, is_active FROM wifi_packages ORDER BY display_order;"
docker exec dsh_postgres psql -U dsh_user -d dsh_db -c "SELECT display_order, slug, name, price, pricing_unit, is_active FROM service_catalog ORDER BY display_order;"
```

### Development & Quality Scripts
```bash
# Start frontend development server (http://localhost:3000)
npm run dev:frontend

# Start backend Express API server (http://localhost:4000)
npm run dev:backend

# Check types across all workspaces
npm run typecheck

# Run linter across all workspaces
npm run lint

# Build all workspaces for production
npm run build
```

### Backend Health Endpoints
- `GET http://localhost:4000/api/v1/health` — Express service status
- `GET http://localhost:4000/api/v1/health/db` — PostgreSQL pool connectivity & latency check

---

## 3. Milestone Roadmap

| Milestone | Title | Status |
| :--- | :--- | :--- |
| **00** | Recovery and project decisions | Completed (Fresh machine bootstrap) |
| **01** | Fresh development foundation | Completed |
| **02** | Application structure and standards | Completed |
| **03** | PostgreSQL and data layer | **Active** |
| **04** | Authentication and role security | Upcoming |
| **05** | Public website and brand system | Upcoming |
| **06** | Wi-Fi packages and session engine | Upcoming |
| **07** | M-Pesa Daraja payment integration | Upcoming |
| **08** | Captive portal and /connect journey | Upcoming |
| **09** | Digital-services order engine | Upcoming |
| **10** | Customer portal | Upcoming |
| **11** | Admin and staff dashboards | Upcoming |
| **12** | Security, integration and regression QA | Upcoming |
| **13** | MikroTik and Omada network integration | Upcoming |
| **14** | Production deployment and pilot launch | Upcoming |

---

## 4. Brand Tokens & Design Rules

* **Palette**:
  * Black: `#0A0A0A`
  * Warm White: `#FAFAF7`
  * Gold: `#C9A227`
  * Bright Gold: `#FFD700`
  * WhatsApp Green: `#25D366` (customer support)
* **Architecture**: npm Workspaces monorepo (`@dsh/frontend` + `@dsh/backend`).
* **Security**: Server-authoritative pricing, RBAC (`CUSTOMER`, `STAFF`, `ADMIN`, `SUPER_ADMIN`), strictly decoupled payment vs. gateway states.
