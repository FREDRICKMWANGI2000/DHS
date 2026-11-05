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

# Drizzle Kit CLI commands (delegated to @dsh/backend)
npm run db:generate   # Generate SQL migrations from schema
npm run db:migrate    # Apply migrations to database
npm run db:studio     # Launch Drizzle Studio browser GUI
```
> **Warning**: Never execute `docker compose down -v` as that deletes the persistent volume and destroys database data.

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
