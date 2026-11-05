# Digital Services Hub (DSH)

> **Connect • Create • Get Things Done**  
> High-speed Wi-Fi, captive portal, and full-service digital agency platform for Kenya.

---

## 1. Quick Start

### Prerequisites
- Node.js LTS (v20+ or v26+)
- npm (v10+)
- Docker & Docker Compose (for PostgreSQL)
- Git

### Installation
```bash
# Clone the repository
git clone <repository_url>
cd DHS

# Install dependencies
npm install

# Setup environment variables
cp .env.example .env.local
```

### Development
```bash
# Run local development server
npm run dev

# Check types
npm run typecheck

# Run linter
npm run lint

# Build for production
npm run build
```

---

## 2. Milestone Roadmap

| Milestone | Title | Status |
| :--- | :--- | :--- |
| **00** | Recovery and project decisions | Completed (Fresh machine bootstrap) |
| **01** | Fresh development foundation | Completed |
| **02** | Application structure and standards | **Active** |
| **03** | PostgreSQL and data layer | Upcoming |
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

## 3. Brand Tokens & Design Rules

* **Palette**:
  * Black: `#0A0A0A`
  * Warm White: `#FAFAF7`
  * Gold: `#C9A227`
  * Bright Gold: `#FFD700`
  * WhatsApp Green: `#25D366` (customer support)
* **Architecture**: Modular monolith built on Next.js App Router.
* **Security**: Server-authoritative pricing, RBAC (`CUSTOMER`, `STAFF`, `ADMIN`, `SUPER_ADMIN`), strictly decoupled payment vs. gateway states.
