# Hospital-AI-Inventory-System
A full-blown "enterprise Hospital AI Inventory System" with microservices, Kubernetes, Keycloak, HashiCorp Vault, multiple ML models, an entire compliance program...

# AI Hospital Inventory Management System — Database Schema

This is a real, runnable PostgreSQL 17 schema for the system described in the
spec — the database layer only. It's the first slice of the build; backend
(NestJS), AI service (FastAPI), and frontend (Next.js) are separate follow-on
pieces, not included here.

## Prerequisites

TimescaleDB and pgvector are **not** things `CREATE EXTENSION` installs on
their own — the extension binaries have to already be present on the Postgres
server. On Ubuntu against Postgres 17:

```bash
# TimescaleDB
sudo apt install -y postgresql-17-timescaledb
sudo timescaledb-tune --quiet --yes
sudo systemctl restart postgresql

# pgvector
sudo apt install -y postgresql-17-pgvector
```

(Package names/repos vary by distro — see timescale.com/install and
github.com/pgvector/pgvector for the current instructions for your OS.)

## Files, in run order

| File | Contents |
|---|---|
| `001_extensions_and_types.sql` | Extensions, schemas, enum types, shared trigger fn |
| `002_identity_and_org.sql` | Hospitals, departments, warehouses, users, roles, permissions (RBAC) |
| `003_catalog.sql` | Suppliers, medicine categories, unified item catalog |
| `004_inventory.sql` | Batches, current stock, movements ledger (TimescaleDB hypertable), transfers |
| `005_procurement.sql` | Purchase orders, PO line items, invoices |
| `006_ai.sql` | Model registry, demand forecasts (hypertable), predictions, anomalies, waste, purchase recommendations |
| `007_ops_and_audit.sql` | Documents (MinIO refs), alerts, notifications, audit log (hypertable) |
| `008_security.sql` | DB roles/grants, row-level security policies, column-encryption helpers, seed roles |
| `000_full_schema.sql` | All of the above concatenated, for a single `psql -f` run |

Run either the numbered files in order, or the combined file:

```bash
createdb hospital_inventory
psql -d hospital_inventory -f 000_full_schema.sql
```

## Design notes

- **One `catalog.items` table**, not separate tables per item type
  (medicines/consumables/lab supplies/equipment). An `item_type` enum
  discriminates. This avoids a 4-way FK fan-out on every inventory,
  movement, and PO table — the spec's per-category tracking requirements
  are met via that column plus category-specific fields, not duplicated
  schema.
- **`inventory.movements` is the source of truth**; `inventory.stock` is a
  denormalized projection kept in sync by a trigger. Never write to
  `inventory.stock` directly — insert a movement row and let the trigger
  update it, or the two will drift.
- **Hypertables** (`inventory.movements`, `ai.demand_forecasts`,
  `audit.audit_logs`) are partitioned on their timestamp column for
  time-range query performance at scale, with compression policies so old
  data doesn't bloat storage while still being queryable.
- **Multi-tenancy** is enforced via row-level security keyed on
  `app.current_hospital_id`, a session variable your NestJS backend must set
  per-request after resolving the authenticated user's hospital (e.g.
  `SET LOCAL app.current_hospital_id = '<uuid>';` inside the request's
  transaction). RLS is enabled on the highest-sensitivity tables as a
  pattern — apply the same `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` +
  policy to every other multi-tenant table before production use.

## What this is *not*

- **Not a HIPAA/GDPR/ISO 27001 compliance package.** RLS, column-encryption
  helpers, and an immutable audit log are real building blocks toward that,
  but actual compliance needs a security review, data processing
  agreements, breach procedures, and usually a third-party audit — none of
  which comes from a schema file.
- **Passwords in `008_security.sql` are placeholders.** Pull real
  credentials from Vault at deploy time; never commit them.
- **No seed/sample dataset yet** — the spec asks for one; it's a reasonable
  next slice once the backend exists to generate realistic data through,
  rather than hand-written INSERTs that won't match your real workflows.
