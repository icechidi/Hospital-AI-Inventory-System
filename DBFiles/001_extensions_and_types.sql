-- ============================================================================
-- AI Hospital Inventory Management System
-- 001_extensions_and_types.sql
-- Postgres 17. Requires TimescaleDB and pgvector extensions installed on
-- the server (apt/binary install, not just "CREATE EXTENSION" — see
-- README.md for install steps before running this file).
-- ============================================================================

-- ---- Extensions -------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;        -- AES-256 column encryption, gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS timescaledb;      -- hypertables for time-series (movements, forecasts)
CREATE EXTENSION IF NOT EXISTS vector;           -- pgvector, supplier/document semantic search
CREATE EXTENSION IF NOT EXISTS pg_trgm;          -- fuzzy text search on medicine/supplier names
CREATE EXTENSION IF NOT EXISTS btree_gist;        -- exclusion constraints (e.g. no overlapping batches)

-- ---- Schemas ------------------------------------------------------------
-- Separate schema per bounded context keeps the DDD module boundaries visible
-- in the database itself and makes per-schema grants straightforward.

CREATE SCHEMA IF NOT EXISTS identity;      -- users, roles, permissions, auth
CREATE SCHEMA IF NOT EXISTS org;           -- hospitals, departments, warehouses
CREATE SCHEMA IF NOT EXISTS catalog;       -- medicines, categories, suppliers
CREATE SCHEMA IF NOT EXISTS inventory;     -- stock, batches, movements, transfers
CREATE SCHEMA IF NOT EXISTS procurement;   -- purchase orders, invoices
CREATE SCHEMA IF NOT EXISTS ai;            -- forecasts, predictions, anomalies
CREATE SCHEMA IF NOT EXISTS audit;         -- immutable audit logs
CREATE SCHEMA IF NOT EXISTS ops;           -- notifications, documents, alerts

-- ---- Enum types -----------------------------------------------------------

CREATE TYPE identity.user_role AS ENUM (
    'super_admin', 'hospital_admin', 'pharmacist', 'inventory_manager',
    'procurement_officer', 'doctor', 'auditor'
);

CREATE TYPE identity.user_status AS ENUM ('active', 'inactive', 'suspended', 'locked');

CREATE TYPE catalog.item_type AS ENUM ('medicine', 'consumable', 'lab_supply', 'equipment');

CREATE TYPE inventory.movement_type AS ENUM (
    'receipt', 'issue', 'transfer_out', 'transfer_in', 'adjustment_positive',
    'adjustment_negative', 'return', 'disposal', 'expired_writeoff'
);

CREATE TYPE inventory.batch_status AS ENUM ('active', 'quarantined', 'expired', 'recalled', 'depleted');

CREATE TYPE procurement.po_status AS ENUM (
    'draft', 'pending_approval', 'approved', 'sent_to_supplier',
    'partially_received', 'received', 'cancelled', 'closed'
);

CREATE TYPE procurement.invoice_status AS ENUM ('pending', 'matched', 'disputed', 'paid', 'void');

CREATE TYPE ai.prediction_status AS ENUM ('pending', 'confirmed', 'dismissed', 'expired');

CREATE TYPE ai.anomaly_severity AS ENUM ('low', 'medium', 'high', 'critical');

CREATE TYPE ops.alert_severity AS ENUM ('info', 'warning', 'critical');

CREATE TYPE ops.notification_channel AS ENUM ('email', 'sms', 'push', 'in_app');

-- ---- Shared trigger function: updated_at maintenance ------------------------

CREATE OR REPLACE FUNCTION audit.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
