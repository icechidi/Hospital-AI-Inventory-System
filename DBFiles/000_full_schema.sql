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
-- ============================================================================
-- 002_identity_and_org.sql
-- Users/roles/permissions (RBAC + ABAC-ready) and organizational structure.
-- ============================================================================

-- ---- org.hospitals ----------------------------------------------------------

CREATE TABLE org.hospitals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    code            TEXT NOT NULL UNIQUE,          -- short code used in barcodes/reports
    address         TEXT,
    city            TEXT,
    country         TEXT,
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    license_number  TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_hospitals_updated_at
    BEFORE UPDATE ON org.hospitals
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

-- ---- org.departments ---------------------------------------------------------

CREATE TABLE org.departments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id     UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    code            TEXT NOT NULL,
    parent_id       UUID REFERENCES org.departments(id) ON DELETE SET NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, code)
);

CREATE TRIGGER trg_departments_updated_at
    BEFORE UPDATE ON org.departments
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

-- ---- org.warehouses -----------------------------------------------------------
-- Physical or logical storage locations (pharmacy store, central warehouse,
-- ward sub-stores, lab stores, etc).

CREATE TABLE org.warehouses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id     UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    department_id   UUID REFERENCES org.departments(id) ON DELETE SET NULL,
    name            TEXT NOT NULL,
    code            TEXT NOT NULL,
    location_detail TEXT,
    is_cold_chain   BOOLEAN NOT NULL DEFAULT false,  -- requires temperature-controlled storage
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, code)
);

CREATE TRIGGER trg_warehouses_updated_at
    BEFORE UPDATE ON org.warehouses
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

-- ---- identity.roles / identity.permissions -----------------------------------
-- RBAC base tables. Fine-grained ABAC attributes (e.g. "only own department")
-- are layered on top via the `attributes` jsonb column and enforced in the
-- application layer / row-level security policies, not hardcoded here.

CREATE TABLE identity.roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            identity.user_role NOT NULL UNIQUE,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity.permissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT NOT NULL UNIQUE,      -- e.g. 'inventory.adjust', 'po.approve'
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity.role_permissions (
    role_id         UUID NOT NULL REFERENCES identity.roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES identity.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- ---- identity.users -----------------------------------------------------------
-- Password hash column exists for local/dev fallback auth only; production
-- auth is delegated to Keycloak (OIDC). keycloak_subject is the OIDC "sub"
-- claim used to map external identities to internal users.

CREATE TABLE identity.users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE RESTRICT,
    department_id       UUID REFERENCES org.departments(id) ON DELETE SET NULL,
    keycloak_subject    TEXT UNIQUE,
    email               TEXT NOT NULL UNIQUE,
    full_name           TEXT NOT NULL,
    phone               TEXT,
    password_hash       TEXT,                  -- Argon2id, local fallback only
    status              identity.user_status NOT NULL DEFAULT 'active',
    mfa_enabled         BOOLEAN NOT NULL DEFAULT false,
    last_login_at       TIMESTAMPTZ,
    last_password_change_at TIMESTAMPTZ,
    attributes          JSONB NOT NULL DEFAULT '{}'::jsonb,  -- ABAC attributes
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON identity.users
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

CREATE TABLE identity.user_roles (
    user_id         UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES identity.roles(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by      UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_users_hospital ON identity.users(hospital_id);
CREATE INDEX idx_users_status ON identity.users(status);
CREATE INDEX idx_users_email_trgm ON identity.users USING gin (email gin_trgm_ops);
-- ============================================================================
-- 003_catalog.sql
-- Medicines, categories, consumables/equipment, suppliers.
-- ============================================================================

-- ---- catalog.suppliers ---------------------------------------------------

CREATE TABLE catalog.suppliers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    code                TEXT NOT NULL,
    contact_name        TEXT,
    contact_email       TEXT,
    contact_phone       TEXT,
    address             TEXT,
    payment_terms_days  INTEGER DEFAULT 30,
    avg_lead_time_days  NUMERIC(6,2),           -- rolling average, updated by ETL/AI job
    performance_score   NUMERIC(5,2),           -- 0-100, computed by AI purchasing engine
    embedding           vector(1536),           -- pgvector: semantic profile for supplier matching
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, code)
);

CREATE TRIGGER trg_suppliers_updated_at
    BEFORE UPDATE ON catalog.suppliers
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

CREATE INDEX idx_suppliers_name_trgm ON catalog.suppliers USING gin (name gin_trgm_ops);
CREATE INDEX idx_suppliers_embedding ON catalog.suppliers USING hnsw (embedding vector_cosine_ops);

-- ---- catalog.medicine_categories ------------------------------------------

CREATE TABLE catalog.medicine_categories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    parent_id       UUID REFERENCES catalog.medicine_categories(id) ON DELETE SET NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- catalog.items ----------------------------------------------------------
-- Unifies medicines, consumables, lab supplies, and equipment under one
-- catalog table (item_type discriminates). Keeps FK fan-out on inventory/
-- movement tables manageable instead of one table per item type.

CREATE TABLE catalog.items (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    category_id         UUID REFERENCES catalog.medicine_categories(id) ON DELETE SET NULL,
    item_type           catalog.item_type NOT NULL,
    name                TEXT NOT NULL,
    generic_name         TEXT,                   -- for medicines
    sku                 TEXT NOT NULL,
    barcode              TEXT,
    qr_code              TEXT,
    unit_of_measure      TEXT NOT NULL,           -- e.g. 'box', 'vial', 'unit'
    pack_size             NUMERIC(10,2) DEFAULT 1,
    requires_cold_chain   BOOLEAN NOT NULL DEFAULT false,
    is_controlled_substance BOOLEAN NOT NULL DEFAULT false,
    reorder_point        NUMERIC(12,2) NOT NULL DEFAULT 0,
    reorder_quantity      NUMERIC(12,2) NOT NULL DEFAULT 0,
    max_stock_level       NUMERIC(12,2),
    standard_cost          NUMERIC(14,2),         -- encrypted at rest in production, see README
    is_active             BOOLEAN NOT NULL DEFAULT true,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, sku)
);

CREATE TRIGGER trg_items_updated_at
    BEFORE UPDATE ON catalog.items
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

CREATE INDEX idx_items_hospital_type ON catalog.items(hospital_id, item_type);
CREATE INDEX idx_items_barcode ON catalog.items(barcode) WHERE barcode IS NOT NULL;
CREATE INDEX idx_items_qr_code ON catalog.items(qr_code) WHERE qr_code IS NOT NULL;
CREATE INDEX idx_items_name_trgm ON catalog.items USING gin (name gin_trgm_ops);

-- ---- catalog.item_suppliers ------------------------------------------------
-- Many-to-many: which suppliers can fulfil which items, at what price.

CREATE TABLE catalog.item_suppliers (
    item_id         UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    supplier_id     UUID NOT NULL REFERENCES catalog.suppliers(id) ON DELETE CASCADE,
    unit_price      NUMERIC(14,2) NOT NULL,
    lead_time_days  INTEGER,
    is_preferred    BOOLEAN NOT NULL DEFAULT false,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, supplier_id)
);
-- ============================================================================
-- 004_inventory.sql
-- Stock levels, batch/expiry tracking, movement ledger (time-series), transfers.
-- ============================================================================

-- ---- inventory.batches -------------------------------------------------------
-- One row per received batch/lot. Expiry lives here, not on inventory, since
-- a single item can have multiple batches in stock with different expiries.

CREATE TABLE inventory.batches (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id             UUID NOT NULL REFERENCES catalog.items(id) ON DELETE RESTRICT,
    warehouse_id        UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE RESTRICT,
    supplier_id         UUID REFERENCES catalog.suppliers(id) ON DELETE SET NULL,
    batch_number        TEXT NOT NULL,
    manufacture_date    DATE,
    expiry_date         DATE NOT NULL,
    quantity_received   NUMERIC(12,2) NOT NULL,
    quantity_remaining  NUMERIC(12,2) NOT NULL,
    unit_cost           NUMERIC(14,2),
    status              inventory.batch_status NOT NULL DEFAULT 'active',
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (item_id, warehouse_id, batch_number),
    CHECK (quantity_remaining >= 0),
    CHECK (quantity_remaining <= quantity_received)
);

CREATE TRIGGER trg_batches_updated_at
    BEFORE UPDATE ON inventory.batches
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

CREATE INDEX idx_batches_item_warehouse ON inventory.batches(item_id, warehouse_id);
CREATE INDEX idx_batches_expiry ON inventory.batches(expiry_date) WHERE status = 'active';
CREATE INDEX idx_batches_status ON inventory.batches(status);

-- ---- inventory.stock ---------------------------------------------------------
-- Denormalized current on-hand quantity per item/warehouse, maintained by
-- triggers off inventory_movements. Read-heavy dashboards hit this table
-- instead of aggregating the movements ledger on every page load.

CREATE TABLE inventory.stock (
    item_id             UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    warehouse_id        UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE CASCADE,
    quantity_on_hand    NUMERIC(12,2) NOT NULL DEFAULT 0,
    quantity_reserved   NUMERIC(12,2) NOT NULL DEFAULT 0,
    last_movement_at    TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, warehouse_id),
    CHECK (quantity_on_hand >= 0)
);

-- ---- inventory.movements (TimescaleDB hypertable) ---------------------------
-- Append-only ledger of every stock movement. This is the source of truth;
-- inventory.stock is a materialized projection of it. Converted to a
-- hypertable partitioned on occurred_at for efficient time-range queries
-- (demand forecasting, trend analysis) at hospital scale.

CREATE TABLE inventory.movements (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    item_id             UUID NOT NULL REFERENCES catalog.items(id) ON DELETE RESTRICT,
    warehouse_id        UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE RESTRICT,
    batch_id            UUID REFERENCES inventory.batches(id) ON DELETE SET NULL,
    movement_type       inventory.movement_type NOT NULL,
    quantity             NUMERIC(12,2) NOT NULL,   -- always positive; direction from movement_type
    reference_type       TEXT,                      -- 'purchase_order', 'stock_transfer', etc.
    reference_id          UUID,
    performed_by          UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    notes                  TEXT,
    occurred_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at),
    CHECK (quantity > 0)
);

SELECT create_hypertable('inventory.movements', 'occurred_at', if_not_exists => TRUE);

CREATE INDEX idx_movements_item_time ON inventory.movements (item_id, occurred_at DESC);
CREATE INDEX idx_movements_warehouse_time ON inventory.movements (warehouse_id, occurred_at DESC);
CREATE INDEX idx_movements_type ON inventory.movements (movement_type);
CREATE INDEX idx_movements_reference ON inventory.movements (reference_type, reference_id);

-- Retention/compression policy: raw movement rows compressed after 90 days,
-- kept indefinitely for audit purposes (healthcare retention requirements).
ALTER TABLE inventory.movements SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'item_id, warehouse_id'
);
SELECT add_compression_policy('inventory.movements', INTERVAL '90 days', if_not_exists => TRUE);

-- ---- Trigger: keep inventory.stock in sync with movements --------------------

CREATE OR REPLACE FUNCTION inventory.apply_movement()
RETURNS TRIGGER AS $$
DECLARE
    delta NUMERIC(12,2);
BEGIN
    delta := CASE
        WHEN NEW.movement_type IN ('receipt', 'transfer_in', 'adjustment_positive', 'return')
            THEN NEW.quantity
        ELSE -NEW.quantity
    END;

    -- Two-step upsert rather than a single INSERT ... ON CONFLICT DO UPDATE
    -- with `delta` as the insert value: Postgres validates CHECK constraints
    -- against that speculative insert row before it resolves the conflict,
    -- so a negative delta against an *existing* row would spuriously fail
    -- the `quantity_on_hand >= 0` check even though the final updated value
    -- is non-negative. Ensuring a zero-row exists first, then always taking
    -- the UPDATE path, makes the constraint check run against the real
    -- final value instead.
    INSERT INTO inventory.stock (item_id, warehouse_id, quantity_on_hand, last_movement_at)
    VALUES (NEW.item_id, NEW.warehouse_id, 0, NEW.occurred_at)
    ON CONFLICT (item_id, warehouse_id) DO NOTHING;

    UPDATE inventory.stock
    SET quantity_on_hand = quantity_on_hand + delta,
        last_movement_at = NEW.occurred_at,
        updated_at = now()
    WHERE item_id = NEW.item_id AND warehouse_id = NEW.warehouse_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_apply_movement
    AFTER INSERT ON inventory.movements
    FOR EACH ROW EXECUTE FUNCTION inventory.apply_movement();

-- ---- inventory.stock_transfers -----------------------------------------------

CREATE TABLE inventory.stock_transfers (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id             UUID NOT NULL REFERENCES catalog.items(id) ON DELETE RESTRICT,
    batch_id            UUID REFERENCES inventory.batches(id) ON DELETE SET NULL,
    from_warehouse_id   UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE RESTRICT,
    to_warehouse_id     UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE RESTRICT,
    quantity             NUMERIC(12,2) NOT NULL CHECK (quantity > 0),
    status                TEXT NOT NULL DEFAULT 'pending', -- pending / in_transit / completed / cancelled
    requested_by           UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    approved_by             UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    requested_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at              TIMESTAMPTZ,
    CHECK (from_warehouse_id <> to_warehouse_id)
);

CREATE INDEX idx_transfers_status ON inventory.stock_transfers(status);
CREATE INDEX idx_transfers_item ON inventory.stock_transfers(item_id);
-- ============================================================================
-- 005_procurement.sql
-- Purchase orders, PO line items, invoices.
-- ============================================================================

CREATE TABLE procurement.purchase_orders (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    supplier_id         UUID NOT NULL REFERENCES catalog.suppliers(id) ON DELETE RESTRICT,
    warehouse_id        UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE RESTRICT,
    po_number            TEXT NOT NULL,
    status                procurement.po_status NOT NULL DEFAULT 'draft',
    is_ai_generated       BOOLEAN NOT NULL DEFAULT false,   -- drafted by purchasing recommendation engine
    source_recommendation_id UUID,  -- FK added in 006 after ai.purchase_recommendations exists
    subtotal               NUMERIC(14,2) NOT NULL DEFAULT 0,
    tax_amount               NUMERIC(14,2) NOT NULL DEFAULT 0,
    total_amount              NUMERIC(14,2) NOT NULL DEFAULT 0,
    requested_by                UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    approved_by                  UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    expected_delivery_date        DATE,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, po_number)
);

CREATE TRIGGER trg_po_updated_at
    BEFORE UPDATE ON procurement.purchase_orders
    FOR EACH ROW EXECUTE FUNCTION audit.set_updated_at();

CREATE INDEX idx_po_status ON procurement.purchase_orders(status);
CREATE INDEX idx_po_supplier ON procurement.purchase_orders(supplier_id);

CREATE TABLE procurement.purchase_order_items (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purchase_order_id   UUID NOT NULL REFERENCES procurement.purchase_orders(id) ON DELETE CASCADE,
    item_id             UUID NOT NULL REFERENCES catalog.items(id) ON DELETE RESTRICT,
    quantity_ordered     NUMERIC(12,2) NOT NULL CHECK (quantity_ordered > 0),
    quantity_received     NUMERIC(12,2) NOT NULL DEFAULT 0,
    unit_price              NUMERIC(14,2) NOT NULL,
    line_total                NUMERIC(14,2) GENERATED ALWAYS AS (quantity_ordered * unit_price) STORED
);

CREATE INDEX idx_po_items_po ON procurement.purchase_order_items(purchase_order_id);
CREATE INDEX idx_po_items_item ON procurement.purchase_order_items(item_id);

CREATE TABLE procurement.invoices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purchase_order_id   UUID REFERENCES procurement.purchase_orders(id) ON DELETE SET NULL,
    supplier_id         UUID NOT NULL REFERENCES catalog.suppliers(id) ON DELETE RESTRICT,
    invoice_number        TEXT NOT NULL,
    status                  procurement.invoice_status NOT NULL DEFAULT 'pending',
    amount                    NUMERIC(14,2) NOT NULL,
    document_id                UUID,   -- FK added in 007 after ops.documents exists
    issued_date                 DATE NOT NULL,
    due_date                      DATE,
    paid_at                        TIMESTAMPTZ,
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (supplier_id, invoice_number)
);

CREATE INDEX idx_invoices_status ON procurement.invoices(status);
-- ============================================================================
-- 006_ai.sql
-- AI/ML tables: model registry, forecasts, predictions, anomalies,
-- waste detection, purchase recommendations, training data.
-- Written by the Python/FastAPI AI service; read by the NestJS backend.
-- ============================================================================

-- ---- ai.forecast_models -------------------------------------------------------
-- Registry of trained model artifacts (versioned). model_uri points at
-- object storage (MinIO) where the serialized model lives.

CREATE TABLE ai.forecast_models (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,             -- e.g. 'shortage-xgboost-v3'
    model_type            TEXT NOT NULL,             -- 'xgboost' | 'lightgbm' | 'random_forest' | 'prophet' | 'lstm' | 'arima'
    task                    TEXT NOT NULL,             -- 'shortage_prediction' | 'demand_forecast' | 'anomaly_detection' | 'waste_detection'
    version                  TEXT NOT NULL,
    model_uri                 TEXT NOT NULL,            -- MinIO object path
    hyperparameters             JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active                    BOOLEAN NOT NULL DEFAULT false,
    trained_at                    TIMESTAMPTZ,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (hospital_id, name, version)
);

CREATE INDEX idx_forecast_models_active ON ai.forecast_models(hospital_id, task) WHERE is_active;

-- ---- ai.model_performance -----------------------------------------------------
-- Evaluation metrics per model version, tracked over time so forecast
-- accuracy on the executive dashboard is a real query, not a guess.

CREATE TABLE ai.model_performance (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID NOT NULL REFERENCES ai.forecast_models(id) ON DELETE CASCADE,
    evaluated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    mae                      NUMERIC(12,4),   -- mean absolute error
    rmse                       NUMERIC(12,4),
    mape                         NUMERIC(6,3),   -- mean absolute percentage error
    precision_score                NUMERIC(5,4),  -- for classification-style tasks (anomaly, shortage flag)
    recall_score                     NUMERIC(5,4),
    f1_score                           NUMERIC(5,4),
    notes                                TEXT
);

CREATE INDEX idx_model_perf_model_time ON ai.model_performance(model_id, evaluated_at DESC);

-- ---- ai.training_datasets ------------------------------------------------------
-- Snapshot metadata for reproducibility: which data window trained which model.

CREATE TABLE ai.training_datasets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID NOT NULL REFERENCES ai.forecast_models(id) ON DELETE CASCADE,
    dataset_uri            TEXT NOT NULL,          -- MinIO path to the extracted training set
    row_count                 BIGINT,
    date_range_start            DATE,
    date_range_end                DATE,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- ai.demand_forecasts (TimescaleDB hypertable) -------------------------------
-- One row per item/warehouse/day forecast horizon point, with confidence
-- interval. This is the table the dashboard forecast charts query directly.

CREATE TABLE ai.demand_forecasts (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    model_id             UUID NOT NULL REFERENCES ai.forecast_models(id) ON DELETE CASCADE,
    item_id               UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    warehouse_id           UUID REFERENCES org.warehouses(id) ON DELETE CASCADE,
    forecast_date            DATE NOT NULL,          -- the date being forecast
    granularity                TEXT NOT NULL,          -- 'daily' | 'weekly' | 'monthly'
    predicted_demand             NUMERIC(12,2) NOT NULL,
    confidence_lower                NUMERIC(12,2),
    confidence_upper                 NUMERIC(12,2),
    generated_at                       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, generated_at)
);

SELECT create_hypertable('ai.demand_forecasts', 'generated_at', if_not_exists => TRUE);
CREATE INDEX idx_demand_forecasts_item ON ai.demand_forecasts(item_id, forecast_date);

-- ---- ai.prediction_history -------------------------------------------------------
-- Generic log of every prediction emitted (shortage predictions primarily),
-- so accuracy can be back-tested once actuals are known.

CREATE TABLE ai.prediction_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID NOT NULL REFERENCES ai.forecast_models(id) ON DELETE CASCADE,
    item_id               UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    warehouse_id           UUID REFERENCES org.warehouses(id) ON DELETE CASCADE,
    predicted_shortage_date  DATE NOT NULL,
    confidence_score           NUMERIC(5,4) NOT NULL CHECK (confidence_score BETWEEN 0 AND 1),
    recommended_reorder_qty     NUMERIC(12,2),
    status                        ai.prediction_status NOT NULL DEFAULT 'pending',
    actual_shortage_date            DATE,          -- filled in retrospectively for model evaluation
    created_at                        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_prediction_history_item ON ai.prediction_history(item_id, created_at DESC);
CREATE INDEX idx_prediction_history_status ON ai.prediction_history(status);

-- ---- ai.anomaly_detections --------------------------------------------------------

CREATE TABLE ai.anomaly_detections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID NOT NULL REFERENCES ai.forecast_models(id) ON DELETE CASCADE,
    item_id               UUID REFERENCES catalog.items(id) ON DELETE CASCADE,
    warehouse_id           UUID REFERENCES org.warehouses(id) ON DELETE CASCADE,
    related_movement_id      UUID,                 -- points at inventory.movements.id (not FK: hypertable + composite PK)
    anomaly_type                TEXT NOT NULL,        -- 'theft_suspected' | 'unusual_movement' | 'fraud_pattern' | 'suspicious_purchasing'
    severity                      ai.anomaly_severity NOT NULL,
    anomaly_score                   NUMERIC(6,4) NOT NULL,   -- raw model output (e.g. isolation forest score)
    explanation                       TEXT,                    -- human-readable summary for the auditor
    status                              ai.prediction_status NOT NULL DEFAULT 'pending',
    reviewed_by                          UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    reviewed_at                            TIMESTAMPTZ,
    detected_at                              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_anomalies_severity ON ai.anomaly_detections(severity, status);
CREATE INDEX idx_anomalies_detected_at ON ai.anomaly_detections(detected_at DESC);

-- ---- ai.waste_predictions ----------------------------------------------------------

CREATE TABLE ai.waste_predictions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID REFERENCES ai.forecast_models(id) ON DELETE SET NULL,
    item_id               UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    warehouse_id           UUID NOT NULL REFERENCES org.warehouses(id) ON DELETE CASCADE,
    batch_id                 UUID REFERENCES inventory.batches(id) ON DELETE SET NULL,
    waste_type                  TEXT NOT NULL,      -- 'near_expiry' | 'overstock' | 'dead_stock' | 'slow_moving'
    estimated_waste_qty           NUMERIC(12,2),
    estimated_waste_value           NUMERIC(14,2),
    recommendation                    TEXT,          -- e.g. redistribution suggestion, discount-and-sell, etc.
    status                                ai.prediction_status NOT NULL DEFAULT 'pending',
    created_at                              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_waste_predictions_type ON ai.waste_predictions(waste_type, status);

-- ---- ai.purchase_recommendations -----------------------------------------------------

CREATE TABLE ai.purchase_recommendations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_id             UUID REFERENCES ai.forecast_models(id) ON DELETE SET NULL,
    item_id               UUID NOT NULL REFERENCES catalog.items(id) ON DELETE CASCADE,
    recommended_supplier_id UUID REFERENCES catalog.suppliers(id) ON DELETE SET NULL,
    recommended_quantity      NUMERIC(12,2) NOT NULL,
    recommended_order_date      DATE NOT NULL,
    rationale                     TEXT,             -- explanation combining forecast + supplier ranking + budget
    status                           ai.prediction_status NOT NULL DEFAULT 'pending',
    resulting_po_id                    UUID REFERENCES procurement.purchase_orders(id) ON DELETE SET NULL,
    created_at                            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_purchase_rec_status ON ai.purchase_recommendations(status);

-- Now that ai.purchase_recommendations exists, wire up the deferred FK from 005.
ALTER TABLE procurement.purchase_orders
    ADD CONSTRAINT fk_po_source_recommendation
    FOREIGN KEY (source_recommendation_id) REFERENCES ai.purchase_recommendations(id) ON DELETE SET NULL;

-- ---- ai.forecasts / ai.alerts -------------------------------------------------------
-- Generic containers referenced by the spec ("Forecasts", "Alerts" as top-level
-- tables) — kept as thin views over the more specific tables above so the
-- dashboard can query one place without duplicating data.

CREATE VIEW ai.forecasts AS
    SELECT id, model_id, item_id, warehouse_id, forecast_date, granularity,
           predicted_demand, confidence_lower, confidence_upper, generated_at
    FROM ai.demand_forecasts;
-- ============================================================================
-- 007_ops_and_audit.sql
-- Documents (MinIO object references), notifications, alerts, audit logs.
-- ============================================================================

-- ---- ops.documents -----------------------------------------------------------
-- Metadata row for every file stored in MinIO. The actual bytes live in
-- object storage; this table is the searchable, permissioned index over them.

CREATE TABLE ops.documents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    document_type        TEXT NOT NULL,           -- 'purchase_document' | 'invoice' | 'supplier_contract' | 'medicine_image' | 'audit_report'
    related_type            TEXT,                    -- e.g. 'purchase_order', 'supplier'
    related_id                UUID,
    object_key                   TEXT NOT NULL,           -- MinIO object key
    bucket                          TEXT NOT NULL,
    original_filename                 TEXT NOT NULL,
    mime_type                           TEXT,
    size_bytes                            BIGINT,
    embedding                               vector(1536),  -- pgvector: document semantic search
    uploaded_by                              UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    uploaded_at                                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_documents_related ON ops.documents(related_type, related_id);
CREATE INDEX idx_documents_embedding ON ops.documents USING hnsw (embedding vector_cosine_ops);

ALTER TABLE procurement.invoices
    ADD CONSTRAINT fk_invoices_document
    FOREIGN KEY (document_id) REFERENCES ops.documents(id) ON DELETE SET NULL;

-- ---- ops.alerts ----------------------------------------------------------------
-- Low stock, expiring medicines, AI shortage predictions, procurement
-- recommendations — all surfaced through one alerts table the dashboard polls.

CREATE TABLE ops.alerts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hospital_id         UUID NOT NULL REFERENCES org.hospitals(id) ON DELETE CASCADE,
    alert_type            TEXT NOT NULL,          -- 'low_stock' | 'expiring_medicine' | 'ai_shortage_prediction' | 'procurement_recommendation' | 'anomaly'
    severity                ops.alert_severity NOT NULL DEFAULT 'warning',
    related_type              TEXT,
    related_id                  UUID,
    title                          TEXT NOT NULL,
    message                          TEXT,
    is_acknowledged                    BOOLEAN NOT NULL DEFAULT false,
    acknowledged_by                       UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    acknowledged_at                         TIMESTAMPTZ,
    created_at                                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_unacknowledged ON ops.alerts(hospital_id, is_acknowledged) WHERE NOT is_acknowledged;
CREATE INDEX idx_alerts_type ON ops.alerts(alert_type);

-- ---- ops.notifications -----------------------------------------------------------

CREATE TABLE ops.notifications (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
    alert_id                UUID REFERENCES ops.alerts(id) ON DELETE CASCADE,
    channel                    ops.notification_channel NOT NULL,
    subject                       TEXT,
    body                             TEXT,
    is_read                            BOOLEAN NOT NULL DEFAULT false,
    sent_at                              TIMESTAMPTZ,
    read_at                                TIMESTAMPTZ,
    created_at                               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_notifications_user_unread ON ops.notifications(user_id, is_read) WHERE NOT is_read;

-- ---- audit.audit_logs (TimescaleDB hypertable, append-only) ------------------------
-- Immutable log: no UPDATE/DELETE grants issued to the application role
-- (see 008_security.sql). Covers login attempts, inventory updates,
-- purchases, stock adjustments, AI recommendations acted on, etc.

CREATE TABLE audit.audit_logs (
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    hospital_id         UUID REFERENCES org.hospitals(id) ON DELETE SET NULL,
    actor_user_id         UUID REFERENCES identity.users(id) ON DELETE SET NULL,
    action                  TEXT NOT NULL,        -- 'login', 'inventory.adjust', 'po.approve', 'ai_recommendation.accept', ...
    entity_type                TEXT,
    entity_id                    UUID,
    ip_address                     INET,
    user_agent                       TEXT,
    before_state                       JSONB,
    after_state                          JSONB,
    occurred_at                            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, occurred_at)
);

SELECT create_hypertable('audit.audit_logs', 'occurred_at', if_not_exists => TRUE);
CREATE INDEX idx_audit_logs_actor ON audit.audit_logs(actor_user_id, occurred_at DESC);
CREATE INDEX idx_audit_logs_entity ON audit.audit_logs(entity_type, entity_id);
CREATE INDEX idx_audit_logs_action ON audit.audit_logs(action);

-- Long-term retention: compress after 30 days, never auto-drop (compliance).
ALTER TABLE audit.audit_logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'hospital_id, action'
);
SELECT add_compression_policy('audit.audit_logs', INTERVAL '30 days', if_not_exists => TRUE);
-- ============================================================================
-- 008_security.sql
-- Database roles/grants, row-level security (multi-tenant isolation by
-- hospital), and column-level encryption pattern.
--
-- This gives you a real, working baseline — not the full HIPAA/GDPR program
-- described in the spec (that also requires policy docs, BAAs, pen testing,
-- and an actual compliance review, none of which is a SQL file).
-- ============================================================================

-- ---- Application roles --------------------------------------------------------
-- The NestJS backend connects as app_user (no DDL rights, no direct access
-- to audit.audit_logs beyond INSERT — enforced by REVOKE below).

CREATE ROLE app_user LOGIN PASSWORD 'CHANGE_ME_VIA_VAULT';
CREATE ROLE app_readonly LOGIN PASSWORD 'CHANGE_ME_VIA_VAULT';   -- BI / reporting tools
CREATE ROLE ai_service LOGIN PASSWORD 'CHANGE_ME_VIA_VAULT';      -- FastAPI AI microservice

GRANT USAGE ON SCHEMA identity, org, catalog, inventory, procurement, ai, ops, audit
    TO app_user, app_readonly, ai_service;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA identity, org, catalog, inventory, procurement, ops
    TO app_user;
GRANT SELECT ON ALL TABLES IN SCHEMA identity, org, catalog, inventory, procurement, ai, ops, audit
    TO app_readonly;

-- Audit logs: application can INSERT (write the event) but never UPDATE or
-- DELETE — that's what "immutable" means in practice.
GRANT SELECT, INSERT ON audit.audit_logs TO app_user;
REVOKE UPDATE, DELETE ON audit.audit_logs FROM app_user;

-- AI service: full read on operational data it forecasts from, full write
-- only on its own ai.* tables.
GRANT SELECT ON ALL TABLES IN SCHEMA org, catalog, inventory, procurement TO ai_service;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA ai TO ai_service;

-- ---- Row-Level Security: hospital tenant isolation -----------------------------
-- Every multi-tenant table gets a policy keyed off the session variable
-- `app.current_hospital_id`, set by the backend per-request after auth
-- (SET LOCAL app.current_hospital_id = '<uuid>';). Shown here for the
-- highest-sensitivity tables; apply the same pattern to the rest.

ALTER TABLE identity.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON identity.users
    USING (hospital_id = current_setting('app.current_hospital_id', true)::uuid);

ALTER TABLE catalog.items ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_items ON catalog.items
    USING (hospital_id = current_setting('app.current_hospital_id', true)::uuid);

ALTER TABLE catalog.suppliers ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_suppliers ON catalog.suppliers
    USING (hospital_id = current_setting('app.current_hospital_id', true)::uuid);

ALTER TABLE procurement.purchase_orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_po ON procurement.purchase_orders
    USING (hospital_id = current_setting('app.current_hospital_id', true)::uuid);

ALTER TABLE audit.audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit ON audit.audit_logs
    USING (hospital_id = current_setting('app.current_hospital_id', true)::uuid);

-- Auditors get a bypass policy so they can see across hospitals if their
-- role requires it — enforce that at the application layer (check role
-- before setting a broader session context), not by weakening RLS here.

-- ---- Column-level encryption pattern (pgcrypto) --------------------------------
-- Sensitive fields (purchase prices, supplier contract terms) use
-- pgp_sym_encrypt/decrypt with a key pulled from Vault at connection time
-- via the app.current_encryption_key session variable — never hardcode the
-- key in SQL. Example helper functions:

CREATE OR REPLACE FUNCTION identity.encrypt_field(plain TEXT)
RETURNS BYTEA AS $$
    SELECT pgp_sym_encrypt(plain, current_setting('app.current_encryption_key', true));
$$ LANGUAGE sql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION identity.decrypt_field(cipher BYTEA)
RETURNS TEXT AS $$
    SELECT pgp_sym_decrypt(cipher, current_setting('app.current_encryption_key', true));
$$ LANGUAGE sql SECURITY DEFINER;

-- Usage example (apply to a real encrypted column when you add one):
--   ALTER TABLE catalog.suppliers ADD COLUMN contract_terms_encrypted BYTEA;
--   UPDATE catalog.suppliers SET contract_terms_encrypted = identity.encrypt_field('...');
--   SELECT identity.decrypt_field(contract_terms_encrypted) FROM catalog.suppliers;

-- ---- Seed baseline roles/permissions -------------------------------------------

INSERT INTO identity.roles (name, description) VALUES
    ('super_admin', 'Full system access across all hospitals'),
    ('hospital_admin', 'Full access within a single hospital'),
    ('pharmacist', 'Medicine dispensing and stock management'),
    ('inventory_manager', 'Inventory, batches, transfers, stock adjustments'),
    ('procurement_officer', 'Purchase orders, suppliers, invoices'),
    ('doctor', 'Read access to stock availability, request items'),
    ('auditor', 'Read-only access to audit logs and reports')
ON CONFLICT (name) DO NOTHING;
