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
