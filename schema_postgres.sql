-- ==============================================================================
-- THREATNEX AI-IDS — POSTGRESQL PRODUCTION SCHEMA (Neon / Vercel Postgres)
-- ==============================================================================
-- Compatible with Neon Serverless Postgres, Vercel Postgres, Supabase, and AWS RDS.
-- ==============================================================================

-- 1. Users Table (SOC Analyst authentication, role governance, and preferences)
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    theme VARCHAR(32) DEFAULT 'dark',
    notify_severity VARCHAR(16) DEFAULT 'critical',
    page_size INTEGER DEFAULT 20,
    display_name VARCHAR(64),
    settings_json TEXT DEFAULT '{}'
);

-- Performance Index on Users
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. Events Table (Real-time network security event ingestion and audit log)
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    ts DOUBLE PRECISION NOT NULL,
    src_ip VARCHAR(64) NOT NULL,
    label VARCHAR(32) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    features TEXT NOT NULL,
    investigation_status VARCHAR(32) DEFAULT 'new',
    analyst_notes TEXT DEFAULT '',
    updated_at DOUBLE PRECISION
);

-- Performance Indexes on Events
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_label ON events(label);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(investigation_status);

-- 3. Saved Queries Table (Threat-hunting query presets and investigator bookmarks)
CREATE TABLE IF NOT EXISTS saved_queries (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    name VARCHAR(128) NOT NULL,
    query_params TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL,
    CONSTRAINT fk_saved_queries_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Performance Index on Saved Queries
CREATE INDEX IF NOT EXISTS idx_saved_queries_user ON saved_queries(user_id);
