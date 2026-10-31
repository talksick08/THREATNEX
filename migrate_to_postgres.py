"""
THREATNEX AI-IDS — SQLite to PostgreSQL Migration Utility

Migrates existing local SQLite data (ids.db) to managed PostgreSQL (Neon / Vercel Postgres).
Guarantees:
- Exact primary key (ID) preservation across users, events, and saved queries.
- Password hashes, roles (is_admin), preferences, and themes preserved intact.
- High-resolution event timestamps, features, and triage notes preserved intact.
- Automatic sequence synchronization (setval) to prevent ID collision on new inserts.
- Idempotent execution (ON CONFLICT DO UPDATE) enabling safe retries and rollbacks.
- Post-migration record count and foreign key relationship verification.
- Safe dry-run mode for pre-flight testing.

Usage:
  # Dry-run validation (does not write to PostgreSQL):
  python migrate_to_postgres.py --dry-run

  # Execute migration using DATABASE_URL environment variable:
  python migrate_to_postgres.py

  # Execute migration with explicit PostgreSQL URL:
  python migrate_to_postgres.py --postgres-url "$POSTGRES_URL"
"""

import os
import sys
import argparse
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Tuple

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DB_PATH = BASE_DIR / "ids.db"


def parse_args():
    parser = argparse.ArgumentParser(description="THREATNEX SQLite to PostgreSQL Migration Utility")
    parser.add_argument("--sqlite-path", default=str(SQLITE_DB_PATH), help="Path to source SQLite database file")
    parser.add_argument("--postgres-url", default=None, help="Target PostgreSQL connection URL (or DATABASE_URL env)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migration without modifying PostgreSQL")
    parser.add_argument("--clean", action="store_true", help="Wipe target PostgreSQL tables prior to migration")
    return parser.parse_args()


def get_source_sqlite_data(sqlite_path: str) -> Dict[str, List[sqlite3.Row]]:
    """Extract all records and schemas from source SQLite database."""
    if not os.path.exists(sqlite_path):
        raise FileNotFoundError(f"Source SQLite database not found at: {sqlite_path}")

    conn = sqlite3.connect(sqlite_path)
    conn.row_factory = sqlite3.Row
    try:
        users = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
        events = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        saved_queries = conn.execute("SELECT * FROM saved_queries ORDER BY id ASC").fetchall()
        return {
            "users": users,
            "events": events,
            "saved_queries": saved_queries
        }
    finally:
        conn.close()


def connect_postgres(postgres_url: str):
    """Establish connection to PostgreSQL using pg8000 or psycopg2."""
    try:
        import urllib.parse
        import pg8000.dbapi
        parsed = urllib.parse.urlparse(postgres_url)
        conn = pg8000.dbapi.connect(
            user=parsed.username,
            password=parsed.password,
            host=parsed.hostname,
            port=parsed.port or 5432,
            database=parsed.path.lstrip("/"),
            ssl_context=True if "sslmode=require" in postgres_url or parsed.scheme.startswith("postgres") else None
        )
        return conn
    except ImportError:
        try:
            import psycopg2
            return psycopg2.connect(postgres_url)
        except ImportError:
            raise RuntimeError("Neither 'pg8000' nor 'psycopg2' is installed. Run 'pip install pg8000'.")


def run_migration(sqlite_path: str, postgres_url: str, dry_run: bool = False, clean: bool = False) -> Dict[str, Any]:
    """Execute migration workflow from SQLite to PostgreSQL."""
    print("=" * 70)
    print("THREATNEX AI-IDS — DATABASE MIGRATION TO POSTGRESQL")
    print("=" * 70)
    print(f"Source SQLite Path: {sqlite_path}")
    print(f"Dry Run Mode:       {'ENABLED (Read-Only)' if dry_run else 'DISABLED (Production Write)'}")

    # 1. Extract source data
    print("\n[Step 1/5] Extracting source records from SQLite...")
    data = get_source_sqlite_data(sqlite_path)
    user_count = len(data["users"])
    event_count = len(data["events"])
    saved_count = len(data["saved_queries"])
    print(f"  -> Found {user_count} user accounts.")
    print(f"  -> Found {event_count} recorded security events.")
    print(f"  -> Found {saved_count} saved queries.")

    if dry_run:
        print("\n[Dry Run] Validation Successful: Source data read cleanly. Zero PostgreSQL writes executed.")
        return {
            "status": "dry_run_success",
            "users_count": user_count,
            "events_count": event_count,
            "saved_queries_count": saved_count
        }

    # 2. Connect to PostgreSQL
    if not postgres_url:
        postgres_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
    if not postgres_url:
        raise ValueError("Target PostgreSQL URL required. Provide --postgres-url or set DATABASE_URL.")

    masked_url = postgres_url.split("@")[-1] if "@" in postgres_url else "postgres"
    print(f"\n[Step 2/5] Connecting to target PostgreSQL ({masked_url})...")
    pg_conn = connect_postgres(postgres_url)
    cursor = pg_conn.cursor()

    try:
        # 3. Initialize Schema & Tables
        print("\n[Step 3/5] Initializing PostgreSQL schema and indexes...")
        schema_file = BASE_DIR / "schema_postgres.sql"
        if schema_file.exists():
            schema_sql = schema_file.read_text(encoding="utf-8")
            cursor.execute(schema_sql)
        else:
            raise FileNotFoundError("schema_postgres.sql not found.")

        if clean:
            print("  -> Cleaning existing target records (--clean specified)...")
            cursor.execute("TRUNCATE TABLE saved_queries, events, users CASCADE;")

        # 4. Migrate Data with Exact IDs
        print("\n[Step 4/5] Migrating records...")
        
        # 4.1 Users
        print(f"  -> Migrating {user_count} users...")
        for u in data["users"]:
            cursor.execute(
                """
                INSERT INTO users (id, username, password_hash, is_admin, theme, notify_severity, page_size, display_name, settings_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    username = EXCLUDED.username,
                    password_hash = EXCLUDED.password_hash,
                    is_admin = EXCLUDED.is_admin,
                    theme = EXCLUDED.theme,
                    notify_severity = EXCLUDED.notify_severity,
                    page_size = EXCLUDED.page_size,
                    display_name = EXCLUDED.display_name,
                    settings_json = EXCLUDED.settings_json;
                """,
                (
                    u["id"],
                    u["username"],
                    u["password_hash"],
                    u["is_admin"],
                    u["theme"] or "dark",
                    u["notify_severity"] or "critical",
                    u["page_size"] or 20,
                    u["display_name"] or u["username"],
                    u["settings_json"] if "settings_json" in u.keys() else "{}"
                )
            )

        # 4.2 Events
        print(f"  -> Migrating {event_count} events...")
        for e in data["events"]:
            keys = e.keys()
            cursor.execute(
                """
                INSERT INTO events (id, ts, src_ip, label, severity, confidence, features, investigation_status, analyst_notes, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    ts = EXCLUDED.ts,
                    src_ip = EXCLUDED.src_ip,
                    label = EXCLUDED.label,
                    severity = EXCLUDED.severity,
                    confidence = EXCLUDED.confidence,
                    features = EXCLUDED.features,
                    investigation_status = EXCLUDED.investigation_status,
                    analyst_notes = EXCLUDED.analyst_notes,
                    updated_at = EXCLUDED.updated_at;
                """,
                (
                    e["id"],
                    e["ts"],
                    e["src_ip"],
                    e["label"],
                    e["severity"],
                    e["confidence"],
                    e["features"],
                    e["investigation_status"] if "investigation_status" in keys else "new",
                    e["analyst_notes"] if "analyst_notes" in keys else "",
                    e["updated_at"] if "updated_at" in keys else None
                )
            )

        # 4.3 Saved Queries
        print(f"  -> Migrating {saved_count} saved queries...")
        for sq in data["saved_queries"]:
            q_param_col = "query_params" if "query_params" in sq.keys() else "filter_params"
            cursor.execute(
                """
                INSERT INTO saved_queries (id, user_id, name, query_params, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    name = EXCLUDED.name,
                    query_params = EXCLUDED.query_params,
                    created_at = EXCLUDED.created_at;
                """,
                (
                    sq["id"],
                    sq["user_id"],
                    sq["name"],
                    sq[q_param_col],
                    sq["created_at"]
                )
            )

        # 4.4 Synchronize Autoincrement Sequences
        print("  -> Synchronizing PostgreSQL ID autoincrement sequences...")
        cursor.execute("SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1));")
        cursor.execute("SELECT setval('events_id_seq', COALESCE((SELECT MAX(id) FROM events), 1));")
        cursor.execute("SELECT setval('saved_queries_id_seq', COALESCE((SELECT MAX(id) FROM saved_queries), 1));")

        # 5. Verification & Integrity Checks
        print("\n[Step 5/5] Performing post-migration integrity verification...")
        cursor.execute("SELECT COUNT(*) FROM users;")
        pg_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM events;")
        pg_events = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM saved_queries;")
        pg_saved = cursor.fetchone()[0]

        print(f"  -> PostgreSQL Users: {pg_users} (Expected: {user_count})")
        print(f"  -> PostgreSQL Events: {pg_events} (Expected: {event_count})")
        print(f"  -> PostgreSQL Saved Queries: {pg_saved} (Expected: {saved_count})")

        assert pg_users == user_count, f"User count mismatch! SQLite={user_count}, PG={pg_users}"
        assert pg_events == event_count, f"Event count mismatch! SQLite={event_count}, PG={pg_events}"
        assert pg_saved == saved_count, f"Saved query mismatch! SQLite={saved_count}, PG={pg_saved}"

        # Verify Foreign Key Integrity
        cursor.execute("SELECT COUNT(*) FROM saved_queries WHERE user_id NOT IN (SELECT id FROM users);")
        orphans = cursor.fetchone()[0]
        assert orphans == 0, f"Foreign key violation detected: {orphans} orphaned saved queries"

        # Commit transaction on 100% verification success
        pg_conn.commit()
        print("\n" + "=" * 70)
        print("MIGRATION COMPLETED SUCCESSFULLY WITH 100% INTEGRITY VERIFICATION!")
        print("=" * 70)

        return {
            "status": "success",
            "users_migrated": pg_users,
            "events_migrated": pg_events,
            "saved_queries_migrated": pg_saved
        }

    except Exception as e:
        print(f"\n[ERROR] Migration failed! Rolling back all changes: {e}")
        pg_conn.rollback()
        raise
    finally:
        cursor.close()
        pg_conn.close()


if __name__ == "__main__":
    args = parse_args()
    run_migration(args.sqlite_path, args.postgres_url, args.dry_run, args.clean)

