"""
THREATNEX AI-IDS — Dual-Engine Database Adapter (SQLite & PostgreSQL)

Provides seamless, transparent database abstraction supporting:
1. SQLite: Local development and testing (preserves ids.db).
2. Managed PostgreSQL: Production deployment (Neon / Vercel Postgres / Supabase).

Key Capabilities:
- Automatic backend detection via DATABASE_URL or POSTGRES_URL.
- Unified parameterized query execution with dialect translation:
  - Transparent '?' to '%s' parameter placeholder conversion.
  - SQLite strftime('%Y-%m-%d %H:00', datetime(ts, 'unixepoch')) -> PostgreSQL to_char(to_timestamp(ts), 'YYYY-MM-DD HH24:00').
  - Collision-proof sequence synchronization: resets sequence to COALESCE(MAX(id), 0) + 1, false to eliminate duplicate ID risks.
  - Table-aware RETURNING id append: only targets tables with verified 'id' primary keys and respects existing RETURNING / ON CONFLICT clauses.
  - Idempotent ALTER TABLE ADD COLUMN IF NOT EXISTS translation.
- Standardized PostgresRow wrapper supporting dictionary access (row['col']) and numeric index (row[0]).
- Transactional context manager (with get_connection() as conn: ...).
- Automatic rollback on unhandled exceptions and explicit commit on completion.
- Idempotent schema initialization and performance index creation.
"""

import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

BASE_DIR = Path(__file__).resolve().parent
SQLITE_DB_PATH = BASE_DIR / "ids.db"

# Tables in THREATNEX known to feature an autoincrementing 'id' primary key
TABLES_WITH_ID = ("events", "users", "saved_queries")


class PostgresRow:
    """Dictionary-like row wrapper matching sqlite3.Row functionality for PostgreSQL."""

    def __init__(self, description: Any, values: Tuple[Any, ...]):
        self._columns = [d[0] for d in description] if description else []
        self._values = tuple(values)
        self._map = {col: val for col, val in zip(self._columns, self._values)}

    def __getitem__(self, key: Union[str, int]) -> Any:
        if isinstance(key, str):
            return self._map[key]
        return self._values[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._map.get(key, default)

    def keys(self) -> List[str]:
        return list(self._columns)

    def values(self) -> List[Any]:
        return list(self._values)

    def items(self) -> List[Tuple[str, Any]]:
        return list(self._map.items())

    def __iter__(self):
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)

    def __contains__(self, key: str) -> bool:
        return key in self._map

    def __repr__(self) -> str:
        return f"<PostgresRow {self._map}>"


def translate_sqlite_to_postgres(sql: str, params: Optional[Union[Tuple, List, Dict]] = None) -> Tuple[str, Optional[Tuple]]:
    """
    Translate SQLite-specific SQL syntax to PostgreSQL standard syntax.
    
    Handles:
    1. strftime('%Y-%m-%d %H:00', datetime(ts, 'unixepoch')) -> to_char(to_timestamp(ts), 'YYYY-MM-DD HH24:00')
    2. Collision-proof sequence synchronization:
       DELETE FROM sqlite_sequence WHERE name = 'table' -> 
       SELECT setval('table_id_seq', COALESCE((SELECT MAX(id) FROM table), 0) + 1, false)
    3. Idempotent column addition:
       ALTER TABLE tbl ADD COLUMN col type -> ALTER TABLE tbl ADD COLUMN IF NOT EXISTS col type
    4. Parameter placeholder '?' -> '%s'
    5. Table-aware RETURNING id append on INSERT
    """
    pg_sql = sql.strip()
    out_params = tuple(params) if params is not None else None

    # 1. strftime / datetime translation
    if "strftime" in pg_sql and "datetime" in pg_sql:
        pg_sql = re.sub(
            r"strftime\s*\(\s*'\%Y-\%m-\%d\s+\%H:00'\s*,\s*datetime\s*\(\s*ts\s*,\s*'unixepoch'\s*\)\s*\)",
            "to_char(to_timestamp(ts), 'YYYY-MM-DD HH24:00')",
            pg_sql,
            flags=re.IGNORECASE
        )
    elif "datetime(ts, 'unixepoch')" in pg_sql:
        pg_sql = pg_sql.replace("datetime(ts, 'unixepoch')", "to_timestamp(ts)")

    # 2. Collision-proof sequence synchronization (safe against partial deletes or populated tables)
    if "sqlite_sequence" in pg_sql:
        match = re.search(r"WHERE\s+name\s*=\s*['\"]?([a-zA-Z0-9_]+)['\"]?", pg_sql, re.IGNORECASE)
        table_name = match.group(1).lower() if match else "events"
        # Reset sequence safely: if empty, generates 1; if populated, generates MAX(id) + 1
        pg_sql = f"SELECT setval('{table_name}_id_seq', COALESCE((SELECT MAX(id) FROM {table_name}), 0) + 1, false);"
        out_params = None  # Consume any parameter intended for sqlite_sequence

    # 3. Idempotent column additions
    if pg_sql.upper().startswith("ALTER TABLE") and "ADD COLUMN" in pg_sql.upper():
        if "IF NOT EXISTS" not in pg_sql.upper():
            pg_sql = re.sub(r"ADD\s+COLUMN", "ADD COLUMN IF NOT EXISTS", pg_sql, flags=re.IGNORECASE)

    # 4. Convert '?' placeholders to '%s'
    if "?" in pg_sql:
        pg_sql = pg_sql.replace("?", "%s")

    # 5. Table-aware RETURNING id append for INSERT statements
    insert_match = re.match(r"INSERT\s+INTO\s+([a-zA-Z0-9_]+)", pg_sql, re.IGNORECASE)
    if insert_match:
        table_name = insert_match.group(1).lower()
        if table_name in TABLES_WITH_ID and "RETURNING" not in pg_sql.upper():
            pg_sql = pg_sql.rstrip().rstrip(";") + " RETURNING id;"

    return pg_sql, out_params


class PostgresCursorWrapper:
    """Cursor wrapper for PostgreSQL providing sqlite3-compatible execute & lastrowid."""

    def __init__(self, raw_cursor: Any):
        self._cursor = raw_cursor
        self.lastrowid: Optional[int] = None
        self._description = None

    def execute(self, sql: str, params: Optional[Union[Tuple, List, Dict]] = None) -> "PostgresCursorWrapper":
        pg_sql, pg_params = translate_sqlite_to_postgres(sql, params)
        is_insert = pg_sql.upper().startswith("INSERT INTO")

        if pg_params is not None:
            self._cursor.execute(pg_sql, pg_params)
        else:
            self._cursor.execute(pg_sql)

        # Retrieve inserted ID for lastrowid compatibility
        if is_insert and "RETURNING id" in pg_sql:
            try:
                ret = self._cursor.fetchone()
                if ret:
                    self.lastrowid = ret[0]
                else:
                    self.lastrowid = None
            except Exception:
                self.lastrowid = None
        else:
            self.lastrowid = None

        self._description = getattr(self._cursor, "description", None)
        return self

    def executemany(self, sql: str, seq_of_params: List[Union[Tuple, List]]) -> "PostgresCursorWrapper":
        pg_sql, _ = translate_sqlite_to_postgres(sql)
        self._cursor.executemany(pg_sql, seq_of_params)
        self._description = getattr(self._cursor, "description", None)
        return self

    def fetchone(self) -> Optional[PostgresRow]:
        row = self._cursor.fetchone()
        if row is None:
            return None
        return PostgresRow(self._description, row)

    def fetchall(self) -> List[PostgresRow]:
        rows = self._cursor.fetchall()
        if not rows:
            return []
        return [PostgresRow(self._description, r) for r in rows]

    def fetchmany(self, size: int = 1) -> List[PostgresRow]:
        rows = self._cursor.fetchmany(size)
        if not rows:
            return []
        return [PostgresRow(self._description, r) for r in rows]

    @property
    def description(self):
        return self._description

    @property
    def rowcount(self) -> int:
        return getattr(self._cursor, "rowcount", -1)

    def close(self):
        self._cursor.close()


class PostgresConnectionWrapper:
    """Connection wrapper managing PostgreSQL transactions with context manager support."""

    def __init__(self, raw_connection: Any):
        self._conn = raw_connection

    def cursor(self) -> PostgresCursorWrapper:
        return PostgresCursorWrapper(self._conn.cursor())

    def execute(self, sql: str, params: Optional[Union[Tuple, List, Dict]] = None) -> PostgresCursorWrapper:
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


def get_database_url() -> Optional[str]:
    """Retrieve production PostgreSQL connection URL from environment if configured."""
    return (
        os.getenv("NEON_TEST_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_URL")
        or os.getenv("POSTGRES_PRISMA_URL")
        or os.getenv("POSTGRES_URL_NON_POOLING")
    )


def get_db_engine_name() -> str:
    """Return the name of the active database engine."""
    url = get_database_url()
    if url and ("postgres" in url or "postgresql" in url):
        return "PostgreSQL (Managed Cloud Database)"
    return "SQLite3 (Local / Persistent)"


def get_connection(sqlite_path: Optional[Union[str, Path]] = None):
    """
    Establish a connection to the active database backend.
    
    If DATABASE_URL or POSTGRES_URL is configured:
        Connects to PostgreSQL using pg8000 (preferred pure-Python) or psycopg2.
    Otherwise:
        Connects to SQLite using the designated database path with timeout=15.0.
    """
    db_url = get_database_url()
    if db_url and ("postgres" in db_url or "postgresql" in db_url):
        # Prefer pg8000 for pure-Python AWS Lambda / Vercel compatibility
        try:
            import urllib.parse
            import pg8000.dbapi
            parsed = urllib.parse.urlparse(db_url)
            raw_conn = pg8000.dbapi.connect(
                user=parsed.username,
                password=parsed.password,
                host=parsed.hostname,
                port=parsed.port or 5432,
                database=parsed.path.lstrip("/"),
                ssl_context=True if "sslmode=require" in db_url or parsed.scheme.startswith("postgres") else None
            )
            return PostgresConnectionWrapper(raw_conn)
        except ImportError:
            try:
                import psycopg2
                raw_conn = psycopg2.connect(db_url)
                return PostgresConnectionWrapper(raw_conn)
            except ImportError:
                raise RuntimeError(
                    "PostgreSQL DATABASE_URL is configured, but neither 'pg8000' nor 'psycopg2' is installed. "
                    "Please install pg8000 via 'pip install pg8000'."
                )

    # SQLite Connection (Default Local)
    path = Path(sqlite_path) if sqlite_path else SQLITE_DB_PATH
    conn = sqlite3.connect(str(path), timeout=15.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(connection=None):
    """Create required schema tables on the active database engine."""
    engine = get_db_engine_name()
    if "PostgreSQL" in engine:
        _init_postgres_db(connection)
    else:
        _init_sqlite_db(connection)


def _init_sqlite_db(connection=None):
    """Initialize SQLite schema."""
    close_at_end = False
    if connection is None:
        connection = get_connection()
        close_at_end = True

    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                src_ip TEXT NOT NULL,
                label TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                features TEXT NOT NULL,
                investigation_status TEXT DEFAULT 'new',
                analyst_notes TEXT DEFAULT '',
                updated_at REAL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                theme TEXT,
                notify_severity TEXT,
                page_size INTEGER,
                display_name TEXT,
                settings_json TEXT DEFAULT '{}'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                query_params TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """
        )
        connection.commit()
    finally:
        if close_at_end:
            connection.close()


def _init_postgres_db(connection=None):
    """Initialize PostgreSQL schema with strict constraints and foreign keys."""
    close_at_end = False
    if connection is None:
        connection = get_connection()
        close_at_end = True

    try:
        connection.execute(
            """
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
            )
            """
        )
        connection.execute(
            """
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
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_queries (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                name VARCHAR(128) NOT NULL,
                query_params TEXT NOT NULL,
                created_at DOUBLE PRECISION NOT NULL,
                CONSTRAINT fk_saved_queries_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        connection.commit()
    finally:
        if close_at_end:
            connection.close()


def ensure_database_indexes(connection=None):
    """Create performance indexes idempotently on the active database engine."""
    close_at_end = False
    if connection is None:
        connection = get_connection()
        close_at_end = True

    indexes = [
        ("idx_users_username", "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"),
        ("idx_events_ts", "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC)"),
        ("idx_events_src_ip", "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)"),
        ("idx_events_label", "CREATE INDEX IF NOT EXISTS idx_events_label ON events(label)"),
        ("idx_events_severity", "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)"),
        ("idx_events_status", "CREATE INDEX IF NOT EXISTS idx_events_status ON events(investigation_status)"),
        ("idx_saved_queries_user", "CREATE INDEX IF NOT EXISTS idx_saved_queries_user ON saved_queries(user_id)"),
    ]

    try:
        for idx_name, sql in indexes:
            try:
                connection.execute(sql)
            except Exception:
                pass
        connection.commit()
    finally:
        if close_at_end:
            connection.close()
