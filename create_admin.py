#!/usr/bin/env python3
"""
Interactive admin-account creation script for THREATNEX.

Usage:
    python create_admin.py

The script prompts for a username and password (the password is never
displayed on screen), hashes it with the same werkzeug method used by
the login route, and inserts a new admin row into the existing database.

Existing users, events, model files, and all other data are preserved.
"""

import getpass
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

# Reuse the same database path logic as app.py
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ids.db"


def main():
    if not DB_PATH.exists():
        print(f"Error: database not found at {DB_PATH}")
        sys.exit(1)

    # Ensure the users table exists (mirrors init_db() in app.py)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute(
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
    try:
        conn.execute("ALTER TABLE users ADD COLUMN settings_json TEXT DEFAULT '{}'")
    except sqlite3.OperationalError:
        pass
    conn.commit()

    # ── Prompt for username ──────────────────────────────────────────
    username = input("Enter admin username: ").strip()
    if not username:
        print("Error: username cannot be empty.")
        conn.close()
        sys.exit(1)

    # Check whether the username already exists
    existing = conn.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing:
        print(f'Error: user "{username}" already exists.')
        conn.close()
        sys.exit(1)

    # ── Prompt for password (hidden input) ───────────────────────────
    password = getpass.getpass("Enter admin password: ")
    if len(password) < 6:
        print("Error: password must be at least 6 characters.")
        conn.close()
        sys.exit(1)

    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: passwords do not match.")
        conn.close()
        sys.exit(1)

    # ── Insert the admin user ────────────────────────────────────────
    hashed = generate_password_hash(password)
    conn.execute(
        "INSERT INTO users (username, password_hash, is_admin, theme, notify_severity, page_size, display_name, settings_json) VALUES (?, ?, 1, 'dark', 'critical', 20, ?, '{}')",
        (username, hashed, username),
    )
    conn.commit()
    conn.close()

    print(f'Admin user "{username}" created successfully.')
    print("You can now log in at http://localhost:5000/login")


if __name__ == "__main__":
    main()
