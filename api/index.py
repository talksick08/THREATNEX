"""
THREATNEX AI-IDS — Vercel Serverless Function Entry Point (WSGI)

Exposes the core Flask application instance to Vercel's Python runtime.
Ensures static directory resolution and environment variable defaults.
"""

import os
import sys
from pathlib import Path

# Add project root directory to Python search path so local imports resolve cleanly
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Signal Vercel runtime environment to internal configuration
os.environ.setdefault("VERCEL", "1")

# Import the initialized Flask application instance
from app import app

# Vercel's Python serverless builder automatically uses 'app' as the WSGI callable.
if __name__ == "__main__":
    app.run()

