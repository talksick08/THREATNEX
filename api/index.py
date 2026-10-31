"""
THREATNEX AI-IDS — Vercel Serverless Function Entry Point (WSGI)

Exposes the core Flask application instance to Vercel's Python runtime.
Ensures static directory resolution, diagnostic routing inspection,
and WSGI PATH_INFO normalization.
"""

import os
import sys
import json
import urllib.parse
from pathlib import Path

# Add project root directory to Python search path so local imports resolve cleanly
CURRENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = CURRENT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Signal Vercel runtime environment to internal configuration
os.environ.setdefault("VERCEL", "1")

# Import the initialized Flask application instance
from app import app as flask_app


class VercelWSGIProxy:
    """
    WSGI middleware for Vercel Serverless Python runtime:
    1. Intercepts /api/debug-routing and X-Debug-Routing header for live diagnostics.
    2. Detects if PATH_INFO was rewritten or altered by Vercel Edge, and resolves
       the true client request path from __vercel_path or available headers.
    3. Normalizes SCRIPT_NAME and cleans any spurious forwarded prefixes.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        
        # Diagnostic hook to inspect live Vercel WSGI environment
        if path_info == "/api/debug-routing" or environ.get("HTTP_X_DEBUG_ROUTING") == "1":
            diagnostic_data = {
                "PATH_INFO": environ.get("PATH_INFO"),
                "SCRIPT_NAME": environ.get("SCRIPT_NAME"),
                "RAW_URI": environ.get("RAW_URI"),
                "REQUEST_URI": environ.get("REQUEST_URI"),
                "QUERY_STRING": environ.get("QUERY_STRING"),
                "SERVER_NAME": environ.get("SERVER_NAME"),
                "SERVER_PORT": environ.get("SERVER_PORT"),
                "headers": {
                    k: v for k, v in environ.items()
                    if k.startswith("HTTP_") or k in ("CONTENT_TYPE", "CONTENT_LENGTH", "REMOTE_ADDR")
                }
            }
            body = json.dumps(diagnostic_data, indent=2).encode("utf-8")
            start_response("200 OK", [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body)))
            ])
            return [body]

        # Prevent ProxyFix from poisoning SCRIPT_NAME if Vercel passes internal prefix
        if environ.get("HTTP_X_FORWARDED_PREFIX") in ("/api/index", "/api/index.py", "/api"):
            del environ["HTTP_X_FORWARDED_PREFIX"]

        # 1. Primary path resolution: __vercel_path passed via vercel.json rewrite
        query = environ.get("QUERY_STRING", "")
        target_path = None
        if "__vercel_path=" in query:
            clean_query_parts = []
            for part in query.split("&"):
                if part.startswith("__vercel_path="):
                    val = part.split("=", 1)[1]
                    target_path = "/" + urllib.parse.unquote(val).lstrip("/")
                else:
                    clean_query_parts.append(part)
            environ["QUERY_STRING"] = "&".join(clean_query_parts)
            if target_path:
                environ["PATH_INFO"] = target_path

        # 2. Secondary path resolution: fallback to proxy/edge headers if path is still /api/index
        elif environ.get("PATH_INFO", "") in ("/api/index", "/api/index.py", "/api", ""):
            for header_key in (
                "HTTP_X_FORWARDED_URI",
                "HTTP_X_ORIGINAL_PATH",
                "HTTP_X_ORIGINAL_URI",
                "HTTP_X_VERCEL_PATH",
                "RAW_URI",
                "REQUEST_URI",
                "HTTP_X_MATCHED_PATH",
            ):
                candidate = environ.get(header_key)
                if candidate and candidate not in ("/api/index", "/api/index.py", "/api"):
                    if "?" in candidate:
                        candidate = candidate.split("?", 1)[0]
                    environ["PATH_INFO"] = candidate
                    break

        # Fallback default if path_info is still empty or points to /api/index
        current_path = environ.get("PATH_INFO", "")
        if not current_path or current_path in ("/api/index", "/api/index.py", "/api"):
            environ["PATH_INFO"] = "/"

        return self.wsgi_app(environ, start_response)


# Vercel's Python serverless builder automatically uses 'app' or 'application' as the WSGI callable.
app = VercelWSGIProxy(flask_app)
application = app

if __name__ == "__main__":
    flask_app.run()
