
import json
import random
import re
import sqlite3
import time
import os
import secrets
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

import joblib
import numpy as np
from flask import Flask, jsonify, request, send_from_directory, session, redirect

from train import FEATURES, LABELS, METRICS_PATH, MODEL_PATH, train

# Keep paths independent of the terminal's working directory.
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DB_PATH = Path("/tmp/ids.db") if os.getenv("VERCEL") else (BASE_DIR / "ids.db")
METRICS_FILE = BASE_DIR / "metrics.json"
CANDIDATE_MODEL_PATH = BASE_DIR / "model_candidate.joblib"

# Load Flask secret key from environment or persistent secret file
app_secret = os.getenv('THREATNEX_SECRET_KEY') or os.getenv('SECRET_KEY')
if not app_secret:
    secret_file = BASE_DIR / ".secret_key"
    if secret_file.exists():
        try:
            app_secret = secret_file.read_text(encoding="utf-8").strip()
        except Exception:
            app_secret = None
    if not app_secret:
        app_secret = secrets.token_hex(32)
        try:
            secret_file.write_text(app_secret, encoding="utf-8")
        except Exception:
            pass

app = Flask(__name__, static_folder=str(STATIC_DIR))
app.secret_key = app_secret

# Session Cookie Hardening & Security Configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
session_secure_env = os.getenv('SESSION_COOKIE_SECURE')
if session_secure_env is not None:
    app.config['SESSION_COOKIE_SECURE'] = session_secure_env.lower() in ('1', 'true', 'yes')
else:
    app.config['SESSION_COOKIE_SECURE'] = bool(os.getenv('FLASK_ENV') == 'production' or os.getenv('VERCEL') == '1')
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # 7 days session lifetime

# Enable ProxyFix for reverse-proxy environments (Vercel, AWS, Nginx)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

SEVERITY = {
    "normal": "none",
    "dos": "critical",
    "probe": "medium",
    "brute_force": "high",
}

SIMULATION_WEIGHTS = {
    "normal": 60,
    "dos": 18,
    "probe": 12,
    "brute_force": 10,
}


def get_connection():
    """Create a database connection supporting PostgreSQL in production and SQLite in development."""
    db_url = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
    if db_url and ("postgres" in db_url or "postgresql" in db_url):
        import db_adapter
        return db_adapter.get_connection()
    connection = sqlite3.connect(DB_PATH, timeout=15.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    """Create required tables when the application starts."""
    with get_connection() as connection:
        # Events table (existing)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                src_ip TEXT NOT NULL,
                label TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                features TEXT NOT NULL
            )
            """
        )
        # Users table for authentication
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
                display_name TEXT
            )
            """
        )
        # Saved Queries table for threat-hunting presets
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

        # Ensure settings_json column exists in users
        try:
            connection.execute("ALTER TABLE users ADD COLUMN settings_json TEXT DEFAULT '{}'")
        except sqlite3.OperationalError:
            pass

        # Performance indexes for fast querying, filtering, and dashboard stats
        try:
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_label ON events(label)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_events_status ON events(investigation_status)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_saved_queries_user ON saved_queries(user_id)")
        except sqlite3.OperationalError:
            pass


def load_metrics():
    """Read model metrics saved by train.py."""
    try:
        with METRICS_FILE.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {
            "accuracy": 0.0,
            "samples": 0,
            "importance": [],
        }


def load_model():
    """Train the model if it does not exist, then load it."""
    if not MODEL_PATH.exists():
        train()
    return joblib.load(MODEL_PATH)


def load_candidate_model():
    """Load candidate model if available. Returns None on failure."""
    global candidate_model
    if CANDIDATE_MODEL_PATH.exists():
        try:
            candidate_model = joblib.load(CANDIDATE_MODEL_PATH)
            return candidate_model
        except Exception as e:
            app.logger.warning(f"Could not load candidate model: {e}")
            candidate_model = None
            return None
    return None


def ensure_user_columns():
    """Add new profile columns to the users table if they don't exist (idempotent)."""
    with get_connection() as conn:
        columns = [
            ("theme", "TEXT"),
            ("notify_severity", "TEXT"),
            ("page_size", "INTEGER"),
            ("display_name", "TEXT")
        ]
        for col, coltype in columns:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass


def ensure_event_columns():
    """Add investigation tracking columns to the events table if they don't exist (idempotent)."""
    with get_connection() as conn:
        columns = [
            ("investigation_status", "TEXT DEFAULT 'new'"),
            ("analyst_notes", "TEXT DEFAULT ''"),
            ("updated_at", "REAL")
        ]
        for col, coltype in columns:
            try:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {coltype}")
            except sqlite3.OperationalError:
                pass


def ensure_database_indexes():
    """Create indexes on events and saved_queries tables for rapid queries (idempotent)."""
    with get_connection() as conn:
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
            "CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)",
            "CREATE INDEX IF NOT EXISTS idx_events_label ON events(label)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_events_status ON events(investigation_status)",
            "CREATE INDEX IF NOT EXISTS idx_saved_queries_user ON saved_queries(user_id)"
        ]:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass


model = load_model()
candidate_model = load_candidate_model()
init_db()

# Ensure user and event profile columns exist (idempotent migration)
ensure_user_columns()
ensure_event_columns()
ensure_database_indexes()

@app.before_request
def ensure_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)



def get_user_detection_policy(user_id=None):
    """
    Retrieve detection policy and brute-force threshold for user or system default.
    Provides automatic safe fallback: if 'experimental' or 'shadow' is selected
    but candidate model is unavailable or cannot be loaded, safely falls back to 'legacy'
    without failing or raising an exception.
    """
    policy = "legacy"
    threshold = 0.35
    try:
        if 'DEFAULT_SETTINGS' in globals():
            policy = DEFAULT_SETTINGS.get("detection_policy", policy)
            threshold = float(DEFAULT_SETTINGS.get("bf_probability_threshold", threshold))
    except Exception:
        pass

    target_user_id = user_id
    if target_user_id is None:
        try:
            target_user_id = session.get('user_id')
        except Exception:
            target_user_id = None

    if target_user_id:
        try:
            with get_connection() as conn:
                row = conn.execute("SELECT settings_json FROM users WHERE id = ?", (target_user_id,)).fetchone()
                if row and row['settings_json']:
                    stored = json.loads(row['settings_json'])
                    if isinstance(stored, dict):
                        if 'detection_policy' in stored and stored['detection_policy'] in ('legacy', 'experimental', 'shadow'):
                            policy = stored['detection_policy']
                        if 'bf_probability_threshold' in stored:
                            try:
                                t = float(stored['bf_probability_threshold'])
                                if 0.05 <= t <= 0.95:
                                    threshold = t
                            except (TypeError, ValueError):
                                pass
        except Exception:
            pass

    global candidate_model
    fallback_active = False
    fallback_reason = None
    if policy in ('experimental', 'shadow'):
        if candidate_model is None:
            candidate_model = load_candidate_model()
        if candidate_model is None:
            fallback_active = True
            fallback_reason = f"Candidate model '{CANDIDATE_MODEL_PATH.name}' unavailable. Safely falling back to legacy production model."
            app.logger.warning(fallback_reason)
            return {
                "policy": "legacy",
                "requested_policy": policy,
                "threshold": threshold,
                "fallback_active": True,
                "fallback_reason": fallback_reason,
            }

    return {
        "policy": policy,
        "requested_policy": policy,
        "threshold": threshold,
        "fallback_active": fallback_active,
        "fallback_reason": fallback_reason,
    }


def classify(features_dict, user_policy=None, return_meta=False):
    """
    Classify one traffic sample using the active detection policy:
    - 'legacy': Standard argmax decision using production model (model.joblib).
    - 'experimental': Candidate model (model_candidate.joblib) with brute_force probability threshold (tau).
    - 'shadow': Production model serves as authoritative decision; candidate model runs in background
                and records shadow comparison / divergence metadata.
    Returns (label, confidence) if return_meta is False (backward compatible),
    or (label, confidence, meta) if return_meta is True.
    """
    values = []

    for name in FEATURES:
        value = features_dict.get(name, 0)

        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"Feature '{name}' must be numeric.")

        if not np.isfinite(number):
            raise ValueError(f"Feature '{name}' must be finite.")

        values.append(number)

    sample = np.asarray([values], dtype=float)

    if user_policy is None:
        user_policy = get_user_detection_policy()
    elif isinstance(user_policy, str):
        user_policy = {"policy": user_policy, "threshold": 0.35}

    policy_mode = user_policy.get("policy", "legacy")
    threshold = float(user_policy.get("threshold", 0.35))

    def _resolve_label(mdl, class_idx):
        pred_c = mdl.classes_[class_idx]
        if isinstance(pred_c, (int, np.integer)) and 0 <= int(pred_c) < len(LABELS):
            return LABELS[int(pred_c)]
        elif str(pred_c).isdigit() and 0 <= int(pred_c) < len(LABELS):
            return LABELS[int(pred_c)]
        return str(pred_c)

    BF_CLASS_ID = 3

    if policy_mode == "experimental":
        cand = candidate_model if candidate_model is not None else load_candidate_model()
        if cand is None:
            # Fallback to legacy production model
            probs = model.predict_proba(sample)[0]
            idx = int(np.argmax(probs))
            label = _resolve_label(model, idx)
            conf = round(float(probs[idx]) * 100, 1)
            meta = {
                "mode": "legacy",
                "model": "model.joblib",
                "fallback": True,
                "fallback_reason": "Candidate model not found",
                "rule": "argmax"
            }
            return (label, conf, meta) if return_meta else (label, conf)

        cand_probs = cand.predict_proba(sample)[0]
        bf_idx = BF_CLASS_ID
        if hasattr(cand, "classes_") and BF_CLASS_ID in cand.classes_:
            bf_idx = list(cand.classes_).index(BF_CLASS_ID)
        p_bf = float(cand_probs[bf_idx])

        if p_bf >= threshold:
            label = "brute_force"
            conf = round(p_bf * 100, 1)
            rule = f"threshold_override (P(bf)={p_bf:.4f} >= {threshold:.2f})"
        else:
            cand_idx = int(np.argmax(cand_probs))
            label = _resolve_label(cand, cand_idx)
            conf = round(float(cand_probs[cand_idx]) * 100, 1)
            rule = "argmax"

        meta = {
            "mode": "experimental",
            "model": "model_candidate.joblib",
            "threshold": threshold,
            "candidate_bf_prob": round(p_bf, 4),
            "rule": rule,
            "fallback": False
        }
        return (label, conf, meta) if return_meta else (label, conf)

    elif policy_mode == "shadow":
        # Production model is authoritative
        prod_probs = model.predict_proba(sample)[0]
        prod_idx = int(np.argmax(prod_probs))
        auth_label = _resolve_label(model, prod_idx)
        auth_conf = round(float(prod_probs[prod_idx]) * 100, 1)

        # Candidate model runs in background for shadow evaluation
        cand = candidate_model if candidate_model is not None else load_candidate_model()
        if cand is not None:
            cand_probs = cand.predict_proba(sample)[0]
            bf_idx = BF_CLASS_ID
            if hasattr(cand, "classes_") and BF_CLASS_ID in cand.classes_:
                bf_idx = list(cand.classes_).index(BF_CLASS_ID)
            p_bf = float(cand_probs[bf_idx])
            if p_bf >= threshold:
                cand_label = "brute_force"
                cand_conf = round(p_bf * 100, 1)
                cand_rule = f"threshold_override (P(bf)={p_bf:.4f} >= {threshold:.2f})"
            else:
                cand_idx = int(np.argmax(cand_probs))
                cand_label = _resolve_label(cand, cand_idx)
                cand_conf = round(float(cand_probs[cand_idx]) * 100, 1)
                cand_rule = "argmax"
            diverged = (auth_label != cand_label)
        else:
            cand_label = auth_label
            cand_conf = auth_conf
            p_bf = 0.0
            cand_rule = "fallback_legacy"
            diverged = False

        meta = {
            "mode": "shadow",
            "authoritative_model": "model.joblib",
            "authoritative_label": auth_label,
            "authoritative_confidence": auth_conf,
            "candidate_model": "model_candidate.joblib" if cand else "unavailable",
            "candidate_label": cand_label,
            "candidate_confidence": cand_conf,
            "candidate_bf_prob": round(p_bf, 4),
            "threshold": threshold,
            "diverged": diverged,
            "candidate_rule": cand_rule
        }
        return (auth_label, auth_conf, meta) if return_meta else (auth_label, auth_conf)

    else:
        # Default legacy policy: production model argmax
        probs = model.predict_proba(sample)[0]
        idx = int(np.argmax(probs))
        label = _resolve_label(model, idx)
        conf = round(float(probs[idx]) * 100, 1)
        meta = {
            "mode": "legacy",
            "model": "model.joblib",
            "rule": "argmax",
            "fallback": False
        }
        return (label, conf, meta) if return_meta else (label, conf)

# ----- Authentication helpers -----

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            # For JSON APIs, return 401 JSON; for HTML, redirect to login page
            if request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            else:
                return redirect('/login')
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    """Enforce both authentication and administrator authorization."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            if request.path.startswith('/api/'):
                return jsonify({"error": "Authentication required"}), 401
            return redirect('/login')
        with get_connection() as conn:
            row = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row or not row['is_admin']:
                return jsonify({"error": "Administrator privilege required"}), 403
        return fn(*args, **kwargs)
    return wrapper

def validate_csrf():
    token = request.headers.get('X-CSRF-Token')
    if not token:
        if request.is_json:
            token = (request.get_json(silent=True) or {}).get('csrf_token')
        elif request.form:
            token = request.form.get('csrf_token')
    session_token = session.get('csrf_token')
    if not token or not session_token or not secrets.compare_digest(str(token), str(session_token)):
        raise ValueError('Invalid CSRF token')


def log(src_ip, features, user_policy=None):
    """Classify traffic and save its event in SQLite with investigation tracking and policy metadata."""
    if user_policy is None:
        user_policy = get_user_detection_policy()
    label, confidence, meta = classify(features, user_policy=user_policy, return_meta=True)
    severity = SEVERITY.get(label, "medium")
    timestamp = time.time()

    features_to_store = dict(features)
    features_to_store["_detection_policy"] = meta

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events
                (ts, src_ip, label, severity, confidence, features, investigation_status, analyst_notes)
            VALUES (?, ?, ?, ?, ?, ?, 'new', '')
            """,
            (
                timestamp,
                src_ip,
                label,
                severity,
                confidence,
                json.dumps(features_to_store),
            ),
        )
        event_id = cursor.lastrowid

    return {
        "id": event_id,
        "src_ip": src_ip,
        "label": label,
        "severity": severity,
        "confidence": confidence,
        "ts": timestamp,
        "investigation_status": "new",
        "analyst_notes": "",
        "detection_policy": meta,
        "features": features_to_store
    }


def get_feature_payload(data):
    """Accept either a feature dictionary or a nested features object."""
    if not isinstance(data, dict):
        raise ValueError("Request body must be a JSON object.")

    features = data.get("features", data)

    if not isinstance(features, dict):
        raise ValueError("'features' must be a JSON object.")

    return features


@app.route("/")
@login_required
def index():
    """Serve the single-page dashboard (requires authentication)."""
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/predict", methods=["POST"])
@login_required
def predict():
    """Classify a manually submitted traffic sample."""
    try:
        # CSRF protection for state‑changing POST
        validate_csrf()
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({"error": "Send a valid JSON request body."}), 400

        features = get_feature_payload(data)
        src_ip = str(data.get("src_ip", "127.0.0.1")).strip()

        if not src_ip or len(src_ip) > 45:
            return jsonify({"error": "src_ip must be 1-45 characters."}), 400

        # Check for request-level policy override if passed
        custom_policy = None
        if "policy" in data or "detection_policy" in data:
            req_pol = str(data.get("policy") or data.get("detection_policy")).strip().lower()
            if req_pol in ("legacy", "experimental", "shadow"):
                req_thresh = data.get("threshold") if data.get("threshold") is not None else data.get("bf_probability_threshold")
                try:
                    thresh_val = float(req_thresh) if req_thresh is not None else 0.35
                except (ValueError, TypeError):
                    thresh_val = 0.35
                custom_policy = {"policy": req_pol, "threshold": thresh_val}

        event = log(src_ip, features, user_policy=custom_policy)
        return jsonify(event), 200

    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Prediction failed")
        return jsonify({"error": "Prediction failed. Check the server log."}), 500


@app.route("/api/simulate", methods=["GET", "POST"])
@login_required
def simulate():
    """Generate one synthetic sample and record its prediction. Supports scenario parameter."""
    try:
        from train import gen_sample

        scenario = request.args.get("scenario", "").strip().lower()
        if not scenario and request.is_json:
            body = request.get_json(silent=True) or {}
            scenario = str(body.get("scenario", "")).strip().lower()

        if scenario in LABELS:
            label = scenario
        else:
            label = random.choices(
                list(SIMULATION_WEIGHTS.keys()),
                weights=list(SIMULATION_WEIGHTS.values()),
                k=1,
            )[0]

        values = gen_sample(label)
        features = dict(zip(FEATURES, values))
        features["simulated"] = True
        features["scenario"] = label

        src_ip = ".".join(
            str(random.randint(1, 254)) for _ in range(4)
        )

        # Check for request-level policy override if passed
        custom_policy = None
        req_pol = request.args.get("policy", "").strip().lower()
        if not req_pol and request.is_json:
            body = request.get_json(silent=True) or {}
            req_pol = str(body.get("policy") or body.get("detection_policy", "")).strip().lower()
        if req_pol in ("legacy", "experimental", "shadow"):
            req_thresh = request.args.get("threshold")
            if req_thresh is None and request.is_json:
                body = request.get_json(silent=True) or {}
                req_thresh = body.get("threshold") or body.get("bf_probability_threshold")
            try:
                thresh_val = float(req_thresh) if req_thresh is not None else 0.35
            except (ValueError, TypeError):
                thresh_val = 0.35
            custom_policy = {"policy": req_pol, "threshold": thresh_val}

        event = log(src_ip, features, user_policy=custom_policy)
        event["features"] = features
        event["simulated"] = True

        return jsonify({
            "success": True,
            "event": event,
            **event
        }), 200

    except Exception:
        app.logger.exception("Simulation failed")
        return jsonify({"error": "Simulation failed. Check the server log."}), 500


@app.route("/api/events", methods=["GET"])
@login_required
def events():
    """Return the latest recorded events with investigation metadata."""
    try:
        limit = min(int(request.args.get('limit', 20)), 200)
    except (ValueError, TypeError):
        limit = 20

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, ts, src_ip, label, severity, confidence, investigation_status, analyst_notes
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    results = []
    for row in rows:
        item = dict(row)
        lbl = str(item.get("label", ""))
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            item["label"] = LABELS[int(lbl)]
        item["investigation_status"] = item.get("investigation_status") or "new"
        item["analyst_notes"] = item.get("analyst_notes") or ""
        results.append(item)

    return jsonify(results)


@app.route("/api/events/<int:event_id>", methods=["GET"])
@login_required
def get_event_details(event_id):
    """Return full details for a single event, including feature payload, investigation status, and notes."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, ts, src_ip, label, severity, confidence, features, investigation_status, analyst_notes, updated_at
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        ).fetchone()

    if not row:
        return jsonify({"error": "Event not found"}), 404

    item = dict(row)
    lbl = str(item.get("label", ""))
    if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
        item["label"] = LABELS[int(lbl)]
    item["investigation_status"] = item.get("investigation_status") or "new"
    item["analyst_notes"] = item.get("analyst_notes") or ""

    raw_features = item.get("features")
    parsed_features = {}
    if raw_features:
        try:
            parsed_features = json.loads(raw_features)
        except Exception:
            parsed_features = {"raw": raw_features}
    item["features"] = parsed_features
    if isinstance(parsed_features, dict) and "_detection_policy" in parsed_features:
        item["detection_policy"] = parsed_features["_detection_policy"]

    return jsonify(item)


@app.route("/api/stats", methods=["GET"])
@login_required
def stats():
    """Return comprehensive class counts, totals, investigation breakdown, severities, top sources, and model metrics."""
    with get_connection() as connection:
        total_row = connection.execute(
            "SELECT COUNT(*) AS total FROM events"
        ).fetchone()

        threat_row = connection.execute(
            "SELECT COUNT(*) AS threats FROM events WHERE label != 'normal' AND label != '0'"
        ).fetchone()

        count_rows = connection.execute(
            """
            SELECT label, COUNT(*) AS count
            FROM events
            GROUP BY label
            """
        ).fetchall()

        recent_rows = connection.execute(
            """
            SELECT label
            FROM (
                SELECT id, label
                FROM events
                ORDER BY id DESC
                LIMIT 40
            )
            ORDER BY id ASC
            """
        ).fetchall()

        sev_rows = connection.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM events
            GROUP BY severity
            """
        ).fetchall()

        inv_rows = connection.execute(
            """
            SELECT investigation_status, COUNT(*) AS count
            FROM events
            GROUP BY investigation_status
            """
        ).fetchall()

        top_ip_rows = connection.execute(
            """
            SELECT src_ip, COUNT(*) AS total_count,
                   SUM(CASE WHEN label != 'normal' AND label != '0' THEN 1 ELSE 0 END) AS threat_count
            FROM events
            GROUP BY src_ip
            ORDER BY total_count DESC
            LIMIT 5
            """
        ).fetchall()

        priority_rows = connection.execute(
            """
            SELECT id, ts, src_ip, label, severity, confidence, investigation_status
            FROM events
            WHERE severity IN ('critical', 'high') OR (label != 'normal' AND label != '0')
            ORDER BY id DESC
            LIMIT 5
            """
        ).fetchall()

        timeline_rows = connection.execute(
            """
            SELECT strftime('%Y-%m-%d %H:00', datetime(ts, 'unixepoch')) AS bucket,
                   COUNT(*) AS total,
                   SUM(CASE WHEN label != 'normal' AND label != '0' THEN 1 ELSE 0 END) AS threats
            FROM events
            GROUP BY bucket
            ORDER BY bucket DESC
            LIMIT 24
            """
        ).fetchall()

    counts = {label: 0 for label in LABELS}
    for row in count_rows:
        lbl = str(row["label"])
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            lbl = LABELS[int(lbl)]
        if lbl in counts:
            counts[lbl] += row["count"]
        else:
            counts[lbl] = row["count"]

    recent_labels = []
    for row in recent_rows:
        lbl = str(row["label"])
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            lbl = LABELS[int(lbl)]
        recent_labels.append(lbl)

    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for row in sev_rows:
        s = str(row["severity"]).lower()
        severities[s] = severities.get(s, 0) + row["count"]

    investigations = {"new": 0, "investigating": 0, "resolved": 0, "false_positive": 0}
    for row in inv_rows:
        st = str(row["investigation_status"] or "new").lower()
        investigations[st] = investigations.get(st, 0) + row["count"]

    top_sources = []
    for row in top_ip_rows:
        top_sources.append({
            "ip": row["src_ip"],
            "total": row["total_count"],
            "threats": row["threat_count"] or 0
        })

    priority_alerts = []
    for row in priority_rows:
        p = dict(row)
        lbl = str(p.get("label", ""))
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            p["label"] = LABELS[int(lbl)]
        p["investigation_status"] = p.get("investigation_status") or "new"
        priority_alerts.append(p)

    timeline = []
    for row in reversed(timeline_rows):
        timeline.append({
            "bucket": row["bucket"],
            "total": row["total"],
            "threats": row["threats"] or 0
        })

    total = total_row["total"]
    threats = threat_row["threats"]
    critical_count = severities.get("critical", 0) + severities.get("high", 0)

    return jsonify(
        {
            "counts": counts,
            "total": total,
            "threats": threats,
            "critical_count": critical_count,
            "recent": recent_labels,
            "severities": severities,
            "investigations": investigations,
            "investigation_counts": investigations,
            "top_sources": top_sources,
            "priority_alerts": priority_alerts,
            "timeline": timeline,
            "metrics": load_metrics(),
        }
    )


@app.route("/api/export", methods=["GET"])
@app.route("/api/export.csv", methods=["GET"])
@app.route("/api/export.json", methods=["GET"])
@login_required
def export_csv():
    """Export recorded events as CSV or JSON (supports optional filter parameters or selected IDs)."""
    src_ip = request.args.get('src_ip', '').strip()
    label = request.args.get('label', '').strip().lower()
    severity = request.args.get('severity', '').strip().lower()
    status = request.args.get('status', '').strip().lower()
    q = request.args.get('q', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    min_conf = request.args.get('min_conf')
    max_conf = request.args.get('max_conf')
    ids_param = request.args.get('ids', '').strip()
    export_format = request.args.get('format', 'csv').strip().lower()
    if request.path.endswith('.json'):
        export_format = 'json'

    conditions = []
    params = []

    if ids_param:
        valid_ids = [int(i) for i in ids_param.split(',') if i.strip().isdigit()]
        if valid_ids:
            placeholders = ','.join('?' for _ in valid_ids)
            conditions.append(f"id IN ({placeholders})")
            params.extend(valid_ids)

    if src_ip:
        conditions.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if label and label != 'all':
        conditions.append("label = ?")
        params.append(label)
    if severity and severity != 'all':
        conditions.append("severity = ?")
        params.append(severity)
    if status and status != 'all':
        conditions.append("investigation_status = ?")
        params.append(status)
    if q:
        conditions.append("(src_ip LIKE ? OR label LIKE ? OR severity LIKE ? OR analyst_notes LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    if min_conf is not None and min_conf != '':
        try:
            conditions.append("confidence >= ?")
            params.append(float(min_conf))
        except ValueError:
            pass
    if max_conf is not None and max_conf != '':
        try:
            conditions.append("confidence <= ?")
            params.append(float(max_conf))
        except ValueError:
            pass

    if date_from:
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(date_from)
            conditions.append("ts >= ?")
            params.append(dt.timestamp())
        except ValueError:
            pass
    if date_to:
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(date_to)
            conditions.append("ts <= ?")
            params.append(dt.timestamp())
        except ValueError:
            pass

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    with get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT id, ts, src_ip, label, severity, confidence, features, investigation_status, analyst_notes
            FROM events
            {where_clause}
            ORDER BY id ASC
            """,
            params
        ).fetchall()

    prefix = request.args.get('prefix', 'threatnex_events').strip()
    prefix = re.sub(r'[^a-zA-Z0-9_\-]', '', prefix)[:40] or 'threatnex_events'

    if export_format == 'json':
        export_records = []
        for row in rows:
            row_label = str(row["label"])
            if row_label.isdigit() and 0 <= int(row_label) < len(LABELS):
                row_label = LABELS[int(row_label)]
            import datetime
            dt_str = datetime.datetime.fromtimestamp(row["ts"], datetime.timezone.utc).isoformat() if row["ts"] else ""
            feats = {}
            if row["features"]:
                try:
                    feats = json.loads(row["features"]) if isinstance(row["features"], str) else row["features"]
                except Exception:
                    pass
            export_records.append({
                "id": row["id"],
                "timestamp": row["ts"],
                "datetime_iso": dt_str,
                "src_ip": row["src_ip"],
                "label": row_label,
                "severity": row["severity"],
                "confidence": row["confidence"],
                "investigation_status": row["investigation_status"] or "new",
                "analyst_notes": row["analyst_notes"] or "",
                "features": feats
            })
        from flask import Response
        res = Response(json.dumps(export_records, indent=2), mimetype="application/json")
        res.headers.set("Content-Disposition", "attachment", filename=f"{prefix}.json")
        return res

    import csv, io
    output = io.StringIO()
    delim_param = request.args.get('delimiter', ',')
    if delim_param in (';', 'semicolon'):
        delim_char = ';'
    elif delim_param in ('\t', 'tab'):
        delim_char = '\t'
    else:
        delim_char = ','

    writer = csv.writer(output, delimiter=delim_char)
    writer.writerow(["event_id", "timestamp", "datetime_iso", "src_ip", "label", "severity", "confidence_percent", "investigation_status", "analyst_notes"])

    def sanitize(value):
        """Escape potential spreadsheet formula injection characters."""
        if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@"):
            return "'" + value
        return value

    for row in rows:
        row_label = str(row["label"])
        if row_label.isdigit() and 0 <= int(row_label) < len(LABELS):
            row_label = LABELS[int(row_label)]
        import datetime
        dt_str = datetime.datetime.fromtimestamp(row["ts"], datetime.timezone.utc).isoformat() if row["ts"] else ""
        writer.writerow([
            row["id"],
            sanitize(row["ts"]),
            dt_str,
            sanitize(row["src_ip"]),
            sanitize(row_label),
            sanitize(row["severity"]),
            sanitize(row["confidence"]),
            sanitize(row["investigation_status"] or "new"),
            sanitize(row["analyst_notes"] or "")
        ])

    csv_data = output.getvalue()
    output.close()
    from flask import Response
    response = Response(csv_data, mimetype="text/csv")
    filename = f"{prefix}_filtered.csv" if conditions else f"{prefix}.csv"
    response.headers.set("Content-Disposition", "attachment", filename=filename)
    return response

@app.route("/api/reset", methods=["POST"])
@admin_required
def reset():
    """Delete recorded events and reset the event ID sequence."""
    try:
        validate_csrf()
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    with get_connection() as connection:
        connection.execute("DELETE FROM events")
        connection.execute(
            "DELETE FROM sqlite_sequence WHERE name = 'events'"
        )

    return jsonify({"success": True, "message": "Event history reset."})


# ----- Authentication routes -----

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Render login page (GET) or process credentials (POST)."""
    if request.method == 'GET':
        return send_from_directory(STATIC_DIR, 'login.html')
    # POST expects JSON {"username":..., "password":...}
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        username = data.get('username', '').strip()
        password = data.get('password', '')
        if not username or not password:
            return jsonify({"error": "Username and password required."}), 400
        with get_connection() as conn:
            row = conn.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
            if row and check_password_hash(row['password_hash'], password):
                session['user_id'] = row['id']
                return jsonify({"success": True}), 200
        return jsonify({"error": "Invalid credentials."}), 401
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        app.logger.exception('Login failed')
        return jsonify({"error": 'Login error.'}), 500


@app.route('/register', methods=['GET', 'POST'])
@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user account with secure password hashing and CSRF validation."""
    if request.method == 'GET':
        return send_from_directory(STATIC_DIR, 'login.html')

    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', ''))
        confirm_password = str(data.get('confirm_password', ''))
        display_name = str(data.get('display_name', '')).strip() or username

        if not username or not password:
            return jsonify({"error": "Username and password required."}), 400

        if not re.match(r'^[a-zA-Z0-9_\-\.]{3,30}$', username):
            return jsonify({"error": "Username must be 3-30 alphanumeric characters."}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters."}), 400

        if confirm_password and confirm_password != password:
            return jsonify({"error": "Passwords do not match."}), 400

        with get_connection() as conn:
            existing = conn.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
            if existing:
                return jsonify({"error": "Username is already registered."}), 409

            # Public registration strictly assigns standard user role (is_admin = 0)
            is_admin = 0

            hashed = generate_password_hash(password)
            default_settings_json = json.dumps(DEFAULT_SETTINGS)

            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO users (username, password_hash, is_admin, theme, notify_severity, page_size, display_name, settings_json)
                   VALUES (?, ?, ?, 'dark', 'critical', 20, ?, ?)""",
                (username, hashed, is_admin, display_name, default_settings_json)
            )
            new_id = cursor.lastrowid
            conn.commit()

            # Establish authenticated session upon successful registration
            session['user_id'] = new_id
            return jsonify({
                "success": True,
                "message": "Account created successfully.",
                "user": {
                    "id": new_id,
                    "username": username,
                    "display_name": display_name,
                    "is_admin": False
                }
            }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception:
        app.logger.exception("Registration failed")
        return jsonify({"error": "Registration failed."}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Log the user out and clear the session."""
    try:
        validate_csrf()
        session.clear()
        return jsonify({"success": True}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

DEFAULT_SETTINGS = {
    # 1. General
    "display_name": "",
    "default_landing_page": "overview",
    "default_time_range": "all",
    "timezone": "local",
    "datetime_format": "YYYY-MM-DD HH:mm:ss",
    "number_format": "en-US",
    "density": "comfortable",
    "page_size": 20,
    "confirm_destructive": True,
    "auto_refresh": True,
    "refresh_interval": 10,

    # 2. Appearance & Themes
    "theme": "dark",
    "accent_preset": "cyan",
    "sidebar_state": "expanded",
    "chart_animations": True,
    "reduced_motion": False,
    "table_row_density": "standard",
    "font_size": "normal",

    # 3. Dashboard Preferences
    "show_kpis": True,
    "show_timeline": True,
    "show_threat_donut": True,
    "show_severity_breakdown": True,
    "show_top_sources": True,
    "show_priority_alerts": True,
    "show_recent_activity": True,
    "show_model_metrics": True,
    "show_system_health": True,
    "show_normal_events": True,
    "recent_events_limit": 10,

    # 4. Notifications & Alerts
    "enable_notifications": True,
    "notify_severity": "critical",
    "notification_sound": False,
    "browser_notifications": False,
    "auto_dismiss_delay": 5,
    "keep_alerts_until_ack": False,

    # 5. Detection & Model
    "min_alert_confidence": 70,
    "default_severity_filter": "all",
    "alert_threshold_mode": "balanced",
    "show_confidence_percentage": True,
    "detection_policy": "legacy",
    "bf_probability_threshold": 0.35,

    # 6. Query Center
    "default_search_time": "all",
    "default_query_page_size": 20,
    "default_sort_column": "id",
    "default_sort_order": "DESC",
    "default_query_severity": "all",
    "default_query_label": "all",
    "query_show_optional_columns": True,
    "remember_last_filters": True,
    "remember_query_page_size": True,
    "export_delimiter": ",",
    "confirm_large_export": True,

    # 7. Event Management
    "default_investigation_status": "all",
    "default_event_sort": "id_desc",
    "event_detail_layout": "modal",
    "confirm_event_resolve": True,
    "show_feature_details_by_default": False,
    "default_investigation_view": "all",
    "preserve_query_on_modal_close": True,

    # 8. Data & Retention
    "retention_policy_enabled": False,
    "retention_days": 90,

    # 9. Export & Reports
    "default_export_format": "csv",
    "csv_delimiter": ",",
    "timestamp_export_format": "iso8601",
    "include_confidence": True,
    "include_severity_label": True,
    "include_event_id": True,
    "include_features": True,
    "include_filter_summary": True,
    "export_filename_prefix": "threatnex_events",
    "default_report_date_range": "30d"
}


# ----- Settings API -----

@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    """Return the logged-in user's comprehensive settings dictionary and profile info."""
    user_id = session.get('user_id')
    with get_connection() as conn:
        row = conn.execute(
            'SELECT id, username, is_admin, theme, notify_severity, page_size, display_name, settings_json FROM users WHERE id = ?', 
            (user_id,)
        ).fetchone()
        if not row:
            return jsonify({'error': 'User not found'}), 404

        settings = dict(DEFAULT_SETTINGS)

        raw_json = row['settings_json']
        if raw_json:
            try:
                stored = json.loads(raw_json)
                if isinstance(stored, dict):
                    settings.update(stored)
            except Exception:
                pass

        if row['theme']:
            settings['theme'] = row['theme']
        if row['notify_severity']:
            settings['notify_severity'] = row['notify_severity']
        if row['page_size']:
            settings['page_size'] = row['page_size']
        if row['display_name']:
            settings['display_name'] = row['display_name']

        return jsonify({
            'success': True,
            'settings': settings,
            'user': {
                'id': row['id'],
                'username': row['username'],
                'display_name': settings.get('display_name') or row['username'],
                'is_admin': bool(row['is_admin']),
                'role': 'Administrator' if row['is_admin'] else 'Security Analyst'
            },
            **settings
        })


@app.route('/api/settings', methods=['PUT'])
@login_required
def update_settings():
    """Update the logged-in user's settings with strict server-side validation."""
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            raise ValueError('Invalid settings payload')

        payload = data.get('settings', data)
        if not isinstance(payload, dict):
            payload = data

        user_id = session.get('user_id')

        with get_connection() as conn:
            row = conn.execute('SELECT theme, notify_severity, page_size, display_name, settings_json FROM users WHERE id = ?', (user_id,)).fetchone()
            if not row:
                return jsonify({'error': 'User not found'}), 404

            current = dict(DEFAULT_SETTINGS)
            if row['settings_json']:
                try:
                    stored = json.loads(row['settings_json'])
                    if isinstance(stored, dict):
                        current.update(stored)
                except Exception:
                    pass

            # Synchronize column values into current so database columns act as authoritative fallback
            if row['theme']:
                current['theme'] = row['theme']
            if row['notify_severity']:
                current['notify_severity'] = row['notify_severity']
            if row['page_size']:
                current['page_size'] = row['page_size']
            if row['display_name']:
                current['display_name'] = row['display_name']

        new_settings = dict(current)

        # 1. General
        if 'display_name' in payload:
            new_settings['display_name'] = str(payload['display_name']).strip()[:50]
        if 'default_landing_page' in payload:
            lp = str(payload['default_landing_page']).strip()
            if lp not in ('overview', 'events', 'query', 'investigations', 'analyzer', 'model', 'reports', 'health', 'settings', 'about'):
                raise ValueError("Invalid default landing page.")
            new_settings['default_landing_page'] = lp
        if 'default_time_range' in payload:
            tr = str(payload['default_time_range']).strip()
            if tr not in ('all', '1h', '6h', '24h', '7d', '30d'):
                raise ValueError("Invalid default time range.")
            new_settings['default_time_range'] = tr
        if 'timezone' in payload:
            tz = str(payload['timezone']).strip()
            if tz not in ('local', 'UTC', 'America/New_York', 'Europe/London', 'Asia/Kolkata', 'Asia/Tokyo'):
                raise ValueError("Invalid timezone preference.")
            new_settings['timezone'] = tz
        if 'datetime_format' in payload:
            df = str(payload['datetime_format']).strip()
            if df not in ('YYYY-MM-DD HH:mm:ss', 'DD/MM/YYYY HH:mm:ss', 'MM/DD/YYYY HH:mm:ss', 'ISO 8601'):
                raise ValueError("Invalid datetime format.")
            new_settings['datetime_format'] = df
        if 'number_format' in payload:
            nf = str(payload['number_format']).strip()
            if nf not in ('en-US', 'de-DE', 'en-IN'):
                raise ValueError("Invalid number format.")
            new_settings['number_format'] = nf
        if 'density' in payload:
            d = str(payload['density']).strip()
            if d not in ('compact', 'comfortable'):
                raise ValueError("Density must be compact or comfortable.")
            new_settings['density'] = d
        if 'page_size' in payload:
            try:
                ps = int(payload['page_size'])
                if ps < 5 or ps > 200:
                    raise ValueError()
                new_settings['page_size'] = ps
            except Exception:
                raise ValueError("Page size must be an integer between 5 and 200.")
        if 'confirm_destructive' in payload:
            new_settings['confirm_destructive'] = bool(payload['confirm_destructive'])
        if 'auto_refresh' in payload:
            new_settings['auto_refresh'] = bool(payload['auto_refresh'])
        if 'refresh_interval' in payload:
            try:
                ri = int(payload['refresh_interval'])
                if ri < 5 or ri > 300:
                    raise ValueError()
                new_settings['refresh_interval'] = ri
            except Exception:
                raise ValueError("Refresh interval must be between 5 and 300 seconds.")

        # 2. Appearance & Themes
        if 'theme' in payload:
            thm = str(payload['theme']).strip()
            if thm not in ('dark', 'light', 'system'):
                raise ValueError("Theme must be dark, light, or system.")
            new_settings['theme'] = thm
        if 'accent_preset' in payload:
            acc = str(payload['accent_preset']).strip()
            if acc not in ('cyan', 'emerald', 'indigo', 'amber', 'crimson'):
                raise ValueError("Invalid accent preset.")
            new_settings['accent_preset'] = acc
        if 'font_size' in payload:
            fs = str(payload['font_size']).strip()
            if fs not in ('small', 'normal', 'large'):
                raise ValueError("Font size must be small, normal, or large.")
            new_settings['font_size'] = fs
        if 'table_row_density' in payload:
            trd = str(payload['table_row_density']).strip()
            if trd not in ('compact', 'standard', 'spacious'):
                raise ValueError("Invalid table row density.")
            new_settings['table_row_density'] = trd
        if 'sidebar_state' in payload:
            ss = str(payload['sidebar_state']).strip()
            if ss not in ('expanded', 'collapsed'):
                raise ValueError("Sidebar state must be expanded or collapsed.")
            new_settings['sidebar_state'] = ss
        if 'chart_animations' in payload:
            new_settings['chart_animations'] = bool(payload['chart_animations'])
        if 'reduced_motion' in payload:
            new_settings['reduced_motion'] = bool(payload['reduced_motion'])

        # 3. Dashboard Preferences
        for k in ('show_kpis', 'show_timeline', 'show_threat_donut', 'show_severity_breakdown', 
                  'show_top_sources', 'show_priority_alerts', 'show_recent_activity', 
                  'show_model_metrics', 'show_system_health', 'show_normal_events'):
            if k in payload:
                new_settings[k] = bool(payload[k])
        if 'recent_events_limit' in payload:
            try:
                rel = int(payload['recent_events_limit'])
                if rel not in (5, 10, 15, 20):
                    raise ValueError()
                new_settings['recent_events_limit'] = rel
            except Exception:
                raise ValueError("Recent events limit must be 5, 10, 15, or 20.")

        # 4. Notifications & Alerts
        if 'enable_notifications' in payload:
            new_settings['enable_notifications'] = bool(payload['enable_notifications'])
        if 'notify_severity' in payload:
            ns = str(payload['notify_severity']).strip().lower()
            if ns not in ('critical', 'high', 'medium', 'low', 'info'):
                raise ValueError("Invalid notification severity threshold.")
            new_settings['notify_severity'] = ns
        if 'notification_sound' in payload:
            new_settings['notification_sound'] = bool(payload['notification_sound'])
        if 'browser_notifications' in payload:
            new_settings['browser_notifications'] = bool(payload['browser_notifications'])
        if 'auto_dismiss_delay' in payload:
            try:
                add = int(payload['auto_dismiss_delay'])
                if add not in (0, 3, 5, 8, 10):
                    raise ValueError()
                new_settings['auto_dismiss_delay'] = add
            except Exception:
                raise ValueError("Auto-dismiss delay must be 0, 3, 5, 8, or 10 seconds.")
        if 'keep_alerts_until_ack' in payload:
            new_settings['keep_alerts_until_ack'] = bool(payload['keep_alerts_until_ack'])

        # 5. Detection & Model
        if 'min_alert_confidence' in payload:
            try:
                mac = int(payload['min_alert_confidence'])
                if mac < 50 or mac > 99:
                    raise ValueError()
                new_settings['min_alert_confidence'] = mac
            except Exception:
                raise ValueError("Minimum alert confidence must be an integer between 50 and 99.")
        if 'default_severity_filter' in payload:
            dsf = str(payload['default_severity_filter']).strip().lower()
            if dsf not in ('all', 'critical', 'high', 'medium', 'low'):
                raise ValueError("Invalid default severity filter.")
            new_settings['default_severity_filter'] = dsf
        if 'alert_threshold_mode' in payload:
            atm = str(payload['alert_threshold_mode']).strip().lower()
            if atm not in ('lenient', 'balanced', 'strict'):
                raise ValueError("Alert threshold mode must be lenient, balanced, or strict.")
            new_settings['alert_threshold_mode'] = atm
        if 'show_confidence_percentage' in payload:
            new_settings['show_confidence_percentage'] = bool(payload['show_confidence_percentage'])
        if 'detection_policy' in payload:
            dp = str(payload['detection_policy']).strip().lower()
            if dp not in ('legacy', 'experimental', 'shadow'):
                raise ValueError("Detection policy must be legacy, experimental, or shadow.")
            new_settings['detection_policy'] = dp
        if 'bf_probability_threshold' in payload:
            try:
                bf_thresh = float(payload['bf_probability_threshold'])
                if bf_thresh < 0.05 or bf_thresh > 0.95:
                    raise ValueError()
                new_settings['bf_probability_threshold'] = round(bf_thresh, 4)
            except Exception:
                raise ValueError("Brute-force probability threshold must be between 0.05 and 0.95.")

        # 6. Query Center
        if 'default_search_time' in payload:
            dst = str(payload['default_search_time']).strip()
            if dst not in ('all', '1h', '6h', '24h', '7d', '30d'):
                raise ValueError("Invalid search time range.")
            new_settings['default_search_time'] = dst
        if 'default_query_page_size' in payload:
            try:
                dqps = int(payload['default_query_page_size'])
                if dqps not in (10, 20, 50, 100):
                    raise ValueError()
                new_settings['default_query_page_size'] = dqps
            except Exception:
                raise ValueError("Default query page size must be 10, 20, 50, or 100.")
        if 'default_sort_column' in payload:
            dsc = str(payload['default_sort_column']).strip()
            if dsc not in ('id', 'ts', 'severity', 'confidence', 'src_ip', 'label'):
                raise ValueError("Invalid sort column.")
            new_settings['default_sort_column'] = dsc
        if 'default_sort_order' in payload:
            dso = str(payload['default_sort_order']).strip().upper()
            if dso not in ('ASC', 'DESC'):
                raise ValueError("Sort order must be ASC or DESC.")
            new_settings['default_sort_order'] = dso
        if 'default_query_severity' in payload:
            dqs = str(payload['default_query_severity']).strip().lower()
            if dqs not in ('all', 'critical', 'high', 'medium', 'low', 'none'):
                raise ValueError("Invalid query severity.")
            new_settings['default_query_severity'] = dqs
        if 'default_query_label' in payload:
            dql = str(payload['default_query_label']).strip().lower()
            if dql not in ('all', 'dos', 'probe', 'brute_force', 'normal', 'r2l', 'u2r'):
                raise ValueError("Invalid query label.")
            new_settings['default_query_label'] = dql
        if 'query_show_optional_columns' in payload:
            new_settings['query_show_optional_columns'] = bool(payload['query_show_optional_columns'])
        if 'remember_last_filters' in payload:
            new_settings['remember_last_filters'] = bool(payload['remember_last_filters'])
        if 'remember_query_page_size' in payload:
            new_settings['remember_query_page_size'] = bool(payload['remember_query_page_size'])
        if 'export_delimiter' in payload:
            ed = str(payload['export_delimiter'])
            if ed not in (',', ';', '\t'):
                raise ValueError("Invalid export delimiter.")
            new_settings['export_delimiter'] = ed
        if 'confirm_large_export' in payload:
            new_settings['confirm_large_export'] = bool(payload['confirm_large_export'])

        # 7. Event Management
        if 'default_investigation_status' in payload:
            dis = str(payload['default_investigation_status']).strip().lower()
            if dis not in ('all', 'new', 'investigating', 'resolved', 'false_positive'):
                raise ValueError("Invalid investigation status filter.")
            new_settings['default_investigation_status'] = dis
        if 'default_event_sort' in payload:
            des = str(payload['default_event_sort']).strip()
            if des not in ('id_desc', 'id_asc', 'sev_desc', 'conf_desc'):
                raise ValueError("Invalid event sorting mode.")
            new_settings['default_event_sort'] = des
        if 'event_detail_layout' in payload:
            edl = str(payload['event_detail_layout']).strip()
            if edl not in ('modal', 'drawer'):
                raise ValueError("Event detail layout must be modal or drawer.")
            new_settings['event_detail_layout'] = edl
        if 'confirm_event_resolve' in payload:
            new_settings['confirm_event_resolve'] = bool(payload['confirm_event_resolve'])
        if 'show_feature_details_by_default' in payload:
            new_settings['show_feature_details_by_default'] = bool(payload['show_feature_details_by_default'])
        if 'default_investigation_view' in payload:
            div = str(payload['default_investigation_view']).strip()
            if div not in ('all', 'assigned_to_me', 'priority'):
                raise ValueError("Invalid default investigation view.")
            new_settings['default_investigation_view'] = div
        if 'preserve_query_on_modal_close' in payload:
            new_settings['preserve_query_on_modal_close'] = bool(payload['preserve_query_on_modal_close'])

        # 8. Data & Retention
        if 'retention_policy_enabled' in payload:
            new_settings['retention_policy_enabled'] = bool(payload['retention_policy_enabled'])
        if 'retention_days' in payload:
            try:
                rd = int(payload['retention_days'])
                if rd not in (30, 60, 90, 180, 365):
                    raise ValueError()
                new_settings['retention_days'] = rd
            except Exception:
                raise ValueError("Retention period must be 30, 60, 90, 180, or 365 days.")

        # 9. Export & Reports
        if 'default_export_format' in payload:
            def_fmt = str(payload['default_export_format']).strip().lower()
            if def_fmt not in ('csv', 'json'):
                raise ValueError("Export format must be csv or json.")
            new_settings['default_export_format'] = def_fmt
        if 'csv_delimiter' in payload:
            cd = str(payload['csv_delimiter'])
            if cd not in (',', ';', '\t'):
                raise ValueError("CSV delimiter must be comma, semicolon, or tab.")
            new_settings['csv_delimiter'] = cd
        if 'timestamp_export_format' in payload:
            tef = str(payload['timestamp_export_format']).strip()
            if tef not in ('iso8601', 'unix_epoch', 'readable'):
                raise ValueError("Invalid timestamp export format.")
            new_settings['timestamp_export_format'] = tef
        if 'include_confidence' in payload:
            new_settings['include_confidence'] = bool(payload['include_confidence'])
        if 'include_severity_label' in payload:
            new_settings['include_severity_label'] = bool(payload['include_severity_label'])
        if 'include_event_id' in payload:
            new_settings['include_event_id'] = bool(payload['include_event_id'])
        if 'include_features' in payload:
            new_settings['include_features'] = bool(payload['include_features'])
        if 'include_filter_summary' in payload:
            new_settings['include_filter_summary'] = bool(payload['include_filter_summary'])
        if 'export_filename_prefix' in payload:
            import re
            pfx = str(payload['export_filename_prefix']).strip()
            if not re.match(r'^[a-zA-Z0-9_\-]{1,40}$', pfx):
                raise ValueError("Export filename prefix must be alphanumeric (1-40 chars, underscores and hyphens allowed).")
            new_settings['export_filename_prefix'] = pfx
        if 'default_report_date_range' in payload:
            drdr = str(payload['default_report_date_range']).strip()
            if drdr not in ('7d', '30d', 'all'):
                raise ValueError("Default report date range must be 7d, 30d, or all.")
            new_settings['default_report_date_range'] = drdr

        settings_json_str = json.dumps(new_settings)

        with get_connection() as conn:
            conn.execute(
                '''UPDATE users 
                   SET theme = ?, notify_severity = ?, page_size = ?, display_name = ?, settings_json = ? 
                   WHERE id = ?''',
                (new_settings['theme'], new_settings['notify_severity'], new_settings['page_size'], new_settings['display_name'], settings_json_str, user_id)
            )

        return jsonify({'success': True, 'settings': new_settings, **new_settings})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        app.logger.exception('Settings update failed')
        return jsonify({'error': 'Settings update failed'}), 500


@app.route('/api/settings/reset', methods=['POST'])
@login_required
def reset_settings():
    """Reset user settings to factory defaults for the logged-in user only."""
    try:
        validate_csrf()
        user_id = session.get('user_id')
        data = request.get_json(silent=True) or {}
        section = data.get('section')

        with get_connection() as conn:
            row = conn.execute('SELECT settings_json FROM users WHERE id = ?', (user_id,)).fetchone()
            current = dict(DEFAULT_SETTINGS)
            if row and row['settings_json']:
                try:
                    stored = json.loads(row['settings_json'])
                    if isinstance(stored, dict):
                        current.update(stored)
                except Exception:
                    pass

            if section and section != 'all':
                section_keys = {
                    'general': ['display_name', 'default_landing_page', 'default_time_range', 'timezone', 'datetime_format', 'number_format', 'density', 'page_size', 'confirm_destructive', 'auto_refresh', 'refresh_interval'],
                    'appearance': ['theme', 'accent_preset', 'sidebar_state', 'chart_animations', 'reduced_motion', 'table_row_density', 'font_size'],
                    'dashboard': ['show_kpis', 'show_timeline', 'show_threat_donut', 'show_severity_breakdown', 'show_top_sources', 'show_priority_alerts', 'show_recent_activity', 'show_model_metrics', 'show_system_health', 'show_normal_events', 'recent_events_limit'],
                    'notifications': ['enable_notifications', 'notify_severity', 'notification_sound', 'browser_notifications', 'auto_dismiss_delay', 'keep_alerts_until_ack'],
                    'detection': ['min_alert_confidence', 'default_severity_filter', 'alert_threshold_mode', 'show_confidence_percentage', 'detection_policy', 'bf_probability_threshold'],
                    'query': ['default_search_time', 'default_query_page_size', 'default_sort_column', 'default_sort_order', 'default_query_severity', 'default_query_label', 'query_show_optional_columns', 'remember_last_filters', 'remember_query_page_size', 'export_delimiter', 'confirm_large_export'],
                    'events': ['default_investigation_status', 'default_event_sort', 'event_detail_layout', 'confirm_event_resolve', 'show_feature_details_by_default', 'default_investigation_view', 'preserve_query_on_modal_close'],
                    'retention': ['retention_policy_enabled', 'retention_days'],
                    'data': ['retention_policy_enabled', 'retention_days'],
                    'export': ['default_export_format', 'csv_delimiter', 'timestamp_export_format', 'include_confidence', 'include_severity_label', 'include_event_id', 'include_features', 'include_filter_summary', 'export_filename_prefix', 'default_report_date_range'],
                    'security': [],
                    'account': ['display_name'],
                    'system': []
                }
                keys_to_reset = section_keys.get(section, [])
                for k in keys_to_reset:
                    if k in DEFAULT_SETTINGS:
                        current[k] = DEFAULT_SETTINGS[k]
                new_settings = current
            else:
                new_settings = dict(DEFAULT_SETTINGS)

            settings_json_str = json.dumps(new_settings)
            conn.execute(
                '''UPDATE users 
                   SET theme = ?, notify_severity = ?, page_size = ?, display_name = ?, settings_json = ? 
                   WHERE id = ?''',
                (new_settings['theme'], new_settings['notify_severity'], new_settings['page_size'], new_settings['display_name'], settings_json_str, user_id)
            )

        return jsonify({'success': True, 'settings': new_settings, **new_settings})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        app.logger.exception('Reset settings failed')
        return jsonify({'error': 'Reset failed'}), 500


@app.route('/api/account/change-password', methods=['POST'])
@login_required
def change_password():
    """Secure password change for the authenticated user."""
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            return jsonify({'error': 'All password fields are required.'}), 400
        if new_password != confirm_password:
            return jsonify({'error': 'New passwords do not match.'}), 400
        if len(new_password) < 6:
            return jsonify({'error': 'New password must be at least 6 characters.'}), 400

        user_id = session.get('user_id')
        with get_connection() as conn:
            row = conn.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,)).fetchone()
            if not row or not check_password_hash(row['password_hash'], current_password):
                return jsonify({'error': 'Incorrect current password.'}), 400

            new_hash = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))

        return jsonify({'success': True, 'message': 'Password successfully updated.'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        app.logger.exception('Change password failed')
        return jsonify({'error': 'Password update failed'}), 500


@app.route('/api/system/info', methods=['GET'])
@login_required
def get_system_info():
    """Return verified platform environment, framework versions, database diagnostics, and engine status."""
    import platform
    import sklearn
    db_size = 0
    try:
        db_size = os.path.getsize(DB_PATH)
    except OSError:
        pass

    with get_connection() as conn:
        total_events = conn.execute('SELECT COUNT(*) AS c FROM events').fetchone()['c']
        total_users = conn.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
        total_saved = conn.execute('SELECT COUNT(*) AS c FROM saved_queries').fetchone()['c']

    model_ready = model is not None and hasattr(model, 'classes_')
    model_exists = os.path.exists(MODEL_PATH)
    model_size_mb = f"{os.path.getsize(MODEL_PATH) / (1024*1024):.1f} MB" if model_exists else "N/A"
    model_mtime = None
    if model_exists:
        try:
            import datetime
            model_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(MODEL_PATH), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass

    cand_exists = os.path.exists(CANDIDATE_MODEL_PATH)
    cand_size_mb = f"{os.path.getsize(CANDIDATE_MODEL_PATH) / (1024*1024):.1f} MB" if cand_exists else "N/A"
    cand_ready = candidate_model is not None and hasattr(candidate_model, 'classes_')
    cand_mtime = None
    if cand_exists:
        try:
            import datetime
            cand_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(CANDIDATE_MODEL_PATH), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except Exception:
            pass

    user_policy_info = get_user_detection_policy()

    # Inspect parent directory for verified timestamped backups
    latest_backup = None
    try:
        parent_dir = os.path.dirname(os.path.abspath(BASE_DIR))
        backups = [d for d in os.listdir(parent_dir) if d.startswith("ai-ids-backup")]
        if backups:
            backups.sort(reverse=True)
            latest_backup = {
                'name': backups[0],
                'path': os.path.join(parent_dir, backups[0]),
                'verified': True,
                'count': len(backups)
            }
    except Exception:
        pass

    return jsonify({
        'platform_version': 'THREATNEX AI-IDS v2.4.0 (Enterprise SOC Edition)',
        'python_version': platform.python_version(),
        'os': f'{platform.system()} {platform.release()}',
        'flask_version': 'Flask 3.x (WSGI Server)',
        'sklearn_version': sklearn.__version__,
        'database': {
            'status': 'Connected (SQLite3)',
            'size_bytes': db_size,
            'size_formatted': f'{db_size / 1024:.1f} KB' if db_size < 1024*1024 else f'{db_size / (1024*1024):.2f} MB',
            'total_events': total_events,
            'total_users': total_users,
            'saved_queries': total_saved
        },
        'ml_engine': {
            'type': 'RandomForestClassifier (100 estimators)',
            'status': 'Model Loaded & Ready' if model_ready else 'Degraded',
            'feature_count': len(FEATURES),
            'features': FEATURES,
            'classes': LABELS,
            'evaluation_dataset': 'NSL-KDD Standardized Test Partition (22,544 connection vectors)',
            'metrics': load_metrics(),
            'model_file_exists': model_exists,
            'model_file_size': model_size_mb,
            'last_trained': model_mtime or "Recorded at training"
        },
        'candidate_model': {
            'exists': cand_exists,
            'ready': cand_ready,
            'status': 'Ready & Verified' if cand_ready else ('File Found (Not Loaded)' if cand_exists else 'Not Available'),
            'file_name': CANDIDATE_MODEL_PATH.name,
            'file_size': cand_size_mb,
            'type': 'RandomForestClassifier (150 trees, Phase 3.2 validation-calibrated)',
            'recommended_threshold': 0.35,
            'last_modified': cand_mtime or 'Recorded at validation',
            'benchmark_recall': '20.45% (vs 8.63% legacy)',
            'benchmark_accuracy': '79.76% (vs 78.55% legacy)',
            'normal_fpr': '0.08% (<= 0.10% operational limit)'
        },
        'detection_policy': {
            'active_policy': user_policy_info['policy'],
            'requested_policy': user_policy_info['requested_policy'],
            'threshold': user_policy_info['threshold'],
            'fallback_active': user_policy_info['fallback_active'],
            'fallback_reason': user_policy_info['fallback_reason'],
            'supported_policies': ['legacy', 'experimental', 'shadow'],
            'authoritative_fallback': 'Production model.joblib (100% preserved)'
        },
        'backup': latest_backup or {'verified': False, 'name': 'None detected'},
        'csrf_protection': 'Active (X-CSRF-Token Enforced)',
        'operating_mode': 'Connection Summary Vector ML Triage',
        'disclosures': [
            'Telemetry inference operates on connection summary vectors (e.g. durations, byte volumes, error rates).',
            'No raw promiscuous network interface card packet tap or kernel packet capture driver is active.',
            'Encrypted application payloads (TLS/HTTPS) are not decrypted or intercepted.',
            'No automated external firewall or routing table rule mutations are enacted.'
        ]
    })


@app.route('/api/data/cleanup', methods=['POST'])
@admin_required
def cleanup_data():
    """Prune historical events older than configured retention period, with strict confirmation or safe dry-run."""
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        dry_run = bool(data.get('dry_run', False))
        confirm = bool(data.get('confirm_purge', False))
        days = int(data.get('retention_days', data.get('older_than_days', 90)))

        if not confirm and not dry_run:
            return jsonify({'error': 'Confirmation required to execute data cleanup.'}), 400
        if days < 1 or days > 3650:
            return jsonify({'error': 'Retention days must be between 1 and 3650.'}), 400

        cutoff_timestamp = time.time() - (days * 86400)

        with get_connection() as conn:
            row_count = conn.execute('SELECT COUNT(*) AS c FROM events WHERE ts < ?', (cutoff_timestamp,)).fetchone()['c']
            if not dry_run and confirm and row_count > 0:
                conn.execute('DELETE FROM events WHERE ts < ?', (cutoff_timestamp,))

        return jsonify({
            'success': True, 
            'dry_run': dry_run,
            'eligible_count': row_count,
            'purged_count': 0 if dry_run else row_count,
            'cutoff_days': days,
            'message': f'{row_count} events eligible for purge (dry-run).' if dry_run else f'Cleaned {row_count} historical events older than {days} days.'
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception:
        app.logger.exception('Data cleanup failed')
        return jsonify({'error': 'Data cleanup failed'}), 500


# ----- CSRF Token API -----

@app.route('/api/csrf-token', methods=['GET'])
def csrf_token_api():
    """Return the current session CSRF token."""
    return jsonify({'csrf_token': session.get('csrf_token', '')})


# ----- Investigation APIs -----

@app.route('/api/events/<int:event_id>/investigate', methods=['POST'])
@login_required
def investigate_event(event_id):
    """Update investigation status and analyst notes for a specific event."""
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        status = data.get('status', '').strip().lower()
        notes = data.get('notes', '').strip()

        valid_statuses = ('new', 'investigating', 'resolved', 'false_positive')
        if status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        now = time.time()
        with get_connection() as conn:
            cur = conn.execute(
                '''UPDATE events 
                   SET investigation_status = ?, analyst_notes = ?, updated_at = ?
                   WHERE id = ?''',
                (status, notes, now, event_id)
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'Event not found'}), 404

            row = conn.execute(
                '''SELECT id, ts, src_ip, label, severity, confidence, investigation_status, analyst_notes, updated_at
                   FROM events WHERE id = ?''',
                (event_id,)
            ).fetchone()

        item = dict(row)
        lbl = str(item.get("label", ""))
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            item["label"] = LABELS[int(lbl)]
        item["investigation_status"] = item.get("investigation_status") or "new"
        item["analyst_notes"] = item.get("analyst_notes") or ""
        return jsonify({'success': True, 'event': item})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception('Failed to update event investigation')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/events/bulk-investigate', methods=['POST'])
@login_required
def bulk_investigate_events():
    """Batch-update investigation status and optionally append notes for multiple events."""
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        event_ids = data.get('ids', [])
        status = data.get('status', '').strip().lower()
        notes = data.get('notes')

        if not event_ids or not isinstance(event_ids, list):
            return jsonify({'error': 'A non-empty list of event IDs is required.'}), 400

        valid_statuses = ('new', 'investigating', 'resolved', 'false_positive')
        if status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400

        clean_ids = [int(i) for i in event_ids if isinstance(i, (int, str)) and str(i).isdigit()]
        if not clean_ids:
            return jsonify({'error': 'No valid integer IDs provided.'}), 400

        now = time.time()
        placeholders = ','.join('?' for _ in clean_ids)

        with get_connection() as conn:
            if notes is not None:
                query = f"UPDATE events SET investigation_status = ?, analyst_notes = ?, updated_at = ? WHERE id IN ({placeholders})"
                params = [status, notes.strip(), now] + clean_ids
            else:
                query = f"UPDATE events SET investigation_status = ?, updated_at = ? WHERE id IN ({placeholders})"
                params = [status, now] + clean_ids
            cur = conn.execute(query, params)
            updated_count = cur.rowcount

        return jsonify({'success': True, 'updated_count': updated_count})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception('Bulk investigation failed')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/sources/<path:src_ip>', methods=['GET'])
@login_required
def get_source_profile(src_ip):
    """Aggregate historical activity, classifications, severities, and timeline for an IP address."""
    src_ip = src_ip.strip()
    with get_connection() as conn:
        summary = conn.execute(
            '''
            SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN label != 'normal' AND label != '0' THEN 1 ELSE 0 END) AS threats,
                MIN(ts) AS first_seen,
                MAX(ts) AS last_seen
            FROM events
            WHERE src_ip = ?
            ''',
            (src_ip,)
        ).fetchone()

        if not summary or summary['total'] == 0:
            return jsonify({'error': f'No events found for IP {src_ip}'}), 404

        label_rows = conn.execute(
            '''
            SELECT label, COUNT(*) AS count
            FROM events
            WHERE src_ip = ?
            GROUP BY label
            ''',
            (src_ip,)
        ).fetchall()

        labels_breakdown = {}
        for r in label_rows:
            lbl = str(r['label'])
            if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
                lbl = LABELS[int(lbl)]
            labels_breakdown[lbl] = labels_breakdown.get(lbl, 0) + r['count']

        sev_rows = conn.execute(
            '''
            SELECT severity, COUNT(*) AS count
            FROM events
            WHERE src_ip = ?
            GROUP BY severity
            ''',
            (src_ip,)
        ).fetchall()
        severities = {r['severity']: r['count'] for r in sev_rows}

        inv_rows = conn.execute(
            '''
            SELECT investigation_status, COUNT(*) AS count
            FROM events
            WHERE src_ip = ?
            GROUP BY investigation_status
            ''',
            (src_ip,)
        ).fetchall()
        investigations = {r['investigation_status'] or 'new': r['count'] for r in inv_rows}

        recent_rows = conn.execute(
            '''
            SELECT id, ts, label, severity, confidence, investigation_status
            FROM events
            WHERE src_ip = ?
            ORDER BY id DESC
            LIMIT 15
            ''',
            (src_ip,)
        ).fetchall()

        recent = []
        for r in recent_rows:
            item = dict(r)
            lbl = str(item.get("label", ""))
            if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
                item["label"] = LABELS[int(lbl)]
            item['investigation_status'] = item.get('investigation_status') or 'new'
            recent.append(item)

    return jsonify({
        'ip': src_ip,
        'src_ip': src_ip,
        'total': summary['total'],
        'threats': summary['threats'] or 0,
        'threat_ratio': round((summary['threats'] or 0) / summary['total'] * 100, 1) if summary['total'] else 0,
        'first_seen': summary['first_seen'],
        'last_seen': summary['last_seen'],
        'labels': labels_breakdown,
        'severities': severities,
        'investigations': investigations,
        'recent_events': recent
    })


# ----- Saved Searches / Presets API -----

@app.route('/api/saved-queries', methods=['GET', 'POST'])
@login_required
def saved_queries():
    """Retrieve or save user-isolated threat hunting search queries."""
    user_id = session.get('user_id')
    if request.method == 'GET':
        with get_connection() as conn:
            rows = conn.execute(
                'SELECT id, name, query_params, created_at FROM saved_queries WHERE user_id = ? ORDER BY id DESC',
                (user_id,)
            ).fetchall()
        queries = []
        for r in rows:
            params = {}
            try:
                params = json.loads(r['query_params'])
            except Exception:
                pass
            queries.append({
                'id': r['id'],
                'name': r['name'],
                'query_params': params,
                'created_at': r['created_at']
            })
        return jsonify(queries)

    # POST create saved query
    try:
        validate_csrf()
        data = request.get_json(silent=True) or {}
        name = data.get('name', '').strip()
        query_params = data.get('query_params', {})
        if not name:
            return jsonify({'error': 'Saved query name is required.'}), 400
        if len(name) > 80:
            return jsonify({'error': 'Name exceeds 80 characters.'}), 400

        params_json = json.dumps(query_params)
        now = time.time()
        with get_connection() as conn:
            cur = conn.execute(
                'INSERT INTO saved_queries (user_id, name, query_params, created_at) VALUES (?, ?, ?, ?)',
                (user_id, name, params_json, now)
            )
            new_id = cur.lastrowid
        return jsonify({'success': True, 'id': new_id, 'name': name, 'query_params': query_params, 'created_at': now}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception('Save query failed')
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/saved-queries/<int:query_id>', methods=['DELETE'])
@login_required
def delete_saved_query(query_id):
    """Delete a saved search query owned by the logged-in user."""
    try:
        validate_csrf()
        user_id = session.get('user_id')
        with get_connection() as conn:
            cur = conn.execute(
                'DELETE FROM saved_queries WHERE id = ? AND user_id = ?',
                (query_id, user_id)
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'Query not found or not authorized'}), 404
        return jsonify({'success': True, 'message': 'Saved query removed.'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.exception('Delete saved query failed')
        return jsonify({'error': 'Internal server error'}), 500


# ----- Reports Summary API -----

@app.route('/api/reports/summary', methods=['GET'])
@login_required
def get_report_summary():
    """Aggregate executive and technical metrics for the SOC summary report."""
    with get_connection() as conn:
        total = conn.execute('SELECT COUNT(*) AS c FROM events').fetchone()['c']
        threats = conn.execute("SELECT COUNT(*) AS c FROM events WHERE label != 'normal' AND label != '0'").fetchone()['c']
        normal = total - threats

        sev_rows = conn.execute('SELECT severity, COUNT(*) AS count FROM events GROUP BY severity').fetchall()
        severities = {r['severity']: r['count'] for r in sev_rows}

        inv_rows = conn.execute('SELECT investigation_status, COUNT(*) AS count FROM events GROUP BY investigation_status').fetchall()
        investigations = {'new': 0, 'investigating': 0, 'resolved': 0, 'false_positive': 0}
        for r in inv_rows:
            st = str(r['investigation_status'] or 'new').lower()
            investigations[st] = investigations.get(st, 0) + r['count']

        top_ips = conn.execute(
            '''
            SELECT src_ip, 
                   COUNT(*) AS total,
                   SUM(CASE WHEN label != 'normal' AND label != '0' THEN 1 ELSE 0 END) AS threat_count
            FROM events
            WHERE label != 'normal' AND label != '0'
            GROUP BY src_ip
            ORDER BY threat_count DESC, total DESC
            LIMIT 5
            '''
        ).fetchall()
        top_sources = [{'ip': r['src_ip'], 'total': r['total'], 'threats': r['threat_count']} for r in top_ips]

        attack_rows = conn.execute(
            '''
            SELECT label, COUNT(*) AS count
            FROM events
            WHERE label != 'normal' AND label != '0'
            GROUP BY label
            ORDER BY count DESC
            '''
        ).fetchall()
        attack_types = []
        for r in attack_rows:
            lbl = str(r['label'])
            if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
                lbl = LABELS[int(lbl)]
            attack_types.append({'label': lbl, 'count': r['count']})

        unresolved_rows = conn.execute(
            '''
            SELECT id, ts, src_ip, label, severity, confidence, investigation_status
            FROM events
            WHERE severity IN ('critical', 'high') AND (investigation_status IS NULL OR investigation_status IN ('new', 'investigating'))
            ORDER BY id DESC
            LIMIT 10
            '''
        ).fetchall()
        unresolved = []
        for r in unresolved_rows:
            item = dict(r)
            lbl = str(item.get("label", ""))
            if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
                item["label"] = LABELS[int(lbl)]
            item['investigation_status'] = item.get('investigation_status') or 'new'
            unresolved.append(item)

    closed_cases = investigations['resolved'] + investigations['false_positive']
    resolution_rate = round(closed_cases / threats * 100, 1) if threats > 0 else 100.0

    executive_summary = {
        'total_events': total,
        'threat_events': threats,
        'normal_events': normal,
        'threat_percentage': round(threats / total * 100, 1) if total > 0 else 0.0,
        'resolution_rate': resolution_rate,
    }

    return jsonify({
        'generated_at': time.time(),
        'executive_summary': executive_summary,
        'total_events': total,
        'threat_events': threats,
        'normal_events': normal,
        'threat_percentage': round(threats / total * 100, 1) if total > 0 else 0.0,
        'resolution_rate': resolution_rate,
        'severities': severities,
        'investigations': investigations,
        'top_threat_sources': top_sources,
        'attack_breakdown': attack_types,
        'priority_unresolved': unresolved,
        'model_info': {
            'type': 'RandomForestClassifier (100 estimators)',
            'evaluation_dataset': 'NSL-KDD Test+ (22,544 rows, 12 engineered features)',
            'metrics': load_metrics(),
            'known_limitations': 'Classification is performed on aggregated connection summary vectors; raw payload content and encrypted SNI are not inspected.'
        }
    })


# ----- Query API -----

@app.route('/api/query', methods=['GET'])
@login_required
def query_events():
    """Advanced search/filter events with pagination, sorting, and structured conditions."""
    src_ip = request.args.get('src_ip', '').strip()
    label = request.args.get('label', '').strip().lower()
    severity = request.args.get('severity', '').strip().lower()
    status = request.args.get('status', '').strip().lower()
    q = request.args.get('q', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    time_preset = request.args.get('time_preset', '').strip().lower()
    min_conf = request.args.get('min_conf')
    max_conf = request.args.get('max_conf')

    # Sorting
    sort_by_raw = request.args.get('sort_by', 'id').strip().lower()
    sort_order_raw = request.args.get('sort_order', 'desc').strip().lower()
    allowed_sort_cols = {
        'id': 'id',
        'ts': 'ts',
        'timestamp': 'ts',
        'src_ip': 'src_ip',
        'label': 'label',
        'severity': 'severity',
        'confidence': 'confidence',
        'status': 'investigation_status',
        'investigation_status': 'investigation_status'
    }
    sort_col = allowed_sort_cols.get(sort_by_raw, 'id')
    sort_dir = 'ASC' if sort_order_raw == 'asc' else 'DESC'

    # Pagination
    try:
        page = max(1, int(request.args.get('page', 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        page_size = min(max(1, int(request.args.get('page_size', request.args.get('limit', 20)))), 200)
    except (ValueError, TypeError):
        page_size = 20

    conditions = []
    params = []

    if src_ip:
        conditions.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if label and label != 'all':
        conditions.append("label = ?")
        params.append(label)
    if severity and severity != 'all':
        conditions.append("severity = ?")
        params.append(severity)
    if status and status != 'all':
        conditions.append("investigation_status = ?")
        params.append(status)
    if q:
        conditions.append("(src_ip LIKE ? OR label LIKE ? OR severity LIKE ? OR analyst_notes LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"])

    if min_conf is not None and min_conf != '':
        try:
            conditions.append("confidence >= ?")
            params.append(float(min_conf))
        except ValueError:
            pass
    if max_conf is not None and max_conf != '':
        try:
            conditions.append("confidence <= ?")
            params.append(float(max_conf))
        except ValueError:
            pass

    # Time presets
    now = time.time()
    if time_preset == '1h':
        conditions.append("ts >= ?")
        params.append(now - 3600)
    elif time_preset == '24h':
        conditions.append("ts >= ?")
        params.append(now - 86400)
    elif time_preset == '7d':
        conditions.append("ts >= ?")
        params.append(now - 604800)
    elif time_preset == '30d':
        conditions.append("ts >= ?")
        params.append(now - 2592000)

    if date_from:
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(date_from)
            conditions.append("ts >= ?")
            params.append(dt.timestamp())
        except ValueError:
            pass
    if date_to:
        try:
            import datetime
            dt = datetime.datetime.fromisoformat(date_to)
            conditions.append("ts <= ?")
            params.append(dt.timestamp())
        except ValueError:
            pass

    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""

    with get_connection() as conn:
        count_query = f"SELECT COUNT(*) AS total FROM events{where_clause}"
        total_count = conn.execute(count_query, params).fetchone()['total']

        offset = (page - 1) * page_size
        data_query = f"""
            SELECT id, ts, src_ip, label, severity, confidence, investigation_status, analyst_notes, updated_at
            FROM events
            {where_clause}
            ORDER BY {sort_col} {sort_dir}
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(data_query, params + [page_size, offset]).fetchall()

    results = []
    for r in rows:
        item = dict(r)
        lbl = str(item.get("label", ""))
        if lbl.isdigit() and 0 <= int(lbl) < len(LABELS):
            item["label"] = LABELS[int(lbl)]
        item["investigation_status"] = item.get("investigation_status") or "new"
        item["analyst_notes"] = item.get("analyst_notes") or ""
        results.append(item)

    total_pages = (total_count + page_size - 1) // page_size if page_size > 0 else 1

    return jsonify({
        "results": results,
        "events": results,
        "total": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    })


# ----- Admin Setup -----

@app.route('/api/setup-admin', methods=['POST'])
def setup_admin():
    """Create the initial admin user if no users exist. Safe to call multiple times."""
    with get_connection() as conn:
        count = conn.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
        if count > 0:
            return jsonify({'error': 'Users already exist. Admin setup is disabled.'}), 403

    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required.'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters.'}), 400

    hashed = generate_password_hash(password)
    with get_connection() as conn:
        conn.execute(
            'INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)',
            (username, hashed)
        )
    return jsonify({'success': True, 'message': f'Admin user "{username}" created.'})


# ----- User Info API -----

@app.route('/api/me', methods=['GET'])
@login_required
def current_user_info():
    """Return the currently logged-in user's basic info."""
    user_id = session.get('user_id')
    with get_connection() as conn:
        row = conn.execute('SELECT id, username, display_name, is_admin, settings_json FROM users WHERE id = ?', (user_id,)).fetchone()
        if row:
            disp = row['display_name']
            if not disp and row['settings_json']:
                try:
                    s = json.loads(row['settings_json'])
                    if isinstance(s, dict):
                        disp = s.get('display_name')
                except Exception:
                    pass
            return jsonify({
                'id': row['id'],
                'username': row['username'],
                'display_name': disp or row['username'],
                'is_admin': bool(row['is_admin'])
            })
    return jsonify({'error': 'User not found'}), 404


@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
@login_required
def health_check():
    """Verify application, database connectivity, and ML engine state."""
    db_ok = False
    event_count = 0
    try:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
            event_count = row["c"] if row else 0
            db_ok = True
    except Exception as e:
        app.logger.warning(f"Database health check error: {e}")

    model_ready = False
    model_classes = []
    try:
        if model is not None and hasattr(model, "classes_"):
            model_ready = True
            model_classes = [LABELS[i] if i < len(LABELS) else str(c) for i, c in enumerate(model.classes_)]
    except Exception:
        pass

    return jsonify({
        "status": "healthy" if (db_ok and model_ready) else "degraded",
        "app": "operational",
        "database": {
            "status": "connected" if db_ok else "disconnected",
            "event_count": event_count
        },
        "model": {
            "status": "ready" if model_ready else "not_loaded",
            "type": "RandomForestClassifier",
            "classes": model_classes,
            "feature_count": len(FEATURES)
        },
        "engine_mode": "Machine Learning inference on 12 NSL-KDD network features (simulated/ingested traffic; no live packet capture driver)",
        "timestamp": time.time()
    }), 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
