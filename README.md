# THREATNEX — AI-Driven Intrusion Detection System (AI-IDS)

THREATNEX is an enterprise-grade, machine-learning-powered Network Intrusion Detection System (NIDS) designed for Security Operations Centers (SOC). It provides real-time traffic classification, behavioral anomaly detection, probability-calibrated threat hunting, and automated incident investigation.

---

## Key Features

- **Multi-Class AI Detection Engine:** High-performance Random Forest classifier trained on the NSL-KDD benchmark dataset, categorizing traffic into 4 primary classes:
  - `normal` (Legitimate network traffic)
  - `dos` (Denial of Service attacks)
  - `probe` (Network surveillance, port scans, host sweeps)
  - `brute_force` (Password guessing, credential stuffing, SSH/FTP attacks)
- **Calibrated Policy Governance:**
  - *Legacy Policy:* Standard argmax classification.
  - *Experimental Policy:* Threshold calibration ($\tau = 0.35$) for enhanced brute-force recall.
  - *Shadow Mode:* Real-time candidate model evaluation without operational disruption.
- **Cyber SOC Dashboard:** Real-time threat KPIs, priority alerts, source IP threat intelligence, hourly timeline analytics, and MITRE ATT&CK alignment.
- **Interactive Query Center:** Advanced multi-column search, severity filtering, pagination, analyst notes, and CSV/JSON export.
- **Dual-Engine Architecture:** Transparent database abstraction supporting SQLite for local development and managed PostgreSQL (Neon / Vercel Postgres) for cloud serverless deployment.
- **Enterprise Security Hardening:** Role-based access control (`@admin_required`), `scrypt` password hashing, timing-attack-resistant CSRF validation, and `HttpOnly`/`SameSite`/`Secure` session protection.

---

## Architecture Overview

```
THREATNEX AI-IDS
├── api/
│   └── index.py            # Vercel Serverless Function entry point (WSGI)
├── static/
│   ├── index.html          # SOC Analyst dashboard single-page workspace
│   ├── login.html          # Dual-tab authentication portal (Sign In / Register)
│   ├── styles.css          # Dark SOC & Light Enterprise themes
│   └── app.js              # Real-time dashboard controller and chart engine
├── app.py                  # Core Flask WSGI application & REST API routes
├── db_adapter.py           # Dual-engine database adapter (SQLite / PostgreSQL)
├── schema_postgres.sql     # PostgreSQL DDL schema & performance indexes
├── migrate_to_postgres.py  # Idempotent SQLite-to-PostgreSQL migration utility
├── model.joblib            # Production ML classifier (150 estimators, 12 features)
├── model_candidate.joblib  # Calibrated candidate ML classifier
├── metrics.json            # Model evaluation metrics & confusion matrix
├── requirements.txt        # Production Python dependencies
└── vercel.json             # Vercel serverless routing configuration
```

---

## Local Quickstart

### Prerequisites
- Python 3.10+ (Tested on Python 3.12–3.15)
- Git

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/THREATNEX-AI-IDS.git
   cd THREATNEX-AI-IDS
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python app.py
   ```
5. Open your browser and navigate to `http://localhost:5000`.

---

## Production Deployment (Vercel + Neon)

1. Provision a free serverless PostgreSQL database on [Neon](https://neon.tech).
2. Migrate existing records:
   ```bash
   python migrate_to_postgres.py --postgres-url "YOUR_NEON_CONNECTION_STRING"
   ```
3. Deploy to Vercel:
   ```bash
   vercel
   ```
4. In your Vercel Project Settings, configure the following Environment Variables:
   - `DATABASE_URL`: `YOUR_NEON_CONNECTION_STRING`
   - `THREATNEX_SECRET_KEY`: `(Generated 64-character hex key)`
   - `VERCEL_SUPPORT_LARGE_FUNCTIONS`: `1`
   - `SESSION_COOKIE_SECURE`: `1`
   - `FLASK_ENV`: `production`

---

## License

This project is developed for BCA Final Year Academic & Educational Demonstration.

