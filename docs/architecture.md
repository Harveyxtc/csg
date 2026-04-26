# Architecture Overview — Project Proactive Defense

## System Architecture

Project Proactive Defense follows a **modular monolith** architecture built with Flask. Each security function is encapsulated in its own module, all sharing a single SQLite database.

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Browser (Client)                    │
│                  HTML / CSS / Chart.js / JS                  │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP
┌──────────────────────────┴──────────────────────────────────┐
│                     Flask Application (app.py)               │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────────┐ │
│  │ Auth Routes │  │ Dashboard  │  │ API Endpoints          │ │
│  │ /login     │  │ Routes     │  │ /api/chat              │ │
│  │ /register  │  │ /          │  │ /event/<id>/acknowledge │ │
│  │ /logout    │  │ /events    │  │ /event/<id>/resolve     │ │
│  └────────────┘  │ /ingest    │  │ /scan                   │ │
│                  │ /reports   │  └────────────────────────┘ │
│                  │ /settings  │                              │
│                  └────────────┘                              │
│                                                              │
│  ┌───────────────────── Modules ──────────────────────────┐ │
│  │                                                         │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │ │
│  │  │ Module 1    │  │ Module 2    │  │ Module 3       │ │ │
│  │  │ Ingestion   │  │ Detection   │  │ Interpretation │ │ │
│  │  │ (ingest.py) │  │(detector.py)│  │(interpreter.py)│ │ │
│  │  └─────────────┘  └─────────────┘  └────────────────┘ │ │
│  │                                                         │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │ │
│  │  │ Module 4    │  │ Module 5    │  │ AI Assistant   │ │ │
│  │  │ Reporting   │  │ Auth        │  │ (chatbot)      │ │ │
│  │  │(report_gen.)│  │(auth_mgr.)  │  │(assistant.py)  │ │ │
│  │  └─────────────┘  └─────────────┘  └────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  database.py (SQLite)                    │ │
│  │  users │ threat_events │ ingested_logs │ audit_log      │ │
│  │  system_config │ reports                                │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

## Data Flow

```
CSV Upload ──► Module 1: Ingestion ──► ingested_logs table
                                            │
                                            ▼
                                   Module 2: Detection
                                   (10 detection rules)
                                            │
                                            ▼
                                   Module 3: Interpretation
                                   (plain-English explanations)
                                            │
                                            ▼
                                   threat_events table
                                            │
                            ┌───────────────┼───────────────┐
                            ▼               ▼               ▼
                       Dashboard       Reports Page     AI Assistant
                      (6 SIEM charts)  (PDF/CSV)       (chatbot)
```

### Step-by-Step Flow

1. **Ingestion** — User uploads a CSV log file. Module 1 validates the format (required columns: `timestamp`, `event_type`, `user`, `ip_address`, `details`) and stores each valid row in the `ingested_logs` table.

2. **Detection** — When the user clicks "Run Detection Scan", Module 2 fetches unprocessed logs and runs them through 10 detection rules (brute force, phishing, malware, port scans, privilege escalation, etc.). Each rule checks specific patterns in the log data.

3. **Interpretation** — Module 3 translates each detected threat into a plain-English explanation and actionable recommendation, making the output accessible to non-technical SME users.

4. **Storage** — Detected threats are saved to the `threat_events` table with severity level, source module, explanation, and recommendation.

5. **Visualisation** — The dashboard renders 6 SIEM-style charts (Chart.js) from live database queries. The AI Assistant can also pull live threat summaries.

6. **Reporting** — Module 4 generates PDF or CSV reports on demand or on a weekly schedule via Flask-APScheduler.

## Module Details

### Module 1: Log Ingestion (`src/ingestion/ingest.py`)
- CSV file validation (column checks, timestamp format)
- Row-level error handling (malformed entries are rejected, valid ones are saved)
- Tracks which logs have been processed via a `processed` flag

### Module 2: Threat Detection (`src/detection/detector.py`)
10 data-driven detection rules:

| # | Rule | Severity | Trigger |
|---|------|----------|---------|
| 1 | Brute Force Login | High | Multiple failed logins from same IP |
| 2 | Phishing Email | Medium | Suspicious sender domains or known phishing patterns |
| 3 | Malware Detected | High | Known malware signatures or suspicious file activity |
| 4 | Suspicious File Modification | Medium | Rapid file renames or modifications |
| 5 | Unauthorised Access Attempt | High | Access to restricted resources |
| 6 | Network Port Scan | Low | Sequential port scanning activity |
| 7 | Privilege Escalation Attempt | High | Attempts to gain elevated permissions |
| 8 | Suspicious Download | Medium | Downloads of potentially dangerous file types |
| 9 | Configuration Change | Low | Unexpected system configuration modifications |
| 10 | Phishing via Email Link | High | Emails containing links to known malicious domains |

### Module 3: Interpretation Engine (`src/interpretation/interpreter.py`)
- Maps each detection rule to a plain-English template
- Injects context-specific details (IP addresses, usernames, file paths)
- Provides severity-appropriate recommendations

### Module 4: Report Generation (`src/reporting/report_generator.py`)
- **On-Demand PDF** — Full security report with event summaries
- **Weekly PDF** — Scheduled report via Flask-APScheduler
- **CSV Export** — Raw event data for spreadsheet analysis
- Reports stored in `reports/` directory with metadata in `reports` table

### Module 5: Authentication (`src/auth/auth_manager.py`)
- PBKDF2-SHA256 password hashing (600,000 iterations)
- Flask-Login session management
- Role-based access (admin role)
- CSRF protection via Flask-WTF

### AI Security Assistant (`src/chatbot/assistant.py`)
- Rule-based chatbot with 15 knowledge base topics
- Keyword matching with weighted scoring
- Dynamic threat summary from live database queries
- Accessible from every page via floating panel

## Database Schema

Six SQLite tables (see `docs/database_schema.md` for full column details):

| Table | Records |
|-------|---------|
| `users` | User accounts and hashed passwords |
| `threat_events` | Detected threats with severity, status, explanations |
| `ingested_logs` | Raw uploaded log entries |
| `audit_log` | User action trail |
| `system_config` | Application settings |
| `reports` | Report generation history |

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.9+, Flask |
| Database | SQLite (via `sqlite3`) |
| Frontend | Jinja2 templates, HTML5, CSS3 |
| Charts | Chart.js (CDN) |
| Auth | Flask-Login, PBKDF2-SHA256 |
| Forms | Flask-WTF (CSRF) |
| Scheduling | Flask-APScheduler |
| PDF Generation | fpdf2 |
| Testing | Pytest |
