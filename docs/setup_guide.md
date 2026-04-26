# Setup Guide — Project Proactive Defense

## Prerequisites

- **Python 3.9+** installed on your system
- **pip** (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/basicl1fe/csg3101-proactive-defense.git
cd csg3101-proactive-defense
```

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| Flask-Login | User session management |
| Flask-WTF | Form handling & CSRF protection |
| Flask-APScheduler | Scheduled background tasks |
| fpdf2 | PDF report generation |
| pytest | Test framework |
| transformers | Local AI model interface |
| torch | ML backend for AI model |
| accelerate | Optimised model execution |
| safetensors | Safe tensor storage for models |

### 4. Run the Application

```bash
python src/app.py
```

The server starts at **http://127.0.0.1:5000**.

### 5. Default Login

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `admin123` |

A default admin account is created automatically on first launch.

## Quick Start Workflow

1. **Log in** with the default credentials
2. **Ingest logs** — Navigate to *Ingest Logs* and upload `data/sample_logs/logs.csv`
3. **Run a detection scan** — Click *Run Detection Scan* on the dashboard
4. **Review threats** — Check the dashboard charts and the *All Events* page
5. **Generate a report** — Click *Export PDF Report* or visit the *Reports* page

## Running Tests

```bash
python -m pytest tests/ -v
```

All 33 tests should pass, covering all 5 modules:
- `test_auth.py` — Authentication & user management (8 tests)
- `test_detection.py` — Threat detection engine (7 tests)
- `test_ingestion.py` — Log ingestion & validation (7 tests)
- `test_interpretation.py` — Plain-English explanations (6 tests)
- `test_reporting.py` — PDF/CSV report generation (5 tests)

## Project Structure

```
project-proactive-defense/
├── src/
│   ├── app.py                  # Flask application entry point
│   ├── config.py               # Configuration settings
│   ├── database.py             # SQLite database models & queries
│   ├── auth/
│   │   └── auth_manager.py     # Module 5: Authentication (PBKDF2)
│   ├── ingestion/
│   │   └── ingest.py           # Module 1: Log ingestion & CSV validation
│   ├── detection/
│   │   └── detector.py         # Module 2: 10 data-driven detection rules
│   ├── interpretation/
│   │   └── interpreter.py      # Module 3: Plain-English explanations
│   ├── reporting/
│   │   └── report_generator.py # Module 4: PDF/CSV report generation
│   ├── chatbot/
│   │   └── assistant.py        # AI Security Assistant (rule-based)
│   ├── routes/
│   │   ├── dashboard_routes.py # Dashboard, events, module & API routes
│   │   └── auth_routes.py      # Login, logout, register routes
│   └── templates/              # 12 Jinja2 HTML templates
│       └── static/css/style.css
├── data/sample_logs/
│   └── logs.csv                # 34 sample log entries
├── docs/                       # Project documentation
├── reports/                    # Generated PDF/CSV reports (runtime)
├── tests/                      # 33 Pytest test cases
├── requirements.txt
└── README.md
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Make sure you've activated the virtual environment and run `pip install -r requirements.txt` |
| Port 5000 already in use | Stop any other Flask apps or change the port in `src/config.py` |
| Database errors | Delete `data/proactive_defense.db` and restart — it will be recreated automatically |
| Login not working | The default admin account is created on first launch; restart the app if needed |
