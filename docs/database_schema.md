# Database Schema — Project Proactive Defense

The application uses a single SQLite database file (`proactive_defense.db`) created automatically on first launch. All schema definitions are in `src/database.py`.

## Tables

### 1. `users`

Stores registered user accounts with hashed passwords.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique user ID |
| `username` | TEXT | UNIQUE, NOT NULL | Login username |
| `password_hash` | TEXT | NOT NULL | PBKDF2-SHA256 hashed password |
| `role` | TEXT | DEFAULT 'admin' | User role |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Account creation time |

### 2. `threat_events`

Central store for all detected security threats. Populated by the detection engine.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique event ID |
| `timestamp` | TEXT | NOT NULL | When the original log event occurred |
| `event_type` | TEXT | NOT NULL | Type of threat (e.g., "Brute Force Login Attempt") |
| `source_module` | TEXT | NOT NULL | Which module detected it (e.g., "System Monitor") |
| `severity` | TEXT | NOT NULL, CHECK IN ('Low','Medium','High') | Threat severity level |
| `user_affected` | TEXT | | Username involved in the event |
| `ip_address` | TEXT | | Source IP address |
| `details` | TEXT | | Raw event details from the log |
| `explanation` | TEXT | | Plain-English explanation (Module 3) |
| `recommendation` | TEXT | | Actionable recommendation for the user |
| `status` | TEXT | DEFAULT 'Open', CHECK IN ('Open','Acknowledged','Resolved') | Current event status |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | When the event was created in the database |

### 3. `ingested_logs`

Stores raw log entries uploaded via CSV files before they are processed by the detection engine.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique log entry ID |
| `timestamp` | TEXT | NOT NULL | Original log timestamp |
| `event_type` | TEXT | NOT NULL | Log event type |
| `user` | TEXT | | Username from the log |
| `ip_address` | TEXT | | IP address from the log |
| `details` | TEXT | | Raw log details |
| `source_file` | TEXT | | Filename of the uploaded CSV |
| `ingested_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | When the log was imported |
| `processed` | INTEGER | DEFAULT 0 | 0 = unprocessed, 1 = processed by detection engine |

### 4. `audit_log`

Tracks user actions within the application for accountability.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique entry ID |
| `timestamp` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | When the action occurred |
| `action` | TEXT | NOT NULL | Action performed (e.g., "User login", "Detection scan") |
| `performed_by` | TEXT | | Username who performed the action |
| `details` | TEXT | | Additional context about the action |

### 5. `system_config`

Key-value store for application settings, configurable from the Settings page.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `key` | TEXT | PRIMARY KEY | Setting name |
| `value` | TEXT | NOT NULL | Setting value |
| `updated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Last modification time |

**Default values:**

| Key | Default Value |
|-----|---------------|
| `malware_detection_enabled` | `true` |
| `email_analysis_enabled` | `true` |
| `scan_interval` | `daily` |
| `alert_threshold` | `Medium` |

### 6. `reports`

Metadata for generated security reports (actual files are stored in the `reports/` directory).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique report ID |
| `report_type` | TEXT | NOT NULL | Type of report (e.g., "on_demand", "weekly", "csv") |
| `filename` | TEXT | NOT NULL | Generated report filename |
| `generated_by` | TEXT | | Username who generated the report |
| `generated_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Generation timestamp |
| `parameters` | TEXT | | JSON string of report parameters |

## Entity Relationship Diagram

```
┌──────────────┐       ┌─────────────────┐       ┌──────────────┐
│    users     │       │  ingested_logs   │       │  audit_log   │
├──────────────┤       ├─────────────────┤       ├──────────────┤
│ id (PK)      │       │ id (PK)          │       │ id (PK)      │
│ username     │       │ timestamp         │       │ timestamp    │
│ password_hash│       │ event_type        │       │ action       │
│ role         │       │ user              │       │ performed_by │
│ created_at   │       │ ip_address        │       │ details      │
└──────────────┘       │ details           │       └──────────────┘
                       │ source_file       │
                       │ ingested_at       │
                       │ processed ────────┼──► Detection Engine
                       └─────────────────┘              │
                                                         ▼
┌──────────────────┐                        ┌────────────────────┐
│  system_config   │                        │   threat_events    │
├──────────────────┤                        ├────────────────────┤
│ key (PK)         │                        │ id (PK)            │
│ value            │                        │ timestamp          │
│ updated_at       │                        │ event_type         │
└──────────────────┘                        │ source_module      │
                                            │ severity           │
┌──────────────────┐                        │ user_affected      │
│     reports      │                        │ ip_address         │
├──────────────────┤                        │ details            │
│ id (PK)          │                        │ explanation        │
│ report_type      │                        │ recommendation     │
│ filename         │                        │ status             │
│ generated_by     │                        │ created_at         │
│ generated_at     │                        └────────────────────┘
│ parameters       │
└──────────────────┘
```

## Key Queries (Dashboard Stats)

The `get_dashboard_stats()` function runs the following queries to power the SIEM charts:

| Query | Chart |
|-------|-------|
| Count by severity (High/Medium/Low) | Severity Distribution (doughnut) |
| Count by date (last 7 days) | Event Trend (line) |
| Count by source_module + severity | Severity by Module (stacked bar) |
| Count by event_type (top 10) | Top Threat Categories (horizontal bar) |
| Count by hour of day | Activity by Hour of Day (bar) |
| Count by status (Open/Acknowledged/Resolved) | Event Status Overview (pie) |
