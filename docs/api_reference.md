# API Reference — Project Proactive Defense

All routes require authentication via Flask-Login unless otherwise noted.

## Authentication Routes

| Method | Route | Description | Auth Required |
|--------|-------|-------------|:-------------:|
| GET | `/login` | Display login form | No |
| POST | `/login` | Authenticate user | No |
| GET | `/register` | Display registration form | No |
| POST | `/register` | Create new user account | No |
| GET | `/logout` | Log out current user | Yes |

### POST `/login`

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `username` | string | Yes | User's login name |
| `password` | string | Yes | User's password |

**Response:** Redirect to `/` on success, re-render login page with error on failure.

### POST `/register`

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `username` | string | Yes | Desired username |
| `password` | string | Yes | Password (min 6 characters) |
| `confirm_password` | string | Yes | Must match password |

**Response:** Redirect to `/login` on success with flash message.

---

## Dashboard Routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/` | Main dashboard with SIEM charts and stats |
| GET | `/events` | All threat events table with filtering |
| GET | `/malware` | Malware Detection module page |
| GET | `/email-analysis` | Email Analysis module page |
| GET | `/system-monitor` | System Monitor module page |
| GET | `/ingest` | Log ingestion upload page |
| GET | `/reports` | Reports generation page |
| GET | `/settings` | System configuration page |
| GET | `/audit-log` | Audit trail viewer |

---

## Action Routes

### POST `/ingest`

Upload a CSV log file for ingestion.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `log_file` | file | Yes | CSV file with columns: `timestamp`, `event_type`, `user`, `ip_address`, `details` |

**Response:** Redirect to `/ingest` with flash message showing count of ingested records.

### POST `/scan`

Run the detection engine on all unprocessed logs.

**Response:** Redirect to `/` with flash message showing scan results (logs processed, threats detected).

### POST `/event/<int:event_id>/acknowledge`

Mark a threat event as "Acknowledged".

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `event_id` | integer | ID of the threat event |

**Response:** Redirect to referrer page.

### POST `/event/<int:event_id>/resolve`

Mark a threat event as "Resolved".

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `event_id` | integer | ID of the threat event |

**Response:** Redirect to referrer page.

### POST `/settings`

Update system configuration values.

**Form Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `malware_detection_enabled` | checkbox | Enable/disable malware detection |
| `email_analysis_enabled` | checkbox | Enable/disable email analysis |
| `scan_interval` | select | Scan frequency (hourly, daily, weekly) |
| `alert_threshold` | select | Minimum severity for alerts (Low, Medium, High) |

**Response:** Redirect to `/settings` with flash message.

---

## Report Generation Routes

### POST `/generate-report`

Generate a security report.

**Form Fields:**
| Field | Type | Required | Description |
|-------|------|:--------:|-------------|
| `report_type` | string | Yes | One of: `on_demand`, `weekly`, `csv` |

**Response:**
- PDF reports: File download (`application/pdf`)
- CSV reports: File download (`text/csv`)

### GET `/export-pdf`

Quick export — generates and downloads an on-demand PDF report directly from the dashboard.

**Response:** PDF file download.

---

## API Endpoints

### POST `/api/chat`

Send a message to the AI Security Assistant.

**Request Body (JSON):**
```json
{
  "message": "What is phishing?"
}
```

**Response (JSON):**
```json
{
  "response": "**Phishing** is when attackers send fake emails...",
  "topic": "Phishing"
}
```

**Error Response (400):**
```json
{
  "error": "No message provided"
}
```

**Topics the assistant can respond to:**
| Topic | Example Questions |
|-------|-------------------|
| Phishing | "What is phishing?", "How to spot fake emails?" |
| Malware | "What is malware?", "How to protect against viruses?" |
| Password Security | "How do I create a strong password?" |
| Ransomware | "What should I do about ransomware?" |
| Data Backups | "How should I back up my data?" |
| Two-Factor Auth | "What is 2FA?", "How do I enable MFA?" |
| Firewall & Network | "What is a firewall?", "How to secure my network?" |
| Software Updates | "Why are updates important?" |
| Reports | "How do I generate a report?" |
| Severity Levels | "What do High, Medium, and Low mean?" |
| Threat Summary | "Show me my current threat summary" (live data) |
| Responding to Threats | "What should I do about a high severity alert?" |
| Wi-Fi Security | "How to secure my Wi-Fi?" |
| Social Engineering | "What is social engineering?" |
| General Help | "Hello", "What can you do?" |
