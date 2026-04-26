# User Guide — Project Proactive Defense

A step-by-step guide for SME users to monitor and manage cybersecurity threats using the dashboard.

---

## Logging In

1. Open your browser and navigate to `http://127.0.0.1:5000`
2. Enter your **username** and **password**
3. Click **Sign In**

Default credentials: `admin` / `admin123`

> Change the default password after your first login via the Settings page.

---

## Dashboard Overview

The main dashboard provides a real-time view of your security posture through six charts:

| Chart | What It Shows |
|-------|--------------|
| **Severity Distribution** | Doughnut chart — proportion of High, Medium, and Low severity events |
| **Event Trend (Last 7 Days)** | Line chart — how many events were detected each day |
| **Severity by Module** | Stacked bar — severity breakdown for each detection module |
| **Top Threat Categories** | Horizontal bar — the most common types of threats detected |
| **Activity by Hour of Day** | Bar chart — which hours of the day have the most activity |
| **Event Status Overview** | Pie chart — how many events are Open, Acknowledged, or Resolved |

At the top of the dashboard you'll also see summary cards showing total events and counts by severity.

---

## Ingesting Logs

Before the system can detect threats, you need to upload log data.

1. Click **Ingest Logs** in the sidebar
2. Click **Choose File** and select a CSV file
3. Click **Upload & Ingest**

### CSV File Format

Your CSV file must include these columns:

| Column | Format | Example |
|--------|--------|---------|
| `timestamp` | `YYYY-MM-DD HH:MM` | `2026-03-10 08:03` |
| `event_type` | Text | `Failed Login` |
| `user` | Text | `admin` |
| `ip_address` | Text | `192.168.1.105` |
| `details` | Text | `Multiple failed login attempts` |

A sample CSV file is provided at `data/sample_logs/logs.csv` with 34 entries.

---

## Running a Detection Scan

1. From the **Dashboard**, click the **Run Detection Scan** button
2. The system processes all unprocessed logs through 10 detection rules
3. A confirmation message shows how many logs were processed and threats detected
4. The dashboard charts update automatically with the new data

### Detection Rules

The system checks for:
- Brute force login attempts
- Phishing emails
- Malware activity
- Suspicious file modifications
- Unauthorised access attempts
- Network port scans
- Privilege escalation attempts
- Suspicious downloads
- Configuration changes
- Phishing via email links

---

## Managing Threat Events

### Viewing Events

Click **All Events** in the sidebar to see every detected threat in a table with:
- Timestamp, event type, severity, source module
- Plain-English explanation of what happened
- Recommended actions to take

### Responding to Events

Each event has two action buttons:

- **Acknowledge** — Marks the event as seen. Use this when you've reviewed the threat and are aware of it.
- **Resolve** — Marks the event as handled. Use this after you've taken the recommended action.

> **Tip:** Always address High severity events first, then Medium, then Low.

---

## Using the AI Security Assistant

The chatbot is available on every page via the purple robot icon in the bottom-right corner.

### How to Use

1. Click the **robot icon** (bottom-right) to open the chat panel
2. Type your question and press **Enter** or click the send button
3. The assistant responds with cybersecurity guidance

### What You Can Ask

| Question Type | Example |
|--------------|---------|
| Threat explanations | "What is phishing?" |
| Best practices | "How do I create a strong password?" |
| Live data | "Show me my threat summary" |
| Guidance | "What should I do about a high severity alert?" |
| Dashboard help | "How do I generate a report?" |

The assistant covers 15 cybersecurity topics including phishing, malware, ransomware, passwords, 2FA, firewalls, Wi-Fi security, social engineering, and more.

---

## Generating Reports

### From the Dashboard

Click **Export PDF Report** at the top-right of the dashboard for a quick PDF export.

### From the Reports Page

1. Click **Reports** in the sidebar
2. Choose a report type:
   - **On-Demand PDF** — Full security report with all current events
   - **Weekly PDF** — Summary report formatted for regular reviews
   - **CSV Export** — Raw data for spreadsheet analysis
3. Click **Generate**
4. The report downloads automatically

Reports are also saved in the `reports/` folder for future access.

---

## Module Pages

### Malware Detection

Displays events detected by the malware detection rules, filtered to show malware-specific threats. Access via **Malware Detection** in the sidebar.

### Email Analysis

Shows phishing and email-based threats. Includes events from both phishing detection rules. Access via **Email Analysis** in the sidebar.

### System Monitor

Displays system-level threats including unauthorised access, port scans, privilege escalation, and configuration changes. Access via **System Monitor** in the sidebar.

---

## Settings

Access system settings via **Settings** in the sidebar:

| Setting | Options | Description |
|---------|---------|-------------|
| Malware Detection | Enabled / Disabled | Toggle malware scanning |
| Email Analysis | Enabled / Disabled | Toggle email threat analysis |
| Scan Interval | Hourly / Daily / Weekly | How often automatic scans run |
| Alert Threshold | Low / Medium / High | Minimum severity level for alerts |

---

## Audit Log

The **Audit Log** page (under Admin in the sidebar) shows a chronological record of all actions taken in the system:
- User logins and logouts
- Log file uploads
- Detection scans
- Event status changes
- Report generation
- Settings modifications

This provides accountability and helps track who did what and when.
