"""
Module 4: Report Generator
Generates PDF and CSV exports of security alerts, logs, and summaries.
Supports weekly and on-demand reports with risk levels, alert sources,
timestamps, and recommended actions.
"""

import csv
import os
from datetime import datetime
from fpdf import FPDF
from src.database import (
    get_db_connection, get_threat_events, get_dashboard_stats,
    add_audit_entry
)
from src.config import Config


class SecurityReportPDF(FPDF):
    """Custom PDF class for security reports."""

    def header(self):
        self.set_font("Helvetica", "B", 16)
        self.set_fill_color(75, 0, 130)
        self.set_text_color(255, 255, 255)
        self.cell(0, 14, "  Project Proactive Defense - Security Report", new_x="LMARGIN", new_y="NEXT", fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}  |  Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}", align="C")


class ReportGenerator:
    """Handles generation of PDF and CSV security reports."""

    def __init__(self):
        Config.init_dirs()

    def generate_pdf_report(self, report_type="on_demand", generated_by="system"):
        """
        Generate a comprehensive PDF security report.

        Args:
            report_type: 'weekly' or 'on_demand'
            generated_by: Username who requested the report

        Returns:
            dict with success status and file path.
        """
        stats = get_dashboard_stats()
        events = get_threat_events(limit=200)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{report_type}_{timestamp}.pdf"
        filepath = os.path.join(Config.REPORTS_DIR, filename)

        pdf = SecurityReportPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # ── Report Title and Date ──
        pdf.set_font("Helvetica", "B", 14)
        report_title = "Weekly Security Report" if report_type == "weekly" else "On-Demand Security Report"
        pdf.cell(0, 10, report_title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%d %B %Y at %H:%M')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Requested by: {generated_by}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        # ── Executive Summary (key findings at the top) ──
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 8, "  Executive Summary", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(3)

        pdf.cell(0, 6, f"Total Threat Events: {stats['total_events']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"High Severity: {stats['high_severity']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Medium Severity: {stats['medium_severity']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Low Severity: {stats['low_severity']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Open (Unresolved) Events: {stats['open_events']}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # ── Risk Summary by Category ──
        if stats["events_by_module"]:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "  Threats by Module", new_x="LMARGIN", new_y="NEXT", fill=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.ln(3)
            for mod in stats["events_by_module"]:
                pdf.cell(0, 6, f"  {mod['source_module']}: {mod['count']} events", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

        # ── Trend Data ──
        if stats["events_by_day"]:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, "  Daily Trend (Last 7 Days)", new_x="LMARGIN", new_y="NEXT", fill=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.ln(3)
            for day in reversed(stats["events_by_day"]):
                pdf.cell(0, 6, f"  {day['day']}: {day['count']} events", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

        # ── Detailed Event Table ──
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "  Detailed Threat Events", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.ln(3)

        if events:
            # Table header
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(75, 0, 130)
            pdf.set_text_color(255, 255, 255)
            col_widths = [28, 34, 26, 16, 86]
            headers = ["Time", "Threat", "Module", "Risk", "Explanation"]
            for i, header in enumerate(headers):
                pdf.cell(col_widths[i], 7, header, border=1, fill=True)
            pdf.ln()
            pdf.set_text_color(0, 0, 0)

            # Table rows
            pdf.set_font("Helvetica", "", 7)
            for event in events[:50]:  # Limit to 50 for readability
                # Colour-code severity
                if event["severity"] == "High":
                    pdf.set_fill_color(255, 200, 200)
                elif event["severity"] == "Medium":
                    pdf.set_fill_color(255, 235, 200)
                else:
                    pdf.set_fill_color(255, 255, 255)

                row_data = [
                    str(event.get("timestamp", ""))[:16],
                    str(event.get("event_type", ""))[:22],
                    str(event.get("source_module", ""))[:18],
                    str(event.get("severity", "")),
                    str(event.get("explanation", ""))[:60],
                ]
                for i, cell_data in enumerate(row_data):
                    pdf.cell(col_widths[i], 6, cell_data, border=1, fill=True)
                pdf.ln()
        else:
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 8, "  No threat events recorded.", new_x="LMARGIN", new_y="NEXT")

        # ── Recommendations Section ──
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(240, 240, 240)
        pdf.cell(0, 8, "  Key Recommendations", new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(3)

        high_events = [e for e in events if e["severity"] == "High"]
        if high_events:
            for event in high_events[:10]:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, f"  {event['event_type']} ({event['timestamp']})", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                recommendation = event.get("recommendation", "Review this event with your IT advisor.")
                for line in recommendation.split("\n"):
                    pdf.cell(0, 5, f"    {line.strip()}", new_x="LMARGIN", new_y="NEXT")
                pdf.ln(3)
        else:
            pdf.cell(0, 6, "  No high-severity events require immediate action.", new_x="LMARGIN", new_y="NEXT")

        # Save PDF
        pdf.output(filepath)

        # Record in database
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO reports (report_type, filename, generated_by, parameters) VALUES (?, ?, ?, ?)",
            (report_type, filename, generated_by, f"events: {len(events)}")
        )
        conn.commit()
        conn.close()

        add_audit_entry(
            action="report_generated",
            performed_by=generated_by,
            details=f"Generated {report_type} PDF report: {filename}"
        )

        return {"success": True, "filename": filename, "filepath": filepath}

    def generate_csv_export(self, generated_by="system"):
        """
        Export all threat events as a CSV file.
        Returns dict with success status and file path.
        """
        events = get_threat_events(limit=10000)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_events_export_{timestamp}.csv"
        filepath = os.path.join(Config.REPORTS_DIR, filename)

        fieldnames = [
            "id", "timestamp", "event_type", "source_module", "severity",
            "user_affected", "ip_address", "details", "explanation",
            "recommendation", "status", "created_at"
        ]

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for event in events:
                writer.writerow(event)

        # Record in database
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO reports (report_type, filename, generated_by, parameters) VALUES (?, ?, ?, ?)",
            ("csv_export", filename, generated_by, f"events: {len(events)}")
        )
        conn.commit()
        conn.close()

        add_audit_entry(
            action="csv_export",
            performed_by=generated_by,
            details=f"Exported {len(events)} events to CSV: {filename}"
        )

        return {"success": True, "filename": filename, "filepath": filepath}

    def get_report_history(self, limit=20):
        """Retrieve list of previously generated reports."""
        conn = get_db_connection()
        reports = conn.execute(
            "SELECT * FROM reports ORDER BY generated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in reports]
