"""
AI Security Assistant
A rule-based chatbot that provides cybersecurity guidance to SME users.
Uses keyword matching and contextual awareness of current threat data
to deliver plain-English security advice without requiring external APIs.
"""

import re
from src.database import get_dashboard_stats, get_threat_events

#from src.chatbot.local_llm import ask_local_llm

# ──────────────────────────────────────────────────────────────
# Knowledge Base — categorised Q&A for SME cybersecurity topics
# ──────────────────────────────────────────────────────────────
KNOWLEDGE_BASE = [
    {
        "keywords": ["phishing", "phish", "fake email", "suspicious email", "scam email"],
        "topic": "Phishing",
        "response": (
            "**Phishing** is when attackers send fake emails that look like they come from "
            "trusted sources (like your bank or a supplier) to trick you into clicking malicious "
            "links or sharing passwords.\n\n"
            "**How to protect yourself:**\n"
            "- Never click links in unexpected emails — hover over them first to check the real URL\n"
            "- Check the sender's email address carefully for misspellings\n"
            "- Don't download attachments from unknown senders\n"
            "- When in doubt, contact the sender through a different channel to verify\n"
            "- Report suspicious emails to your email provider"
        ),
    },
    {
        "keywords": ["malware", "virus", "trojan", "ransomware", "infected", "malicious software"],
        "topic": "Malware",
        "response": (
            "**Malware** is malicious software designed to damage your computer or steal your data. "
            "Common types include viruses, trojans, and ransomware.\n\n"
            "**How to protect yourself:**\n"
            "- Keep your antivirus software updated and run regular scans\n"
            "- Don't download software from untrusted websites\n"
            "- Be cautious with email attachments and USB drives\n"
            "- Keep your operating system and all software up to date\n"
            "- Back up your important files regularly to an external drive or cloud service"
        ),
    },
    {
        "keywords": ["password", "passwords", "credential", "login", "strong password", "brute force"],
        "topic": "Password Security",
        "response": (
            "**Strong passwords** are your first line of defence against attackers.\n\n"
            "**Best practices:**\n"
            "- Use at least 12 characters with a mix of uppercase, lowercase, numbers, and symbols\n"
            "- Never reuse the same password across different accounts\n"
            "- Use a password manager to generate and store complex passwords\n"
            "- Enable two-factor authentication (2FA) wherever possible\n"
            "- Change passwords immediately if you suspect they've been compromised\n"
            "- Never share your passwords with anyone via email or chat"
        ),
    },
    {
        "keywords": ["ransomware", "encrypt", "locked files", "ransom", "pay ransom"],
        "topic": "Ransomware",
        "response": (
            "**Ransomware** is a type of malware that encrypts your files and demands payment "
            "to unlock them.\n\n"
            "**If you're hit by ransomware:**\n"
            "- Disconnect your computer from the network immediately\n"
            "- Do NOT pay the ransom — there's no guarantee you'll get your files back\n"
            "- Report the incident to the Australian Cyber Security Centre (ACSC)\n"
            "- Restore your files from your most recent backup\n\n"
            "**Prevention:**\n"
            "- Keep regular backups on a separate, disconnected drive\n"
            "- Keep all software updated\n"
            "- Be very cautious with email attachments"
        ),
    },
    {
        "keywords": ["backup", "backups", "back up", "data loss", "recovery"],
        "topic": "Data Backups",
        "response": (
            "**Regular backups** are essential protection against ransomware, hardware failure, "
            "and accidental deletion.\n\n"
            "**Backup best practices:**\n"
            "- Follow the 3-2-1 rule: 3 copies, on 2 different media, with 1 offsite\n"
            "- Automate your backups so you don't forget\n"
            "- Test your backups regularly to make sure they work\n"
            "- Keep at least one backup disconnected from your network\n"
            "- Consider cloud backup services for offsite protection"
        ),
    },
    {
        "keywords": ["2fa", "two factor", "two-factor", "mfa", "multi factor", "authentication"],
        "topic": "Two-Factor Authentication",
        "response": (
            "**Two-Factor Authentication (2FA)** adds an extra layer of security by requiring "
            "a second form of verification beyond your password.\n\n"
            "**How to set it up:**\n"
            "- Enable 2FA on all critical accounts (email, banking, cloud services)\n"
            "- Use an authenticator app (like Google Authenticator or Microsoft Authenticator) "
            "rather than SMS when possible\n"
            "- Keep backup codes in a safe place\n"
            "- 2FA dramatically reduces the risk of account takeover even if your password is stolen"
        ),
    },
    {
        "keywords": ["firewall", "network security", "port", "ports", "network scan", "port scan"],
        "topic": "Firewall & Network Security",
        "response": (
            "A **firewall** monitors and controls incoming and outgoing network traffic.\n\n"
            "**Network security tips:**\n"
            "- Ensure your Windows Firewall is turned on\n"
            "- Close any network ports that aren't needed for your business\n"
            "- Use a router with built-in firewall capabilities\n"
            "- Keep your router firmware updated\n"
            "- Change default passwords on all network devices\n"
            "- Consider separating your guest Wi-Fi from your business network"
        ),
    },
    {
        "keywords": ["update", "updates", "patch", "patches", "software update", "out of date"],
        "topic": "Software Updates",
        "response": (
            "**Keeping software updated** is one of the most effective security measures.\n\n"
            "**Why it matters:**\n"
            "- Updates often fix security vulnerabilities that attackers can exploit\n"
            "- Enable automatic updates for your operating system\n"
            "- Update your web browser, email client, and business applications regularly\n"
            "- Don't ignore update notifications — they often contain critical security patches\n"
            "- Remove software you no longer use to reduce your attack surface"
        ),
    },
    {
        "keywords": ["report", "pdf", "csv", "export", "generate report"],
        "topic": "Reports",
        "response": (
            "You can generate security reports from the **Reports** page in the dashboard.\n\n"
            "**Available report types:**\n"
            "- **On-Demand PDF** — a full security report with summaries, charts, and recommendations\n"
            "- **Weekly PDF** — designed for regular security reviews\n"
            "- **CSV Export** — raw event data for further analysis in spreadsheets\n\n"
            "Navigate to the Reports page using the sidebar menu, or click the "
            "'Export PDF Report' button at the top of the dashboard."
        ),
    },
    {
        "keywords": ["high", "severity", "critical", "urgent", "priority", "risk level"],
        "topic": "Severity Levels",
        "response": (
            "Events are categorised into three **severity levels**:\n\n"
            "- **High** — Requires immediate attention. Could lead to data loss or system "
            "compromise (e.g., malware detected, brute force attacks, privilege escalation)\n"
            "- **Medium** — Should be investigated soon. Not immediately critical but could "
            "escalate (e.g., phishing emails, suspicious downloads)\n"
            "- **Low** — Worth monitoring but not urgent. May be normal activity "
            "(e.g., port scans, configuration changes)\n\n"
            "Start by addressing High severity events first, then work through Medium and Low."
        ),
    },
    {
        "keywords": ["what can you do", "hello", "hi", "help me", "how do you work"],
        "topic": "General Help",
        "response": (
            "I'm your **AI Security Assistant**. I can help you with:\n\n"
            "- Understanding threat alerts and what they mean\n"
            "- Cybersecurity best practices for your business\n"
            "- Guidance on phishing, malware, passwords, and more\n"
            "- Explaining your dashboard data and reports\n"
            "- Recommending next steps for security events\n\n"
            "Try asking me things like:\n"
            "- *\"What is phishing?\"*\n"
            "- *\"How do I create a strong password?\"*\n"
            "- *\"What should I do about a high severity alert?\"*\n"
            "- *\"Show me my current threat summary\"*"
        ),
    },
    {
        "keywords": ["summary", "overview", "status", "current threats", "threat summary", "how many",
                      "dashboard", "stats", "statistics"],
        "topic": "Threat Summary",
        "response": "__DYNAMIC_SUMMARY__",
    },
    {
        "keywords": ["acknowledge", "resolve", "dismiss", "action", "what should i do",
                      "respond", "next steps", "handle"],
        "topic": "Responding to Threats",
        "response": (
            "**How to respond to threat events:**\n\n"
            "1. **Review** — Read the plain-English explanation for each alert\n"
            "2. **Acknowledge** — Click 'Acknowledge' to show you've seen the event\n"
            "3. **Follow recommendations** — Each alert has specific guidance on what to do\n"
            "4. **Resolve** — Once you've taken action, mark the event as 'Resolved'\n"
            "5. **Generate a report** — Create a PDF report for your records\n\n"
            "Always address **High** severity events first. If unsure, consult a "
            "cybersecurity professional."
        ),
    },
    {
        "keywords": ["wifi", "wireless", "wi-fi", "network"],
        "topic": "Wi-Fi Security",
        "response": (
            "**Securing your Wi-Fi network:**\n\n"
            "- Use WPA3 or WPA2 encryption (never WEP)\n"
            "- Change your router's default admin password\n"
            "- Use a strong, unique Wi-Fi password\n"
            "- Hide your network name (SSID) if possible\n"
            "- Create a separate guest network for visitors\n"
            "- Keep your router's firmware updated\n"
            "- Disable remote management unless you need it"
        ),
    },
    {
        "keywords": ["social engineering", "impersonation", "pretexting", "vishing", "smishing"],
        "topic": "Social Engineering",
        "response": (
            "**Social engineering** is when attackers manipulate people into giving up "
            "confidential information or access.\n\n"
            "**Common tactics:**\n"
            "- Impersonating IT support, suppliers, or management\n"
            "- Creating urgency ('Your account will be locked!')\n"
            "- Offering something too good to be true\n"
            "- Phone scams (vishing) and SMS scams (smishing)\n\n"
            "**Protection:**\n"
            "- Verify requests through a separate communication channel\n"
            "- Never give out passwords or sensitive data over the phone\n"
            "- Train all staff to recognise social engineering attempts"
        ),
    },
]


class SecurityAssistant:
    """AI-powered security assistant for SME users."""

    def get_response(self, user_message):
        """
        Process a user message and return a helpful response.
        Uses keyword matching against the knowledge base, with
        dynamic data injection for threat summaries.
        """
        if not user_message or not user_message.strip():
            return {
                "response": "Please type a question and I'll do my best to help you with cybersecurity guidance.",
                "topic": "Empty Input"
            }

        message_lower = user_message.lower().strip()

        # Score each knowledge base entry by keyword matches
        best_match = None
        best_score = 0

        for entry in KNOWLEDGE_BASE:
            score = 0
            for keyword in entry["keywords"]:
                if keyword.lower() in message_lower:
                    # Give longer keyword matches more weight
                    score += len(keyword.split())
            # De-prioritise General Help so specific topics always win
            if entry["topic"] == "General Help":
                score *= 0.5
            if score > best_score:
                best_score = score
                best_match = entry

        if best_match and best_score > 0 and best_match["topic"] != "General Help":
            response_text = best_match["response"]

            # Handle dynamic summary
            if response_text == "__DYNAMIC_SUMMARY__":
                response_text = self._generate_dynamic_summary()

            return {
                "response": response_text,
                "topic": best_match["topic"]
            }

    def _generate_dynamic_summary(self):
        """Generate a real-time threat summary from the database."""
        try:
            stats = get_dashboard_stats()
            recent = get_threat_events(limit=3)

            summary = f"**Current Threat Summary:**\n\n"
            summary += f"- **Total events:** {stats['total_events']}\n"
            summary += f"- **High severity:** {stats['high_severity']}\n"
            summary += f"- **Medium severity:** {stats['medium_severity']}\n"
            summary += f"- **Low severity:** {stats['low_severity']}\n"
            summary += f"- **Open (unresolved):** {stats['open_events']}\n\n"

            if stats['high_severity'] > 0:
                summary += (
                    "**Action needed:** You have high-severity events that require "
                    "immediate attention. Check the dashboard and address these first.\n\n"
                )
            elif stats['open_events'] > 0:
                summary += (
                    "No critical threats at the moment, but you have open events "
                    "that should be reviewed.\n\n"
                )
            else:
                summary += "All clear — no outstanding threats require action.\n\n"

            if recent:
                summary += "**Most recent events:**\n"
                for event in recent:
                    summary += (
                        f"- [{event['severity']}] {event['event_type']} "
                        f"({event['timestamp']})\n"
                    )

            return summary

        except Exception:
            return (
                "I couldn't fetch the latest threat data. Please check the dashboard "
                "directly for your current security status."
            )
