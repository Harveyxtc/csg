"""
Module 3: Interpretation Engine
Generates plain-English explanations and SME-friendly remediation guidance
for every detection event. Designed so non-technical users can understand
threats and take appropriate action.
"""


# ──────────────────────────────────────────────────────────────
# Explanation and Recommendation Templates (data-driven)
# ──────────────────────────────────────────────────────────────
INTERPRETATION_TEMPLATES = {
    "Brute Force Login Attempt": {
        "explanation": (
            "Someone tried to log in to your system multiple times with incorrect "
            "passwords. This is often a sign that an attacker is trying to guess "
            "a user's password by trying many combinations."
        ),
        "recommendation": (
            "1. Check if the affected user account is still secure and change the password immediately.\n"
            "2. Consider blocking the IP address ({ip_address}) if it is not recognised.\n"
            "3. Enable two-factor authentication for all user accounts.\n"
            "4. Review login logs for any successful logins from this IP address."
        ),
    },
    "Phishing Email Detected": {
        "explanation": (
            "An email was received from a domain that appears suspicious or is known "
            "to be used in phishing attacks. Phishing emails try to trick you into "
            "clicking dangerous links or sharing sensitive information like passwords."
        ),
        "recommendation": (
            "1. Do NOT click any links or download any attachments from this email.\n"
            "2. Do NOT reply to the email or provide any personal information.\n"
            "3. Report the email to your email provider as phishing.\n"
            "4. If you already clicked a link, change your passwords immediately and run a malware scan."
        ),
    },
    "Suspicious File Modification": {
        "explanation": (
            "Unusual file activity was detected on your system. Multiple files were "
            "renamed or modified in a short period of time. This could indicate "
            "ransomware attempting to encrypt your files, or an unauthorised user "
            "making changes."
        ),
        "recommendation": (
            "1. Check the affected files and folders to see what was changed.\n"
            "2. If files have unusual extensions (e.g., .locked, .encrypted), disconnect from the network immediately.\n"
            "3. Run a full malware scan on your system.\n"
            "4. Restore any affected files from your most recent backup.\n"
            "5. Contact your IT support or cybersecurity advisor if you suspect ransomware."
        ),
    },
    "Malware Detected on System": {
        "explanation": (
            "A file on your system has been identified as malware (malicious software). "
            "Malware can steal your data, damage your files, or give attackers "
            "access to your computer without your knowledge."
        ),
        "recommendation": (
            "1. Do NOT open or run the detected file.\n"
            "2. Run a full system scan with your antivirus software.\n"
            "3. Delete or quarantine the infected file.\n"
            "4. Check if any sensitive data may have been accessed or stolen.\n"
            "5. Update your antivirus definitions and operating system."
        ),
    },
        "Coin Miner Malware Signature Detected": {
            "explanation": (
                "A coin-mining malware signature was detected in a scanned file. "
                "This type of malware can abuse system CPU/GPU resources and may "
                "cause performance degradation, overheating, and higher power usage."
            ),
            "recommendation": (
                "1. Isolate the affected file and avoid executing it.\n"
                "2. Run a full endpoint scan to find related miner components.\n"
                "3. Check recent startup tasks and scheduled jobs for unknown entries.\n"
                "4. Review host performance and resource spikes around the event time."
            ),
        },
        "Ransomware Malware Signature Detected": {
            "explanation": (
                "A ransomware signature was detected in a scanned file. Ransomware can "
                "encrypt business data and disrupt operations if executed."
            ),
            "recommendation": (
                "1. Immediately isolate the affected endpoint from the network.\n"
                "2. Quarantine the file and preserve forensic evidence.\n"
                "3. Verify backup integrity and recovery readiness.\n"
                "4. Review nearby file-change events for signs of encryption activity."
            ),
        },
        "Trojan Malware Signature Detected": {
            "explanation": (
                "A Trojan malware signature was detected. Trojans often disguise "
                "themselves as legitimate files to gain initial access."
            ),
            "recommendation": (
                "1. Quarantine and remove the detected file.\n"
                "2. Investigate how the file was introduced (download, email, USB).\n"
                "3. Scan for additional payloads and persistence artifacts.\n"
                "4. Reset credentials for users who interacted with the file."
            ),
        },
        "Stealer Malware Signature Detected": {
            "explanation": (
                "A credential or data stealer signature was detected. This malware family "
                "may attempt to collect browser credentials, tokens, and sensitive files."
            ),
            "recommendation": (
                "1. Isolate the host and remove the detected sample.\n"
                "2. Force password resets for impacted user accounts.\n"
                "3. Revoke active sessions and tokens where applicable.\n"
                "4. Monitor for suspicious account access after the detection."
            ),
        },
        "Backdoor Malware Signature Detected": {
            "explanation": (
                "A backdoor signature was detected. Backdoors can provide remote, "
                "unauthorised access and enable follow-on attacks."
            ),
            "recommendation": (
                "1. Immediately isolate the endpoint and quarantine the file.\n"
                "2. Review inbound and outbound network connections for C2 activity.\n"
                "3. Rotate credentials and secrets that may be exposed.\n"
                "4. Hunt for related persistence mechanisms and lateral movement."
            ),
        },
        "Keylogger Malware Signature Detected": {
            "explanation": (
                "A keylogger signature was detected. Keyloggers can capture keystrokes "
                "to steal credentials and confidential data."
            ),
            "recommendation": (
                "1. Quarantine the detected file and isolate the host.\n"
                "2. Reset passwords for all accounts used on the affected machine.\n"
                "3. Review authentication logs for unusual sign-in behavior.\n"
                "4. Enable or enforce multi-factor authentication for critical systems."
            ),
        },
        "Adware Malware Signature Detected": {
            "explanation": (
                "An adware signature was detected. Adware may inject unwanted content, "
                "track user activity, and reduce endpoint stability."
            ),
            "recommendation": (
                "1. Remove the file and uninstall suspicious bundled software.\n"
                "2. Reset browser extensions and startup settings.\n"
                "3. Run a follow-up scan to confirm cleanup.\n"
                "4. Educate users about trusted software sources."
            ),
        },
        "Spammer Malware Signature Detected": {
            "explanation": (
                "A spammer-related malware signature was detected. This can be used to "
                "send unsolicited messages and may damage domain or IP reputation."
            ),
            "recommendation": (
                "1. Quarantine the sample and inspect mail-sending activity.\n"
                "2. Review outbound mail logs for unusual volume patterns.\n"
                "3. Reset compromised credentials and API keys.\n"
                "4. Apply sender protections and rate controls where possible."
            ),
        },
        "Worm Malware Signature Detected": {
            "explanation": (
                "A worm malware signature was detected. Worms can self-propagate across "
                "systems and spread quickly in connected environments."
            ),
            "recommendation": (
                "1. Isolate the affected host from the network immediately.\n"
                "2. Patch known vulnerabilities and update endpoint controls.\n"
                "3. Scan adjacent systems for similar indicators.\n"
                "4. Review lateral movement telemetry for additional spread."
            ),
        },
        "Rootkit Malware Signature Detected": {
            "explanation": (
                "A rootkit signature was detected. Rootkits can hide malicious activity "
                "deep in the system and interfere with normal detection tools."
            ),
            "recommendation": (
                "1. Treat the endpoint as high risk and isolate it.\n"
                "2. Run offline or trusted-boot malware analysis where possible.\n"
                "3. Validate system integrity and consider reimaging if required.\n"
                "4. Investigate for privilege abuse and persistence artifacts."
            ),
        },
        "Botnet Malware Signature Detected": {
            "explanation": (
                "A botnet malware signature was detected. Botnet agents can receive "
                "remote commands and participate in coordinated malicious activity."
            ),
            "recommendation": (
                "1. Isolate the host and block suspected command-and-control endpoints.\n"
                "2. Quarantine the detected file and perform full malware triage.\n"
                "3. Review outbound network patterns for beaconing behavior.\n"
                "4. Check peer systems for matching indicators of compromise."
            ),
        },
    "Privilege Escalation Attempt": {
        "explanation": (
            "A user or process attempted to gain higher-level access rights than "
            "they are authorised to have. This is a serious security concern as it "
            "could allow an attacker to take control of your system or access "
            "confidential data."
        ),
        "recommendation": (
            "1. Verify which user account was involved and confirm if the action was legitimate.\n"
            "2. If unauthorised, immediately disable the user account.\n"
            "3. Review all recent activity from this user for other suspicious behaviour.\n"
            "4. Ensure all user accounts follow the principle of least privilege.\n"
            "5. Report this incident to your cybersecurity advisor."
        ),
    },
    "Suspicious Download": {
        "explanation": (
            "A file was downloaded that may be dangerous. Certain file types "
            "(such as .exe, .bat, or .ps1 files) can run programs on your "
            "computer that may harm your system or steal your information."
        ),
        "recommendation": (
            "1. Do NOT open or run the downloaded file.\n"
            "2. Scan the file with your antivirus software before opening.\n"
            "3. Verify the source of the download — only download files from trusted websites.\n"
            "4. Delete the file if you did not intentionally download it."
        ),
    },
    "Unauthorized Access Attempt": {
        "explanation": (
            "Someone tried to access a part of your system or data that they "
            "are not authorised to use. This could be an attacker testing your "
            "security or a misconfigured user account."
        ),
        "recommendation": (
            "1. Identify which resource was being accessed and by whom.\n"
            "2. Verify that access permissions are correctly configured.\n"
            "3. If the attempt came from an unknown source, consider blocking the IP address.\n"
            "4. Review your access control settings and user permissions."
        ),
    },
    "Network Port Scan Detected": {
        "explanation": (
            "An external computer scanned your network to find open ports and "
            "services. Port scanning is often the first step in a cyberattack, "
            "where attackers look for vulnerable entry points into your system."
        ),
        "recommendation": (
            "1. Check your firewall settings and ensure unnecessary ports are closed.\n"
            "2. Block the scanning IP address ({ip_address}) if it is not recognised.\n"
            "3. Verify that only required services are running on your network.\n"
            "4. Monitor for follow-up attacks from the same IP address."
        ),
    },
    "Configuration Change": {
        "explanation": (
            "A system configuration setting was changed. While this may be a "
            "normal administrative action, unexpected configuration changes could "
            "indicate that someone is tampering with your system settings."
        ),
        "recommendation": (
            "1. Verify that the configuration change was made by an authorised person.\n"
            "2. Review what was changed and confirm it was intentional.\n"
            "3. Keep a record of all configuration changes for auditing purposes."
        ),
    },
    "Phishing Attempt via Email Link": {
        "explanation": (
            "An email was received containing a link to a website known for phishing. "
            "These websites are designed to look like legitimate sites (such as your "
            "bank or email provider) to steal your login credentials and personal data."
        ),
        "recommendation": (
            "1. Do NOT click the link in the email under any circumstances.\n"
            "2. Delete the email or report it as phishing to your email provider.\n"
            "3. If you clicked the link, immediately change your passwords for all accounts.\n"
            "4. Run a malware scan on your computer.\n"
            "5. Enable two-factor authentication on all critical accounts."
        ),
    },
}

# Fallback for rules that do not have a specific template
DEFAULT_TEMPLATE = {
    "explanation": (
        "A security event was detected on your system. The details of this "
        "event suggest potential suspicious activity that should be reviewed."
    ),
    "recommendation": (
        "1. Review the event details carefully.\n"
        "2. Check if this activity was expected or authorised.\n"
        "3. If suspicious, consult your IT support or cybersecurity advisor.\n"
        "4. Document the event for future reference."
    ),
}


class InterpretationEngine:
    """
    Converts technical detection alerts into plain-English explanations
    with actionable, SME-friendly remediation guidance.
    """

    def interpret(self, rule, log_entry):
        """
        Generate a plain-English explanation and recommendation for a detection.

        Args:
            rule: The detection rule that was triggered (dict).
            log_entry: The log entry that triggered the rule (dict).

        Returns:
            dict with 'explanation' and 'recommendation' keys.
        """
        rule_name = rule.get("name", "Unknown Rule")
        template = INTERPRETATION_TEMPLATES.get(rule_name, DEFAULT_TEMPLATE)

        # Personalise the explanation with event-specific data
        explanation = template["explanation"]
        recommendation = template["recommendation"]

        # Replace placeholders with actual log data
        replacements = {
            "{ip_address}": log_entry.get("ip_address", "unknown IP"),
            "{user}": log_entry.get("user", "unknown user"),
            "{details}": log_entry.get("details", "no additional details"),
            "{timestamp}": log_entry.get("timestamp", "unknown time"),
            "{event_type}": log_entry.get("event_type", "unknown event"),
        }

        for placeholder, value in replacements.items():
            explanation = explanation.replace(placeholder, value)
            recommendation = recommendation.replace(placeholder, value)

        return {
            "explanation": explanation,
            "recommendation": recommendation,
            "severity": rule.get("severity", "Medium"),
            "rule_id": rule.get("id", "UNKNOWN"),
            "rule_name": rule_name,
        }

    def get_severity_summary(self, severity):
        """Return a plain-English summary of what a severity level means."""
        summaries = {
            "High": (
                "This is a high-priority threat that requires immediate attention. "
                "It could lead to data loss, system compromise, or financial damage "
                "if not addressed quickly."
            ),
            "Medium": (
                "This is a moderate threat that should be investigated soon. "
                "While not immediately critical, ignoring it could allow the "
                "threat to escalate."
            ),
            "Low": (
                "This is a low-priority alert for your awareness. It may be "
                "normal activity, but it is worth monitoring in case a pattern "
                "develops over time."
            ),
        }
        return summaries.get(severity, "Unknown severity level.")
