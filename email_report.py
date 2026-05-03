"""
=============================================================================
email_report.py - Email Report Sender
=============================================================================
AI-Powered Vulnerability Assessment System v4.0
Send PDF reports via email using Gmail SMTP
=============================================================================
"""

import smtplib
import ssl
import os
import json
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email                import encoders
from datetime             import datetime

logger = logging.getLogger(__name__)

EMAIL_CONFIG_FILE = "email_config.json"


def load_email_config() -> dict:
    if not os.path.exists(EMAIL_CONFIG_FILE):
        return {"sender_email": "", "sender_password": "", "default_recipient": ""}
    try:
        with open(EMAIL_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_email_config(config: dict):
    try:
        with open(EMAIL_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.error(f"Config save error: {e}")


def send_report_email(sender_email: str, sender_password: str,
                       recipient_email: str, pdf_path: str,
                       risk_level: str, risk_score: int,
                       target_ip: str) -> tuple:
    """
    Send vulnerability report PDF via email.

    Returns:
        (success: bool, message: str)
    """
    if not os.path.exists(pdf_path):
        return False, f"PDF file not found: {pdf_path}"

    try:
        # Build email
        msg = MIMEMultipart()
        msg["From"]    = sender_email
        msg["To"]      = recipient_email
        msg["Subject"] = (
            f"[{risk_level}] Vulnerability Report — {target_ip} — "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"
        )

        # Email body
        body = f"""
AI-Powered Vulnerability Assessment Report

Scan Summary:
─────────────────────────────────────────
Target IP    : {target_ip}
Risk Level   : {risk_level}
Risk Score   : {risk_score}/100
Scan Time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
─────────────────────────────────────────

The full PDF report is attached to this email.

{'⚠️  CRITICAL/HIGH risk detected — immediate action recommended!' 
 if risk_level in ['CRITICAL','HIGH'] else 
 '✓ System is in acceptable security condition.'}

─────────────────────────────────────────
AI-Powered Vulnerability Assessment System v4.0
Final Year Project — Computer Science
        """

        msg.attach(MIMEText(body, "plain"))

        # Attach PDF
        with open(pdf_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        filename = os.path.basename(pdf_path)
        part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
        msg.attach(part)

        # Send via Gmail SMTP
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())

        logger.info(f"Email sent to {recipient_email}")
        return True, f"Report sent successfully to {recipient_email}"

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed!\n\n"
            "Fix:\n"
            "1. Go to myaccount.google.com\n"
            "2. Security → 2-Step Verification → ON\n"
            "3. App Passwords → Generate password\n"
            "4. Use that 16-char password here (not your Gmail password)"
        )
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Error: {str(e)}"
