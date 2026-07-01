"""
notifier.py - Email Alert Notifications
LNSM System - B00971364
Sends email when a security alert is triggered.
Configure your Gmail credentials below.
"""

import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ── Email Configuration ───────────────────────────────────────────
# To enable: set ENABLED = True and fill in your Gmail details.
# You must enable "App Passwords" in your Google account settings.
ENABLED        = False          # Set to True to activate
SMTP_HOST      = "smtp.gmail.com"
SMTP_PORT      = 587
SENDER_EMAIL   = "your_email@gmail.com"
SENDER_PASSWORD= "your_app_password"
RECIPIENT_EMAIL= "your_email@gmail.com"

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

ALERT_DESCRIPTIONS = {
    "PORT_SCAN_DETECTED": "A device is systematically probing multiple ports on your network.",
    "BRUTE_FORCE":        "Repeated connection attempts detected to the same port.",
    "SYN_FLOOD":          "A high volume of SYN packets detected — possible DoS attack.",
    "ICMP_FLOOD":         "Excessive ICMP (ping) traffic detected from this source.",
    "UDP_SCAN_DETECTED":  "A device is probing multiple UDP ports on your network.",
}


def send_alert_email(rule_name, src_ip, detail):
    """
    Sends email notification in a daemon thread so it never
    blocks the consumer thread or causes packet drops.
    """
    if not ENABLED:
        return
    threading.Thread(
        target=_send, args=(rule_name, src_ip, detail), daemon=True
    ).start()


def _send(rule_name, src_ip, detail):
    try:
        severity    = "HIGH"
        emoji       = SEVERITY_EMOJI.get(severity, "⚠️")
        description = ALERT_DESCRIPTIONS.get(rule_name, "Suspicious activity detected.")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"{emoji} LNSM Alert: {rule_name} from {src_ip}"
        msg["From"]    = SENDER_EMAIL
        msg["To"]      = RECIPIENT_EMAIL

        html = f"""
        <html><body style="font-family:sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;">
          <div style="max-width:600px;margin:auto;background:#161b22;
                      border:1px solid #30363d;border-radius:8px;padding:24px;">
            <h2 style="color:#f85149;">{emoji} LNSM Security Alert</h2>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="color:#8b949e;padding:6px 0;">Rule</td>
                  <td style="color:#f0f6fc;font-weight:700;">{rule_name}</td></tr>
              <tr><td style="color:#8b949e;padding:6px 0;">Source IP</td>
                  <td><code style="color:#79c0ff;">{src_ip}</code></td></tr>
              <tr><td style="color:#8b949e;padding:6px 0;">Detail</td>
                  <td>{detail}</td></tr>
              <tr><td style="color:#8b949e;padding:6px 0;">Time</td>
                  <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
              <tr><td style="color:#8b949e;padding:6px 0;">Description</td>
                  <td>{description}</td></tr>
            </table>
            <p style="color:#8b949e;font-size:12px;margin-top:20px;">
              LNSM System &mdash; Lightweight Network Security Monitor &mdash; B00971364
            </p>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        print(f"[Notifier] Email sent for {rule_name} from {src_ip}")

    except Exception as e:
        print(f"[Notifier] Email failed: {e}")
