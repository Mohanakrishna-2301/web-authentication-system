"""
Email utilities for SecureAuth+
Sends verification emails, OTPs, and risk alerts.
Falls back to console printing when SMTP is not configured.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config


def _smtp_available():
    return bool(Config.MAIL_SERVER and Config.MAIL_USERNAME)


def _send_email(to, subject, html_body):
    """Send an email via SMTP or print to console."""
    if _smtp_available():
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = Config.MAIL_FROM
        msg["To"] = to
        msg.attach(MIMEText(html_body, "html"))
        try:
            with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
                server.starttls()
                server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
                server.sendmail(Config.MAIL_FROM, to, msg.as_string())
            return True
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
            return False
    else:
        print(f"\n{'='*60}")
        print(f"  📧 EMAIL TO: {to}")
        print(f"  📌 SUBJECT : {subject}")
        print(f"  📋 BODY    :")
        print(f"  {html_body[:500]}")
        print(f"{'='*60}\n")
        return True


def send_verification_email(to, token):
    link = f"{Config.APP_URL}/verify-email/{token}"
    html = f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #e0e0e0;border-radius:10px;">
        <h2 style="color:#6c63ff;">SecureAuth+ Email Verification</h2>
        <p>Click the button below to verify your email address:</p>
        <a href="{link}" style="display:inline-block;padding:12px 30px;background:#6c63ff;color:#fff;text-decoration:none;border-radius:6px;font-weight:bold;">Verify Email</a>
        <p style="margin-top:20px;font-size:12px;color:#888;">If the button doesn't work, copy this link:<br>{link}</p>
    </div>"""
    return _send_email(to, "Verify your SecureAuth+ account", html)


def send_otp_email(to, otp_code, purpose="password reset"):
    html = f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #e0e0e0;border-radius:10px;">
        <h2 style="color:#6c63ff;">SecureAuth+ OTP</h2>
        <p>Your one-time password for <b>{purpose}</b> is:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;padding:15px;background:#f4f3ff;border-radius:8px;color:#6c63ff;">{otp_code}</div>
        <p style="margin-top:15px;font-size:12px;color:#888;">This code expires in 10 minutes. Do not share it with anyone.</p>
    </div>"""
    return _send_email(to, f"SecureAuth+ OTP for {purpose}", html)


def send_risk_alert_email(to, risk_level, ip, device, time_str):
    color_map = {"Low": "#22c55e", "Medium": "#f59e0b", "High": "#ef4444"}
    emoji_map = {"Low": "🟢", "Medium": "🟡", "High": "🔴"}
    color = color_map.get(risk_level, "#888")
    emoji = emoji_map.get(risk_level, "⚪")
    html = f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;padding:20px;border:1px solid #e0e0e0;border-radius:10px;">
        <h2 style="color:{color};">{emoji} {risk_level} Risk Login Detected</h2>
        <p>A login to your SecureAuth+ account was detected:</p>
        <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:8px;font-weight:bold;">IP Address</td><td style="padding:8px;">{ip}</td></tr>
            <tr><td style="padding:8px;font-weight:bold;">Device</td><td style="padding:8px;">{device}</td></tr>
            <tr><td style="padding:8px;font-weight:bold;">Time</td><td style="padding:8px;">{time_str}</td></tr>
            <tr><td style="padding:8px;font-weight:bold;">Risk Level</td><td style="padding:8px;color:{color};font-weight:bold;">{emoji} {risk_level}</td></tr>
        </table>
        <p style="margin-top:15px;font-size:12px;color:#888;">If this wasn't you, please change your password immediately.</p>
    </div>"""
    return _send_email(to, f"{emoji} {risk_level} Risk Login Alert — SecureAuth+", html)
