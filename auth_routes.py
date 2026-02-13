"""
Auth routes for SecureAuth+
Handles registration, login, logout, email verification, password reset, 2FA, and Google OAuth stub.
"""

import uuid
import random
import string
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import jwt
import pyotp
import qrcode
import io
import base64

from flask import Blueprint, request, session, redirect, url_for, render_template, flash, jsonify
from config import Config
from db import query
from risk_engine import calculate_risk
from email_utils import send_verification_email, send_otp_email, send_risk_alert_email
from captcha_utils import generate_captcha, verify_captcha

auth_bp = Blueprint("auth", __name__)


# ── Helpers ───────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login_page"))
        # Session timeout check
        last_activity = session.get("last_activity")
        if last_activity:
            elapsed = (datetime.utcnow() - datetime.fromisoformat(last_activity)).total_seconds()
            if elapsed > Config.SESSION_TIMEOUT_MINUTES * 60:
                session.clear()
                flash("Session expired. Please log in again.", "warning")
                return redirect(url_for("auth.login_page"))
        session["last_activity"] = datetime.utcnow().isoformat()
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("auth.login_page"))
        return f(*args, **kwargs)
    return decorated


def _generate_otp():
    return "".join(random.choices(string.digits, k=6))


def _hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def _get_device_info():
    ua = request.headers.get("User-Agent", "Unknown")
    return ua[:500]


def _get_client_ip():
    return request.remote_addr or "127.0.0.1"


def _create_session_token(user_id, ip, device):
    token = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES)
    query(
        "INSERT INTO user_sessions (session_token, user_id, ip_address, device_info, expires_at) VALUES (%s,%s,%s,%s,%s)",
        (token, user_id, ip, device, expires),
        commit=True,
    )
    return token


# ── Pages ─────────────────────────────────────────────────

@auth_bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard.dashboard_page"))
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/login")
def login_page():
    captcha_q, captcha_a = generate_captcha()
    session["captcha_answer"] = captcha_a
    return render_template("login.html", captcha_question=captcha_q)


@auth_bp.route("/register")
def register_page():
    return render_template("register.html")


@auth_bp.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


@auth_bp.route("/verify-2fa")
def verify_2fa_page():
    if "pending_2fa_user" not in session:
        return redirect(url_for("auth.login_page"))
    return render_template("verify_2fa.html")


# ── API: Register ─────────────────────────────────────────

@auth_bp.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() if request.is_json else request.form
    full_name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""

    # Validation
    errors = []
    if len(full_name) < 2:
        errors.append("Full name is required (min 2 characters).")
    if "@" not in email or "." not in email:
        errors.append("Please enter a valid email address.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")

    existing = query("SELECT id FROM users WHERE email=%s", (email,), fetchone=True)
    if existing:
        errors.append("An account with this email already exists.")

    if errors:
        if request.is_json:
            return jsonify({"success": False, "errors": errors}), 400
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("auth.register_page"))

    # Create user
    hashed = _hash_password(password)
    email_token = str(uuid.uuid4())
    query(
        "INSERT INTO users (full_name, email, password_hash, email_token) VALUES (%s,%s,%s,%s)",
        (full_name, email, hashed, email_token),
        commit=True,
    )
    send_verification_email(email, email_token)

    if request.is_json:
        return jsonify({"success": True, "message": "Registration successful! Please check your email to verify your account."})
    flash("Registration successful! Please check your email (or console) to verify your account.", "success")
    return redirect(url_for("auth.login_page"))


# ── API: Login ────────────────────────────────────────────

@auth_bp.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() if request.is_json else request.form
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    captcha_input = data.get("captcha") or ""

    device = _get_device_info()
    ip = _get_client_ip()

    # CAPTCHA verification
    if not verify_captcha(session.get("captcha_answer"), captcha_input):
        _log_failure(email, ip, device, "Invalid CAPTCHA")
        return _login_error("Invalid CAPTCHA answer. Please try again.")

    # Find user
    user = query("SELECT * FROM users WHERE email=%s", (email,), fetchone=True)
    if not user:
        _log_failure_no_user(ip, device, "User not found")
        return _login_error("Invalid email or password.")

    if not user["is_active"]:
        _log_failure(email, ip, device, "Account disabled")
        return _login_error("Your account has been disabled. Contact admin.")

    # Password check
    if not _check_password(password, user["password_hash"]):
        query(
            "INSERT INTO login_history (user_id, ip_address, device_info, risk_level, success, failure_reason) VALUES (%s,%s,%s,'Low',0,'Wrong password')",
            (user["id"], ip, device),
            commit=True,
        )
        return _login_error("Invalid email or password.")

    # 2FA check
    if user["twofa_enabled"]:
        session["pending_2fa_user"] = user["id"]
        session["pending_2fa_device"] = device
        session["pending_2fa_ip"] = ip
        if request.is_json:
            return jsonify({"success": True, "requires_2fa": True})
        return redirect(url_for("auth.verify_2fa_page"))

    # Complete login
    return _complete_login(user, ip, device)


def _complete_login(user, ip, device):
    risk = calculate_risk(user["id"], device, ip)
    session_token = _create_session_token(user["id"], ip, device)

    # Log successful login
    query(
        "INSERT INTO login_history (user_id, ip_address, device_info, risk_level, success) VALUES (%s,%s,%s,%s,1)",
        (user["id"], ip, device, risk),
        commit=True,
    )

    # Set session
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session["full_name"] = user["full_name"]
    session["role"] = user["role"]
    session["session_token"] = session_token
    session["risk_level"] = risk
    session["last_activity"] = datetime.utcnow().isoformat()

    # Send risk alert email for Medium/High
    if risk in ("Medium", "High"):
        send_risk_alert_email(
            user["email"], risk, ip, device[:100],
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    if request.is_json:
        return jsonify({"success": True, "risk_level": risk, "redirect": url_for("dashboard.dashboard_page")})
    flash(f"Welcome back, {user['full_name']}!", "success")
    return redirect(url_for("dashboard.dashboard_page"))


def _login_error(msg):
    # Refresh captcha
    captcha_q, captcha_a = generate_captcha()
    session["captcha_answer"] = captcha_a
    if request.is_json:
        return jsonify({"success": False, "errors": [msg], "captcha_question": captcha_q}), 401
    flash(msg, "danger")
    return redirect(url_for("auth.login_page"))


def _log_failure(email, ip, device, reason):
    user = query("SELECT id FROM users WHERE email=%s", (email,), fetchone=True)
    if user:
        query(
            "INSERT INTO login_history (user_id, ip_address, device_info, risk_level, success, failure_reason) VALUES (%s,%s,%s,'Low',0,%s)",
            (user["id"], ip, device, reason),
            commit=True,
        )


def _log_failure_no_user(ip, device, reason):
    pass  # Don't log for non-existent users to avoid enumeration


# ── API: 2FA Verify ──────────────────────────────────────

@auth_bp.route("/api/verify-2fa", methods=["POST"])
def api_verify_2fa():
    data = request.get_json() if request.is_json else request.form
    code = (data.get("code") or "").strip()
    user_id = session.get("pending_2fa_user")

    if not user_id:
        return _login_error("Session expired. Please log in again.")

    user = query("SELECT * FROM users WHERE id=%s", (user_id,), fetchone=True)
    if not user or not user["twofa_secret"]:
        return _login_error("2FA not configured.")

    totp = pyotp.TOTP(user["twofa_secret"])
    if not totp.verify(code, valid_window=1):
        if request.is_json:
            return jsonify({"success": False, "errors": ["Invalid 2FA code."]}), 401
        flash("Invalid 2FA code.", "danger")
        return redirect(url_for("auth.verify_2fa_page"))

    device = session.pop("pending_2fa_device", _get_device_info())
    ip = session.pop("pending_2fa_ip", _get_client_ip())
    session.pop("pending_2fa_user", None)

    return _complete_login(user, ip, device)


# ── API: Logout ───────────────────────────────────────────

@auth_bp.route("/api/logout", methods=["POST", "GET"])
def api_logout():
    token = session.get("session_token")
    if token:
        query("UPDATE user_sessions SET is_active=0 WHERE session_token=%s", (token,), commit=True)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login_page"))


# ── API: Email Verification ──────────────────────────────

@auth_bp.route("/verify-email/<token>")
def verify_email(token):
    user = query("SELECT id FROM users WHERE email_token=%s", (token,), fetchone=True)
    if user:
        query("UPDATE users SET email_verified=1, email_token=NULL WHERE id=%s", (user["id"],), commit=True)
        flash("Email verified successfully! You can now log in.", "success")
    else:
        flash("Invalid or expired verification link.", "danger")
    return redirect(url_for("auth.login_page"))


# ── API: Forgot Password ─────────────────────────────────

@auth_bp.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json() if request.is_json else request.form
    email = (data.get("email") or "").strip().lower()

    user = query("SELECT id, email FROM users WHERE email=%s", (email,), fetchone=True)
    if user:
        otp = _generate_otp()
        expires = datetime.utcnow() + timedelta(minutes=10)
        query("UPDATE users SET otp_code=%s, otp_expires_at=%s WHERE id=%s", (otp, expires, user["id"]), commit=True)
        send_otp_email(email, otp, "password reset")

    # Always show success to prevent email enumeration
    msg = "If an account with that email exists, an OTP has been sent."
    if request.is_json:
        return jsonify({"success": True, "message": msg})
    flash(msg, "info")
    return redirect(url_for("auth.forgot_password_page"))


@auth_bp.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json() if request.is_json else request.form
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()
    new_password = data.get("new_password") or ""

    if len(new_password) < 8:
        msg = "Password must be at least 8 characters."
        if request.is_json:
            return jsonify({"success": False, "errors": [msg]}), 400
        flash(msg, "danger")
        return redirect(url_for("auth.forgot_password_page"))

    user = query("SELECT id, otp_code, otp_expires_at FROM users WHERE email=%s", (email,), fetchone=True)
    if not user or user["otp_code"] != otp:
        msg = "Invalid OTP."
        if request.is_json:
            return jsonify({"success": False, "errors": [msg]}), 400
        flash(msg, "danger")
        return redirect(url_for("auth.forgot_password_page"))

    if user["otp_expires_at"] and datetime.utcnow() > user["otp_expires_at"]:
        msg = "OTP has expired. Please request a new one."
        if request.is_json:
            return jsonify({"success": False, "errors": [msg]}), 400
        flash(msg, "danger")
        return redirect(url_for("auth.forgot_password_page"))

    hashed = _hash_password(new_password)
    query("UPDATE users SET password_hash=%s, otp_code=NULL, otp_expires_at=NULL WHERE id=%s", (hashed, user["id"]), commit=True)

    msg = "Password reset successfully! You can now log in."
    if request.is_json:
        return jsonify({"success": True, "message": msg})
    flash(msg, "success")
    return redirect(url_for("auth.login_page"))


# ── API: CAPTCHA Refresh ─────────────────────────────────

@auth_bp.route("/api/captcha", methods=["GET"])
def api_captcha():
    q, a = generate_captcha()
    session["captcha_answer"] = a
    return jsonify({"question": q})


# ── API: Google OAuth Stub ────────────────────────────────

@auth_bp.route("/api/google-login", methods=["POST"])
def api_google_login():
    """Placeholder for Google OAuth. Requires real Google credentials."""
    return jsonify({
        "success": False,
        "errors": ["Google OAuth is not configured yet. Please set up Google Cloud OAuth credentials."]
    }), 501
