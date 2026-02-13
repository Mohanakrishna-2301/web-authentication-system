"""
Dashboard & Profile routes for SecureAuth+
"""

from datetime import datetime, timedelta
import random
import string

import pyotp
import qrcode
import io
import base64
import bcrypt

from flask import Blueprint, request, session, redirect, url_for, render_template, flash, jsonify
from config import Config
from db import query
from auth_routes import login_required
from email_utils import send_otp_email

dashboard_bp = Blueprint("dashboard", __name__)


# ── Dashboard ─────────────────────────────────────────────

@dashboard_bp.route("/dashboard")
@login_required
def dashboard_page():
    user_id = session["user_id"]
    user = query("SELECT * FROM users WHERE id=%s", (user_id,), fetchone=True)

    # Recent activity
    recent = query(
        "SELECT * FROM login_history WHERE user_id=%s ORDER BY login_time DESC LIMIT 10",
        (user_id,),
        fetchall=True,
    )

    # Stats
    total_logins = query(
        "SELECT COUNT(*) as cnt FROM login_history WHERE user_id=%s AND success=1",
        (user_id,),
        fetchone=True,
    )["cnt"]

    active_sessions = query(
        "SELECT COUNT(*) as cnt FROM user_sessions WHERE user_id=%s AND is_active=1 AND expires_at > NOW()",
        (user_id,),
        fetchone=True,
    )["cnt"]

    # Account age
    created = user["created_at"]
    if created:
        days = (datetime.utcnow() - created).days
    else:
        days = 0

    return render_template(
        "dashboard.html",
        user=user,
        recent_activity=recent,
        total_logins=total_logins,
        active_sessions=active_sessions,
        account_age_days=days,
        risk_level=session.get("risk_level", "Low"),
        session_token=session.get("session_token", "N/A"),
    )


# ── Activity API (with filters) ──────────────────────────

@dashboard_bp.route("/api/activity")
@login_required
def api_activity():
    user_id = session["user_id"]
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 15))
    risk_filter = request.args.get("risk", "")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    status_filter = request.args.get("status", "")

    conditions = ["user_id=%s"]
    params = [user_id]

    if risk_filter:
        conditions.append("risk_level=%s")
        params.append(risk_filter)
    if date_from:
        conditions.append("login_time >= %s")
        params.append(date_from)
    if date_to:
        conditions.append("login_time <= %s")
        params.append(date_to + " 23:59:59")
    if status_filter == "success":
        conditions.append("success=1")
    elif status_filter == "failed":
        conditions.append("success=0")

    where = " AND ".join(conditions)
    total = query(f"SELECT COUNT(*) as cnt FROM login_history WHERE {where}", params, fetchone=True)["cnt"]

    offset = (page - 1) * per_page
    rows = query(
        f"SELECT * FROM login_history WHERE {where} ORDER BY login_time DESC LIMIT %s OFFSET %s",
        params + [per_page, offset],
        fetchall=True,
    )

    # Serialize datetime
    for r in rows:
        if r.get("login_time"):
            r["login_time"] = r["login_time"].isoformat()

    return jsonify({
        "activity": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
    })


# ── Profile Page ──────────────────────────────────────────

@dashboard_bp.route("/profile")
@login_required
def profile_page():
    user = query("SELECT * FROM users WHERE id=%s", (session["user_id"],), fetchone=True)
    sessions_list = query(
        "SELECT * FROM user_sessions WHERE user_id=%s AND is_active=1 ORDER BY created_at DESC",
        (session["user_id"],),
        fetchall=True,
    )
    return render_template("profile.html", user=user, sessions=sessions_list)


# ── API: Update Profile ──────────────────────────────────

@dashboard_bp.route("/api/profile", methods=["PUT", "POST"])
@login_required
def api_update_profile():
    data = request.get_json() if request.is_json else request.form
    full_name = (data.get("full_name") or "").strip()
    phone = (data.get("phone") or "").strip()

    if len(full_name) < 2:
        return jsonify({"success": False, "errors": ["Full name must be at least 2 characters."]}), 400

    query(
        "UPDATE users SET full_name=%s, phone=%s WHERE id=%s",
        (full_name, phone, session["user_id"]),
        commit=True,
    )
    session["full_name"] = full_name
    return jsonify({"success": True, "message": "Profile updated successfully."})


# ── API: Change Password (OTP flow) ──────────────────────

@dashboard_bp.route("/api/profile/send-otp", methods=["POST"])
@login_required
def api_send_password_otp():
    user = query("SELECT email FROM users WHERE id=%s", (session["user_id"],), fetchone=True)
    otp = "".join(random.choices(string.digits, k=6))
    expires = datetime.utcnow() + timedelta(minutes=10)
    query("UPDATE users SET otp_code=%s, otp_expires_at=%s WHERE id=%s", (otp, expires, session["user_id"]), commit=True)
    send_otp_email(user["email"], otp, "password change")
    return jsonify({"success": True, "message": "OTP sent to your email."})


@dashboard_bp.route("/api/profile/change-password", methods=["POST"])
@login_required
def api_change_password():
    data = request.get_json() if request.is_json else request.form
    otp = (data.get("otp") or "").strip()
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    user = query("SELECT * FROM users WHERE id=%s", (session["user_id"],), fetchone=True)

    # Verify current password
    if not bcrypt.checkpw(current_password.encode(), user["password_hash"].encode()):
        return jsonify({"success": False, "errors": ["Current password is incorrect."]}), 400

    # Verify OTP
    if user["otp_code"] != otp:
        return jsonify({"success": False, "errors": ["Invalid OTP."]}), 400
    if user["otp_expires_at"] and datetime.utcnow() > user["otp_expires_at"]:
        return jsonify({"success": False, "errors": ["OTP expired. Please request a new one."]}), 400

    if len(new_password) < 8:
        return jsonify({"success": False, "errors": ["New password must be at least 8 characters."]}), 400

    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    query("UPDATE users SET password_hash=%s, otp_code=NULL, otp_expires_at=NULL WHERE id=%s",
          (hashed, session["user_id"]), commit=True)

    return jsonify({"success": True, "message": "Password changed successfully."})


# ── API: 2FA Setup ────────────────────────────────────────

@dashboard_bp.route("/api/2fa/setup", methods=["POST"])
@login_required
def api_setup_2fa():
    user = query("SELECT * FROM users WHERE id=%s", (session["user_id"],), fetchone=True)
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(user["email"], issuer_name="SecureAuth+")

    # Generate QR code as base64
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Store secret temporarily
    query("UPDATE users SET twofa_secret=%s WHERE id=%s", (secret, session["user_id"]), commit=True)

    return jsonify({
        "success": True,
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
    })


@dashboard_bp.route("/api/2fa/enable", methods=["POST"])
@login_required
def api_enable_2fa():
    data = request.get_json() if request.is_json else request.form
    code = (data.get("code") or "").strip()

    user = query("SELECT twofa_secret FROM users WHERE id=%s", (session["user_id"],), fetchone=True)
    if not user or not user["twofa_secret"]:
        return jsonify({"success": False, "errors": ["Please set up 2FA first."]}), 400

    totp = pyotp.TOTP(user["twofa_secret"])
    if not totp.verify(code, valid_window=1):
        return jsonify({"success": False, "errors": ["Invalid code. Please try again."]}), 400

    query("UPDATE users SET twofa_enabled=1 WHERE id=%s", (session["user_id"],), commit=True)
    return jsonify({"success": True, "message": "Two-Factor Authentication enabled successfully!"})


@dashboard_bp.route("/api/2fa/disable", methods=["POST"])
@login_required
def api_disable_2fa():
    query("UPDATE users SET twofa_enabled=0, twofa_secret=NULL WHERE id=%s", (session["user_id"],), commit=True)
    return jsonify({"success": True, "message": "Two-Factor Authentication disabled."})


# ── API: Revoke Session ──────────────────────────────────

@dashboard_bp.route("/api/sessions/revoke", methods=["POST"])
@login_required
def api_revoke_session():
    data = request.get_json() if request.is_json else request.form
    session_id = data.get("session_id")
    if session_id:
        query(
            "UPDATE user_sessions SET is_active=0 WHERE id=%s AND user_id=%s",
            (session_id, session["user_id"]),
            commit=True,
        )
    return jsonify({"success": True, "message": "Session revoked."})
