"""
Admin routes for SecureAuth+
User management, audit logs, global activity.
"""

from flask import Blueprint, request, session, redirect, url_for, render_template, jsonify
from db import query
from auth_routes import admin_required

admin_bp = Blueprint("admin", __name__)


def _log_admin_action(action_type, target_user_id=None, description=""):
    from auth_routes import _get_client_ip
    query(
        "INSERT INTO admin_actions (admin_id, action_type, target_user_id, description, ip_address) VALUES (%s,%s,%s,%s,%s)",
        (session["user_id"], action_type, target_user_id, description, _get_client_ip()),
        commit=True,
    )


# ── Admin Panel Page ─────────────────────────────────────

@admin_bp.route("/admin")
@admin_required
def admin_page():
    users = query("SELECT id, full_name, email, role, is_active, email_verified, created_at FROM users ORDER BY created_at DESC", fetchall=True)
    actions = query(
        """SELECT a.*, u.full_name as admin_name
           FROM admin_actions a
           JOIN users u ON a.admin_id = u.id
           ORDER BY a.performed_at DESC LIMIT 50""",
        fetchall=True,
    )
    return render_template("admin.html", users=users, admin_actions=actions)


# ── API: Toggle User Status ─────────────────────────────

@admin_bp.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def api_toggle_user(user_id):
    if user_id == session["user_id"]:
        return jsonify({"success": False, "errors": ["Cannot disable your own account."]}), 400

    user = query("SELECT id, is_active, full_name FROM users WHERE id=%s", (user_id,), fetchone=True)
    if not user:
        return jsonify({"success": False, "errors": ["User not found."]}), 404

    new_status = 0 if user["is_active"] else 1
    query("UPDATE users SET is_active=%s WHERE id=%s", (new_status, user_id), commit=True)
    action = "Enabled" if new_status else "Disabled"
    _log_admin_action(f"{action} user", user_id, f"{action} user: {user['full_name']}")

    # If disabling, kill their sessions
    if not new_status:
        query("UPDATE user_sessions SET is_active=0 WHERE user_id=%s", (user_id,), commit=True)

    return jsonify({"success": True, "message": f"User {action.lower()} successfully."})


# ── API: All Activity ────────────────────────────────────

@admin_bp.route("/api/admin/activity")
@admin_required
def api_admin_activity():
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))
    offset = (page - 1) * per_page

    total = query("SELECT COUNT(*) as cnt FROM login_history", fetchone=True)["cnt"]
    rows = query(
        """SELECT lh.*, u.full_name, u.email
           FROM login_history lh
           JOIN users u ON lh.user_id = u.id
           ORDER BY lh.login_time DESC
           LIMIT %s OFFSET %s""",
        (per_page, offset),
        fetchall=True,
    )
    for r in rows:
        if r.get("login_time"):
            r["login_time"] = r["login_time"].isoformat()
    return jsonify({
        "activity": rows,
        "total": total,
        "page": page,
        "total_pages": (total + per_page - 1) // per_page,
    })


# ── API: Admin Audit Log ─────────────────────────────────

@admin_bp.route("/api/admin/logs")
@admin_required
def api_admin_logs():
    rows = query(
        """SELECT a.*, u.full_name as admin_name
           FROM admin_actions a
           JOIN users u ON a.admin_id = u.id
           ORDER BY a.performed_at DESC LIMIT 100""",
        fetchall=True,
    )
    for r in rows:
        if r.get("performed_at"):
            r["performed_at"] = r["performed_at"].isoformat()
    return jsonify({"logs": rows})
