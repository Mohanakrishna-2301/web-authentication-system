"""
Risk Engine for SecureAuth+
Calculates login risk level based on device, IP, and time-of-day.

🟢 Low   — Known device AND known IP AND normal hours (6 AM – 11 PM)
🟡 Medium — New device OR new IP
🔴 High  — (New device OR new IP) AND unusual time (before 6 AM or after 11 PM)
"""

from datetime import datetime
from db import query


def _get_known_devices(user_id):
    rows = query(
        "SELECT DISTINCT device_info FROM login_history WHERE user_id=%s AND success=1",
        (user_id,),
        fetchall=True,
    )
    return {r["device_info"] for r in rows if r["device_info"]}


def _get_known_ips(user_id):
    rows = query(
        "SELECT DISTINCT ip_address FROM login_history WHERE user_id=%s AND success=1",
        (user_id,),
        fetchall=True,
    )
    return {r["ip_address"] for r in rows if r["ip_address"]}


def _is_unusual_time():
    hour = datetime.now().hour
    return hour < 6 or hour >= 23


def calculate_risk(user_id, device_info, ip_address):
    """Return 'Low', 'Medium', or 'High'."""
    known_devices = _get_known_devices(user_id)
    known_ips = _get_known_ips(user_id)

    new_device = device_info not in known_devices
    new_ip = ip_address not in known_ips
    unusual_time = _is_unusual_time()

    # First-time login → treat as Low (no history to compare)
    if not known_devices and not known_ips:
        return "Low"

    if (new_device or new_ip) and unusual_time:
        return "High"
    if new_device or new_ip:
        return "Medium"
    return "Low"
