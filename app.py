"""
SecureAuth+ — Main Application
"""

from flask import Flask
from config import Config
from auth_routes import auth_bp
from dashboard_routes import dashboard_bp
from admin_routes import admin_bp

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = Config.SESSION_TIMEOUT_MINUTES * 60

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(admin_bp)


# ── Error Handlers ────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return "<h1>404 — Page Not Found</h1><p><a href='/'>Go Home</a></p>", 404


@app.errorhandler(500)
def server_error(e):
    return "<h1>500 — Internal Server Error</h1><p>Something went wrong. Please try again later.</p>", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
