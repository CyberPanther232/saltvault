from flask import Flask, redirect, url_for, request
import os
from pathlib import Path
from .routes import login_manager

def create_app():
    app = Flask(__name__)

    # Stable SECRET_KEY to avoid session loss between dev reloads / restarts
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        # Persist a generated key to instance folder
        instance_path = Path(app.instance_path)
        instance_path.mkdir(parents=True, exist_ok=True)
        key_file = instance_path / 'secret_key'
        if key_file.is_file():
            secret_key = key_file.read_text().strip()
        else:
            secret_key = os.urandom(32).hex()
            key_file.write_text(secret_key)
        
    app.config['SECRET_KEY'] = secret_key
    # Store DB under app/data by default; allow env override
    default_db = os.path.join('app', 'data', 'dev_database.db')
    app.config['DATABASE_PATH'] = os.environ.get('DATABASE_PATH', default_db)

    # Optional session & security settings via environment variables
    cookie_secure = os.environ.get('SESSION_COOKIE_SECURE')
    if cookie_secure is not None:
        app.config['SESSION_COOKIE_SECURE'] = cookie_secure.lower() == 'true'

    cookie_httponly = os.environ.get('SESSION_COOKIE_HTTPONLY')
    if cookie_httponly is not None:
        app.config['SESSION_COOKIE_HTTPONLY'] = cookie_httponly.lower() == 'true'

    cookie_samesite = os.environ.get('SESSION_COOKIE_SAMESITE')
    if cookie_samesite:
        app.config['SESSION_COOKIE_SAMESITE'] = cookie_samesite  # e.g. 'Strict', 'Lax', 'None'

    lifetime_seconds = os.environ.get('PERMANENT_SESSION_LIFETIME')
    if lifetime_seconds and lifetime_seconds.isdigit():
        from datetime import timedelta
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(lifetime_seconds))

    # Expose issuer for TOTP provisioning (default: SaltVault)
    app.config['TOTP_ISSUER'] = os.environ.get('TOTP_ISSUER', 'SaltVault')

    @app.before_request
    def check_setup():
        # List of endpoints that are allowed without a user being set up
        allowed_endpoints = ['main.setup', 'main.mfa_setup', 'main.verify_mfa', 'static']

        # Allow access to setup-related pages and static files
        if request.endpoint in allowed_endpoints:
            return

        from .init_db import get_db
        try:
            db = get_db()
            user_count = db.execute('SELECT COUNT(id) FROM users').fetchone()[0]
            if user_count == 0:
                return redirect(url_for('main.setup'))
        except Exception as e:
            # This can happen if the database is not initialized yet
            # In that case, we should allow access to the init-db command
            if request.endpoint and 'init-db' not in request.endpoint:
                 # In a web context, if the DB is not ready, go to setup.
                return redirect(url_for('main.setup'))

    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    from . import init_db
    init_db.init_app(app)

    from . import routes
    app.register_blueprint(routes.main)
    app.register_blueprint(routes.api)


    return app