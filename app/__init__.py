from flask import Flask, redirect, url_for, request, g
import os
from .routes import login_manager

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    # Store DB under app/data by default; allow env override
    default_db = os.path.join('app', 'data', 'dev_database.db')
    app.config['DATABASE_PATH'] = os.environ.get('DATABASE_PATH', default_db)

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


    return app