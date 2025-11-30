import sqlite3
import os
from flask import g, current_app
import click
from pathlib import Path


def get_db():
    # Prefer Flask config; fallback to env; finally default under app/data
    configured = current_app.config.get('DATABASE_PATH') if current_app else None
    env_path = os.environ.get('DATABASE_PATH')
    default_path = os.path.join(os.path.dirname(__file__), 'data', 'dev_database.db')
    db_path = configured or env_path or default_path

    # If relative, make it relative to the project root
    if not os.path.isabs(db_path):
        # Resolve relative to the workspace root where main.py runs
        db_path = os.path.join(os.getcwd(), db_path)

    # Ensure the directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    if 'db' not in g:
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_connection(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def _exec_schema(db):
    """Execute the full schema file (idempotent due to IF NOT EXISTS)."""
    schema_path = Path(os.path.dirname(__file__)) / 'data' / 'database_schema.sql'
    with schema_path.open('r') as f:
        db.executescript(f.read())
    db.commit()

def init_db():
    """Initialize a fresh database using the schema file."""
    db = get_db()
    _exec_schema(db)

def migrate_db():
    """Ensure all tables exist (safe to run on existing DB)."""
    db = get_db()
    _exec_schema(db)


@click.command('init-db')
def init_db_command():
    init_db()
    click.echo('Initialized the database.')

@click.command('migrate-db')
def migrate_db_command():
    migrate_db()
    click.echo('Database schema verified / migrated.')


def init_app(app):
    app.teardown_appcontext(close_connection)
    app.cli.add_command(init_db_command)
    app.cli.add_command(migrate_db_command)
    # Attempt automatic migration at startup (within app context)
    with app.app_context():
        migrate_db()