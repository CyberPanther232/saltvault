#!/usr/bin/env python3
"""Interactive setup script for SaltVault deployment.
Supports Linux and Windows (requires Docker installed).

Steps:
  1. Prompt for domain name
  2. Choose SSL mode (self-signed, existing, cloudflare)
  3. Generate / copy certs (if applicable)
  4. Render nginx.conf from template
  5. Build and start docker-compose stack
  6. Provide post-setup tips
"""
import os
import sys
import subprocess
import importlib
from pathlib import Path
from textwrap import dedent
from datetime import datetime, timedelta

TEMPLATE_PATH = Path('nginx/nginx.conf.template')
OUTPUT_CONF = Path('nginx/nginx.conf')
CERT_DIR = Path('nginx/certs')
DEFAULT_CERT = CERT_DIR / 'fullchain.pem'
DEFAULT_KEY = CERT_DIR / 'privkey.pem'
SELF_SIGNED_VALID_DAYS = 825  # ~27 months

# Lazy cryptography import; we'll attempt auto-install if missing.
x509 = None
NameOID = None
hashes = None
serialization = None
rsa = None

def ensure_python_dependencies():
    """Ensure Python modules required for optional features are installed.
    Currently only 'cryptography' is needed for in-Python self-signed cert generation.
    Falls back to 'openssl' if installation fails or module absent.
    """
    global x509, NameOID, hashes, serialization, rsa
    try:
        import cryptography  # noqa: F401
    except ImportError:
        print("'cryptography' not found. Attempting installation...")
        # Choose pip invocation method
        py_exec = sys.executable or 'python'
        try:
            subprocess.run([py_exec, '-m', 'pip', 'install', '--upgrade', 'pip'], check=False)
            subprocess.run([py_exec, '-m', 'pip', 'install', 'cryptography'], check=True)
            print("Installed 'cryptography'.")
        except Exception as e:
            print(f"Failed to install 'cryptography': {e}. Will fallback to openssl CLI if available.")
            return
    # Attempt import after install
    try:
        from cryptography import x509 as _x509
        from cryptography.x509.oid import NameOID as _NameOID
        from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        x509, NameOID, hashes, serialization, rsa = _x509, _NameOID, _hashes, _serialization, _rsa
    except Exception as e:
        print(f"Unexpected error importing cryptography modules: {e}. Will fallback to openssl CLI.")
        x509 = None


def header(title: str):
    print(f"\n=== {title} ===")


def ensure_docker():
    try:
        subprocess.run(['docker', 'version'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        print("Docker is required. Please install Docker and re-run this script.")
        sys.exit(1)
    # Detect compose availability
    if not detect_compose_command():
        print("Neither 'docker compose' nor 'docker-compose' found. Install Docker Compose plugin or legacy docker-compose.")
        sys.exit(1)

def have_openssl() -> bool:
    return subprocess.run(['openssl','version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

_COMPOSE_CMD = None

def detect_compose_command():
    """Detect whether 'docker compose' (plugin) or 'docker-compose' (legacy) is available.
    Returns the chosen command list or None if neither exists."""
    global _COMPOSE_CMD
    if _COMPOSE_CMD is not None:
        return _COMPOSE_CMD
    # Prefer plugin syntax
    try:
        subprocess.run(['docker','compose','version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        _COMPOSE_CMD = ['docker','compose']
        return _COMPOSE_CMD
    except Exception:
        pass
    # Fallback to legacy binary
    try:
        subprocess.run(['docker-compose','version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        _COMPOSE_CMD = ['docker-compose']
        return _COMPOSE_CMD
    except Exception:
        return None


def prompt_domain() -> str:
    return input("Enter domain (e.g., vault.example.com) [vault.local]: ").strip() or 'vault.local'


def prompt_ssl_mode() -> str:
    print("Select SSL mode:")
    print("  1) self-signed")
    print("  2) existing (provide cert & key paths)")
    print("  3) cloudflare (HTTP only; Cloudflare terminates TLS)")
    choice = input("Choice [1]: ").strip() or '1'
    mapping = {'1': 'self-signed', '2': 'existing', '3': 'cloudflare'}
    return mapping.get(choice, 'self-signed')


def generate_self_signed(domain: str):
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if x509 is None:
        if have_openssl():
            print("Using openssl CLI to generate self-signed certificate (cryptography not available).")
            cmd = [
                'openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:4096',
                '-days', str(SELF_SIGNED_VALID_DAYS), '-subj', f'/CN={domain}',
                '-keyout', str(DEFAULT_KEY), '-out', str(DEFAULT_CERT)
            ]
            subprocess.run(cmd, check=True)
            return
        else:
            print("Neither 'cryptography' nor 'openssl' are available; cannot generate self-signed certificate.")
            sys.exit(1)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    # Use standard datetime utilities (cryptography does not expose x509.datetime)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=SELF_SIGNED_VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    DEFAULT_KEY.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()))
    DEFAULT_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated self-signed certificate -> {DEFAULT_CERT}, key -> {DEFAULT_KEY}")


def copy_existing():
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    fullchain = Path(input("Path to existing fullchain/cert: ").strip())
    privkey = Path(input("Path to existing private key: ").strip())
    if not fullchain.is_file() or not privkey.is_file():
        print("Provided paths invalid.")
        sys.exit(1)
    DEFAULT_CERT.write_bytes(fullchain.read_bytes())
    DEFAULT_KEY.write_bytes(privkey.read_bytes())
    print("Copied existing certificate and key into nginx/certs.")


def render_nginx(domain: str, ssl_mode: str):
    template = TEMPLATE_PATH.read_text()
    if ssl_mode == 'cloudflare':
        redirect_block = "    # Cloudflare mode: no HTTPS redirect\n    # TLS terminated at Cloudflare edge."
        ssl_server_block = ""  # No local TLS server block
    else:
        redirect_block = "    return 301 https://$host$request_uri;"
        ssl_server_block = dedent(f"""
        server {{
            listen 443 ssl;
            server_name {domain};
            ssl_certificate /etc/nginx/certs/fullchain.pem;
            ssl_certificate_key /etc/nginx/certs/privkey.pem;
            location / {{
                proxy_pass http://web;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }}
        }}
        """)
    rendered = (template
                .replace('{{DOMAIN}}', domain)
                .replace('{{SSL_MODE}}', ssl_mode)
                .replace('{{REDIRECT_BLOCK}}', redirect_block)
                .replace('{{SSL_SERVER_BLOCK}}', ssl_server_block))
    OUTPUT_CONF.write_text(rendered)
    print(f"Rendered nginx config -> {OUTPUT_CONF}")


def docker_compose_up():
    print("Building containers...")
    compose = detect_compose_command()
    if compose is None:
        print("Docker Compose not available. Aborting.")
        sys.exit(1)
    subprocess.run([*compose, 'build'], check=True)
    print("Starting stack...")
    subprocess.run([*compose, 'up', '-d'], check=True)
    print("Stack is up.")


def post_setup(domain: str, ssl_mode: str):
    print(dedent(f"""
    Setup complete.
      Domain: {domain}
      SSL Mode: {ssl_mode}
      Nginx config: {OUTPUT_CONF}
      Cert directory: {CERT_DIR if ssl_mode != 'cloudflare' else 'N/A'}

    Next steps:
      1. Point DNS for {domain} to this host.
      2. Initialize DB (if first run): docker compose exec web flask init-db
      3. View logs: docker compose logs -f nginx
      4. Renew certs (self-signed) by re-running this script (it overwrites files).

    Security notes:
      - SQLite file persists in ./app/data; back it up regularly.
      - For Cloudflare mode, consider an origin certificate for end-to-end encryption.
    """))


def main():
    header("SaltVault Deployment Setup")
    ensure_docker()
    ensure_python_dependencies()
    domain = prompt_domain()
    ssl_mode = prompt_ssl_mode()

    # Optional environment variable configuration
    header("Environment Configuration (Optional)")
    if input("Configure environment variables now? [y/N]: ").strip().lower() == 'y':
        env_path = Path('app/app.env')
        print(f"Writing environment variables to {env_path} ...")
        # Collect values with sensible defaults
        flask_env = input("FLASK_ENV [production]: ").strip() or 'production'
        debug = input("DEBUG (True/False) [False]: ").strip() or 'False'
        db_path = input("DATABASE_PATH [/app/data/dev_database.db]: ").strip() or '/app/data/dev_database.db'
        sess_secure = input("SESSION_COOKIE_SECURE (True/False) [True]: ").strip() or 'True'
        sess_httponly = input("SESSION_COOKIE_HTTPONLY (True/False) [True]: ").strip() or 'True'
        sess_samesite = input("SESSION_COOKIE_SAMESITE (Strict/Lax/None) [Strict]: ").strip() or 'Strict'
        sess_lifetime = input("PERMANENT_SESSION_LIFETIME seconds [3600]: ").strip() or '3600'
        totp_issuer = input("TOTP_ISSUER [SaltVault]: ").strip() or 'SaltVault'
        log_level = input("LOG_LEVEL (DEBUG/INFO/WARNING/ERROR) [INFO]: ").strip() or 'INFO'
        workers = input("Gunicorn WORKERS [3]: ").strip() or '3'
        threads = input("Gunicorn THREADS [2]: ").strip() or '2'
        log_directory = input("LOG_DIRECTORY [/app/logs]: ").strip() or '/app/logs'
        with env_path.open('w') as f:
            f.write('[Application Environment Variables]\n')
            f.write(f'FLASK_ENV={flask_env}\n')
            f.write(f'DEBUG={debug}\n')
            f.write(f'DATABASE_PATH={db_path}\n')
            f.write(f'SESSION_COOKIE_SECURE={sess_secure}\n')
            f.write(f'SESSION_COOKIE_HTTPONLY={sess_httponly}\n')
            f.write(f'SESSION_COOKIE_SAMESITE={sess_samesite}\n')
            f.write(f'PERMANENT_SESSION_LIFETIME={sess_lifetime}\n')
            f.write(f'TOTP_ISSUER={totp_issuer}\n')
            f.write(f'LOG_LEVEL={log_level}\n')
            f.write(f'WORKERS={workers}\n')
            f.write(f'THREADS={threads}\n')
            f.write(f'APP_DOMAIN={domain}\n')
            f.write(f'SSL_MODE={ssl_mode}\n')
            f.write(f'LOG_DIRECTORY={log_directory}\n')
        print("Environment file written.")

    if ssl_mode == 'self-signed':
        header("Generate Self-Signed Certificate")
        generate_self_signed(domain)
    elif ssl_mode == 'existing':
        header("Use Existing Certificate")
        copy_existing()
    else:
        header("Cloudflare Mode Selected")
        print("Proceeding without local TLS termination.")

    header("Render Nginx Configuration")
    render_nginx(domain, ssl_mode)

    header("Launch Containers")
    docker_compose_up()

    header("Post Setup")
    post_setup(domain, ssl_mode)

    # Optional DB initialization
    compose = detect_compose_command()
    if input("Initialize database now (flask init-db)? [y/N]: ").strip().lower() == 'y':
        try:
            print("Initializing database inside 'web' container...")
            subprocess.run([*compose, 'exec', 'web', 'flask', 'init-db'], check=True)
            print("Database initialized.")
        except Exception as e:
            print(f"Database initialization failed: {e}")
    else:
        print("Skipped database initialization. You can run it later with: docker compose exec web flask init-db")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
