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

def have_openssl() -> bool:
    return subprocess.run(['openssl','version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


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
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(x509.datetime.datetime.utcnow())
            .not_valid_after(x509.datetime.datetime.utcnow() + x509.datetime.timedelta(days=SELF_SIGNED_VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(key, hashes.SHA256()))
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
    subprocess.run(['docker', 'compose', 'build'], check=True)
    print("Starting stack...")
    subprocess.run(['docker', 'compose', 'up', '-d'], check=True)
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

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(1)
