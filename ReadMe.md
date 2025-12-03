# SaltVault Password Manager

![SaltVault Logo](./salt_vault_repo_logo.png)

**Version:** Beta - 1.2.0

SaltVault is a secure, lightweight, and containerized private password manager built with Flask. It focuses on minimal trusted surface area: secret material (passwords) is encrypted in the browser using a key derived from your master password and is stored encrypted on the server. SaltVault also supports TOTP-based two-factor authentication to protect account access.

## Core Features

- End-to-End Encryption: Passwords are encrypted in the client/browser; the server stores ciphertext only.
- Two-Factor Authentication (2FA): TOTP-based 2FA compatible with standard authenticator apps.
- Secure Storage: Encrypted entries are stored in an SQLite database (configurable path).
- Simple, self-hostable architecture: Docker Compose or local Python execution supported.
- Notifications: Setup a SMTP server to send emails or a Discord Webhook for event notifications

---

## Quick Start

Choose one of the following deployment options.

A. Production (recommended): Docker Compose

1. Clone the repository

   ```bash
   git clone https://github.com/CyberPanther232/saltvault
   cd saltvault
   ```
2. Copy the environment template and edit:

   ```bash
   cp app/app.env.example app/app.env
   # or if app/app.env.example is at the repo root:
   # cp app.env.example app.env
   ```

   - Set `DATABASE_PATH` to a persistent path outside your repo for production (e.g., `/var/lib/saltvault/saltvault.db`).
   - Set `APP_DOMAIN` and `SSL_MODE` as needed for HTTPS.
3. Place certificates (production):

   - Put `fullchain.pem` and `privkey.pem` into `nginx/certs/` if you use `SSL_MODE=existing` or Cloudflare origin certs. The setup script or your deploy process can handle this per your environment.
4. Start containers:

   ```bash
   # If using legacy docker-compose
   docker-compose up -d
   # Or with the docker Compose plugin:
   docker compose up -d
   ```

B. Local development (no Docker)

1. Create and activate a virtual environment:
   ```bash
   python -m venv .env
   source .env/bin/activate      # macOS / Linux
   # .\.env\Scripts\activate     # Windows PowerShell / CMD
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database and start:
   ```bash
   flask init-db
   python main.py
   ```

   The app will run on the configured host/port (default 0.0.0.0:8080 for the dev server).

C. Automated setup script
A helper script at `scripts/setup_saltvault.py` assists with rendering nginx configuration, creating a persistent secret key under `instance/secret_key`, detecting/validating Docker Compose, and optionally generating self-signed certs. Run:

```bash
python scripts/setup_saltvault.py
```

---

## First-time Use & Typical Workflow

1. First visit

   - Open your browser to the app domain (e.g., https://vault.example.com) or http://localhost:8080 for local dev.
   - You will be guided to create a master account. Choose a strong master password — this is used to derive encryption keys in the browser.
2. Enable two-factor authentication (TOTP)

   - During or immediately after account creation you will be prompted to set up TOTP 2FA. Scan the QR code with your authenticator app and save recovery codes if provided.
3. Add a password entry

   - From the dashboard, choose "Add Password" (or similar).
   - Enter the name, username, URL, and any notes. The plaintext password field is encrypted client-side before being sent to the server.
4. View an entry

   - Click the view/decrypt action for a given row. The decryption happens locally in your browser session after verifying your master password (or session-derived key).
5. Edit or delete

   - Edit: Modify the entry fields in the UI; on save the updated plaintext is encrypted client-side and replaced on the server.
   - Delete: Permanently removes the entry from the database.
6. Export / Import (if enabled)

   - Export: If the installation supports export, the application will require re-authentication (master password and TOTP) prior to exporting your data. Exported files may be plaintext CSV or JSON formatted depending on the chosen export mode — treat exported data as highly sensitive.
   - Import: Import functionality accepts generic CSV or JSON import files when available. Validate imported data carefully before trusting or deleting originals.

Security note: Always keep exported files and backups under strict access control. Exported data is plaintext and should be handled like any other secret.

---

## Environment Variables

SaltVault reads settings from environment variables (or an env file). See `app/app.env.example` for a full template.

Some key variables:

- FLASK_ENV — application environment (development / production)
- DEBUG — debug mode flag (False in production)
- HOST / PORT — dev server binding
- DATABASE_PATH — SQLite DB path (use a persistent external path in production)
- SECRET_KEY — optional override for the instance secret file; prefer letting the app create and manage `instance/secret_key`
- SESSION_COOKIE_SECURE — set True in production (HTTPS)
- SESSION_COOKIE_HTTPONLY — recommended True
- SESSION_COOKIE_SAMESITE — recommended Strict
- PERMANENT_SESSION_LIFETIME — seconds for session persistence
- TOTP_ISSUER — label for TOTP entries in authenticator apps
- LOG_DIRECTORY / LOG_LEVEL — logging configuration
- APP_DOMAIN / SSL_MODE — used by setup scripts / nginx rendering
- WORKERS / THREADS — gunicorn tuning parameters

Best practice highlights:

- Do not commit `.env` or secret files to source control.
- Use secure file permissions on database and secret files.
- Serve over HTTPS in production and enable secure cookies.

---

## Operations & Maintenance

- Secret key: SaltVault persists a stable secret key in `instance/secret_key`. Deleting it will invalidate sessions and require users to re-setup MFA. Back up this file when you backup the app.
- Backups: Back up the SQLite database file from `DATABASE_PATH`. Backups contain ciphertext but should be protected as sensitive data.
- Logs & rotation: Configure log rotation for `LOG_DIRECTORY` so logs do not fill disks.
- Upgrades: Pull new images or code, and restart containers. Test upgrades in a staging environment first.

---

## Troubleshooting

- "Cannot connect to database": Verify `DATABASE_PATH` exists and is writable by the application user.
- "MFA fails" or "Invalid TOTP": Verify device time is accurate (NTP sync) and that the TOTP issuer/time window matches your authenticator app.
- Docker compose not found: Use either `docker compose` (plugin) or install legacy `docker-compose` binary.

If you need help diagnosing a problem, open an issue in the repository with reproduction steps, logs, and configuration details (do not paste secrets).

---

## Security & Privacy Notes

- SaltVault encrypts secrets client-side; the server never stores plaintext values.
- Master password strength is critical: choose a long, unique password.
- Treat export files and database backups as highly sensitive and restrict file-system and backup access.
- If you plan to expose the app to the public internet, use a valid TLS certificate and reputable reverse-proxy (nginx) configuration. Use secure cookies and set `SESSION_COOKIE_SECURE=True`.

---

## Contributing

Contributions, bug reports, and pull requests are welcome. Please open issues for bugs or feature requests and read CONTRIBUTING.md (if present) for contribution guidelines.

---

## Other Projects & Portfolio

I maintain other projects and professional work at my portfolio: https://www.cyberpanther-dev.space

If you'd like to collaborate, review other work, or contact me for professional services, that site contains background, featured projects, and contact details.

---

## License

TBD
