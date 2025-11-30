# SaltVault Password Manager

![SaltVault Logo](./salt_vault_repo_logo.png)

**Version:** Beta - 1.1.1

A secure, lightweight, and containerized private password manager built with Flask. This application utilizes the PyNACL library to perform fast effective encryption and decryption of passwords stored within the application. This project is intended to showcase an understanding of secure software development, encryption algorithms, and provide an effective solution for those seeking to utilize a free password manager that does not create a ton of overhead on a user's device. This project is currently in a beta phase and is still under development.

## Features

* **End-to-End Encryption:** Your passwords are encrypted and decrypted on the client-side, using a key derived from your master password.
* **Two-Factor Authentication (2FA):** Secure your account with TOTP-based two-factor authentication.
* **Password Generator:** Create strong, random passwords with customizable criteria.
* **Password Strength Meter:** Get immediate feedback on the strength of your passwords.
* **CSV Export:** Export your passwords to a CSV file compatible with other password managers.
* **Password Filtering/Search:** Search through your list of passwords to view.
* **Dark Theme:** A modern, dark theme for a pleasant user experience.

## Upcoming Features

* [ ] Browser extensions
* [ ] Secure sharing of passwords
* [ ] Password history and audit
* [ ] Locally Hosted Application

## Getting Started

### Prerequisites

* [Python 3.12+](https://www.python.org/)
* [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://www.github.com/CyberPanther232/saltvault
   cd saltvault
   ```
2. **Set up the environment:**

   - Rename `app.env.example` to `app.env`.
   - For production, it is recommended to change the `DATABASE_PATH` to a location outside of the `app` directory.
3. **SSL Certificates (for production with Docker) - CloudFlare Recommended:**

   - If you are using CloudFlare, ensure you generate a new certificate to host on the server/workstation you run this application on.
   - SSL/TLS is highly recommended for using this application. Even if hosted locally on your own machine.
   - Place your SSL certificate (`fullchain.pem`) and private key (`privkey.pem`) in the `nginx/certs/` directory.
   - Update `nginx/nginx.conf` with your domain name.
4. **Automated Setup (Optional – Recommended for Docker Production):**
   You can use the provided setup scripts to streamline configuration (domain, SSL mode, certificates, nginx config, Docker Compose). These scripts will:

   - Detect whether `docker compose` plugin or legacy `docker-compose` binary is available.
   - Auto-install required Python dependencies (e.g., `cryptography`) in the Python version.
   - Generate a persistent Flask `SECRET_KEY` file to keep sessions & MFA stable (do not delete `instance/secret_key`).
   - Render `nginx/nginx.conf` from the template and handle certificates based on your selection.
   - Optionally generate a self-signed certificate if you choose that mode.
   - Warn and abort cleanly if Docker Compose is missing.

   SSL Mode Options during scripted setup:

   - `cloudflare`: Use Cloudflare-origin certs you place into `nginx/certs/`.
   - `existing`: Use existing `fullchain.pem` and `privkey.pem` in `nginx/certs/`.
   - `self-signed`: Auto-generate a self-signed certificate (suitable for internal/testing use).

   Python (cross-platform):

   ```bash
   python scripts/setup_saltvault.py
   ```

   Bash (Linux/macOS):

   ```bash
   bash scripts/setup_saltvault.sh
   ```

   PowerShell (Windows):

   ```powershell
   pwsh .\scripts\setup_saltvault.ps1
   ```

   After the script completes, it will run (or instruct you to run) Docker Compose. Access the site via `https://<your-domain>` (or the chosen host). On first visit you will be guided through master account + MFA setup.
5. **Run the application (Manual path):**

   - **With Docker (recommended for production):**
     ```bash
     docker-compose up -d
     ```
   - **Locally (for development):**
     - Create a virtual environment: `python -m venv .env`
     - Activate it: `source .env/bin/activate` (or `.\.env\Scripts\activate` on Windows)
     - Install dependencies: `pip install -r requirements.txt`
     - Initialize the database: `flask init-db`
     - Run the app: `python main.py`

## Usage

1. **Initial Setup:** The first time you access the application, you will be prompted to create a master account and set up two-factor authentication.
2. **Login:** Log in with your master password and a TOTP code from your authenticator app.
3. **Dashboard:** The main dashboard displays all your stored passwords.
4. **Add Password:** Click the "Add Password" button to add a new entry. You can use the built-in password generator to create a strong password.
5. **View/Edit/Delete:** Use the buttons on each row to view, edit, or delete a password entry.
6. **Export:** You can export all your passwords to a CSV file from the "Export to CSV" button on the dashboard. You will be prompted to re-enter your password and MFA code for security.
7. **Import:** You can import csv or json files with password lists from other password managers. Currently, the only supported managers are NordPass and BitWarden. I am working to add more

## Environment Variables

SaltVault reads configuration from environment variables (or `app.env`). A full template lives in `app/app.env.example`.

### Core Application

| Variable      | Description                      | Prod Example   |
| ------------- | -------------------------------- | -------------- |
| `FLASK_ENV` | Flask environment mode           | `production` |
| `DEBUG`     | Debug features (disable in prod) | `False`      |
| `HOST`      | Bind interface (dev server)      | `0.0.0.0`    |
| `PORT`      | Dev server port (not gunicorn)   | `8080`       |

### Database

| Variable          | Description                              | Example                             |
| ----------------- | ---------------------------------------- | ----------------------------------- |
| `DATABASE_PATH` | Absolute/relative path to SQLite DB file | `/var/lib/saltvault/saltvault.db` |
| `DATABASE_NAME` | Optional display/reference name          | `saltvault.db`                    |

### Security & Sessions

| Variable                       | Description                                    | Recommendation            |
| ------------------------------ | ---------------------------------------------- | ------------------------- |
| `SECRET_KEY`                 | Overrides persisted instance key (leave unset) | Unset                     |
| `SESSION_COOKIE_SECURE`      | Cookie only over HTTPS                         | `True` (prod)           |
| `SESSION_COOKIE_HTTPONLY`    | Prevent JS access                              | `True`                  |
| `SESSION_COOKIE_SAMESITE`    | CSRF mitigation; `Strict                       | Lax                       |
| `PERMANENT_SESSION_LIFETIME` | Lifetime in seconds                            | `3600` or policy        |
| `TOTP_ISSUER`                | Issuer label in authenticator app              | `SaltVault` or org name |

### Logging

| Variable          | Description          | Example                                    |
| ----------------- | -------------------- | ------------------------------------------ |
| `LOG_DIRECTORY` | Folder for log files | `/var/log/saltvault/`                    |
| `LOG_LEVEL`     | Logging verbosity    | `INFO` (prod) / `DEBUG` (troubleshoot) |

### Deployment (Setup Scripts)

| Variable       | Description                     | Example               |
| -------------- | ------------------------------- | --------------------- |
| `APP_DOMAIN` | Public domain for nginx & certs | `vault.example.com` |
| `SSL_MODE`   | `cloudflare                     | existing              |

### Gunicorn Tuning

| Variable    | Description               | Example |
| ----------- | ------------------------- | ------- |
| `WORKERS` | Gunicorn worker processes | `3`   |
| `THREADS` | Threads per worker        | `2`   |

### Feature Flags (Future Placeholders)

| Variable                    | Description                   | Status      |
| --------------------------- | ----------------------------- | ----------- |
| `ENABLE_IMPORT_BITWARDEN` | Enable Bitwarden import logic | Placeholder |
| `ENABLE_IMPORT_NORDPASS`  | Enable NordPass import logic  | Placeholder |

### Best Practices

1. Do not set `SECRET_KEY` unless you have a rotation procedure; allow auto-managed `instance/secret_key`.
2. If `SESSION_COOKIE_SAMESITE=None`, you must have `SESSION_COOKIE_SECURE=True` and serve strictly over HTTPS.
3. Place your database outside the repo path for production; secure permissions (owner read/write only).
4. Use log rotation (`logrotate`) for `LOG_DIRECTORY` to avoid disk exhaustion.
5. Scale gunicorn using `(2 * CPU cores) + 1` as a heuristic; tune under load tests.
6. Keep `.env` out of version control or store secrets in your orchestrator (Docker secrets, Kubernetes, etc.).

### Optional: Auto Load `.env`

Install `python-dotenv` and load early in `main.py` if not using Docker exclusively:

```python
from dotenv import load_dotenv
load_dotenv()
```

### Minimal Production Example

```dotenv
FLASK_ENV=production
DEBUG=False
HOST=0.0.0.0
PORT=8080
DATABASE_PATH=/var/lib/saltvault/saltvault.db
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Strict
PERMANENT_SESSION_LIFETIME=3600
TOTP_ISSUER=MyCompanyVault
LOG_LEVEL=INFO
APP_DOMAIN=vault.example.com
SSL_MODE=existing
WORKERS=3
THREADS=2
```

## Notes & Tips

* Persistent Secret Key: The application now writes a stable secret key to `instance/secret_key`. Deleting it will invalidate sessions and require MFA re-setup.
* Docker Compose Detection: If the setup script reports compose is missing, install either the Docker Compose plugin or legacy binary before re-running.
* Self-Signed Certificates: These are suitable only for testing or internal lab use. Browsers will show a warning unless you trust the root.
* Security Hardening (Production): Consider enabling secure cookies (`SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE='Strict'`) via environment variables.

# Version Control

1.0.0 - Beta version with the basic functions listed above - 29-Nov-2025

1.1.0 - Added improved import/export functionality, notifications, settings, and improved functionality on action buttons. - 30-Nov-2025

1.1.1 - Updated UI to make navbar easier to use and updated the dialog boxes on the index.html
