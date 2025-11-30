# SaltVault Password Manager

![SaltVault Logo](./salt_vault_repo_logo.png)

**Version:** Beta - 1.0.0

A secure, lightweight, and containerized private password manager built with Flask. This application utilizes the PyNACL library to perform fast effective encryption and decryption of passwords stored within the application. This project is intended to showcase an understanding of secure software development, encryption algorithms, and provide an effective solution for those seeking to utilize a free password manager that does not create a ton of overhead on a user's device. This project is currently in a beta phase and is still under development.

## Features

*   **End-to-End Encryption:** Your passwords are encrypted and decrypted on the client-side, using a key derived from your master password.
*   **Two-Factor Authentication (2FA):** Secure your account with TOTP-based two-factor authentication.
*   **Password Generator:** Create strong, random passwords with customizable criteria.
*   **Password Strength Meter:** Get immediate feedback on the strength of your passwords.
*   **CSV Export:** Export your passwords to a CSV file compatible with other password managers.
*   **Password Filtering/Search:** Search through your list of passwords to view.
*   **Dark Theme:** A modern, dark theme for a pleasant user experience.

## Upcoming Features

*   [ ] Browser extensions
*   [ ] Secure sharing of passwords
*   [ ] Password history and audit
*   [ ] Locally Hosted Application

## Getting Started

### Prerequisites

*   [Python 3.12+](https://www.python.org/)
*   [Docker](https://www.docker.com/get-started) and [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://www.github.com/CyberPanther232/saltvault
    cd saltvault
    ```

2.  **Set up the environment:**
    -   Rename `app.env.example` to `app.env`.
    -   For production, it is recommended to change the `DATABASE_PATH` to a location outside of the `app` directory.

3.  **SSL Certificates (for production with Docker) - CloudFlare Recommended:**
    -   If you are using CloudFlare, ensure you generate a new certificate to host on the server/workstation you run this application on.
    -   SSL/TLS is highly recommended for using this application. Even if hosted locally on your own machine. 
    -   Place your SSL certificate (`fullchain.pem`) and private key (`privkey.pem`) in the `nginx/certs/` directory.
    -   Update `nginx/nginx.conf` with your domain name.

5.  **Run the application:**
    -   **With Docker (recommended for production):**
        ```bash
        docker-compose up -d
        ```
    -   **Locally (for development):**
        -   Create a virtual environment: `python -m venv .env`
        -   Activate it: `source .env/bin/activate` (or `.\.env\Scripts\activate` on Windows)
        -   Install dependencies: `pip install -r requirements.txt`
        -   Initialize the database: `flask init-db`
        -   Run the app: `python main.py`

## Usage

1.  **Initial Setup:** The first time you access the application, you will be prompted to create a master account and set up two-factor authentication.
2.  **Login:** Log in with your master password and a TOTP code from your authenticator app.
3.  **Dashboard:** The main dashboard displays all your stored passwords.
4.  **Add Password:** Click the "Add Password" button to add a new entry. You can use the built-in password generator to create a strong password.
5.  **View/Edit/Delete:** Use the buttons on each row to view, edit, or delete a password entry.
6.  **Export:** You can export all your passwords to a CSV file from the "Export to CSV" button on the dashboard. You will be prompted to re-enter your password and MFA code for security.
7.  **Import:** You can import csv or json files with password lists from other password managers. Currently, the only supported managers are NordPass and BitWarden. I am working to add more
