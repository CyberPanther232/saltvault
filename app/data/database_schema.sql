CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    url TEXT,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    mfa_secret TEXT,
    encryption_salt TEXT NOT NULL
);

-- Backup codes for MFA recovery; each code is one-time use
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Notification preferences per user (separate categories per medium)
CREATE TABLE IF NOT EXISTS notification_preferences (
    user_id INTEGER PRIMARY KEY,
    discord_login INTEGER NOT NULL DEFAULT 1,
    discord_import_export INTEGER NOT NULL DEFAULT 1,
    discord_deletion INTEGER NOT NULL DEFAULT 1,
    discord_security INTEGER NOT NULL DEFAULT 1,
    email_login INTEGER NOT NULL DEFAULT 1,
    email_import_export INTEGER NOT NULL DEFAULT 1,
    email_deletion INTEGER NOT NULL DEFAULT 1,
    email_security INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
