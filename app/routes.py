# External imports
import os
import csv
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import urllib.request
import json as pyjson
import smtplib
from email.message import EmailMessage
from pathlib import Path

# Internal imports
from .init_db import get_db
from .models import User
from .nacl_tools import encrypt_data, decrypt_data, derive_key, generate_salt
from .logging_functions import get_logger, log_event
from .password_generator import generate_password, strengthen_password, check_password_strength
from .quotes import quotes
from .process_import import *
main = Blueprint('main', __name__)

login_manager = LoginManager()

def get_key():
    """Retrieve the encryption key from the session."""
    if 'key' not in session:
        log_event('MISSING_KEY_IN_SESSION', f'No encryption key found in session for user ID {current_user.id}', severity='ERROR')
        flash('Your session has expired. Please log in again.', 'warning')
        log_event('SESSION_EXPIRED', f'Session expired for user ID {current_user.id}', severity='WARNING')
        return None
    log_event('KEY_RETRIEVED_FROM_SESSION', f'Encryption key retrieved from session for user ID {current_user.id}', severity='INFO')
    return bytes.fromhex(session['key'])

def notify_service(event: str, detail: str):
    """Send notification respecting per-category user preferences.
    Categories: login, import_export, deletion, security.
    Preferences stored in notification_preferences table per user.
    If current_user unavailable, attempt to infer user from session username.
    """
    category_map = {
        'USER_LOGIN_SUCCESSFUL': 'login',
        'VALID_CREDENTIALS_ENTERED': 'login',
        'LOGIN_BACKUP_CODE': 'login',
        'USER_REGISTERED': 'security',
        'PASSWORD_CHANGED': 'security',
        'MFA_REGENERATED': 'security',
        'BACKUP_CODES_GENERATED': 'security',
        'BACKUP_CODE_USED_MFA_RESET': 'security',
        'PASSWORDS_IMPORTED': 'import_export',
        'PASSWORDS_EXPORTED': 'import_export',
        'PASSWORD_DELETED': 'deletion',
    }
    category = category_map.get(event)
    if category is None:
        return  # Unmapped event; skip notifications
    user_id = None
    db = None
    try:
        db = get_db()
    except Exception:
        return
    if current_user and hasattr(current_user, 'id'):
        user_id = current_user.id
    else:
        uname = session.get('username_for_login') or session.get('username_for_mfa_setup')
        if uname:
            row = db.execute('SELECT id FROM users WHERE username = ?', (uname,)).fetchone()
            if row:
                user_id = row['id']
    if user_id is None:
        return
    # Ensure preference row exists
    pref = db.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (user_id,)).fetchone()
    if not pref:
        db.execute('INSERT INTO notification_preferences (user_id) VALUES (?)', (user_id,))
        db.commit()
        pref = db.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (user_id,)).fetchone()
    discord_allowed = pref[f'discord_{category}'] == 1 if f'discord_{category}' in pref.keys() else False
    email_allowed = pref[f'email_{category}'] == 1 if f'email_{category}' in pref.keys() else False
    webhook = os.environ.get('DISCORD_WEBHOOK_URL') if discord_allowed else None
    email_enabled_global = os.environ.get('EMAIL_ENABLED', 'False').lower() == 'true'
    email_enabled = email_allowed and email_enabled_global
    if webhook:
        try:
            data = pyjson.dumps({"content": f"[SaltVault] {event}: {detail}"}).encode('utf-8')
            req = urllib.request.Request(webhook, data=data, headers={'Content-Type': 'application/json'})
        except Exception as e:
            log_event('DISCORD_NOTIFICATION_FAILED', f'Failed to send Discord notification for event {event}. Error: {e}', severity='ERROR')
            pass
    if email_enabled:
        try:
            smtp_server = os.environ.get('SMTP_SERVER')
            smtp_port = int(os.environ.get('SMTP_PORT', '587'))
            smtp_user = os.environ.get('SMTP_USER')
            smtp_password = os.environ.get('SMTP_PASSWORD')
            email_from = os.environ.get('EMAIL_FROM') or smtp_user
            email_to = os.environ.get('EMAIL_TO')
            if smtp_server and smtp_user and smtp_password and email_to:
                msg = EmailMessage()
                msg['Subject'] = f'SaltVault Notification: {event}'
                msg['From'] = email_from
                msg['To'] = email_to
                msg.set_content(detail)
                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
                    s.starttls()
                    s.login(smtp_user, smtp_password)
                    s.send_message(msg)
        except Exception:
            pass

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    user_data = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if user_data:
        log_event('USER_LOADED_FROM_SESSION', f'User ID {user_id} loaded from session', severity='INFO')
        return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], mfa_secret=user_data['mfa_secret'], salt=user_data['encryption_salt'])
    log_event('USER_NOT_FOUND_IN_DB', f'User ID {user_id} not found in database during session load', severity='WARNING')
    return None

@main.route('/')
@login_required
def index_route():
    if request.method != 'GET':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access / with non-GET method', severity='WARNING')
        return "Method not allowed 405", 405

    db = get_db()
    key = get_key()
    if not key:
        flash('Your session has expired. Please log in again.', 'warning')
        log_event('SESSION_EXPIRED', f'Session expired for user ID {current_user.id}', severity='WARNING')
        return redirect(url_for('main.logout'))

    # Search params
    query = request.args.get('q', '').strip()
    fields_param = request.args.get('fields', '').strip()
    allowed_fields = {'title', 'username', 'email', 'notes'}
    active_fields = [f for f in fields_param.split(',') if f in allowed_fields]
    if query and not active_fields:
        # Default to all if user provided query but no fields
        active_fields = list(allowed_fields)

    encrypted_passwords = db.execute('SELECT * FROM passwords WHERE user_id = ?', (current_user.id,)).fetchall()
    passwords = []
    for p in encrypted_passwords:
        try:
            dec_title = decrypt_data(key, p['title'])
            dec_username = decrypt_data(key, p['username'])
            dec_email = decrypt_data(key, p['email'])
            dec_notes = decrypt_data(key, p['notes']) if p['notes'] else ''
            record = {
                'id': p['id'],
                'title': dec_title,
                'username': dec_username,
                'email': dec_email,
                'notes': dec_notes,
                'password': '**********'
            }
            # Apply filtering
            if query:
                q_lower = query.lower()
                match = any(record[f].lower().find(q_lower) != -1 for f in active_fields)
                if not match:
                    continue
            passwords.append(record)
        except Exception:
            log_event('DECRYPTION_ERROR', f'Failed to decrypt password ID {p["id"]} for user ID {current_user.id}', severity='ERROR')
            pass

    random_quote = random.choice(quotes)
    return render_template('index.html', passwords=passwords, quote=random_quote, q=query, fields=','.join(active_fields))

@main.route('/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_passwords():
    ids = request.form.getlist('selected_ids')
    if not ids:
        flash('No passwords selected for deletion.', 'warning')
        log_event('BULK_DELETE_NO_SELECTION', f'User {current_user.username} submitted bulk delete with no selection', severity='WARNING')
        return redirect(url_for('main.index_route'))
    try:
        db = get_db()
        # Ensure IDs are integers to prevent SQL issues
        clean_ids = [int(i) for i in ids if i.isdigit()]
        if not clean_ids:
            flash('Invalid selection.', 'danger')
            log_event('BULK_DELETE_INVALID_IDS', f'User {current_user.username} provided invalid IDs in bulk delete', severity='ERROR')
            return redirect(url_for('main.index_route'))
        placeholders = ','.join('?' for _ in clean_ids)
        db.execute(f'DELETE FROM passwords WHERE user_id = ? AND id IN ({placeholders})', [current_user.id, *clean_ids])
        db.commit()
        flash(f'Deleted {len(clean_ids)} password(s).', 'success')
        log_event('BULK_DELETE_SUCCESS', f'User {current_user.username} deleted {len(clean_ids)} passwords', severity='INFO')
    except Exception as e:
        log_event('BULK_DELETE_ERROR', f'Bulk delete error for user {current_user.username}: {e}', severity='ERROR')
        flash(f'Error deleting selected passwords: {e}', 'danger')
    return redirect(url_for('main.index_route'))

@main.route('/setup', methods=['GET', 'POST'])
def setup():

    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /setup with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    if current_user.is_authenticated:
        log_event('USER_ALREADY_LOGGED_IN', f'User {current_user.username} is already logged in, redirecting to index page', severity='INFO')
        return redirect(url_for('main.index_route'))
    
    db = get_db()
    if db.execute('SELECT COUNT(id) FROM users').fetchone()[0] > 0:
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        salt = generate_salt()
        password_hash = generate_password_hash(password)
        mfa_secret = pyotp.random_base32()
        
        db.execute('INSERT INTO users (username, password_hash, mfa_secret, encryption_salt) VALUES (?, ?, ?, ?)',
                   (username, password_hash, mfa_secret, salt.hex()))
        db.commit()

        # Generate backup codes for initial MFA setup
        generate_and_store_backup_codes(db, username)
        notify_service('USER_REGISTERED', f'User {username} registered.')

        session['username_for_mfa_setup'] = username
        session['email_for_mfa_setup'] = email
        return redirect(url_for('main.mfa_setup'))

    return render_template('setup.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /register with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']

            db = get_db()
            if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
                flash('Username already exists.', 'warning')
                log_event('USERNAME_EXISTS', f'Username {username} already exists', severity='WARNING')
                return redirect(url_for('main.register'))

            salt = generate_salt()
            password_hash = generate_password_hash(password)
            mfa_secret = pyotp.random_base32()

            db.execute('INSERT INTO users (username, password_hash, mfa_secret, encryption_salt) VALUES (?, ?, ?, ?)',
                    (username, password_hash, mfa_secret, salt.hex()))
            db.commit()

            session['username_for_mfa_setup'] = username
            session['email_for_mfa_setup'] = email
            
            log_event('USER_REGISTERED', f'New user registered with username {username}', severity='INFO')
            return redirect(url_for('main.mfa_setup'))
        except Exception as e:
            log_event('REGISTRATION_ERROR', f'Error during registration for username {username}: {e}', severity='ERROR')
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('main.register'))
    
    log_event('ACCESS_REGISTER_PAGE', 'Accessed registration page', severity='INFO')
    return render_template('register.html')

@main.route('/mfa-setup', methods=['GET'])
def mfa_setup():

    if request.method != 'GET':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /mfa-setup with non-GET method', severity='WARNING')
        return "Method not allowed 405", 405

    username = session.get('username_for_mfa_setup')
    email = session.get('email_for_mfa_setup')
    if not username or not email:
        return redirect(url_for('main.setup'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return redirect(url_for('main.setup'))

    totp = pyotp.TOTP(user['mfa_secret'])
    issuer = os.environ.get('TOTP_ISSUER') or 'SaltVault'
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name=issuer)
    
    qr = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    # Fetch unhashed codes from session (generated earlier), show once
    backup_codes = session.get('pending_backup_codes', [])
    return render_template('mfa_setup.html', qr_code=img_str, backup_codes=backup_codes)

@main.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    
    if request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /verify-mfa with non-POST method', severity='WARNING')
        return "Method not allowed 405", 405
    
    username = session.get('username_for_mfa_setup')
    if not username:
        return redirect(url_for('main.setup'))

    db = get_db()
    user_data = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    user = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], mfa_secret=user_data['mfa_secret'], salt=user_data['encryption_salt'])

    if pyotp.TOTP(user.mfa_secret).verify(request.form.get('totp')):
        login_user(user)
        # This is the first login, so we need the password to derive the key.
        # Since we don't have it, we can't derive the key yet.
        # We will derive it on the first "real" login.
        session.pop('username_for_mfa_setup', None)
        session.pop('email_for_mfa_setup', None)
        session.pop('pending_backup_codes', None)  # Remove codes so not shown again
        flash('MFA setup successful! Please log in to continue.', 'success')
        return redirect(url_for('main.login'))
    else:
        flash('Invalid TOTP.', 'danger')
        return redirect(url_for('main.mfa_setup'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /login with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    if current_user.is_authenticated:
        log_event('USER_ALREADY_LOGGED_IN', f'User {current_user.username} is already logged in, redirecting to index page', severity='INFO')
        return redirect(url_for('main.index_route'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user_data and check_password_hash(user_data['password_hash'], password):
            # Temporarily store password in session to derive key after MFA
            session['tmp_password'] = password
            session['username_for_login'] = username
            
            log_event('VALID_CREDENTIALS_ENTERED', f'User {username} credentials entered successfully', severity='INFO')
            
            return redirect(url_for('main.login_mfa'))
        else:
            flash('Invalid username or password.', 'danger')
            log_event('INVALID_LOGIN', f'Invalid login attempt for username {username}', severity='WARNING')
    
    return render_template('login.html')

@main.route('/login-mfa', methods=['GET', 'POST'])
def login_mfa():
    
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /login-mfa with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    if current_user.is_authenticated:
        log_event('USER_ALREADY_LOGGED_IN', f'User {current_user.username} is already logged in, redirecting to index page', severity='INFO')
        return redirect(url_for('main.index_route'))
    
    username = session.get('username_for_login')
    password = session.get('tmp_password')
    if not username or not password:
        log_event('MISSING_SESSION_DATA', 'Missing username or password in session during MFA login', severity='WARNING')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        db = get_db()
        user_data = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user_data and pyotp.TOTP(user_data['mfa_secret']).verify(request.form.get('totp')):
            user = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], mfa_secret=user_data['mfa_secret'], salt=user_data['encryption_salt'])
            login_user(user)
            
            # Derive and store key in session
            salt = bytes.fromhex(user.salt)
            key = derive_key(password, salt)
            session['key'] = key.hex()
            
            session.pop('username_for_login', None)
            session.pop('tmp_password', None)
            log_event('USER_LOGIN_SUCCESSFUL', f'User {username} logged in successfully with MFA', severity='INFO')
            
            return redirect(url_for('main.index_route'))
        else:
            log_event('INVALID_MFA', f'Invalid TOTP entered for username {username}', severity='WARNING')
            flash('Invalid TOTP.', 'danger')
    
    return render_template('login_mfa.html')

@main.route('/login-mfa-backup', methods=['GET', 'POST'])
def login_mfa_backup():
    if request.method != 'GET' and request.method != 'POST':
        return "Method not allowed 405", 405
    if current_user.is_authenticated:
        return redirect(url_for('main.index_route'))
    username = session.get('username_for_login')
    password = session.get('tmp_password')
    if not username or not password:
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        code_entered = request.form.get('backup_code', '').strip()
        if not code_entered:
            flash('Enter a backup code.', 'warning')
            return render_template('login_mfa_backup.html')
        db = get_db()
        user_data = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not user_data:
            flash('Invalid session.', 'danger')
            return redirect(url_for('main.login'))
        # Lookup unused codes
        rows = db.execute('SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = ? AND used = 0', (user_data['id'],)).fetchall()
        matched_id = None
        for r in rows:
            if check_password_hash(r['code_hash'], code_entered):
                matched_id = r['id']
                break
        if matched_id:
            # Mark used
            db.execute('UPDATE mfa_backup_codes SET used = 1 WHERE id = ?', (matched_id,))
            db.commit()
            user = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'], mfa_secret=user_data['mfa_secret'], salt=user_data['encryption_salt'])
            login_user(user)
            salt = bytes.fromhex(user.salt)
            key = derive_key(password, salt)
            session['key'] = key.hex()
            session.pop('username_for_login', None)
            session.pop('tmp_password', None)
            notify_service('LOGIN_BACKUP_CODE', f'User {username} used a backup code.')
            flash('Login successful (backup code).', 'success')
            return redirect(url_for('main.index_route'))
        else:
            flash('Invalid or used backup code.', 'danger')
    return render_template('login_mfa_backup.html')

@main.route('/logout')
@login_required
def logout():
    if request.method != 'GET':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /logout with non-GET method', severity='WARNING')
        return "Method not allowed 405", 405

    username = current_user.username
    logout_user()
    session.clear()
    flash('You have been logged out.', 'success')
    log_event('USER_LOGOUT', f'User {username} logged out', severity='INFO')
    return redirect(url_for('main.login'))

@main.route('/add-password', methods=['GET', 'POST'])
@login_required
def add_password():
    
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /add-password with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    key = get_key()
    if not key:
        log_event('MISSING_KEY', 'Encryption key missing in session during add-password', severity='ERROR')
        return redirect(url_for('main.logout'))

    if request.method == 'POST':
        try:
            encrypted_title = encrypt_data(key, request.form['title']).hex()
            encrypted_username = encrypt_data(key, request.form['username']).hex()
            encrypted_password = encrypt_data(key, request.form['password']).hex()
            encrypted_email = encrypt_data(key, request.form['email']).hex()
            encrypted_notes = encrypt_data(key, request.form['notes']).hex() if request.form['notes'] else None
            
            db = get_db()
            db.execute('INSERT INTO passwords (user_id, title, username, password, email, notes) VALUES (?, ?, ?, ?, ?, ?)',
                       (current_user.id, encrypted_title, encrypted_username, encrypted_password, encrypted_email, encrypted_notes))
            db.commit()
            log_event('PASSWORD_ADDED', f'User {current_user.username} added a new password entry titled {request.form["title"]}', severity='INFO')
            flash('Password added successfully.', 'success')
        except Exception as e:
            log_event('PASSWORD_ADD_ERROR', f'Error adding password for user {current_user.username}: {e}', severity='ERROR')
            flash(f'Error adding password: {e}', 'danger')
        return redirect(url_for('main.index_route'))
    return render_template('add_password.html')

@main.route('/view-password/<int:password_id>')
@login_required
def view_password(password_id):
    
    if request.method != 'GET':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /view-password with non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    key = get_key()
    if not key:
        log_event('MISSING_KEY', 'Encryption key missing in session during view-password', severity='ERROR')
        return jsonify({'error': 'Session expired'}), 401
    
    db = get_db()
    p_data = db.execute('SELECT password, notes FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id)).fetchone()
    
    if p_data:
        try:
            decrypted_password = decrypt_data(key, p_data['password'])
            decrypted_notes = decrypt_data(key, p_data['notes']) if p_data['notes'] else ''
            log_event('PASSWORD_VIEWED', f'User {current_user.username} viewed password ID {password_id}', severity='INFO')
            return jsonify({'password': decrypted_password, 'notes': decrypted_notes})
        except Exception:
            log_event('DECRYPTION_FAILED', f'Decryption failed for password ID {password_id} for user {current_user.username}', severity='ERROR')
            return jsonify({'error': 'Decryption failed'}), 500
    log_event('PASSWORD_NOT_FOUND', f'Password ID {password_id} not found for user {current_user.username}', severity='WARNING')
    return jsonify({'error': 'Password not found'}), 404

@main.route('/edit-password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def edit_password(password_id):
    
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /edit-password with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405
    
    key = get_key()
    if not key:
        log_event('MISSING_KEY', 'Encryption key missing in session during edit-password', severity='ERROR')
        return redirect(url_for('main.logout'))
    
    db = get_db()
    p_data = db.execute('SELECT * FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id)).fetchone()

    if not p_data:
        flash('Password not found.', 'danger')
        log_event('PASSWORD_NOT_FOUND', f'Password ID {password_id} not found for user {current_user.username}', severity='WARNING')
        return redirect(url_for('main.index_route'))

    try:
        decrypted_password = {
            'id': p_data['id'],
            'title': decrypt_data(key, p_data['title']),
            'username': decrypt_data(key, p_data['username']),
            'email': decrypt_data(key, p_data['email']),
            'notes': decrypt_data(key, p_data['notes']) if p_data['notes'] else ''
        }
    except Exception:
        log_event('DECRYPTION_FAILED', f'Could not decrypt password data for user {current_user.username} and password ID {password_id}', severity='ERROR')
        flash('Could not decrypt password data.', 'danger')
        return redirect(url_for('main.index_route'))

    if request.method == 'POST':
        try:
            new_title = encrypt_data(key, request.form['title']).hex()
            new_username = encrypt_data(key, request.form['username']).hex()
            new_email = encrypt_data(key, request.form['email']).hex()
            new_notes = encrypt_data(key, request.form['notes']).hex() if request.form['notes'] else None
            
            if request.form.get('password'):
                new_password = encrypt_data(key, request.form['password']).hex()
                db.execute('UPDATE passwords SET title=?, username=?, password=?, email=?, notes=? WHERE id=?',
                           (new_title, new_username, new_password, new_email, new_notes, password_id))
            else:
                db.execute('UPDATE passwords SET title=?, username=?, email=?, notes=? WHERE id=?',
                           (new_title, new_username, new_email, new_notes, password_id))
            db.commit()
            log_event('PASSWORD_EDITED', f'User {current_user.username} edited password ID {password_id}', severity='INFO')
            flash('Password updated successfully.', 'success')
        except Exception as e:
            log_event('PASSWORD_EDIT_ERROR', f'Error updating password ID {password_id} for user {current_user.username}: {e}', severity='ERROR')
            flash(f'Error updating password: {e}', 'danger')
        return redirect(url_for('main.index_route'))

    return render_template('edit_password.html', password=decrypted_password)

@main.route('/delete-password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    
    if request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /delete-password with non-POST method', severity='WARNING')
        return "Method not allowed 405", 405
    
    try:
        db = get_db()
        db.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (password_id, current_user.id))
        db.commit()
        log_event('PASSWORD_DELETED', f'User {current_user.username} deleted password ID {password_id}', severity='INFO')
        flash('Password deleted successfully.', 'success')
        return redirect(url_for('main.index_route'))
    except Exception as e:
        log_event('PASSWORD_DELETE_ERROR', f'Error deleting password ID {password_id} for user {current_user.username}: {e}', severity='ERROR')
        flash(f'Error deleting password: {e}', 'danger')
        return redirect(url_for('main.index_route'))

@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method != 'GET' and request.method != 'POST':
        log_event('METHOD_NOT_ALLOWED', 'Attempted to access /change-password with non-POST and non-GET method', severity='WARNING')
        return "Method not allowed 405", 405

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        new_password_confirm = request.form['confirm_password']
        
        if not check_password_hash(current_user.password_hash, old_password):
            flash('Incorrect old password.', 'danger')
            log_event('INCORRECT_OLD_PASSWORD', f'User {current_user.username} entered incorrect old password', severity='WARNING')
            return render_template('change_password.html')

        if new_password != new_password_confirm:
            flash('New password and confirmation do not match.', 'danger')
            log_event('PASSWORD_CONFIRMATION_MISMATCH', f'User {current_user.username} new password and confirmation do not match', severity='WARNING')
            return render_template('change_password.html')
        
        try:
            # Verify new password strength (example: at least 8 chars)
            if len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'danger')
                log_event('WEAK_NEW_PASSWORD', f'User {current_user.username} entered a weak new password', severity='WARNING')
                return render_template('change_password.html')
        except Exception as e:
            log_event('PASSWORD_CHANGE_ERROR', f'Error during password change for user {current_user.username}: {e}', severity='ERROR')
            flash(f'Error changing password: {e}', 'danger')
            return render_template('change_password.html')
        
        try:
            db = get_db()
            old_key = get_key()
        except Exception as e:
            log_event('KEY_RETRIEVAL_ERROR', f'Error retrieving encryption key for user {current_user.username}: {e}', severity='ERROR')
            flash(f'Error changing password: {e}', 'danger')
            return render_template('change_password.html')
        
        try:
            # Derive new key
            salt = bytes.fromhex(current_user.salt)
            new_key = derive_key(new_password, salt)
        except Exception as e:
            log_event('KEY_DERIVATION_ERROR', f'Error deriving new encryption key for user {current_user.username}: {e}', severity='ERROR')
            flash(f'Error changing password: {e}', 'danger')
            return render_template('change_password.html')
        
        # Re-encrypt all data
        passwords = db.execute('SELECT * FROM passwords WHERE user_id = ?', (current_user.id,)).fetchall()
        try:
            for p in passwords:
                decrypted_title = decrypt_data(old_key, p['title'])
                decrypted_username = decrypt_data(old_key, p['username'])
                decrypted_password = decrypt_data(old_key, p['password'])
                decrypted_email = decrypt_data(old_key, p['email'])
                decrypted_notes = decrypt_data(old_key, p['notes']) if p['notes'] else ''

                db.execute('UPDATE passwords SET title=?, username=?, password=?, email=?, notes=? WHERE id=?',
                           (encrypt_data(new_key, decrypted_title).hex(),
                            encrypt_data(new_key, decrypted_username).hex(),
                            encrypt_data(new_key, decrypted_password).hex(),
                            encrypt_data(new_key, decrypted_email).hex(),
                            encrypt_data(new_key, decrypted_notes).hex() if decrypted_notes else None,
                            p['id']))
            
            # Update master password hash and session key
            new_password_hash = generate_password_hash(new_password)
            db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, current_user.id))
            db.commit()
            
            session['key'] = new_key.hex()
            log_event('PASSWORD_CHANGED', f'User {current_user.username} changed their password and re-encrypted all data', severity='INFO')
            flash('Password changed and all data re-encrypted successfully.', 'success')
            notify_service('PASSWORD_CHANGED', f'User {current_user.username} changed master password.')
        except Exception as e:
            log_event('RE_ENCRYPTION_ERROR', f'Error re-encrypting data during password change for user {current_user.username}: {e}', severity='ERROR')
            db.rollback()
            flash(f'An error occurred during re-encryption: {e}', 'danger')

        return redirect(url_for('main.index_route'))
        
    return render_template('change_password.html')

@main.route('/export', methods=['GET', 'POST'])
@login_required
def export_passwords():
    if request.method == 'GET':
        log_event('ACCESS_EXPORT_PAGE', f'User {current_user.username} accessed export page', severity='INFO')
        return render_template('export.html')

    password = request.form.get('password')
    totp_code = request.form.get('totp')

    # Re-authenticate user
    if not check_password_hash(current_user.password_hash, password):
        flash('Invalid password.', 'danger')
        log_event('EXPORT_INVALID_PASSWORD', f'User {current_user.username} entered incorrect password for export', severity='WARNING')
        return redirect(url_for('main.export_passwords'))

    if not pyotp.TOTP(current_user.mfa_secret).verify(totp_code):
        flash('Invalid MFA code.', 'danger')
        log_event('EXPORT_INVALID_MFA', f'User {current_user.username} entered incorrect MFA for export', severity='WARNING')
        return redirect(url_for('main.export_passwords'))

    # Fetch and decrypt data
    key = get_key()
    if not key:
        return redirect(url_for('main.logout'))

    db = get_db()
    encrypted_passwords = db.execute('SELECT * FROM passwords WHERE user_id = ?', (current_user.id,)).fetchall()
    
    # Create CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['name', 'login_username', 'login_password', 'login_uri', 'notes'])

    for p in encrypted_passwords:
        try:
            writer.writerow([
                decrypt_data(key, p['title']),
                decrypt_data(key, p['username']),
                decrypt_data(key, p['password']),
                decrypt_data(key, p['email']),
                decrypt_data(key, p['notes']) if p['notes'] else ''
            ])
        except Exception:
            # Skip corrupted data
            log_event('EXPORT_DECRYPTION_ERROR', f'Failed to decrypt password ID {p["id"]} during export for user {current_user.username}', severity='ERROR')
            pass
            
    output.seek(0)
    
    log_event('PASSWORDS_EXPORTED', f'User {current_user.username} exported their passwords', severity='INFO')
    notify_service('PASSWORDS_EXPORTED', f'User {current_user.username} exported passwords.')

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=saltvault_export.csv"}
    )

# Password utilities API
@main.route('/generate-password', methods=['POST'])
def api_generate_password():
    try:
        data = request.get_json(force=True) or {}
        length = int(data.get('length', 16))
        uppercase = bool(data.get('uppercase', True))
        numbers = bool(data.get('numbers', True))
        symbols = bool(data.get('symbols', True))
        pwd = generate_password(length=length, use_uppercase=uppercase, use_numbers=numbers, use_symbols=symbols)
        return jsonify({'password': pwd})
    except Exception as e:
        log_event('GENERATE_PASSWORD_ERROR', f'Error generating password: {e}', severity='ERROR')
        return jsonify({'error': 'Failed to generate password'}), 400

@main.route('/strengthen-password', methods=['POST'])
def api_strengthen_password():
    try:
        data = request.get_json(force=True) or {}
        pwd = data.get('password', '')
        stronger = strengthen_password(pwd)
        return jsonify({'password': stronger})
    except Exception as e:
        log_event('STRENGTHEN_PASSWORD_ERROR', f'Error strengthening password: {e}', severity='ERROR')
        return jsonify({'error': 'Failed to strengthen password'}), 400

@main.route('/check-password-strength', methods=['POST'])
def api_check_password_strength():
    try:
        data = request.get_json(force=True) or {}
        pwd = data.get('password', '')
        score = check_password_strength(pwd)
        return jsonify({'strength': score})
    except Exception as e:
        log_event('CHECK_PASSWORD_STRENGTH_ERROR', f'Error checking password strength: {e}', severity='ERROR')
        return jsonify({'error': 'Failed to check strength'}), 400

@main.route('/import', methods=['GET', 'POST'])
@login_required
def import_passwords():
    if request.method == 'GET':
        log_event('ACCESS_IMPORT_PAGE', f'User {current_user.username} accessed import page', severity='INFO')
        return render_template('import.html')

    file = request.files.get('csv_file')
    if not file or file.filename.strip() == '':
        flash('No file selected.', 'warning')
        log_event('IMPORT_NO_FILE', f'User {current_user.username} submitted import without file', severity='WARNING')
        return redirect(url_for('main.import_passwords'))

    if not (file.filename.lower().endswith('.csv')):
        flash('Only .csv files are supported for import currently.', 'danger')
        log_event('IMPORT_UNSUPPORTED_EXTENSION', f'User {current_user.username} attempted import with file {file.filename}', severity='WARNING')
        return redirect(url_for('main.import_passwords'))

    try:
        key = get_key()
        if not key:
            return redirect(url_for('main.logout'))
        file.stream.seek(0)
        decoded = file.stream.read().decode('utf-8', errors='replace')
        stream = io.StringIO(decoded)
        reader = csv.DictReader(stream)
        db = get_db()
        row_count = 0
        for row in reader:
            if not any(row.values()):
                continue
            title = row.get('name', '')
            username = row.get('login_username', '')
            password_val = row.get('login_password', '')
            email_or_uri = row.get('login_uri', '')
            notes = row.get('notes', '')
            enc_title = encrypt_data(key, title).hex()
            enc_username = encrypt_data(key, username).hex()
            enc_password = encrypt_data(key, password_val).hex()
            enc_email = encrypt_data(key, email_or_uri).hex()
            enc_notes = encrypt_data(key, notes).hex() if notes else None
            db.execute('INSERT INTO passwords (user_id, title, username, password, email, notes) VALUES (?, ?, ?, ?, ?, ?)',
                       (current_user.id, enc_title, enc_username, enc_password, enc_email, enc_notes))
            row_count += 1
        if row_count == 0:
            flash('No rows found in CSV.', 'warning')
            log_event('IMPORT_EMPTY_FILE', f'User {current_user.username} uploaded empty CSV', severity='WARNING')
            return redirect(url_for('main.import_passwords'))
        db.commit()
        flash('Passwords imported successfully.', 'success')
        log_event('PASSWORDS_IMPORTED', f'User {current_user.username} imported passwords from CSV', severity='INFO')
        notify_service('PASSWORDS_IMPORTED', f'User {current_user.username} imported passwords.')
        return redirect(url_for('main.index_route'))
    except Exception as e:
        log_event('IMPORT_ERROR', f'Error importing passwords for user {current_user.username}: {e}', severity='ERROR')
        flash(f'Error importing passwords: {e}', 'danger')
        return redirect(url_for('main.import_passwords'))

def generate_and_store_backup_codes(db, username, count=10, length=10):
    user_row = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if not user_row:
        return []
    user_id = user_row['id']
    codes = []
    charset = string.ascii_uppercase + string.digits
    for _ in range(count):
        code = ''.join(random.choice(charset) for _ in range(length))
        codes.append(code)
        db.execute('INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)', (user_id, generate_password_hash(code)))
    db.commit()
    session['pending_backup_codes'] = codes
    notify_service('BACKUP_CODES_GENERATED', f'User {username} generated new backup codes.')
    return codes

@main.route('/settings', methods=['GET'])
@login_required
def settings():
    db = get_db()
    unused_count = db.execute('SELECT COUNT(id) FROM mfa_backup_codes WHERE user_id = ? AND used = 0', (current_user.id,)).fetchone()[0]
    discord_configured = bool(os.environ.get('DISCORD_WEBHOOK_URL'))
    prefs = db.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (current_user.id,)).fetchone()
    if not prefs:
        db.execute('INSERT INTO notification_preferences (user_id) VALUES (?)', (current_user.id,))
        db.commit()
        prefs = db.execute('SELECT * FROM notification_preferences WHERE user_id = ?', (current_user.id,)).fetchone()
    return render_template('settings.html', unused_backup_codes=unused_count, discord_configured=discord_configured, notification_prefs=prefs)

@main.route('/settings/regenerate-backup-codes', methods=['POST'])
@login_required
def regenerate_backup_codes():
    db = get_db()
    db.execute('DELETE FROM mfa_backup_codes WHERE user_id = ? AND used = 0', (current_user.id,))
    db.commit()
    generate_and_store_backup_codes(db, current_user.username)
    flash('New backup codes generated. Save them now – they will not be shown again.', 'success')
    return redirect(url_for('main.show_new_backup_codes'))

@main.route('/settings/show-backup-codes', methods=['GET'])
@login_required
def show_new_backup_codes():
    codes = session.get('pending_backup_codes', [])
    if not codes:
        flash('No new backup codes to display.', 'warning')
        return redirect(url_for('main.settings'))
    return render_template('settings.html', display_backup_codes=codes, unused_backup_codes=len(codes))

@main.route('/settings/regenerate-mfa', methods=['POST'])
@login_required
def regenerate_mfa():
    password = request.form.get('password')
    totp_code = request.form.get('totp')
    backup_code = request.form.get('backup_code')
    if not check_password_hash(current_user.password_hash, password):
        flash('Invalid password.', 'danger')
        return redirect(url_for('main.settings'))
    db = get_db()
    user_data = db.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    totp_valid = False
    if totp_code and pyotp.TOTP(user_data['mfa_secret']).verify(totp_code):
        totp_valid = True
    elif backup_code:
        rows = db.execute('SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = ? AND used = 0', (current_user.id,)).fetchall()
        for r in rows:
            if check_password_hash(r['code_hash'], backup_code.strip()):
                db.execute('UPDATE mfa_backup_codes SET used = 1 WHERE id = ?', (r['id'],))
                db.commit()
                totp_valid = True
                notify_service('BACKUP_CODE_USED_MFA_RESET', f'User {current_user.username} used backup code to reset MFA.')
                break
    if not totp_valid:
        flash('MFA verification failed (provide current TOTP or a valid backup code).', 'danger')
        return redirect(url_for('main.settings'))
    new_secret = pyotp.random_base32()
    db.execute('UPDATE users SET mfa_secret = ? WHERE id = ?', (new_secret, current_user.id))
    db.commit()
    generate_and_store_backup_codes(db, current_user.username)
    flash('MFA secret regenerated. Scan new QR and store new backup codes.', 'success')
    notify_service('MFA_REGENERATED', f'User {current_user.username} regenerated MFA secret.')
    return redirect(url_for('main.settings'))

def _update_env_variable(var: str, value: str):
    env_file = Path('app/app.env')
    if not env_file.is_file():
        return False
    lines = env_file.read_text().splitlines()
    found = False
    for i, line in enumerate(lines):
        if line.startswith(var + '='):
            lines[i] = f'{var}={value}'
            found = True
            break
    if not found:
        lines.append(f'{var}={value}')
    env_file.write_text('\n'.join(lines) + '\n')
    return True

def _send_discord_test(webhook: str, message: str):
    try:
        data = pyjson.dumps({"content": message}).encode('utf-8')
        req = urllib.request.Request(webhook, data=data, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=5)
        return True
    except Exception as e:
        log_event('DISCORD_TEST_FAILED', f'Failed to send Discord test message. Error: {e}', severity='ERROR')
        return False

@main.route('/settings/update-discord', methods=['POST'])
@login_required
def update_discord():
    password = request.form.get('password')
    webhook = request.form.get('discord_webhook', '').strip()
    if not check_password_hash(current_user.password_hash, password):
        flash('Invalid password.', 'danger')
        return redirect(url_for('main.settings'))
    if not webhook.startswith('https://') or 'discord.com/api/webhooks' not in webhook:
        flash('Invalid Discord webhook URL.', 'danger')
        return redirect(url_for('main.settings'))
    os.environ['DISCORD_WEBHOOK_URL'] = webhook
    saved = _update_env_variable('DISCORD_WEBHOOK_URL', webhook)
    if _send_discord_test(webhook, f"Discord webhook configured for user {current_user.username}."):
        flash('Discord webhook saved and test message sent.', 'success')
        notify_service('DISCORD_CONFIGURED', f'User {current_user.username} configured Discord webhook.')
    else:
        flash('Webhook saved but test message failed.', 'warning')
    if not saved:
        flash('Environment file not found; webhook active only for current process.', 'warning')
    return redirect(url_for('main.settings'))

@main.route('/settings/test-discord', methods=['POST'])
@login_required
def test_discord():
    webhook = os.environ.get('DISCORD_WEBHOOK_URL')
    if not webhook:
        flash('No Discord webhook configured.', 'warning')
        return redirect(url_for('main.settings'))
    if _send_discord_test(webhook, f"Test notification from user {current_user.username}."):
        flash('Test notification sent.', 'success')
    else:
        flash('Failed to send test notification.', 'danger')
    return redirect(url_for('main.settings'))

@main.route('/settings/update-notification-prefs', methods=['POST'])
@login_required
def update_notification_prefs():
    db = get_db()
    # Checkbox values present means enabled
    def val(name):
        return 1 if request.form.get(name) == 'on' else 0
    cols = {
        'discord_login': val('discord_login'),
        'discord_import_export': val('discord_import_export'),
        'discord_deletion': val('discord_deletion'),
        'discord_security': val('discord_security'),
        'email_login': val('email_login'),
        'email_import_export': val('email_import_export'),
        'email_deletion': val('email_deletion'),
        'email_security': val('email_security'),
    }
    exists = db.execute('SELECT user_id FROM notification_preferences WHERE user_id = ?', (current_user.id,)).fetchone()
    if exists:
        db.execute('UPDATE notification_preferences SET discord_login=?, discord_import_export=?, discord_deletion=?, discord_security=?, email_login=?, email_import_export=?, email_deletion=?, email_security=? WHERE user_id=?', (
            cols['discord_login'], cols['discord_import_export'], cols['discord_deletion'], cols['discord_security'], cols['email_login'], cols['email_import_export'], cols['email_deletion'], cols['email_security'], current_user.id
        ))
    else:
        db.execute('INSERT INTO notification_preferences (user_id, discord_login, discord_import_export, discord_deletion, discord_security, email_login, email_import_export, email_deletion, email_security) VALUES (?,?,?,?,?,?,?,?,?)', (
            current_user.id, cols['discord_login'], cols['discord_import_export'], cols['discord_deletion'], cols['discord_security'], cols['email_login'], cols['email_import_export'], cols['email_deletion'], cols['email_security']
        ))
    db.commit()
    flash('Notification preferences updated.', 'success')
    return redirect(url_for('main.settings'))
