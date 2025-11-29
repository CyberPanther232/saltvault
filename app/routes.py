import os
import csv
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from .init_db import get_db
from .models import User
from .nacl_tools import encrypt_data, decrypt_data, derive_key, generate_salt
from .logging_functions import get_logger, log_event
from .password_generator import generate_password, strengthen_password, check_password_strength
from .quotes import quotes
import random

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

    encrypted_passwords = db.execute('SELECT * FROM passwords WHERE user_id = ?', (current_user.id,)).fetchall()
    passwords = []
    for p in encrypted_passwords:
        try:
            passwords.append({
                'id': p['id'],
                'title': decrypt_data(key, p['title']),
                'username': decrypt_data(key, p['username']),
                'email': decrypt_data(key, p['email']),
                'notes': decrypt_data(key, p['notes']) if p['notes'] else '',
                'password': '**********',
            })
        except Exception:
            log_event('DECRYPTION_ERROR', f'Failed to decrypt password ID {p["id"]} for user ID {current_user.id}', severity='ERROR')
            pass
    
    random_quote = random.choice(quotes)
    
    return render_template('index.html', passwords=passwords, quote=random_quote)

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
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name='SaltVault')
    
    qr = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('mfa_setup.html', qr_code=img_str)

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
        flash('Setup complete! Please log in to continue.', 'success')
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
        
        if not check_password_hash(current_user.password_hash, old_password):
            flash('Incorrect old password.', 'danger')
            log_event('INCORRECT_OLD_PASSWORD', f'User {current_user.username} entered incorrect old password', severity='WARNING')
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

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=saltvault_export.csv"}
    )
