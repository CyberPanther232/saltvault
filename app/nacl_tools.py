import os
from nacl.pwhash import argon2id
from nacl.secret import SecretBox
from nacl.utils import random

# KDF configuration
SALT_SIZE = 16
OPS_LIMIT = 2
MEM_LIMIT = 67108864  # 64MB

def generate_salt():
    """Generate a random salt."""
    return random(SALT_SIZE)

def derive_key(password, salt):
    """Derive a key from a password and salt using Argon2."""
    if not isinstance(password, bytes):
        password = password.encode()
    return argon2id.kdf(SecretBox.KEY_SIZE, password, salt, opslimit=OPS_LIMIT, memlimit=MEM_LIMIT)

def encrypt_data(key, data):
    """Encrypt data using the derived key."""
    if not isinstance(data, bytes):
        data = data.encode()
    box = SecretBox(key)
    nonce = random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(data, nonce)
    # The nonce is prepended to the ciphertext.
    return encrypted

def decrypt_data(key, encrypted_data):
    """Decrypt data using the derived key."""
    if isinstance(encrypted_data, str):
        encrypted_data = bytes.fromhex(encrypted_data)
    box = SecretBox(key)
    decrypted = box.decrypt(encrypted_data)
    return decrypted.decode()