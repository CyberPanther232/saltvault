from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id, username, password_hash, mfa_secret, salt):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.mfa_secret = mfa_secret
        self.salt = salt