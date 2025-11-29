import random
import string

def generate_password(length, use_uppercase, use_numbers, use_symbols):
    """Generate a random password based on criteria."""
    character_set = string.ascii_lowercase
    if use_uppercase:
        character_set += string.ascii_uppercase
    if use_numbers:
        character_set += string.digits
    if use_symbols:
        character_set += string.punctuation

    if not character_set:
        return ''

    return ''.join(random.choice(character_set) for _ in range(length))

def check_password_strength(password):
    """Check the strength of a password and return a score from 0 to 4."""
    score = 0
    if len(password) >= 8:
        score += 1
    if any(char.islower() for char in password) and any(char.isupper() for char in password):
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1
    
    if len(password) >= 12 and score >= 3:
        score = 4
        
    return score

def strengthen_password(password):
    """Strengthen a password by adding missing character types."""
    if not any(char.islower() for char in password):
        password += random.choice(string.ascii_lowercase)
    if not any(char.isupper() for char in password):
        password += random.choice(string.ascii_uppercase)
    if not any(char.isdigit() for char in password):
        password += random.choice(string.digits)
    if not any(char in string.punctuation for char in password):
        password += random.choice(string.punctuation)
    
    while len(password) < 12:
        password += random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation)
        
    # Shuffle the password to make it more random
    password_list = list(password)
    random.shuffle(password_list)
    return "".join(password_list)