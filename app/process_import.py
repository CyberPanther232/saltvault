from datetime import datetime

# Acceptable imports
ACCEPTED_IMPORT_ORIGINS = ['Bitwarden', 'NordPass']

def detect_import_origin(file: str) -> str:
    """Detect the origin of the import based on the file name or path."""
    file_lower = file.lower()
    if 'keepass' in file_lower:
        return 'Keepass'
    elif '1password' in file_lower or '1pif' in file_lower:
        return '1Password'
    elif 'lastpass' in file_lower:
        return 'LastPass'
    elif 'bitwarden' in file_lower:
        return 'Bitwarden'
    elif 'dashlane' in file_lower:
        return 'Dashlane'
    else:
        return 'Unknown'
    
def process_bitwarden_import(file: str) -> list:
    """Process Bitwarden import data and return a list of entries."""
    entries = []
    
    if file.endswith('.json'):
        with open(file, 'r', encoding='utf-8') as f:
            data = f.read()
        try:
            items = json.loads(data)
            for item in items:
                entry = {
                    'name': item.get('name', ''),
                    'username': item.get('login', {}).get('username', ''),
                    'password': item.get('login', {}).get('password', ''),
                    'url': item.get('login', {}).get('uris', [''])[0],
                    'notes': item.get('notes', '')
                }
                entries.append(entry)
        except json.JSONDecodeError:
            pass  # Handle error as needed

        return entries

    if file.endswith('.csv'):
        with open(file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                entry = {
                    'created': datetime.strptime('%Y-%m-%dT%H:%M:%S'),
                    'title': row.get('name', ''),
                    'username': row.get('login_username', ''),
                    'email': row.get('login_email', '') if 'login_email' in row else '',
                    'password': row.get('login_password', ''),
                    'notes': row.get('notes', '')
                }
                entries.append(entry)
        return entries
    
def process_nordpass_import(file: str) -> list:
    """Process NordPass import data and return a list of entries."""
    entries = []
    
    with open(file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            entry = {
                'name': row.get('Title', ''),
                'username': row.get('Login', ''),
                'password': row.get('Password', ''),
                'url': row.get('URL', ''),
                'notes': row.get('Notes', '')
            }
            entries.append(entry)
    
    return entries