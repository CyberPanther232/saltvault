import sqlite3
import os

# Assuming the database is in the 'instance' folder, a common Flask pattern.
db_path = os.path.join('app', 'data', 'dev_database.db')

if not os.path.exists(db_path):
    print(f"Error: Database file not found at {db_path}")
else:
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        
        # Check if the column already exists
        cur.execute("PRAGMA table_info(passwords)")
        columns = [info[1] for info in cur.fetchall()]
        
        if 'url' not in columns:
            print("Adding 'url' column to 'passwords' table...")
            cur.execute("ALTER TABLE passwords ADD COLUMN url TEXT")
            con.commit()
            print("Column 'url' added successfully.")
        else:
            print("Column 'url' already exists.")
            
        con.close()
    except Exception as e:
        print(f"An error occurred: {e}")
