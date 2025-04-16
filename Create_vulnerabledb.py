import sqlite3

conn = sqlite3.connect('vulnerable.db')
cursor = conn.cursor()

# Create table for users
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
''')

# Insert a test user (admin)
cursor.execute('''
    INSERT INTO users (username, password)
    VALUES ('admin', 'admin123')
''')

conn.commit()
conn.close()
