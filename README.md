# Flask Vulnerable Web Application

This repository contains a vulnerable Flask web application, designed for educational purposes to help beginners understand and learn about web application security vulnerabilities. Each vulnerability is carefully crafted and can be exploited, allowing users to test and experiment with tools such as **Burp Suite** or **OWASP ZAP**.

The vulnerabilities are based on the [OWASP Top 10](https://owasp.org/www-project-top-ten/) most common web security issues.

---

## Table of Contents

- [How to Run the Application](#how-to-run-the-application)
- [1. SQL Injection Vulnerability](#1-sql-injection-vulnerability)
- [2. Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
- [3. Cross-Site Request Forgery (CSRF)](#3-cross-site-request-forgery-csrf)
- [4. Insecure Direct Object References (IDOR)](#4-insecure-direct-object-references-idor)
- [5. Insecure File Uploads](#5-insecure-file-uploads)
- [6. Insecure Password Storage](#6-insecure-password-storage)
- [7. How to Exploit the Vulnerabilities](#how-to-exploit-the-vulnerabilities)
- [License](#license)

---

## How to Run the Application

### Step 1: Install Dependencies

Install the required Python libraries by running the following command:

pip install -r requirements.txt

This will install all the necessary dependencies for the Flask app.

### Step 2: Set Up the Database

Run the following Python script to set up the database (vulnerable.db):

import sqlite3

conn = sqlite3.connect('vulnerable.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
''')

cursor.execute('''
    INSERT INTO users (username, password)
    VALUES ('admin', 'admin123')
''')

conn.commit()
conn.close()

This script creates a SQLite database and adds a vulnerable user with username: admin and password: admin123.

### Step 3: Run the Flask App

To run the Flask application, use the following command:

python app.py

By default, the app will run on http://localhost:5000.

Once the server is up and running, you can navigate to the following URL in your browser:

http://localhost:5000

#### 1. SQL Injection Vulnerability
Vulnerability Overview

SQL Injection (SQLi) occurs when an attacker can manipulate an SQL query by injecting malicious input. In this application, this happens in the login route, where user inputs are directly inserted into an SQL query without sanitization.

cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")

##### How to Exploit It

To exploit this vulnerability, an attacker could enter the following in the username and password fields:

    Username: admin' OR '1'='1

    Password: anything

This results in the following query:

SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'

Since '1'='1' is always true, the attacker could bypass authentication.

##### How to Prevent It

    Use parameterized queries to prevent SQL injection:

cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))

### 2. Cross-Site Scripting (XSS)
#### Vulnerability Overview

Cross-Site Scripting (XSS) occurs when an attacker injects malicious scripts into web pages. In this case, the application is vulnerable in the search route, where user input is reflected directly in the response without sanitization.

query = request.args.get('query', '')
return f"Search results for: {query}"

#### How to Exploit It

An attacker could craft the following URL to execute JavaScript in the victim’s browser:

http://localhost:5000/search?query=<script>alert('XSS')</script>

This will display an alert box in the victim’s browser.
#### How to Prevent It

    Use escaping to prevent HTML tags from being interpreted:

from flask import escape
query = escape(request.args.get('query', ''))
return f"Search results for: {query}"

### 3. Cross-Site Request Forgery (CSRF)
#### Vulnerability Overview

CSRF occurs when an attacker tricks a user into making a request on their behalf. The submit route in this application is vulnerable to CSRF attacks because it doesn't use a CSRF token.

@app.route('/submit', methods=['POST'])
def submit():
    message = request.form['message']
    return f"Message received: {message}"

#### How to Exploit It

An attacker could create a hidden form on their website that submits a request to the vulnerable submit endpoint. When the victim visits the attacker’s page while logged in, their session will submit the form automatically.

#### How to Prevent It

    Use CSRF Tokens to verify the authenticity of the request:

from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

### 4. Insecure Direct Object References (IDOR)
#### Vulnerability Overview

IDOR occurs when an attacker can access or modify data that they shouldn’t be able to by manipulating identifiers. In the vulnerable application, any authenticated user can access the /admin route without proper authorization.

@app.route('/admin')
def admin():
    if 'user' in session:
        return render_template('admin.html')
    return redirect(url_for('login'))

#### How to Exploit It

An attacker can simply visit the /admin route, and if logged in, they can view or modify admin data without proper role checks.
How to Prevent It

    Implement Role-Based Access Control (RBAC) to restrict access to sensitive routes:

@app.route('/admin')
def admin():
    if 'user' in session and session['user'] == 'admin':
        return render_template('admin.html')
    return "Access denied", 403

### 5. Insecure File Uploads
#### Vulnerability Overview

Insecure file uploads occur when users are allowed to upload files without proper validation. In this app, files are saved directly to the server without checking the file type.

file.save(os.path.join('uploads', file.filename))

#### How to Exploit It

An attacker could upload a malicious file (e.g., a PHP web shell) and execute it on the server.
#### How to Prevent It

    Validate file types before accepting uploads. Only allow certain file types (e.g., images):

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if file and allowed_file(file.filename):
    file.save(os.path.join('uploads', file.filename))
else:
    return "Invalid file type", 400

### 6. Insecure Password Storage
Vulnerability Overview

Insecure password storage occurs when passwords are stored in plaintext, making them vulnerable if an attacker gains access to the database.

cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))

#### How to Exploit It

An attacker with access to the database could view or extract passwords in plaintext.
#### How to Prevent It

    Hash passwords using a strong hashing algorithm like bcrypt before storing them:

import bcrypt

hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))

### 7. How to Exploit the Vulnerabilities

    SQL Injection: Try logging in with the following input:

        Username: admin' OR '1'='1

        Password: anything

    XSS: Inject the following in the search URL:

        URL: http://localhost:5000/search?query=<script>alert('XSS')</script>

    CSRF: Visit a page that contains a malicious form that submits a POST request to /submit.

    IDOR: Try accessing the /admin route as a normal user.

    File Upload: Upload a file without restrictions to see how it behaves.

    Password Storage: If you have access to the database, view the stored passwords.

