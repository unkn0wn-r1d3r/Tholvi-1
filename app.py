from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import sqlite3
import os
import hashlib

app = Flask(__name__)

# Secret key for session (insecure, for demonstration)
app.secret_key = "insecurekey"  # Should be changed in production

# Insecure Database (No password hashing, etc.)
DB_FILE = "vulnerable.db"

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # SQL Injection Vulnerability
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")  # SQL Injection!
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user'] = username  # Storing the username in the session
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials", 401

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome to the dashboard, {session['user']}!"
    return redirect(url_for('login'))


@app.route('/search', methods=['GET'])
def search():
    # Cross-Site Scripting (XSS) Vulnerability
    query = request.args.get('query', '')
    return f"Search results for: {query}"  # Unescaped user input

@app.route('/submit', methods=['POST'])
def submit():
    # Cross-Site Request Forgery (CSRF) Vulnerability
    # Missing CSRF protection
    message = request.form['message']
    return f"Message received: {message}"

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Weak Password Storage Vulnerability (No hashing, storing plaintext passwords)
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return "User created successfully"

    return render_template('signup.html')


@app.route('/file_upload', methods=['POST'])
def file_upload():
    # Insecure File Upload Vulnerability
    file = request.files['file']
    file.save(os.path.join('uploads', file.filename))  # No validation of file type/extension

    return "File uploaded successfully!"

@app.route('/admin')
def admin():
    # Insecure Direct Object References (IDOR)
    # Admin data exposed without proper authorization
    if 'user' in session:
        return render_template('admin.html')
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
