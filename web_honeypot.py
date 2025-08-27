# -------------------------------
# 📦 Imports & Setup
# -------------------------------
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps
import bcrypt
import re
from datetime import datetime
import os
import json

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret")  # 🔐 Load secret from env

# Paths
TRUSTED_USER_FILE = 'trusted_users.json'
TRUSTED_LOG_FILE = 'trusted_users.log'

# -------------------------------
# 📜 Logging Configuration
# -------------------------------
logging_format = logging.Formatter('%(asctime)s %(message)s')
http_logger = logging.getLogger('HTTPLogger')
http_logger.setLevel(logging.INFO)
http_handler = RotatingFileHandler('http_audits.log', maxBytes=2000, backupCount=5)
http_handler.setFormatter(logging_format)
http_logger.addHandler(http_handler)

# -------------------------------
# 🧠 Trusted Users & Session Tracking
# -------------------------------
trusted_users = {}  # username → hashed password
if os.path.exists(TRUSTED_USER_FILE):
    with open(TRUSTED_USER_FILE, 'r') as f:
        trusted_users = json.load(f)
session_states = {}  # IP → session info (trusted / logging)

# -------------------------------
# 🕵️ Suspicious Input Detection
# -------------------------------
def is_suspicious_input(value):
    keywords = {"admin", "administrator", "root", "test", "password", "admin_safe"}
    if value.lower() in keywords:
        return True
    payloads = [
        r"(\'|--|\bOR\b|\bAND\b)",     # SQLi
        r"<script.*?>",                # XSS
        r"(curl|wget|sqlmap|nmap)",    # Recon tools
        r"\.php|\.exe|\.sh|\.zip"      # Suspicious uploads
    ]
    return any(re.search(p, value, re.IGNORECASE) for p in payloads)

# -------------------------------
# 🔐 Login Required Decorator
# -------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if username and username in trusted_users:
            return f(*args, **kwargs)
        return redirect(url_for('signup'))
    return decorated_function

# -------------------------------
# 📊 Conditional Logging Logic
# -------------------------------
def should_log_request(ip, username, suspicious):
    if ip not in session_states:
        session_states[ip] = {
            "trusted": username.lower() in trusted_users,
            "is_logging": False
        }
    session = session_states[ip]
    if session["trusted"] and not suspicious:
        return False
    if suspicious:
        session["is_logging"] = True
    return session["is_logging"]

# -------------------------------
# 🌐 Routes
# -------------------------------
@app.route('/')
def index():
    return render_template_string("""
        <h2>Web Honeypot Login</h2>
        <form method="POST" action="{{ url_for('login') }}">
            <input name="username" placeholder="Username" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <p>Or <a href="{{ url_for('signup') }}">Sign up</a></p>
    """)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').lower()
        password = request.form.get('password', '')

        if username in trusted_users:
            return "❌ Username already exists."

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        trusted_users[username] = hashed
        with open(TRUSTED_USER_FILE, 'w') as f:
            json.dump(trusted_users, f, indent=2)
        with open(TRUSTED_LOG_FILE, 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} - New trusted user created: {username}\n")

        session['username'] = username
        return redirect(url_for('upload'))

    return render_template_string("""
        <h2>Create Trusted User</h2>
        <form method="POST">
            <input name="username" required><br>
            <input name="password" type="password" required><br>
            <button type="submit">Create</button>
        </form>
    """)

@app.route('/auth-admin-login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr
    ua = request.headers.get('User-Agent', 'Unknown')
    suspicious = is_suspicious_input(username) or is_suspicious_input(password)

    stored_hash = trusted_users.get(username.lower())
    is_trusted = stored_hash and bcrypt.checkpw(password.encode(), stored_hash.encode())
    if is_trusted:
        session['username'] = username.lower()

    if should_log_request(ip_address, username, suspicious or not is_trusted):
        http_logger.info(f'[WEB LOGIN TRAP] IP: {ip_address}, UA: {ua} | Username: {username}, Password: {password}')

    return render_template_string("""
        <h2>Welcome, {{ username }}</h2>
        <p>Login successful. Redirecting to dashboard...</p>
    """, username=username)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    return "Welcome to the Upload Trap 🔥"

# -------------------------------
#🍯🌐 Web Honeypot Runner
# -------------------------------
def run_web_honeypot(port=5000, input_username='admin', input_password='password'):
    if input_username.lower() not in trusted_users:
        hashed = bcrypt.hashpw(input_password.encode(), bcrypt.gensalt()).decode()
        trusted_users[input_username.lower()] = hashed
        with open(TRUSTED_USER_FILE, 'w') as f:
            json.dump(trusted_users, f, indent=2)
        with open(TRUSTED_LOG_FILE, 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} - Startup trusted user added: {input_username.lower()}\n")

    app.run(debug=True, port=port, host='0.0.0.0')

# -------------------------------
# 🚀 Run the App
# -------------------------------
if __name__ == "__main__":
    run_web_honeypot()

