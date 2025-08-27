"""
web_honeypot.py - Flask-based HTTP Honeypot
Tracks suspicious logins and fake admin pages.
"""

from flask import Flask, render_template, request, redirect, url_for, render_template_string, session
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import bcrypt
import json
import os
from datetime import datetime
import re

app = Flask(__name__)
app.secret_key = 'replace_with_random_secret'

TRUSTED_USER_FILE = 'trusted_users.json'
TRUSTED_LOG_FILE = 'trusted_users.log'

# Logging
logging_format = logging.Formatter('%(asctime)s %(message)s')
funnel_logger = logging.getLogger('HTTPLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Trusted users
trusted_users = {}
if os.path.exists(TRUSTED_USER_FILE):
    with open(TRUSTED_USER_FILE, 'r') as f:
        trusted_users = json.load(f)
session_states = {}

# Suspicious input detection
def is_suspicious_input(value):
    keywords = {"admin", "administrator", "root", "test", "password"}
    if value.lower() in keywords:
        return True
    payloads = [r"(\'|--|\bOR\b|\bAND\b)", r"<script.*?>", r"(curl|wget|sqlmap|nmap)", r"\.php|\.exe|\.sh|\.zip"]
    return any(re.search(p, value, re.IGNORECASE) for p in payloads)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('username') in trusted_users:
            return f(*args, **kwargs)
        return redirect(url_for('signup'))
    return decorated

@app.route('/')
def index():
    return render_template_string("<h2>Welcome to Honeypot Admin</h2>")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').lower()
        password = request.form.get('password', '')

        if username in trusted_users:
            return "Username already exists."
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        trusted_users[username] = hashed

        with open(TRUSTED_USER_FILE, 'w') as f:
            json.dump(trusted_users, f, indent=2)

        with open(TRUSTED_LOG_FILE, 'a') as f:
            f.write(f"{datetime.utcnow().isoformat()} - New trusted user: {username}\n")
        session['username'] = username
        return redirect(url_for('upload'))

    return render_template_string("""
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
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', 'Unknown')

    suspicious = is_suspicious_input(username) or is_suspicious_input(password)
    stored_hash = trusted_users.get(username.lower())
    is_trusted = stored_hash and bcrypt.checkpw(password.encode(), stored_hash.encode())

    if suspicious or not is_trusted:
        funnel_logger.info(f"[WEB LOGIN TRAP] IP: {ip}, UA: {ua} | Username: {username}, Password: {password}")

    return render_template_string("<h2>Welcome, {{ username }}</h2>", username=username)

@app.route('/upload')
@login_required
def upload():
    return "Welcome to the Upload Trap 🔥"

def run_web_honeypot(port=5000, input_username='admin', input_password='password'):
    if input_username.lower() not in trusted_users:
        hashed = bcrypt.hashpw(input_password.encode(), bcrypt.gensalt()).decode()
        trusted_users[input_username.lower()] = hashed
        with open(TRUSTED_USER_FILE, 'w') as f:
            json.dump(trusted_users, f, indent=2)
    app.run(debug=True, port=port, host='0.0.0.0')
