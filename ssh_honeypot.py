"""
ssh_honeypot.py - SSH Honeypot using Paramiko
Simulates an SSH shell, logs suspicious activity, and uses environment variables for API keys.
"""

import os
import socket
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json
import time
from collections import defaultdict
import paramiko
import requests

# ==============================
# 📦 LOGGING SETUP
# ==============================
logging_format = logging.Formatter('%(message)s')

# Auth attempt logger
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

# Command logger
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename='server.key')  # Make sure to generate this locally

# ==============================
# 📂 PATH NORMALIZATION
# ==============================
def normalize_path(base_path, target_path):
    if target_path.startswith("/"):
        full_path = target_path
    else:
        full_path = os.path.join(base_path, target_path)
    normalized = os.path.normpath(full_path)
    return normalized if normalized else "/"

# ==============================
# 🚨 SUSPICIOUS USER DETECTION
# ==============================
failed_attempts = defaultdict(lambda: {"count": 0, "last_time": time.time()})
API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # Safe API key via environment

def is_ip_bad(ip):
    if not API_KEY:
        return False  # Skip check if no key
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Accept": "application/json", "Key": API_KEY}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            score = resp.json().get("data", {}).get("abuseConfidenceScore", 0)
            return score >= 50
        return False
    except Exception as e:
        print(f"[WARN] AbuseIPDB check failed: {e}")
        return False

def is_geo_anomalous(ip, allowed_country="IN"):
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json")
        if resp.status_code == 200:
            country = resp.json().get("country", "N/A")
            return country != allowed_country
        return False
    except:
        return False

def suspicion_score(ip, username):
    score = 0
    if is_ip_bad(ip):
        score += 2
    if username.lower() in ["root", "admin", "test", "guest", "user", "ubuntu"]:
        score += 1
    if is_geo_anomalous(ip):
        score += 1

    now = time.time()
    if now - failed_attempts[ip]["last_time"] < 60:
        failed_attempts[ip]["count"] += 1
    else:
        failed_attempts[ip] = {"count": 1, "last_time": now}

    if failed_attempts[ip]["count"] > 3:
        score += 1
    return score

# ==============================
# 🗂️ FAKE FILESYSTEM
# ==============================
class FakeFileSystem:
    def __init__(self):
        self.current_path = "/home/corpuser1"
        self.structure = {
            "/": ["home", "etc", "var", "tmp", "root"],
            "/home": ["corpuser1"],
            "/home/corpuser1": ["notes.txt", ".bashrc", ".ssh"],
            "/etc": ["passwd", "shadow", "network.conf"],
            "/var": [],
            "/var/log": ["auth.log", "syslog"],
            "/tmp": [],
            "/root": []
        }

    def cd(self, path):
        full_path = normalize_path(self.current_path, path)
        if full_path in self.structure:
            self.current_path = full_path
            return ""
        return f"bash: cd: {path}: No such file or directory\n"

    def ls(self):
        return "\n".join(self.structure.get(self.current_path, [])) + "\n"

    def cat(self, filename):
        full_path = self.current_path + "/" + filename
        fake_files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ncorpuser1:x:1001:1001::/home/corpuser1:/bin/bash",
            "/home/corpuser1/notes.txt": "Don't forget to backup files to server03.",
        }
        return fake_files.get(full_path, f"cat: {filename}: No such file\n")

# ==============================
# 💻 COMMAND EMULATION
# ==============================
def emulate_command(cmd, fs):
    parts = cmd.strip().split()
    if not parts:
        return ""
    match parts[0]:
        case "pwd":
            return fs.current_path + "\n"
        case "ls":
            return fs.ls()
        case "cd":
            return fs.cd(parts[1]) if len(parts) > 1 else fs.cd("~")
        case "cat":
            return fs.cat(parts[1]) if len(parts) > 1 else "cat: missing filename\n"
        case "whoami":
            return "corpuser1\n"
        case "exit":
            return "exit"
        case _:
            return f"{cmd.strip()}: command not found\n"

# ==============================
# 🪵 LOGGING COMMANDS
# ==============================
def log_command(command, client_ip):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": client_ip,
        "command": command
    }
    creds_logger.info(json.dumps(log_entry))

# ==============================
# 🖥️ EMULATED SHELL
# ==============================
def emulated_shell(channel, client_ip):
    fs = FakeFileSystem()
    prompt = b'corporate-jumpbox2$ '
    command = b""
    channel.send(prompt)
    try:
        while True:
            char = channel.recv(1)
            if not char: break
            channel.send(char)
            if char in [b'\x7f', b'\b']:
                if len(command) > 0: command = command[:-1]; channel.send(b'\b \b')
                continue
            if char in [b'\r', b'\n']:
                clean_cmd = command.decode(errors='ignore').strip()
                command = b""
                channel.send(b"\r\n")
                if clean_cmd.lower() == 'exit': break
                response = emulate_command(clean_cmd, fs)
                log_command(clean_cmd, client_ip)
                channel.send(response.encode() + b"\r\n")
                channel.send(prompt)
            else:
                command += char
    finally:
        channel.close()

# ==============================
# 🔐 SSH SERVER INTERFACE
# ==============================
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == 'session': return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        score = suspicion_score(self.client_ip, username)
        if score >= 2:
            funnel_logger.info(f'[SUSPICIOUS] {self.client_ip} username: {username}, password: {password}')
            creds_logger.info(f'{self.client_ip}, {username}, {password}')
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

# ==============================
# ⚙️ CLIENT HANDLER
# ==============================
def client_handle(client, addr):
    client_ip = addr[0]
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip)
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel: emulated_shell(channel, client_ip)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client.close()

# ==============================
# 🚀 START HONEYPOT
# ==============================
def honeypot(address='127.0.0.1', port=2223):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)
    print(f"SSH Honeypot listening on {address}:{port}")
    while True:
        client, addr = sock.accept()
        threading.Thread(target=client_handle, args=(client, addr)).start()

if __name__ == "__main__":
    honeypot()

