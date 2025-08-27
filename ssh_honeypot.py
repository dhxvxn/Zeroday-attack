"""
ssh_honeypot.py - SSH Honeypot using Paramiko
Simulates an SSH shell, logs suspicious activity.
"""

import paramiko
import socket
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json
import os
import time
import requests
from collections import defaultdict

# Logging setup
logging_format = logging.Formatter('%(message)s')
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

SSH_BANNER = "SSH-2.0-MySSHServer_1.0"
host_key = paramiko.RSAKey(filename='server.key')  # Put a test key in project root

failed_attempts = defaultdict(lambda: {"count": 0, "last_time": time.time()})

def suspicion_score(ip, username):
    score = 0
    if username.lower() in ["root", "admin", "test", "guest"]:
        score += 1
    now = time.time()
    if now - failed_attempts[ip]["last_time"] < 60:
        failed_attempts[ip]["count"] += 1
    else:
        failed_attempts[ip] = {"count": 1, "last_time": now}
    if failed_attempts[ip]["count"] > 3:
        score += 1
    return score

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        score = suspicion_score(self.client_ip, username)
        if score >= 1:
            funnel_logger.info(f'[SUSPICIOUS] {self.client_ip} username: {username}, password: {password}')
            creds_logger.info(f'{self.client_ip}, {username}, {password}')
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def honeypot(address, port, username=None, password=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)
    print(f"SSH Honeypot listening on {address}:{port}")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

def handle_client(client, addr):
    client_ip = addr[0]
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip)
        transport.add_server_key(host_key)
        transport.start_server(server=server)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        client.close()
