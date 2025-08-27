"""
honeypy.py - Main Honeypot Launcher
CLI to run either an SSH honeypot or HTTP honeypot.
"""

import argparse
import json
from ssh_honeypot import honeypot
from web_honeypot import run_web_honeypot

# Load config
with open("config.json", "r") as f:
    config = json.load(f)

DEFAULT_HOST = config.get("host", "127.0.0.1")
DEFAULT_PORT = config.get("port", 2223)

def main():
    parser = argparse.ArgumentParser(description="Run SSH or HTTP Honeypot")

    parser.add_argument('-a', '--address', type=str, default=DEFAULT_HOST, help="IP address to bind")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT, help="Port number")
    parser.add_argument('-u', '--username', type=str, help="Username for HTTP honeypot")
    parser.add_argument('-pw', '--password', type=str, help="Password for HTTP honeypot")
    parser.add_argument('-s', '--ssh', action='store_true', help="Run SSH honeypot")
    parser.add_argument('-w', '--http', action='store_true', help="Run HTTP honeypot")

    args = parser.parse_args()

    try:
        if args.ssh:
            print(f"[+] Starting SSH Honeypot on {args.address}:{args.port}")
            honeypot(args.address, args.port, args.username, args.password)
        elif args.http:
            username = args.username if args.username else 'admin'
            password = args.password if args.password else 'password'
            print(f"[+] Starting HTTP Honeypot on port {args.port} (Username: {username})")
            run_web_honeypot(args.port, username, password)
        else:
            print("[!] Please specify --ssh or --http")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
