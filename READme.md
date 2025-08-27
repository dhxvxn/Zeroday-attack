# Honeypot Project

This project implements a **multi-functional honeypot** with:

- **SSH honeypot** using Paramiko
- **HTTP/Web honeypot** using Flask
- Logging of suspicious activity and user interactions
- Fake file system emulation for SSH honeypot
- Trusted user session tracking for HTTP honeypot

---

## Features

- Detect suspicious usernames/passwords and IPs
- Log commands and attempts to `logs/`
- Emulated shell environment for SSH attackers
- Web login trap with fake success messages
- Configurable IPs, ports, and credentials

---

## Setup

1. Clone the repository:

```bash
git clone <your_repo_url>
cd honeypot-project
