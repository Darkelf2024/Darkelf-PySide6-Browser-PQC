# 🧙 Darkelf CLI Browser — Setup & Usage Walkthrough

Welcome to the Darkelf CLI Browser — a post-quantum OSINT, privacy, and defensive toolkit. This walkthrough will guide you step-by-step through setup, command usage, and advanced capabilities.

---

## 🔧 1. Environment Setup

### Install Python 3.11
Make sure Python 3.11 is installed on your system.

### Create Python Virtual Environment

```bash
python3.11 -m venv ~/pqcrypto_env
source ~/pqcrypto_env/bin/activate
```

---

## 📦 2. Install Dependencies

### Install Specific `liboqs-python` Version (0.12.0) or (0.13.0)

Ensure your **native liboqs version** matches `0.12.0`. You may build liboqs C library separately.

```bash
pip install --upgrade pip
pip install --force-reinstall --no-cache-dir liboqs-python==0.12.0
```

💡 You may also edit the required version in `pyproject.toml` manually using:

```bash
nano pyproject.toml
# Then adjust:
# oqs = "0.12.0"
```

### Install All Other Required Packages

```bash
pip install -r requirements.txt
```
---

## 🚀 3. Running Darkelf CLI

```bash
python Darkelf\ CLI\ TL\ Browser.py
```

---

## 🧾 4. Command Reference

### General OSINT and Searching
- `search <keywords>` — DuckDuckGo .onion search
- `debug <keywords>` — Search with debug info
- `osintscan <term|url>` — Extract emails/phones from a URL
- `findonions <keywords>` — Discover .onion services

### Security and Privacy Tools
- `stealth` — Toggle stealth options
- `genkeys` — Generate post-quantum keys
- `sendmsg` — Encrypt & send message
- `recvmsg` — Decrypt received message
- `checkip` — Tor check
- `iplookup <ip number or blank(self)>` — IP reputation info
- `tlsstatus` — TLS Monitor check
- `beacon <.onion website>` — Check .onion reachability
- `dnsleak` — DNS Leak Test
- `analyze! <url>` — Analyze threat trackers
- `open <url>` — Open URL safely
- `emailintel <email>` — Lookup MX records
- `emailhunt <email>` — Email reconnaissance

### Tools and Utilities
- `tool <name>` — Install and launch utility
- `tools` — List tools
- `toolinfo` — Info on all tools
- `browser` — Launch browser

### Maintenance
- `wipe` — Self-destruct secure files
- `help` — Help menu
- `exit` — Exit browser

---

## 🛡️ 5. Pegasus Monitor

### Command:
```bash
pegasusmonitor in Darkelf CLI 
```

Scans logs and network connections for indicators of Pegasus spyware and similar surveillance threats.

---

## ✅ Tips

- Use `nano pyproject.toml` to manually override versions. 0.12.0 rename to 0.13.0
- Match your native `liboqs` version with `liboqs-python`.
- Use `which python` and `pip list` inside your virtualenv to verify setup.

---

Enjoy the safety, privacy, and insights of Darkelf CLI 🧙‍♂️
