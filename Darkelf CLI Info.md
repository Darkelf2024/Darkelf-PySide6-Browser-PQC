# 🛡️ Darkelf CLI Browser

> **Post-Quantum Hardened CLI Browser for Secure Search, Messaging, and Covert Ops**

Darkelf CLI Browser is a command-line privacy tool built for high-threat environments. It combines anonymous Tor-based search, phishing detection, post-quantum encrypted messaging, and hardened memory handling — all in a single stealth-ready CLI interface.

---

## ⚙️ Features

| Category         | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| 🔐 **Encrypted Messaging** | Send/receive messages encrypted with **ML-KEM-768** (post-quantum) + Fernet |
| 🌐 **Tor Browser Core**    | Fully routed through Tor with support for bridges & obfs4proxy     |
| 🧠 **Phishing Detection**  | Static heuristic analysis of suspicious URLs & page content        |
| 🧬 **Stealth Mechanics**   | Memory locking, decoy traffic, random delays, fake headers, jitter |
| 💀 **Panic Mode**          | Wipe sensitive logs and keys, saturate memory, spoof activity      |
| 📦 **Tool Launcher**       | Launch OSINT/recon tools like `nmap`, `amass`, `shodan` etc.       |
| 🧪 **Log Encryption**      | Logs are encrypted in RAM with AES-GCM derived from PQC secrets    |
| 🔍 **.onion Discovery**    | Automatically search for onion services via Ahmia                 |

---

## 🧩 Getting Started

### 🔧 Requirements

- Python 3.11
- Tor (`sudo apt install tor` or `brew install tor`)
- obfs4proxy (optional but recommended)
- `pip install -r requirements.txt`

## Licenses & Attributions

This software makes use of the following third-party libraries:

- [psutil](https://github.com/giampaolo/psutil) - BSD 3-Clause License
- [Rich](https://github.com/Textualize/rich) - MIT License
- [liboqs](https://github.com/open-quantum-safe/liboqs) and [pyoqs](https://github.com/open-quantum-safe/pyoqs) - BSD 2-Clause and MIT Licenses
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - MIT License
- [Cryptography](https://github.com/pyca/cryptography) - Apache License 2.0
- [Requests](https://requests.readthedocs.io/) - Apache License 2.0

---

Works on MacM1-M4, Windows, Linux, and Android(Termux Recommended)

