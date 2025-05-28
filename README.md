# Darkelf Post-Quantum Secure Browser

## Overview
**Darkelf Browser** is a hardened, privacy-first secure browser developed for investigative journalists, activists, penetration testers, and advanced security professionals. Designed to combat advanced persistent threats, it incorporates **post-quantum cryptography**, live JavaScript malware detection via machine learning, and memory-resident anti-forensics.

Built on a fortified QtWebEngine base, Darkelf ensures no disk persistence, disables swap, and isolates all sessions in hardened runtime environments.

## 🧬 Post-Quantum Editions
Darkelf is available in two post-quantum variants:

| Edition       | PQ Crypto   | ML Detection | Status       | Notes                                  |
|---------------|-------------|--------------|--------------|----------------------------------------|
| **Kyber768**  | Kyber768    | ✅           | ✅ Tested     | Balanced performance and encryption    |
| **Kyber1024** | Kyber1024   | ✅           | ✅ Production | Highest-strength security tier         |

## 🔒 Core Capabilities

### 🔐 Post-Quantum Cryptography
- Uses **Kyber768** or **Kyber1024** from liboqs
- Implements secure key encapsulation (KEM)
- Derives AES-GCM session keys via HKDF
- Keys and secrets live only in memory

### 🧠 Real-Time JavaScript Malware Detection
- Trained `RandomForestClassifier` (scikit-learn)
- Feature extraction + entropy analysis on console JS logs
- Auto-blocks fingerprinting or malicious scripts
- Model integrity checked via `.sha256`

### 🛡 Anti-Fingerprinting & Privacy Suite
- JS APIs blocked or randomized (Canvas, WebGL, Fonts, Audio)
- Network-level protections (spoofed UA, anti-ETag, spoofed headers)
- CSP and DOM injection to block leaks
- Prevents WebRTC, Geolocation, Timezone, and Device-based tracking

### 🕵️ Anti-Forensics & Stealth
- Self-deletion on detection of forensic tools or debuggers
- Disables swap and clears memory buffers
- Anti-VM checks (MACs, environment, user, hostname)
- In-memory encrypted logs using `Fernet`

### 🌐 Secure and Anonymous Networking
- Full Tor routing (via `stem` and SOCKS5 proxy)
- Fallback to DoH and DoT if Tor is down
- Adds jitter, timing noise, and encrypted padding to all traffic

### 📦 Hardened Web Engine Runtime
- Sandboxed WebEngine with hardened settings
- JS disabled by default, per-tab toggles
- Download manager strips EXIF, PDF metadata
- Runtime obfuscated + encrypted cookie store

## 📁 Included Components

- `darkelf.py`: Main application launcher
- `kyber_crypto.py`: Post-quantum key encapsulation logic
- `ml_script_classifier.pkl`: Trained ML model (malicious JS detection)
- `scaler.pkl`: StandardScaler model for feature normalization
- `.ml_script_classifier.sha256`: SHA256 of model for hash check
- `CustomWebEnginePage`: Custom JS log parser and ML hook
- `StealthCovertOps`: RAM-only logging and anti-forensics
- `ObfuscatedEncryptedCookieStore`: Secure ephemeral cookie store

## 🧪 ML Training & Retraining
To regenerate the model:
```bash
python train_script_classifier.py
```
This script outputs:
- `ml_script_classifier.pkl`
- `scaler.pkl`
- `.ml_script_classifier.sha256`

Includes:
- Cross-validation accuracy report
- Test set predictions
- Feature entropy analysis

## ⚙️ Install & Run
Clone:
```bash
git clone https://github.com/Darkelf2024/Darkelf-Browser.git
cd Darkelf-Browser-Kyber768/1024
```

Install requirements:
```bash
pip install -r requirements.txt
```

Launch:
```bash
python darkelf768.py
```

## 📚 License
**LGPLv3** — Community contribution and independent review encouraged.

## 🔗 Project Website
[https://darkelfbrowser.com](https://darkelfbrowser.com)

## 👨‍💻 Developer
**Dr. Kevin Moore** — Creator and lead developer

---

> Disclaimer

Darkelf Browser is a specialized, experimental web browser developed for cybersecurity research, educational use, and academic exploration. It is designed for environments where users operate under adversarial conditions, such as digital forensics, penetration testing, surveillance evasion, and post-quantum cryptography evaluation.

This software is intended solely for lawful, ethical, and non-commercial purposes including:
	•	Cybersecurity research and academic analysis
	•	Educational demonstrations of cryptographic and forensic-resistance techniques
	•	Threat modeling and controlled red-team simulations
	•	Privacy-focused software experimentation

Darkelf is not a general-purpose web browser. It is intended for advanced users with appropriate technical understanding and well-defined threat models. Improper use in unintended environments may lead to operational or legal risks.

Use at your own risk. The author makes no warranties or guarantees regarding fitness for any specific purpose or resistance to advanced threat actors.

⸻

🔐 Legal and Export Notice

Darkelf Browser includes cryptographic functionality and may be subject to U.S. Export Administration Regulations (EAR). It is released in full compliance with EAR §740.13(e) and is made publicly available via open-source distribution for unrestricted access.

Users are responsible for ensuring compliance with all applicable local, national, and international laws regarding cryptographic software and cybersecurity tools. The developer disclaims liability for misuse or deployment in prohibited jurisdictions.

⸻

📄 License

Darkelf Browser is released under the LGPL open-source license, promoting transparency, reproducibility, and responsible research. Redistribution, modification, and peer review are encouraged under the terms of the license.

