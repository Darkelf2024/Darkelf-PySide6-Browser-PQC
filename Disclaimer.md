# :shield: Darkelf Browser

**Darkelf** is a post-quantum secure, memory-resident, anti-forensic browser designed for adversarial environments. It is not a general-purpose browser — it is a specialized tool for cybersecurity research, threat simulation, and secure web interaction in high-risk contexts.

---

## :rotating_light: Disclaimer

> **Darkelf Browser is intended solely for cybersecurity research, educational use, digital rights advocacy, and professional security operations.**  
It is not designed for mainstream web browsing or casual use.

This browser includes advanced features that resist forensic recovery and enable ephemeral, RAM-only sessions. Such capabilities are powerful and must be deployed responsibly. Use is subject to applicable laws and ethical guidelines. The author assumes no responsibility for misuse.

---

## :white_check_mark: Intended Use Cases

### :red_circle: Red Team Operations
- Simulates real-world attacker behavior in penetration testing environments
- Leaves no persistent artifacts
- Includes self-destruct and debugger detection to model advanced APT behaviors

### :detective: OSINT Investigations
- Enables anonymous reconnaissance
- Provides anti-tracking and identity shielding for exploring sensitive public data sources
- Ideal for investigating extremism, disinformation, or threat actors without risk of traceback

### :police_officer: Law Enforcement & Forensic Analysis
- Useful for **digital forensics training** and **counter-forensic tool evaluation**
- Safe malware interaction and exploit site inspection
- Secure internal communications under surveillance

### :newspaper: Investigative Journalists & Whistleblowers
- Protects sources and communication channels from forensic analysis and surveillance
- Supports encrypted, RAM-only sessions with no disk artifacts
- Designed for use in repressive environments where privacy is critical

### :bust_in_silhouette: Privacy Advocates & Human Rights Defenders
- Empowers individuals under surveillance to browse safely
- Open-source and auditable
- Compatible with privacy infrastructures (e.g., VPNs, Tails OS)

---

## :tools: Features

- :closed_lock_with_key: **Post-Quantum TLS (ML-KEM-768/1024)** using [liboqs](https://openquantumsafe.org/)
- :brain: **Real-time JavaScript threat detection** with RandomForestClassifier (scikit-learn)
- :lock: **RAM-only cryptographic key and session management**
- :test_tube: **Debugger & forensic tool detection**
- :bomb: **Automated self-destruct functionality**
- :desktop: Cross-platform: **macOS (Apple Silicon), Linux, and Windows**
- :scroll: Released under **LGPL License**

---

## :scales: Legal & Compliance

- **Export Compliance:** Features post-quantum cryptography and anti-forensic mechanisms. The author has notified the U.S. Bureau of Industry and Security (BIS) in accordance with EAR encryption regulations.
- **Wassenaar Arrangement Considerations:** Users are responsible for local compliance regarding the use or redistribution of cryptographic or forensic-resistant software.
- **Responsible Use:** This project is for educational, defensive, and ethical purposes only. Any use for unlawful activities is strictly condemned and violates the licensing intent.

---

## :books: Documentation

- [Project Whitepaper / Dissertation (PDF)](link-to-upload-or-site)
- [System Architecture](docs/architecture.md)
- [Threat Detection Flowchart](docs/threat_model.md)
- [Legal Disclaimers & Jurisdictional Use](docs/legal_guidelines.md)

---

## :brain: Acknowledgments

Built using:
- [QtWebEngine](https://doc.qt.io/qt-6/qtwebengine-index.html)
- [liboqs (Open Quantum Safe Project)](https://openquantumsafe.org/)
- [scikit-learn](https://scikit-learn.org/)
- [Fernet AES-GCM](https://eprint.iacr.org/2013/339)

Special thanks to the cybersecurity, privacy, and open-source communities.

---

🧭 Code of Ethics

Users of Darkelf Browser agree to:

- Use this tool only for legal, ethical, and educational purposes.
- Respect the Terms of Service of any queried API or website.
- Avoid targeting or scanning systems without explicit permission.

## :unlock: License

Darkelf Browser is licensed under the **GNU Lesser General Public License (LGPL v3)**.  
See `LICENSE` for full details.
