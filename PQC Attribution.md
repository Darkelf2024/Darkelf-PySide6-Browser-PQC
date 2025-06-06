Darkelf Browser is an original software project developed by Dr. Kevin Moore.

The browser’s anti-fingerprinting engine (DarkelfAIPrivacyManager) implements original techniques tailored for the Darkelf environment. While conceptually informed by best practices and public research from tools such as Brave, Tor Browser, puppeteer-extra-plugin-stealth, and Librewolf, all code was independently written and adapted specifically for PySide6 and Qt WebEngine.

This project also used generative assistance (e.g., ChatGPT) during development for research, prototype generation, and documentation. All architectural decisions, implementations, integrations, and final code were authored, reviewed, and curated by Dr. Moore.

## Attribution by Edition

This repository hosts multiple builds of Darkelf Browser. Attribution for external lists and tools varies by edition:

### Standard Edition
Includes:
- EasyList & Fanboy Lists (CC BY-SA 4.0)
- Disconnect.me Lists (CC BY-NC-SA 4.0 – non-commercial use only)

### PQC Edition
Does **not** include any third-party tracker or ad-blocking lists. All fingerprinting and privacy logic is implemented independently.

## Project Overview

**Darkelf Browser PQC Edition v3.0**  
A secure, privacy-respecting web browser with post-quantum cryptography support and advanced anti-fingerprinting technology.

**Author:** Dr. Kevin Moore  
**Year:** 2025  
**License:** GNU Lesser General Public License v3.0 (LGPL-3.0-or-later)  
[View License](https://www.gnu.org/licenses/lgpl-3.0.html)

---

## Third-party Libraries and Dependencies

This project uses the following libraries and frameworks:

| Library                        | Author / Organization                    | License         |
|-------------------------------|-------------------------------------------|------------------|
| Python                        | Python Software Foundation                | PSF License       |
| PySide6, PySide6-WebEngine    | The Qt Company Ltd.                       | LGPL-3.0          |
| BeautifulSoup4                | Leonard Richardson                        | MIT               |
| Requests                      | Kenneth Reitz & contributors              | Apache 2.0        |
| Adblockparser                 | Andy Chilton                              | MIT               |
| Cryptography                  | The Python Cryptographic Authority        | Apache 2.0        |
| PyCryptodome                  | Dario Izzo                                | Public Domain     |
| `oqs` (liboqs bindings)       | Open Quantum Safe Project                 | MIT               |
| `crypto_rust` bindings        | (Likely custom or BSD/MIT; verify)        | Custom/MIT?       |
| dnspython                     | Bob Halley & contributors                 | ISC               |
| Stem                          | The Tor Project                           | GPL-3.0           |
| NumPy, Scikit-learn, Joblib   | Community                                 | BSD               |
| Matplotlib                    | Community                                 | PSF / MIT         |
| PyNaCl                        | PyNaCl Team                               | Apache 2.0        |
| httpx                         | Encode Team                               | BSD               |
| PIL (Pillow)                  | Alex Clark and contributors               | PIL License       |
| psutil                        | Giampaolo Rodolà                          | BSD               |
| piexif                        | Hironobu Takae                            | MIT               |

---

## Post-Quantum Cryptography (PQC)

This edition includes post-quantum cryptographic mechanisms in alignment with the NIST PQC standardization process.

- **ML-KEM-1024 (Kyber-1024)**  
  - Based on lattice-based cryptography, resistant to quantum attacks.  
  - Integrated via `oqs` (Open Quantum Safe) and/or `crypto_rust`.  
  - [NIST PQC Standard](https://csrc.nist.gov/publications/detail/fips/203/final)

- **LibOQS (Open Quantum Safe)**  
  - https://openquantumsafe.org/  
  - MIT License

---

## Anti-Fingerprinting & Privacy Techniques

The browser includes **dynamic anti-fingerprinting mechanisms** via `DarkelfAIPrivacyManager`, which are **inspired by or adapted from** the following:

| Source / Tool                                | License | Notes |
|---------------------------------------------|---------|-------|
| **puppeteer-extra-plugin-stealth**          | MIT     | JS fingerprint evasion techniques |
| **Brave Browser Fingerprinting Defenses**   | MPL-2.0 | Dynamic spoofing, randomness |
| **Librewolf Privacy Scripts**               | MPL-2.0 | Community hardened Firefox build |
| **Tor Browser**                              | GPL-3.0 | Canvas spoofing, screen/timezone faking |
| **EFF Panopticlick / Cover Your Tracks**    | N/A     | Entropy-based tracking detection |

### Specific Vectors Mitigated

- Canvas fingerprinting (blocking `getImageData`, etc.)
- Font and text measurement spoofing
- Screen size spoofing per session
- Timezone and language spoofing
- Entropy-based anomaly detection and script blocking
- AI-generated user personas for behavioral consistency

Academic inspiration includes:

- **"The Web Never Forgets"**, CCS 2014 – Acar et al.  
- **"FPDetective"**, CCS 2013 – Laperdrix et al.  
- **"Cookieless Monster"**, IEEE S&P 2013 – Nikiforakis et al.

---

## Search Engine & DNS

- **DuckDuckGo Lite Search**  
  - Integrated for anonymous, tracker-free search.  
  - [DuckDuckGo](https://duckduckgo.com/about)

- **Tor Network Integration**  
  - Optional routing of traffic via Tor.  
  - [Tor Project](https://www.torproject.org/)

- **Tor DNS Integration**  
  - DNS-over-Tor for ad-free and privacy-preserving resolution.  
  - Note: No usage of Disconnect.me lists in this PQC Edition.

---

## Ad Blocking

- **EasyList**  
- **Fanboy Annoyance List**  
  - Both licensed under **CC BY-SA 4.0**  
  - https://easylist.to/

*No Disconnect.me lists are used in this PQC version.*

---

## Key Components Summary

- `PySide6` & `Qt WebEngine` for GUI and embedded browser
- `oqs`, `crypto_rust` for PQC
- `cryptography`, `PyNaCl`, `PyCryptodome` for symmetric/asymmetric crypto
- `stem` for Tor control
- Custom privacy and spoofing logic (`DarkelfAIPrivacyManager`)

---

## License

This software is licensed under:  
**GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later)**  
See: [SPDX License](https://spdx.org/licenses/LGPL-3.0-or-later.html)

---

## Contributions

Contributions are welcome!

1. Fork the repo and create a new branch
2. Follow secure coding practices
3. Submit a pull request with clear documentation

For major changes, open an issue for discussion first.

---

© 2024–2025 Dr. Kevin Moore. All rights reserved.
