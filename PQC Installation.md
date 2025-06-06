# 🍏 Darkelf Browser PQC Edition — macOS Installation (M1–M4, Python 3.11)

This guide helps you install the Post-Quantum Edition of Darkelf Browser on Apple Silicon Macs (M1–M4) using Python 3.11.

---

## ✅ Requirements

* macOS 12+ (Monterey or later)
* Python 3.11 (preferably installed via pyenv or Homebrew)
* Homebrew (for dependencies)
* `liboqs` (Post-Quantum crypto library)
* `oqs-python` (Python wrapper for liboqs)
* PySide6 and Qt WebEngine

---

## 📦 Step-by-Step Installation

### 1️⃣ Install System Tools (via Homebrew)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install cmake python@3.11 openssl
```

> ✅ This installs Python 3.11 and dependencies like `cmake`, `make`, and OpenSSL.

---

### 2️⃣ Setup Python 3.11 (if using `pyenv`, skip this)

```bash
brew link python@3.11
python3.11 -m ensurepip --upgrade
python3.11 -m venv venv
source venv/bin/activate
```

---

### 3️⃣ Build and Install `liboqs`

```bash
git clone --recursive https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/liboqs ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

> 📁 This installs `liboqs` into `/opt/liboqs`

---

### 4️⃣ Set Environment for `oqs-python`

```bash
export LDFLAGS="-L/opt/liboqs/lib"
export CPPFLAGS="-I/opt/liboqs/include"
export CFLAGS="-I/opt/liboqs/include"
```

---

### 5️⃣ Install Python Dependencies

```bash
pip install wheel
pip install oqs PySide6 PySide6-WebEngine cryptography pycryptodome requests beautifulsoup4 adblockparser stem
This is an example of installing manually - Refer to requirements.txt in Darkelf PQC Repo
```

📅 If `oqs` fails to build, make sure your `liboqs` path is exported correctly (as above).

---

## 🚀 Run the Browser

```bash
python darkelf_ml_kem_edition.py
```

You should see:

```
[OK] Kyber-1024 initialized
[OK] AES-GCM key derived
```

---

## 🔧 Optional (for Tor Support)

```bash
brew install tor
tor &
```

---

## 🚘 Common Issues

* `oqs not found`
  → Check that `liboqs` is installed to `/opt/liboqs` and environment variables are exported.

* `ModuleNotFoundError`
  → Ensure you activated the virtual environment (`source venv/bin/activate`).

---

## ℹ️ Notes

* Apple Silicon is fully supported.
* Python 3.11 is optimal and tested.
* PQC Edition includes **Kyber-1024** and **Hybrid/768** key exchanges.

---

© 2025 Dr. Kevin Moore
