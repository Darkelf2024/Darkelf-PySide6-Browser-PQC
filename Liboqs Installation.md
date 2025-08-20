## Liboqs Requirements

- macOS or Linux
- Python 3.11
- CMake and build tools
- OpenSSL >= 1.1.1
- Virtual environment (recommended)

---

## Setup Guide

### 1. Clone and Build `liboqs 0.13.0`

```bash
git clone --branch main https://github.com/open-quantum-safe/liboqs.git ~/liboqs
cd ~/liboqs
git checkout 0.13.0

mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(sysctl -n hw.logicalcpu)
sudo make install
```

---

### 2. Create Python Virtual Environment & Install `liboqs-python 0.13.0`

```bash
# Create a new virtual environment
python3.11 -m venv ~/pqcrypto_env
source ~/pqcrypto_env/bin/activate

# Reinstall liboqs-python 0.13.0
pip install --upgrade pip
pip install --force-reinstall --no-cache-dir liboqs-python==0.12.0

# If you have Liboqs 0.13.0 - You can choose to rename liboqs-python from 0.12.0 to 0.13.0 with nano pyproject.toml located in your liboqs-python folder or through Terminal with PICO.
```

---

### 3. Confirm Installation

```bash
python -c "import oqs; print(oqs.__version__); print(oqs.get_enabled_KEMs())"
```

Expected output:

```
0.13.0
['Kyber768', ...]
```
---

## :brain: Notes

- `liboqs` must be compiled and installed **before** installing `liboqs-python`.
- Only **Kyber768** is used — no `ML-KEM`, no hybrid modes.
- All messages are encrypted with a derived AES key from the post-quantum shared secret.

---

## :scroll: License

MIT License — (c) 2024–2025, Darkelf Research
