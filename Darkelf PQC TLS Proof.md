
# 🔐 Darkelf PQC TLS Proof: Setup and Walkthrough

This guide shows how to run a working simulation of **post-quantum key exchange** using **ML-KEM-1024 (Kyber)** and **AES-GCM**, matching the primitives recommended by NIST.

---

## 📦 Requirements

Ensure you have **Python 3.8+** installed.

### 1. Install required libraries:
```bash
pip install oqs cryptography
```

> 💡 On macOS:
```bash
brew install liboqs
pip install oqs
```

---

## 📁 Step 1: Download the Script

Save the file `pqc_tls_oqs.py` from this repository.

---

## ▶️ Step 2: Run the Simulation

From your terminal:
```bash
python3 pqc_tls_oqs.py
```

---

## 🧪 What It Does:

1. **Server** generates a post-quantum Kyber1024 keypair.
2. **Client** encapsulates a secret using the server’s public key.
3. **Server** decapsulates to derive the same secret.
4. Shared secret is used for AES-GCM encryption and decryption.

---

## ✅ Expected Output

```text
=== PQC TLS-like Key Exchange using ML-KEM-1024 ===
[Server] Generating Kyber1024 keypair...
[Client] Encapsulating secret...
✅ Shared secrets match!
[Client] Encrypting: b'This is a quantum-resistant encrypted message!'
[Server] Decrypting ciphertext...
✅ Decrypted message: b'This is a quantum-resistant encrypted message!'
```

---

## 🧠 Purpose

This simulation acts as a **verifiable cryptographic proof-of-concept**:
- Real ML-KEM-1024 and AES-GCM usage
- Demonstrates TLS-like secure session establishment
- Valid for citations in security papers and software documentation

---

## 🧾 Source Code (`pqc_tls_oqs.py`)
```python
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def pqc_tls_simulation():
    print("=== PQC TLS-like Key Exchange using ML-KEM-1024 ===")

    # Server side: generate Kyber keypair
    print("[Server] Generating Kyber1024 keypair...")
    with oqs.KeyEncapsulation('Kyber1024') as server_kem:
        public_key = server_kem.generate_keypair()

        # Client side: encapsulate secret using server's public key
        print("[Client] Encapsulating secret...")
        with oqs.KeyEncapsulation('Kyber1024') as client_kem:
            ciphertext, shared_secret_client = client_kem.encap_secret(public_key)

        # Server side: decapsulate to recover shared secret
        shared_secret_server = server_kem.decap_secret(ciphertext)

    # Check if shared secrets match
    if shared_secret_client != shared_secret_server:
        print("❌ Shared secrets do NOT match!")
        return
    print("✅ Shared secrets match!")

    # Use the shared secret as AES-GCM key
    aes_key = shared_secret_client[:32]  # Use first 32 bytes for AES-256
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    plaintext = b"This is a quantum-resistant encrypted message!"
    print(f"[Client] Encrypting: {plaintext}")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    print("[Server] Decrypting ciphertext...")
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    print(f"✅ Decrypted message: {decrypted}")

if __name__ == "__main__":
    pqc_tls_simulation()
```
