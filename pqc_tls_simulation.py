
# pqc_tls_oqs.py
# Demonstrates ML-KEM-1024 (Kyber) key exchange and AES-GCM encryption using `oqs`

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
