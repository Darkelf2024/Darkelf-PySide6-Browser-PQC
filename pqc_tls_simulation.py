# pqc_tls_sim.py - Post-Quantum TLS Simulation using ML-KEM and AES-GCM
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This file is part of the Darkelf Project.
#
# Copyright (C) 2025 Dr. Kevin Moore
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class PostQuantumTLS:
    def __init__(self, kem_alg="ML-KEM-1024", key_length=32):
        self.kem_alg = kem_alg
        self.key_length = key_length
        self.shared_secret = None
        self.cipher = None

    def establish_secure_channel(self):
        print("[TLS Sim] Initiating post-quantum handshake using:", self.kem_alg)

        # Server generates keypair
        with oqs.KeyEncapsulation(self.kem_alg) as server_kem:
            public_key = server_kem.generate_keypair()

            # Client encapsulates a shared key using server's public key
            with oqs.KeyEncapsulation(self.kem_alg) as client_kem:
                ciphertext, client_secret = client_kem.encap_secret(public_key)

            # Server decapsulates to obtain the same shared key
            server_secret = server_kem.decap_secret(ciphertext)

            # Validate
            assert client_secret == server_secret, "Key mismatch!"
            self.shared_secret = server_secret

            print("[TLS Sim] Shared key established.")
            self.cipher = AESGCM(self.shared_secret[:self.key_length])

    def encrypt_message(self, message: bytes) -> tuple:
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(nonce, message, None)
        return nonce, ciphertext

    def decrypt_message(self, nonce: bytes, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(nonce, ciphertext, None)


def main():
    tls = PostQuantumTLS()
    tls.establish_secure_channel()

    msg = b"Hello from DarkelfAI PQC TLS"
    nonce, encrypted = tls.encrypt_message(msg)
    decrypted = tls.decrypt_message(nonce, encrypted)

    print("Original:", msg)
    print("Encrypted:", encrypted.hex())
    print("Decrypted:", decrypted)


if __name__ == "__main__":
    main()
