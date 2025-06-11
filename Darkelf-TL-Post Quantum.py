# Darkelf Browser v3.0 – Secure, Privacy-Focused Web Browser
# Copyright (C) 2025 Dr. Kevin Moore
#
# SPDX-License-Identifier: LGPL-3.0-or-later
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
#
# EXPORT COMPLIANCE NOTICE:
# This software contains encryption source code and is made publicly available
# under the terms of License Exception TSU pursuant to 15 CFR §740.13(e) of the
# U.S. Export Administration Regulations (EAR).
#
# A public release notification has been submitted to the U.S. Bureau of Industry
# and Security (BIS) and the National Security Agency (NSA) as required by the EAR.
#
# The source code includes implementations of standard encryption technologies
# (such as AES, RSA, ChaCha20, TLS 1.3, and X25519), and is intended for academic,
# research, and general-purpose use.
#
# This code is provided as source only. No compiled binaries are included in this
# distribution. Redistribution, modification, and use must comply with all applicable
# U.S. export control laws and regulations.
#
# Prohibited Destinations:
# This software may not be exported, re-exported, or transferred, either directly
# or indirectly, to:
# - Countries or territories subject to U.S. embargoes or comprehensive sanctions,
#   as identified by the U.S. Department of Treasury’s Office of Foreign Assets Control (OFAC)
#   or the BIS Country Group E:1 or E:2 lists.
# - Entities or individuals listed on the U.S. Denied Persons List, Entity List,
#   Specially Designated Nationals (SDN) List, or any other restricted party list.
#
# End-Use Restrictions:
# This software may not be used in the development, production, or deployment of
# weapons of mass destruction, including nuclear, chemical, or biological weapons,
# or missile technology, as defined in Part 744 of the EAR.
#
# By downloading, using, or distributing this software, you agree to comply with
# all applicable U.S. export control laws and regulations.
#
# This software is published under the LGPL v3.0 license and was authored by
# Dr. Kevin Moore in 2025.


import sys
import random
import os
import re
import numpy as np
import joblib
import requests
import shutil
import shlex
import socket
import httpx
import dns.query
import dns.message
import dns.rdatatype
import dns.resolver
import platform
import json
import logging
import time
import asyncio
import ctypes
import math
import oqs
import socks
import warnings
import mmap
import nacl.public
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from PySide6.QtWebChannel import QWebChannel
from base64 import urlsafe_b64encode, urlsafe_b64decode
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QLineEdit, QVBoxLayout, QMenuBar, QToolBar, QDialog, QMessageBox, QFileDialog, QProgressDialog, QListWidget, QMenu, QWidget, QLabel
)
from PySide6.QtGui import QPalette, QColor, QKeySequence, QShortcut, QAction, QGuiApplication, QActionGroup
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtNetwork import QNetworkProxy, QSslConfiguration, QSslSocket, QSsl, QSslCipher
from PySide6.QtWebEngineCore import QWebEngineUrlRequestInterceptor, QWebEngineSettings, QWebEnginePage, QWebEngineScript, QWebEngineProfile, QWebEngineDownloadRequest, QWebEngineContextMenuRequest, QWebEngineCookieStore
from PySide6.QtCore import QUrl, QSettings, Qt, QObject, Slot, QTimer, QCoreApplication, Signal, QThread
from collections import defaultdict
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import subprocess # nosec - All run through sanitizing and validation
from cryptography.fernet import Fernet
from shiboken6 import isValid
import stem.process
from stem.connection import authenticate_cookie
from stem.control import Controller
from collections import defaultdict
from stem import Signal as StemSignal
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import string
import base64
import threading
import getpass
import uuid
import hashlib
import secrets
import mimetypes
import tempfile
import psutil
from PIL import Image
import piexif

# Please make sure you have SIP Disabled on MacOS M1-M4
class DarkelfKernelMonitor(threading.Thread):
    """
    Monitors system kernel state for swap activity, paging daemon, and config changes.
    Alerts on forensic-risk events like swap reactivation or mid-session kernel tampering.
    """

    def __init__(self, check_interval=5):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self.initial_fingerprint = self.system_fingerprint()
        self._last_swap_active = None
        self._last_pager_state = None
        self._last_fingerprint_hash = hash(str(self.initial_fingerprint))

    def run(self):
        while True:
            time.sleep(self.check_interval)

            # Check for swap
            swap_now = self.swap_active()
            if swap_now != self._last_swap_active:
                if swap_now:
                    print("❌ [DarkelfKernelMonitor] Swap is ACTIVE — memory may be paged to disk!")
                else:
                    print("✅ [DarkelfKernelMonitor] Swap is OFF")
                self._last_swap_active = swap_now

            # Check for dynamic_pager
            pager_now = self.dynamic_pager_running()
            if pager_now != self._last_pager_state:
                if pager_now:
                    print("❌ [DarkelfKernelMonitor] dynamic_pager is RUNNING — swap management enabled!")
                else:
                    print("✅ [DarkelfKernelMonitor] dynamic_pager is not running")
                self._last_pager_state = pager_now

            # Check for system fingerprint tampering
            current_fingerprint = self.system_fingerprint()
            if hash(str(current_fingerprint)) != self._last_fingerprint_hash:
                print("⚠️ [DarkelfKernelMonitor] Kernel config changed mid-session — possible tampering!")
                self._last_fingerprint_hash = hash(str(current_fingerprint))

    def swap_active(self):
        try:
            output = subprocess.check_output(['sysctl', 'vm.swapusage'], stderr=subprocess.DEVNULL).decode()
            return "used = 0.00M" not in output
        except Exception:
            return False

    def dynamic_pager_running(self):
        try:
            output = subprocess.check_output(['ps', 'aux'], stderr=subprocess.DEVNULL).decode().lower()
            return "dynamic_pager" in output
        except Exception:
            return False

    def system_fingerprint(self):
        keys = [
            "kern.osrevision",
            "kern.osversion",
            "kern.bootargs"
        ]
        results = {}
        for key in keys:
            try:
                val = subprocess.check_output(['sysctl', key], stderr=subprocess.DEVNULL).decode().strip()
                results[key] = val
            except Exception:
                results[key] = "ERROR"
        return results

# 🔐 SecureBuffer + 🧠 MemoryMonitor (Embedded for Darkelf Browser)

class SecureBuffer:
    """
    RAM-locked buffer using mmap + mlock to prevent swapping.
    Use for sensitive in-memory data like session tokens, keys, etc.
    """
    def __init__(self, size=4096):
        self.size = size
        self.buffer = mmap.mmap(-1, self.size)

        # Lock memory into RAM using mlock (macOS-compatible)
        libc = ctypes.CDLL("libc.dylib")
        result = libc.mlock(
            ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self.buffer))),
            ctypes.c_size_t(self.size)
        )
        if result != 0:
            raise RuntimeError("🔒 mlock failed: system may not allow locking memory")

    def write(self, data: bytes):
        self.buffer.seek(0)
        self.buffer.write(data[:self.size])

    def zero(self):
        # Securely zero memory
        ctypes.memset(
            ctypes.addressof(ctypes.c_char.from_buffer(self.buffer)),
            0,
            self.size
        )

    def close(self):
        self.zero()
        self.buffer.close()


class MemoryMonitor(threading.Thread):
    """
    Monitors system memory. If available memory falls below threshold,
    exits the program to prevent swap usage and potential forensic leakage.
    """
    def __init__(self, threshold_mb=150, check_interval=5):
        super().__init__(daemon=True)
        self.threshold = threshold_mb * 1024 * 1024  # Convert MB to bytes
        self.check_interval = check_interval
        self._running = True

    def run(self):
        while self._running:
            mem = psutil.virtual_memory()
            if mem.available < self.threshold:
                print("🔻 LOW MEMORY: < {} MB available. Exiting to prevent swap.".format(self.threshold // (1024 * 1024)))
                sys.exit(1)
            time.sleep(self.check_interval)

    def stop(self):
        self._running = False

class PhishingDetectorZeroTrace:
    """
    Zero-trace phishing detection for Darkelf:
    - No logging
    - No disk writes
    - In-memory heuristics only
    - No LLM, no network
    """

    def __init__(self):
        self.static_blacklist = {
            "paypal-login-security.com",
            "update-now-secure.net",
            "signin-account-verification.info"
        }

        self.suspicious_keywords = {
            "login", "verify", "secure", "account", "bank", "update", "signin", "password"
        }

        self.ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        self.session_flags = set()  # ephemeral, cleared on restart

    def is_suspicious_url(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            host = host.lower()
            url_hash = self._hash_url(url)

            if url_hash in self.session_flags:
                return True, "Previously flagged during session."

            if host in self.static_blacklist:
                return True, f"Domain '{host}' is in static blacklist."

            if self.ip_pattern.match(host):
                return True, "URL uses IP address directly."

            if host.count('.') > 3:
                return True, "Too many subdomains."

            for keyword in self.suspicious_keywords:
                if keyword in host:
                    return True, f"Contains suspicious keyword: '{keyword}'."

            return False, "URL appears clean."

        except Exception as e:
            return True, f"URL parsing error: {str(e)}"

    def analyze_page_content(self, html):
        try:
            lowered = html.lower()
            score = 0
            if "<form" in lowered and ("password" in lowered or "login" in lowered):
                score += 2
            if "re-authenticate" in lowered or "enter your credentials" in lowered:
                score += 1
            if "<iframe" in lowered or "hidden input" in lowered:
                score += 1
            if score >= 2:
                return True, "Suspicious elements found in page."
            return False, "Content appears clean."
        except Exception:
            return False, "Content scan error."

    def flag_url_ephemeral(self, url):
        self.session_flags.add(self._hash_url(url))

    def _hash_url(self, url):
        return hashlib.sha256(url.encode()).hexdigest()

    def show_warning_dialog(self, parent_widget, reason):
        msg = QMessageBox(parent_widget)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Phishing Warning")
        msg.setText("Blocked suspicious site")
        msg.setInformativeText(reason)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec()
        
class SecureCryptoUtils:
    @staticmethod
    def derive_key(password: bytes, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password))


class StealthCovertOps:
    def __init__(self, stealth_mode=True):
        self._log_buffer = []
        self._salt = secrets.token_bytes(16)
        self._log_key = SecureCryptoUtils.derive_key(b"darkelf_master_key", self._salt)
        self._stealth_mode = stealth_mode
        self._authorized = False
        self._cipher = Fernet(self._log_key)

    def encrypt(self, data: str) -> str:
        return self._cipher.encrypt(data.encode()).decode()

    def decrypt(self, enc_data: str) -> str:
        return self._cipher.decrypt(enc_data.encode()).decode()

    def log_to_memory(self, message: str):
        encrypted = self.encrypt(message)
        self._log_buffer.append(encrypted)

    def authorize_flush(self, token: str):
        if token == "darkelf-confirm":
            self._authorized = True

    def flush_log(self, path="covert_log.log", require_auth=True):
        if self._stealth_mode:
            raise PermissionError("Stealth mode active: disk log writing is disabled.")
        if require_auth and not self._authorized:
            raise PermissionError("Log flush not authorized.")
        with open(path, "w") as f:
            for encrypted in self._log_buffer:
                f.write(self.decrypt(encrypted) + "\n")
        return path

    def clear_logs(self):
        for i in range(len(self._log_buffer)):
            buffer_len = len(self._log_buffer[i])
            secure_buffer = ctypes.create_string_buffer(buffer_len)
            ctypes.memset(secure_buffer, 0, buffer_len)
        self._log_buffer.clear()

    def cpu_saturate(self, seconds=5):
        def stress():
            end = time.time() + seconds
            while time.time() < end:
                _ = [x**2 for x in range(1000)]
        for _ in range(os.cpu_count() or 2):
            threading.Thread(target=stress, daemon=True).start()

    def memory_saturate(self, mb=100):
        try:
            _ = bytearray(mb * 1024 * 1024)
            time.sleep(2)
            del _
        except:
            pass

    def fake_activity_noise(self):
        fake_files = [f"/tmp/tempfile_{i}.tmp" if platform.system() != "Windows" else f"C:\\Temp\\tempfile_{i}.tmp"
                      for i in range(5)]
        try:
            for path in fake_files:
                with open(path, "w") as f:
                    f.write("Temporary diagnostic output\n")
                with open(path, "r+b") as f:
                    length = os.path.getsize(path)
                    f.seek(0)
                    f.write(secrets.token_bytes(length))
                os.remove(path)
        except:
            pass

    def process_mask_linux(self):
        if platform.system() == "Linux":
            try:
                with open("/proc/self/comm", "w") as f:
                    f.write("systemd")
            except:
                pass
                
def hardened_random_delay(min_delay=0.1, max_delay=1.0, jitter=0.05):
    secure_random = random.SystemRandom()
    base_delay = secure_random.uniform(min_delay, max_delay)
    noise = secure_random.uniform(-jitter, jitter)
    final_delay = max(0, base_delay + noise)
    time.sleep(final_delay)

class ObfuscatedEncryptedCookieStore:
    def __init__(self, qt_cookie_store: QWebEngineCookieStore):
        self.store = {}  # {obfuscated_name: (encrypted_value, salt)}
        self.qt_cookie_store = qt_cookie_store
        self.qt_cookie_store.cookieAdded.connect(self.intercept_cookie)
        self.master_salt = secrets.token_bytes(16)
        self.master_key = SecureCryptoUtils.derive_key(b"cookie_master_key", self.master_salt)

    def obfuscate_name(self, name: str) -> str:
        return hashlib.sha256(name.encode()).hexdigest()[:16]

    def intercept_cookie(self, cookie):
        hardened_random_delay(0.2, 1.5)
        name = bytes(cookie.name()).decode(errors='ignore')
        value = bytes(cookie.value()).decode(errors='ignore')
        obfuscated_name = self.obfuscate_name(name)
        self.set_cookie(obfuscated_name, value)

    def set_cookie(self, name: str, value: str):
        hardened_random_delay(0.2, 1.5)
        salt = secrets.token_bytes(16)
        key = SecureCryptoUtils.derive_key(self.master_key, salt)
        cipher = Fernet(key)
        encrypted = cipher.encrypt(value.encode())
        self.store[name] = (encrypted, salt)
        del cipher
        del key

    def get_cookie(self, name: str) -> str:
        hardened_random_delay(0.1, 1.0)
        entry = self.store.get(name)
        if entry:
            encrypted, salt = entry
            key = SecureCryptoUtils.derive_key(self.master_key, salt)
            cipher = Fernet(key)
            value = cipher.decrypt(encrypted).decode()
            del cipher
            return value
        return None

    def clear(self):
        hardened_random_delay(0.3, 1.0)
        self._secure_erase()
        self.qt_cookie_store.deleteAllCookies()

    def wipe_memory(self):
        hardened_random_delay(0.2, 0.8)
        self._secure_erase()

    def _secure_erase(self):
        for name in list(self.store.keys()):
            encrypted, salt = self.store[name]
            self.store[name] = (secrets.token_bytes(len(encrypted)), secrets.token_bytes(len(salt)))
            del self.store[name]
        self.store.clear()
        
class NetworkProtector:
    def __init__(self, sock):
        self.sock = sock
        self.secure_random = random.SystemRandom()

    def add_jitter(self, min_delay=0.05, max_delay=0.3):
        jitter = self.secure_random.uniform(min_delay, max_delay)
        time.sleep(jitter)
        print(f"[Darkelf] Jitter applied: {jitter:.3f}s")

    def send_with_padding(self, data: bytes, min_padding=128, max_padding=256):
        target_size = max(len(data), self.secure_random.randint(min_padding, max_padding))
        pad_len = target_size - len(data)
        padding = os.urandom(pad_len)
        padded_data = data + padding
        self.sock.sendall(padded_data)
        print(f"[Darkelf] Sent padded data (original: {len(data)}, padded: {len(padded_data)}, pad: {pad_len})")

    def send_protected(self, data: bytes):
        self.add_jitter()
        self.send_with_padding(data)

# Debounce function to limit the rate at which a function can fire
def debounce(func, wait):
    timeout = None

    def debounced(*args, **kwargs):
        nonlocal timeout
        if timeout is not None:
            timeout.cancel()

        def call_it():
            func(*args, **kwargs)

        timeout = Timer(wait / 1000, call_it)
        timeout.start()

    return debounced
    
class MLKEM768Manager:
    """
    A manager for ML-KEM-768 (Kyber768) using OQS for KEM
    and AES-GCM for symmetric encryption.
    """

    def __init__(self, data_to_encrypt: Optional[str] = None, sync: bool = False):
        self.kem: Optional[oqs.KeyEncapsulation] = None
        self.kyber_public_key: Optional[bytes] = None
        self.kyber_private_key: Optional[bytes] = None
        self.data_to_encrypt: str = data_to_encrypt or "Default secret"
        self.encrypted_data: Optional[str] = None
        self.decrypted_data: Optional[str] = None
        self._encryption_done = threading.Event()

        if sync:
            self.generate_keys_and_encrypt()
        else:
            threading.Thread(target=self.generate_keys_and_encrypt, daemon=True).start()

    def generate_keys_and_encrypt(self) -> None:
        try:
            self.kem = oqs.KeyEncapsulation("ML-KEM-768")
            self.kyber_public_key = self.kem.generate_keypair()
            self.kyber_private_key = self.kem.export_secret_key()
            print("[*] ML-KEM-768 keys generated successfully.")

            ciphertext, shared_secret = self.kem.encap_secret(self.kyber_public_key)

            salt = os.urandom(16)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"mlkem768_aes_key"
            ).derive(shared_secret)

            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            encrypted = aesgcm.encrypt(nonce, self.data_to_encrypt.encode(), None)

            encrypted_blob = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "payload": base64.b64encode(encrypted).decode(),
                "salt": base64.b64encode(salt).decode(),
            }

            self.encrypted_data = base64.b64encode(json.dumps(encrypted_blob).encode()).decode()
            print("[*] Data encrypted successfully.")

            self.decrypt_data()
        except Exception as e:
            print(f"[!] Encryption failed: {e}")
        finally:
            self._encryption_done.set()

    def decrypt_data(self) -> None:
        try:
            self._encryption_done.wait()

            if not self.kem:
                self.kem = oqs.KeyEncapsulation("ML-KEM-768")
                self.kem.import_secret_key(self.kyber_private_key)

            decoded_json = base64.b64decode(self.encrypted_data)
            blob = json.loads(decoded_json)

            ciphertext = base64.b64decode(blob["ciphertext"])
            nonce = base64.b64decode(blob["nonce"])
            encrypted_payload = base64.b64decode(blob["payload"])
            salt = base64.b64decode(blob["salt"])

            if len(nonce) != 12:
                raise ValueError(f"Nonce length is invalid: {len(nonce)} (expected 12 bytes).")

            shared_secret = self.kem.decap_secret(ciphertext)

            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"mlkem768_aes_key"
            ).derive(shared_secret)

            aesgcm = AESGCM(aes_key)
            decrypted = aesgcm.decrypt(nonce, encrypted_payload, None)

            self.decrypted_data = decrypted.decode()
            print("[*] Data decrypted successfully.")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")

    def get_encrypted_data(self) -> Optional[str]:
        self._encryption_done.wait()
        return self.encrypted_data

    def get_decrypted_data(self) -> Optional[str]:
        self._encryption_done.wait()
        return self.decrypted_data

    def get_public_key(self) -> Optional[bytes]:
        return self.kyber_public_key

    def get_private_key(self) -> Optional[bytes]:
        return self.kyber_private_key

class PQCryptoAPI(QObject):
    def __init__(self):
        super().__init__()
        self.kyber = MLKEM768Manager()

    @Slot(result=str)
    def generateKeyPair(self) -> str:
        return self.kyber.get_public_key_b64()

    @Slot(str, str, result=str)
    def encrypt(self, peer_public_key_b64: str, message: str) -> str:
        try:
            return self.kyber.encrypt_with_peer_key(peer_public_key_b64, message)
        except Exception as e:
            return f"Error: {str(e)}"

    @Slot(str, result=str)
    def decrypt(self, encrypted_data_b64: str) -> str:
        try:
            return self.kyber.decrypt_base64(encrypted_data_b64)
        except Exception as e:
            return f"Decryption failed: {str(e)}"
            
# === Enhanced ML Detection & Integration for CustomWebEnginePage ===
class CustomWebEnginePage(QWebEnginePage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.log_file = open("javascript_logs.txt", "a", encoding="utf-8")

        self.model_path = "ml_script_classifier.pkl"
        self.scaler_path = "ml_script_scaler.pkl"
        self.hash_file = ".ml_script_classifier.sha256"
        self.script_classifier_model = None
        self.scaler = None

        if self.verify_or_create_hash(self.model_path, self.hash_file):
            self.script_classifier_model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
        else:
            print(f"[!] Model hash check failed or file missing: {self.model_path}")

    def verify_or_create_hash(self, model_path, hash_path):
        if not os.path.exists(model_path):
            return False
        computed_hash = self.compute_sha256(model_path)
        if os.path.exists(hash_path):
            with open(hash_path, "r") as f:
                stored_hash = f.read().strip()
            return stored_hash == computed_hash
        else:
            with open(hash_path, "w") as f:
                f.write(computed_hash)
            return True

    def compute_sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                h.update(block)
        return h.hexdigest()

    def javaScriptConsoleMessage(self, level, message, line, sourceID):
        log_message = f"JavaScript log (level {level}): {message} (line {line} in {sourceID})"
        print(log_message)

        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "line": line,
            "url": sourceID,
            "message": message
        }

        if self.script_classifier_model and self.scaler:
            if any(k in message.lower() for k in [
                "function", "script", "getcontext", "todataurl", "getimagedata",
                "measuretext", "localstorage", "eval", "googletag", "adsbygoogle",
                "adservice", "doubleclick", "track", "analytics", "fingerprint"
            ]):
                prediction = self.detect_script_class(message)
                log_data["prediction"] = int(prediction)

                if prediction == 2:
                    QMessageBox.warning(None, "Blocked!", "Malicious fingerprinting script detected!")
                elif prediction == 1:
                    print("[Ad/Tracker] Script detected. Blocking not enforced by default.")
        else:
            print("[!] ML model not loaded. Skipping JS analysis.")

        self.log_file.write(json.dumps(log_data) + "\n")
        self.log_file.flush()

    def detect_script_class(self, script_code):
        features = self.extract_features(script_code)
        features_scaled = self.scaler.transform([features])
        return self.script_classifier_model.predict(features_scaled)[0]

    def extract_features(self, script):
        length = len(script)
        cookie = script.count("document.cookie")
        local = script.count("localStorage")
        canvas = sum(script.count(k) for k in ["getContext", "getImageData", "toDataURL"])
        fonts = script.count("fonts") + script.count("measureText")
        network = sum(script.count(k) for k in ["fetch", "XMLHttpRequest"])
        entropy = self.shannon_entropy(script)
        obf_ratio = self.obfuscation_ratio(script)
        return [length, cookie, local, canvas, fonts, network, entropy, obf_ratio]

    def shannon_entropy(self, s):
        if not s:
            return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log2(p) for p in prob)

    def obfuscation_ratio(self, script):
        suspicious = re.findall(r"%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}", script)
        return len(suspicious) / len(script) if script else 0

# Download Manager
class DownloadManager(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.downloads = []
        self.timers = {}

    @Slot(QWebEngineDownloadRequest)
    def handle_download(self, download_item):
        """Handles file downloads and assigns correct file extensions."""
        self.downloads.append(download_item)

        # Get the suggested file name from the URL
        suggested_name = download_item.suggestedFileName() if download_item.suggestedFileName() else download_item.url().fileName()

        # Fallback if the name is still empty
        if not suggested_name:
            suggested_name = download_item.url().path().split("/")[-1]  # Extract from URL

        file_ext = os.path.splitext(suggested_name)[1]

        # Use MIME type if no extension is detected
        if not file_ext or file_ext == "":
            mime_type = download_item.mimeType() if hasattr(download_item, 'mimeType') else None
            ext = self.get_extension_from_mime(mime_type)
            
            if ext:
                suggested_name += ext  # Append correct extension

        # Ask user where to save the file
        save_path, _ = QFileDialog.getSaveFileName(self.parent(), "Save File", suggested_name)
        if save_path:
            download_item.setDownloadDirectory(os.path.dirname(save_path))
            download_item.setDownloadFileName(os.path.basename(save_path))
            download_item.accept()

            progress_dialog = QProgressDialog("Downloading...", "Cancel", 0, 100, self.parent())
            progress_dialog.setWindowTitle("Download")
            progress_dialog.setWindowModality(Qt.WindowModal)
            progress_dialog.setMinimumDuration(0)
            progress_dialog.setValue(0)
            progress_dialog.canceled.connect(lambda: download_item.cancel())

            timer = QTimer(self)
            self.timers[download_item] = timer

            def update_progress():
                received = download_item.receivedBytes()
                total = download_item.totalBytes()
                if total > 0:
                    progress_dialog.setValue(int(received * 100 / total))
                if download_item.isFinished():
                    self.finish_download(progress_dialog, download_item, save_path)

            timer.timeout.connect(update_progress)
            timer.start(500)
        else:
            QMessageBox.warning(self.parent(), "Download Cancelled", "The download has been cancelled.")
            self.downloads.remove(download_item)

    def get_extension_from_mime(self, mime_type):
        """Maps MIME types to correct file extensions."""
        mime_map = {
            "application/x-apple-diskimage": ".dmg",
            "application/octet-stream": "",  # Avoid forcing dmg for unknown types
            "application/x-msdownload": ".exe",
            "application/pdf": ".pdf",
            "application/zip": ".zip",
            "application/x-rar-compressed": ".rar",
            "application/x-7z-compressed": ".7z",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "image/webp": ".webp",
            "image/gif": ".gif",
            "image/bmp": ".bmp",
            "image/tiff": ".tiff",
            "image/x-icon": ".ico",
            "text/plain": ".txt",
            "application/msword": ".doc",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
            "application/vnd.ms-excel": ".xls",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx"
        }

        # First, check our predefined mapping
        if mime_type in mime_map:
            return mime_map[mime_type]

        # If not found, use Python's mimetypes module as a fallback
        guessed_ext = mimetypes.guess_extension(mime_type)
        
        return guessed_ext if guessed_ext else ""

    def finish_download(self, progress_dialog, download_item, save_path):
        """Handles post-download tasks, including metadata stripping."""
        if download_item in self.timers:
            self.timers[download_item].stop()
            del self.timers[download_item]

        if download_item.state() == QWebEngineDownloadRequest.DownloadCompleted:
            progress_dialog.setValue(100)
            progress_dialog.close()
            self.strip_metadata(save_path)
            QMessageBox.information(self.parent(), "Download Finished", f"Downloaded to {save_path}")
        else:
            progress_dialog.close()
            QMessageBox.warning(self.parent(), "Download Failed", "The download has failed.")

        self.downloads.remove(download_item)

    def strip_metadata(self, file_path):
        """Removes metadata from images (JPEG, PNG, WebP) and PDFs."""
        try:
            if file_path.lower().endswith((".jpg", ".jpeg", ".png", ".webp")):
                image = Image.open(file_path)
                if "exif" in image.info:
                    exif_bytes = piexif.dump({})
                    image.save(file_path, exif=exif_bytes)
                    print("Metadata stripped from image:", file_path)
                else:
                    print("No EXIF metadata found in image:", file_path)
            elif file_path.lower().endswith(".pdf"):
                from PyPDF2 import PdfReader, PdfWriter
                reader = PdfReader(file_path)
                writer = PdfWriter()
                
                for page in reader.pages:
                    writer.add_page(page)

                # Strip metadata
                writer.add_metadata({})
                with open(file_path, "wb") as output_pdf:
                    writer.write(output_pdf)
                print("Metadata stripped from PDF:", file_path)
            else:
                print("Metadata removal not supported for:", file_path)

        except Exception as e:
            print(f"Failed to strip metadata from {file_path}: {e}")
            
# DarkelfAIPrivacyManager: Fully integrated into CustomWebEnginePage context
# Spoofs fingerprinting data dynamically using AI-generated personas
# No imports or external dependencies required

class DarkelfAIPrivacyManager:
    def __init__(self, page):
        self.page = page  # Expected to be instance of CustomWebEnginePage
        self.persona = self._choose_persona()

    def _choose_persona(self):
        import random
        personas = [
            {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
                "screen": (1366, 768),
                "language": "en-US",
                "timezone": "America/New_York"
            },
            {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/115.0",
                "screen": (1920, 1080),
                "language": "en-GB",
                "timezone": "Europe/London"
            },
            {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/91.0",
                "screen": (1600, 900),
                "language": "en-US",
                "timezone": "America/Los_Angeles"
            }
        ]
        return random.choice(personas)

    def apply(self):
        self._inject_user_agent()
        self._inject_screen()
        self._inject_language()
        self._inject_timezone()

    def _inject_user_agent(self):
        ua = self.persona['userAgent']
        js = f"""
        Object.defineProperty(navigator, 'userAgent', {{ get: () => "{ua}" }});
        Object.defineProperty(navigator, 'appVersion', {{ get: () => "{ua}" }});
        Object.defineProperty(navigator, 'platform', {{ get: () => "Win32" }});
        """
        self.page.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_screen(self):
        w, h = self.persona['screen']
        js = f"""
        Object.defineProperty(window, 'innerWidth', {{ get: () => {w} }});
        Object.defineProperty(window, 'innerHeight', {{ get: () => {h} }});
        Object.defineProperty(screen, 'width', {{ get: () => {w} }});
        Object.defineProperty(screen, 'height', {{ get: () => {h} }});
        Object.defineProperty(screen, 'availWidth', {{ get: () => {w - 20} }});
        Object.defineProperty(screen, 'availHeight', {{ get: () => {h - 40} }});
        """
        self.page.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_language(self):
        lang = self.persona['language']
        js = f"""
        Object.defineProperty(navigator, 'language', {{ get: () => '{lang}' }});
        Object.defineProperty(navigator, 'languages', {{ get: () => ['{lang}', 'en'] }});
        """
        self.page.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_timezone(self):
        tz = self.persona['timezone']
        js = f"""
        Intl.DateTimeFormat.prototype.resolvedOptions = function() {{
            return {{ timeZone: "{tz}" }};
        }};
        """
        self.page.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)
        
class CustomWebEnginePage(QWebEnginePage):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        self.setup_ssl_configuration()
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0")
        self.inject_all_scripts()
        self.privacy_ai = DarkelfAIPrivacyManager(self)
        self.privacy_ai.apply()
        
    def createWindow(self, _type):
        return self.browser.create_new_tab().page()

    def acceptNavigationRequest(self, url, _type, isMainFrame):
        if self.browser.adblock_rules.should_block(url.toString()):
            return False
        if url.scheme() == 'http' and self.browser.https_enforced:
            secure_url = QUrl(url)
            secure_url.setScheme('https')
            self.setUrl(secure_url)
            return False
        return super().acceptNavigationRequest(url, _type, isMainFrame)

    def setup_ssl_configuration(self):
        configuration = QSslConfiguration.defaultConfiguration()
        configuration.setProtocol(QSsl.TlsV1_3)
        QSslConfiguration.setDefaultConfiguration(configuration)

    def inject_script(self, script_str, injection_point=QWebEngineScript.DocumentReady, subframes=True):
        script = QWebEngineScript()
        script.setSourceCode(script_str)
        script.setInjectionPoint(injection_point)
        script.setWorldId(QWebEngineScript.MainWorld)
        script.setRunsOnSubFrames(subframes)
        self.profile.scripts().insert(script)

    def inject_all_scripts(self):
        self.inject_geolocation_override()
        self.spoof_window_dimensions_darkelf_style()
        self.apply_letterboxing_stealth()
        self.block_shadow_dom_inspection()
        self.block_tracking_requests()
        self.protect_fingerprinting()
        self.spoof_canvas_api()
        self.stealth_webrtc_block()
        self.block_webrtc_sdp_logging()
        self.block_supercookies()
        self.block_etag_and_cache_tracking()
        self.block_referrer_headers()
        self.spoof_user_agent()
        self.spoof_plugins_and_mimetypes()
        self.spoof_timezone()
        self.spoof_media_queries()
        self.spoof_battery_api()
        self.spoof_network_connection()
        self.spoof_device_memory()
        self.disable_pointer_detection()
        self.block_cookie_beacon_getstats()
        self.block_audio_context()
        self.spoof_navigator_basics()
        self.block_window_chrome()
        self.spoof_permissions_api()
        self.fuzz_timing_functions()
        self.spoof_storage_estimate()
        self.block_fontfaceset_api()
        self.block_idle_detector()
        self.spoof_language_headers()
        self.hide_webdriver_flag()
        self.block_webauthn()
        self.patch_youtube_compatibility()
        self.block_fedcm_api()
        self.block_speech_synthesis()
        self.clamp_performance_timers()
        self.spoof_audio_fingerprint_response()
        self.block_web_bluetooth()
        self.block_cookie_banners()
        self.block_webgpu_api()
        self.harden_webworkers()
        self._inject_font_protection()
        self.spoof_font_loading_checks()
        self.setup_csp()

    def inject_geolocation_override(self):
        script = """
        (function() {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition = function(success, error, options) {
                    if (error) {
                        error({ code: 1, message: "Geolocation access denied." });
                    }
                };
                navigator.geolocation.watchPosition = function(success, error, options) {
                    if (error) {
                        error({ code: 1, message: "Geolocation access denied." });
                    }
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_font_protection(self):
        js = """
        // Override measureText to return constant dimensions
        Object.defineProperty(CanvasRenderingContext2D.prototype, 'measureText', {
            value: function(text) {
                return {
                    width: 100,
                    actualBoundingBoxLeft: 0,
                    actualBoundingBoxRight: 100
                };
            },
            configurable: true
        });

        // Spoof getComputedStyle to return constant font info
        const originalGetComputedStyle = window.getComputedStyle;
        window.getComputedStyle = function(...args) {
            const style = originalGetComputedStyle.apply(this, args);
            return new Proxy(style, {
                get(target, prop) {
                    if (typeof prop === 'string' && prop.toLowerCase().includes('font')) {
                        return '16px Arial';
                    }
                    return target[prop];
                }
            });
        };

        // Normalize offsetWidth/offsetHeight
        Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
            get: function () { return 100; },
            configurable: true
        });
        Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
            get: function () { return 20; },
            configurable: true
        });

        console.log('[DarkelfAI] Font fingerprinting vectors spoofed.');
        """
        self.inject_script(js, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_font_loading_checks(self):
        script = """
        (function() {
            const originalCheck = document.fonts.check;
            document.fonts.check = function(...args) {
                return true;
            };
            const originalLoad = document.fonts.load;
            document.fonts.load = function(...args) {
                return new Promise(resolve => {
                    setTimeout(() => resolve(["Arial"]), Math.random() * 80 + 50);
                });
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_webgpu_api(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'gpu', {
                get: () => undefined
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def harden_webworkers(self):
        script = """
        (function() {
            const originalWorker = window.Worker;
            window.Worker = new Proxy(originalWorker, {
                construct(target, args) {
                    try {
                        if (args[0] instanceof Blob) {
                            const codeURL = URL.createObjectURL(args[0]);
                            return new target(codeURL);
                        }
                    } catch (e) {}
                    return new target(...args);
                }
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_cookie_banners(self):
        script = """
        (() => {
            const selectors = [
                '[id*="cookie"]',
                '[class*="cookie"]',
                '[aria-label*="cookie"]',
                '[role="dialog"]',
                '[role="alertdialog"]',
                'div[class*="consent"]',
                'div[class*="banner"]',
                'div[class*="notice"]',
                'div[class*="gdpr"]',
                'div[class*="privacy"]',
                'div[class*="optin"]'
            ];

            const textTriggers = [
                /cookie/i,
                /consent/i,
                /gdpr/i,
                /privacy/i,
                /we use/i,
                /accept.*cookies/i,
                /manage.*preferences/i,
                /your.*choices/i
            ];

            const buttonDenyRegex = /\\b(reject|deny|refuse|disagree|decline|only necessary|essential only)\\b/i;

            function isCookieBanner(el) {
                if (!el || !el.tagName) return false;
                const txt = (el.textContent || '').trim().toLowerCase();
                return textTriggers.some(re => re.test(txt));
            }

            function removeElement(el) {
                try {
                    el.remove?.();
                    if (el.parentNode) el.parentNode.removeChild(el);
                } catch (_) {}
            }

            function clickDenyButtons() {
                try {
                    const all = document.querySelectorAll('button, a, input[type="button"]');
                    for (const el of all) {
                        const txt = (el.textContent || el.value || '').toLowerCase();
                        if (buttonDenyRegex.test(txt)) {
                            el.click?.();
                        }
                    }
                } catch (_) {}
            }

            function removeBanners() {
                try {
                    const all = new Set();

                    for (const sel of selectors) {
                        try {
                            document.querySelectorAll(sel).forEach(el => {
                                if (isCookieBanner(el)) all.add(el);
                            });
                        } catch (_) {}
                    }

                    for (const el of all) {
                        removeElement(el);
                    }

                    clickDenyButtons();
                } catch (_) {}
            }

            function shadowDOMScan(root) {
                try {
                    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT, null, false);
                    while (walker.nextNode()) {
                        const node = walker.currentNode;
                        if (node.shadowRoot) {
                            removeBanners(node.shadowRoot);
                            shadowDOMScan(node.shadowRoot);
                        }
                    }
                } catch (_) {}
            }

            function safeIdle(cb) {
                if ('requestIdleCallback' in window) {
                    requestIdleCallback(cb, { timeout: 300 });
                } else {
                    setTimeout(cb, 100);
                }
            }

            function harden() {
                try {
                    removeBanners();
                    shadowDOMScan(document);

                    const observer = new MutationObserver(() => {
                        safeIdle(() => {
                            removeBanners();
                            shadowDOMScan(document);
                        });
                    });

                    observer.observe(document.documentElement, {
                        childList: true,
                        subtree: true
                    });
                } catch (_) {}
            }

            if (document.readyState === 'complete' || document.readyState === 'interactive') {
                safeIdle(harden);
            } else {
                window.addEventListener('DOMContentLoaded', () => safeIdle(harden));
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_webauthn(self):
        script = """
        (function() {
            if (navigator.credentials) {
                navigator.credentials.get = function() {
                    return Promise.reject("WebAuthn disabled for security.");
                };
                navigator.credentials.create = function() {
                    return Promise.reject("WebAuthn creation disabled.");
                };
            }
            if (window.PublicKeyCredential) {
                window.PublicKeyCredential = undefined;
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_web_bluetooth(self):
        script = """
        (function() {
            if ('bluetooth' in navigator) {
                Object.defineProperty(navigator, 'bluetooth', {
                    get: () => ({
                        requestDevice: () => Promise.reject('Web Bluetooth disabled.')
                    })
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_speech_synthesis(self):
        script = """
        (function() {
            if ('speechSynthesis' in window) {
                window.speechSynthesis.getVoices = function() {
                    return [];
                };
                Object.defineProperty(window, 'speechSynthesis', {
                    get: () => ({
                        getVoices: () => []
                    })
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def clamp_performance_timers(self):
        script = """
        (function() {
            const originalNow = performance.now;
            performance.now = function() {
                return Math.floor(originalNow.call(performance) / 10) * 10;
            };
            const originalDateNow = Date.now;
            Date.now = function() {
                return Math.floor(originalDateNow() / 10) * 10;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_audio_fingerprint_response(self):
        script = """
        (function() {
            const originalGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = function() {
                const data = originalGetChannelData.call(this);
                const spoofed = new Float32Array(data.length);
                for (let i = 0; i < data.length; i++) {
                    spoofed[i] = 0.5;  // static waveform to defeat fingerprinting
                }
                return spoofed;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_fedcm_api(self):
        script = """
        (function() {
            if (navigator && 'identity' in navigator) {
                navigator.identity = undefined;
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def patch_youtube_compatibility(self):
        script = """
        (function() {
            const override = () => {
                const hostname = window.location.hostname;
                if (hostname.includes("youtube.com") || hostname.includes("ytimg.com")) {

                    // Restore AudioContext
                    if (typeof AudioContext === 'undefined' && typeof webkitAudioContext !== 'undefined') {
                        window.AudioContext = webkitAudioContext;
                    }   

                    // Fake Permissions API for mic/camera
                    if (navigator.permissions && navigator.permissions.query) {
                        const originalQuery = navigator.permissions.query.bind(navigator.permissions);
                            navigator.permissions.query = function(param) {
                            if (param && (param.name === 'microphone' || param.name === 'camera')) {
                                return Promise.resolve({ state: 'denied' });
                            }
                            return originalQuery(param);
                        };
                    }

                    // Stub WebAuthn
                    if (!window.PublicKeyCredential) {
                        window.PublicKeyCredential = function() {};
                    }

                    // Fingerprint resistance: spoof plugins and webdriver
                    Object.defineProperty(navigator, 'webdriver', { get: () => false });
                    Object.defineProperty(navigator, 'plugins', {
                        get: () => [1, 2, 3], // fake plugin list
                    });
                    Object.defineProperty(navigator, 'languages', {
                        get: () => ['en-US', 'en'],
                    });

                    // Force autoplay: mute video early
                    const muteVideos = () => {
                        const vids = document.querySelectorAll('video');
                        vids.forEach(v => {
                            v.muted = true;
                            v.autoplay = true;
                            v.playsInline = true;
                            v.play().catch(() => {});
                        });
                    };
                    document.addEventListener('DOMContentLoaded', muteVideos);
                    setTimeout(muteVideos, 300); // backup

                }
            };

            if (document.readyState === 'loading') {
                document.addEventListener('readystatechange', () => {
                    if (document.readyState === 'interactive') override();
                });
            } else {
                override();
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_language_headers(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'language', {
                get: function () { return 'en-US'; }
            });
            Object.defineProperty(navigator, 'languages', {
                get: function () { return ['en-US', 'en']; }
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def hide_webdriver_flag(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => false
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_idle_detector(self):
        script = """
        (function() {
            if ('IdleDetector' in window) {
                window.IdleDetector = function() {
                    throw new Error("IdleDetector blocked for privacy reasons.");
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_navigator_basics(self):
        script = """
        (function() {
            Object.defineProperty(navigator, "webdriver", {
                get: () => false,
                configurable: true
            });
            Object.defineProperty(navigator, "doNotTrack", {
                get: () => "1",
                configurable: true
            });
            Object.defineProperty(navigator, "maxTouchPoints", {
                get: () => 1,
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_window_chrome(self):
        script = """
        (function() {
            Object.defineProperty(window, 'chrome', {
                value: undefined,
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
   
    def spoof_permissions_api(self):
        script = """
        (function() {
            if (navigator.permissions && navigator.permissions.query) {
                navigator.permissions.query = function(params) {
                    return Promise.resolve({ state: 'denied' });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
   
    def fuzz_timing_functions(self):
        script = """
        (function() {
            performance.now = () => Math.floor(Math.random() * 50) + 1;
            Date.now = () => Math.floor(new Date().getTime() / 1000) * 1000;
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
    
    def spoof_storage_estimate(self):
        script = """
        (function() {
            if (navigator.storage && navigator.storage.estimate) {
                navigator.storage.estimate = function() {
                    return Promise.resolve({ quota: 120000000, usage: 50000000 });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_fontfaceset_api(self):
        script = """
        (function() {
            try {
                document.fonts = {
                    ready: Promise.resolve(),
                    check: () => false,
                    load: () => Promise.reject("Blocked"),
                    values: () => [],
                    size: 0
                };
            } catch (e) {
                console.warn("FontFaceSet override failed", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_eval_and_websockets(self):
        script = """
        (function() {
            // Monitor eval() usage, but do not block it
            const originalEval = window.eval;
            window.eval = function(code) {
                try {
                    if (typeof code === 'string' && code.length > 0) {
                        console.debug("eval() used — allowing:", code.slice(0, 100));
                    }
                    return originalEval(code);
                } catch (e) {
                    console.warn("eval() error:", e);
                    return undefined;
                }
            };

            // Light filter for suspicious Function constructor usage
            const OriginalFunction = Function;
            window.Function = function(...args) {
                const code = args.join(' ');
                if (code.includes('eval') || code.includes('setTimeout')) {
                    console.debug("Suspicious Function constructor blocked:", code.slice(0, 100));
                    return function() {};  // return a dummy
                }
                return OriginalFunction(...args);
            };

            // Safe WebSocket dummy that won't throw or crash detection
            const DummySocket = function(url, protocols) {
                console.debug("WebSocket attempt intercepted:", url);
                return {
                    send: () => {},
                    close: () => {},
                    addEventListener: () => {},
                    removeEventListener: () => {},
                    readyState: 3,  // CLOSED
                    bufferedAmount: 0
                };
            };

            // Only override WebSocket if it's present
            if ('WebSocket' in window) {
                window.WebSocket = DummySocket;
                Object.defineProperty(window, 'WebSocket', {
                    value: DummySocket,
                    writable: false,
                    configurable: true
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_cookie_beacon_getstats(self):
        script = """
        (function() {
            // Block document.cookie (read/write)
            Object.defineProperty(document, 'cookie', {
                get: function() {
                    return "";
                },
                set: function(_) {
                    console.warn("Blocked attempt to set document.cookie");
                },
                configurable: true
            });

            // Block navigator.sendBeacon
            if (navigator.sendBeacon) {
                navigator.sendBeacon = function() {
                    console.warn("sendBeacon blocked");
                    return false;
                };
            }

            // Block WebRTC getStats (used in fingerprinting)
            if (window.RTCPeerConnection) {
                const original = RTCPeerConnection.prototype.getStats;
                RTCPeerConnection.prototype.getStats = function() {
                    console.warn("RTCPeerConnection.getStats blocked");
                    return Promise.resolve({});
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def apply_letterboxing_stealth(self):
        script = """
        (function () {
            const getRandomOffset = () => Math.floor(Math.random() * 5) - 2;  // -2 to +2 pixels

            // Spoof window dimensions
            Object.defineProperty(window, 'innerWidth', {
                get: () => 1200 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(window, 'innerHeight', {
                get: () => 800 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(window, 'outerWidth', {
                get: () => 1600 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(window, 'outerHeight', {
                get: () => 900 + getRandomOffset(),
                configurable: true
            });

            // Spoof screen dimensions
            Object.defineProperty(screen, 'width', {
                get: () => 1600 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(screen, 'height', {
                get: () => 900 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(screen, 'availWidth', {
                get: () => 1600 + getRandomOffset(),
                configurable: true
            });
            Object.defineProperty(screen, 'availHeight', {
                get: () => 860 + getRandomOffset(),
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_audio_context(self):
        script = """
        (function() {
            try {
                // Disable AudioContext completely
                window.AudioContext = undefined;
                window.webkitAudioContext = undefined;

                // If already instantiated, override methods
                const noop = function() {};

                if (typeof OfflineAudioContext !== "undefined") {
                    OfflineAudioContext.prototype.startRendering = noop;
                    OfflineAudioContext.prototype.suspend = noop;
                }

                if (typeof AudioContext !== "undefined") {
                    AudioContext.prototype.createAnalyser = function() {
                        return {
                            getFloatFrequencyData: function(array) {
                                for (let i = 0; i < array.length; i++) {
                                    array[i] = -100 + Math.random();  // Fake data
                                }
                            }
                        };
                    };
                }
            } catch (e) {
                console.warn("AudioContext block failed:", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_device_memory(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'deviceMemory', {
                get: () => 4,  // Common value in real browsers
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def disable_pointer_detection(self):
        script = """
        (function() {
            // Remove touch support
            Object.defineProperty(navigator, 'maxTouchPoints', {
                get: () => 0,
                configurable: true
            });

            // Override pointer/touch event support checks
            if ('ontouchstart' in window) {
                delete window.ontouchstart;
            }

            // Disable pointer media queries
            const style = document.createElement('style');
            style.innerHTML = `
                @media (pointer: coarse), (hover: none) {
                    body::before {
                        content: none !important;
                    }
                }
            `;
            document.head.appendChild(style);
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_battery_api(self):
        script = """
        (function() {
            if ('getBattery' in navigator) {
                navigator.getBattery = function() {
                    return Promise.resolve({
                        charging: true,
                        chargingTime: 0,
                        dischargingTime: Infinity,
                        level: 1.0,
                        onchargingchange: null,
                        onchargingtimechange: null,
                        ondischargingtimechange: null,
                        onlevelchange: null,
                        addEventListener: () => {},
                        removeEventListener: () => {}
                    });
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_network_connection(self):
        script = """
        (function() {
            if ('connection' in navigator) {
                Object.defineProperty(navigator, 'connection', {
                    get: () => ({
                        downlink: 10,
                        effectiveType: '4g',
                        rtt: 50,
                        saveData: false,
                        type: 'wifi',
                        onchange: null,
                        addEventListener: () => {},
                        removeEventListener: () => {}
                    }),
                    configurable: true
                });
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_plugins_and_mimetypes(self):
        script = """
        (function() {
            Object.defineProperty(navigator, 'plugins', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null
                }),
                configurable: true
            });

            Object.defineProperty(navigator, 'mimeTypes', {
                get: () => ({
                    length: 0,
                    item: () => null,
                    namedItem: () => null
                }),
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_timezone(self):
        script = """
        (function() {
            const spoofedOffset = 0; // UTC

            Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
                value: function() {
                    return {
                        timeZone: "UTC",
                        locale: "en-US"
                    };
                },
                configurable: true
            });

            const originalGetTimezoneOffset = Date.prototype.getTimezoneOffset;
            Date.prototype.getTimezoneOffset = function() {
                return spoofedOffset;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_media_queries(self):
        script = """
        (function() {
            const fakeMatchMedia = (query) => {
                return {
                    matches: false,
                    media: query,
                    onchange: null,
                    addListener: () => {},
                    removeListener: () => {},
                    addEventListener: () => {},
                    removeEventListener: () => {},
                    dispatchEvent: () => false
                };
            };
            window.matchMedia = fakeMatchMedia;
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_referrer_headers(self):
        script = """
        (function() {
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.addEventListener('readystatechange', function() {
                    if (this.readyState === 1) {
                        try {
                            this.setRequestHeader('Referer', '');
                            this.setRequestHeader('Referrer-Policy', 'no-referrer');
                        } catch (e) {}
                    }
                });
                return originalOpen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.referrer = '';
                init.referrerPolicy = 'no-referrer';
                init.headers = Object.assign({}, init.headers || {}, {
                    'Referer': '',
                    'Referrer-Policy': 'no-referrer'
                });
                return originalFetch(resource, init);
            };

            document.addEventListener('DOMContentLoaded', function() {
                const meta = document.createElement('meta');
                meta.name = 'referrer';
                meta.content = 'no-referrer';
                document.head.appendChild(meta);
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def spoof_user_agent(self):
        script = """
        (function() {
            const spoofedUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0";

            Object.defineProperty(navigator, 'userAgent', {
                get: () => spoofedUA,
                configurable: true
            });
            Object.defineProperty(navigator, 'appVersion', {
                get: () => spoofedUA,
                configurable: true
            });
            Object.defineProperty(navigator, 'platform', {
                get: () => 'Win32',
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_window_dimensions_darkelf_style(self):
        script = """
        (function () {
            // Spoof fixed dimensions using Darkelf's privacy strategy (inspired by Tor-style size bucketing)
            const fixedWindow = {
                innerWidth: 1000,
                innerHeight: 1000,
                outerWidth: 1000,
                outerHeight: 1000
            };

            Object.defineProperty(window, 'innerWidth', {
                get: () => fixedWindow.innerWidth,
                configurable: true
            });
            Object.defineProperty(window, 'innerHeight', {
                get: () => fixedWindow.innerHeight,
                configurable: true
            });
            Object.defineProperty(window, 'outerWidth', {
                get: () => fixedWindow.outerWidth,
                configurable: true
            });
            Object.defineProperty(window, 'outerHeight', {
                get: () => fixedWindow.outerHeight,
                configurable: true
            });

            Object.defineProperty(screen, 'width', {
                get: () => 1000,
                configurable: true
            });
            Object.defineProperty(screen, 'height', {
                get: () => 1000,
                configurable: true
            });
            Object.defineProperty(screen, 'availWidth', {
                get: () => 1000,
                configurable: true
            });
            Object.defineProperty(screen, 'availHeight', {
                get: () => 980,
                configurable: true
            });
            Object.defineProperty(screen, 'colorDepth', {
                get: () => 24,
                configurable: true
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_shadow_dom_inspection(self):
        script = """
        (function () {
            const originalAttachShadow = Element.prototype.attachShadow;
            Element.prototype.attachShadow = function(init) {
                init.mode = 'closed';  // Force closed mode
                return originalAttachShadow.call(this, init);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_tracking_requests(self):
        script = """
        (function () {
            const suspiciousPatterns = ['tracker', 'analytics', 'collect', 'pixel'];

            const shouldBlock = (url) => {
                return suspiciousPatterns.some(p => url.includes(p));
            };

            const originalXHRopen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                if (shouldBlock(url)) {
                    console.warn('Blocked XHR to:', url);
                    return;
                }
                return originalXHRopen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(...args) {
                const url = args[0];
                if (typeof url === 'string' && shouldBlock(url)) {
                    console.warn('Blocked fetch to:', url);
                    return new Promise(() => {}); // Never resolves
                }
                return originalFetch.apply(this, args);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_webrtc_sdp_logging(self):
        script = """
        (function() {
            if (!window.RTCPeerConnection) return;

            const OriginalRTCPeerConnection = window.RTCPeerConnection;
            window.RTCPeerConnection = function(...args) {
                const pc = new OriginalRTCPeerConnection(...args);

                const wrap = (method) => {
                    if (pc[method]) {
                        const original = pc[method].bind(pc);
                        pc[method] = async function(...mArgs) {
                            const result = await original(...mArgs);
                            if (result && result.sdp) {
                                result.sdp = result.sdp.replace(/a=candidate:.+\\r\\n/g, '');
                                result.sdp = result.sdp.replace(/ice-ufrag:.+\\r\\n/g, '');
                                result.sdp = result.sdp.replace(/ice-pwd:.+\\r\\n/g, '');
                            }
                            return result;
                        };
                    }
                };

                wrap("createOffer");
                wrap("createAnswer");

                return pc;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def block_supercookies(self):
        script = """
        (function() {
            try {
                // Nullify openDatabase (WebSQL)
                try { delete window.openDatabase; } catch (e) {}
                Object.defineProperty(window, 'openDatabase', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify localStorage
                try { delete window.localStorage; } catch (e) {}
                Object.defineProperty(window, 'localStorage', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify sessionStorage
                try { delete window.sessionStorage; } catch (e) {}
                Object.defineProperty(window, 'sessionStorage', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify indexedDB
                try { delete window.indexedDB; } catch (e) {}
                Object.defineProperty(window, 'indexedDB', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify cookies
                Object.defineProperty(document, 'cookie', {
                    get: function() { return ""; },
                    set: function() {},
                    configurable: false
                });

                // Nullify BroadcastChannel
                try { delete window.BroadcastChannel; } catch (e) {}
                Object.defineProperty(window, 'BroadcastChannel', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify SharedWorker
                try { delete window.SharedWorker; } catch (e) {}
                Object.defineProperty(window, 'SharedWorker', {
                    value: null,
                    writable: false,
                    configurable: false
                });

                // Nullify ServiceWorker
                if ('serviceWorker' in navigator) {
                    Object.defineProperty(navigator, 'serviceWorker', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

                // Nullify CacheStorage
                if ('caches' in window) {
                    Object.defineProperty(window, 'caches', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

                // Nullify FileSystem API (Chrome legacy supercookie)
                if ('webkitRequestFileSystem' in window) {
                    window.webkitRequestFileSystem = null;
                    window.requestFileSystem = null;
                }

                // Nullify persistent storage access
                if ('storage' in navigator && 'persist' in navigator.storage) {
                    Object.defineProperty(navigator, 'storage', {
                        value: null,
                        writable: false,
                        configurable: false
                    });
                }

            } catch (e) {
                console.warn("Supercookie nullification error:", e);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def protect_fingerprinting(self):
        script = """
        (function() {
            // === Canvas Fingerprinting Randomization ===
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
                const data = originalGetImageData.apply(this, arguments);
                for (let i = 0; i < data.data.length; i += 4) {
                    data.data[i]     += Math.floor(Math.random() * 10) - 5;
                    data.data[i + 1] += Math.floor(Math.random() * 10) - 5;
                    data.data[i + 2] += Math.floor(Math.random() * 10) - 5;
                }
                return data;
            };

            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const result = originalToDataURL.apply(this, arguments);
                return result + "#noise";
            };

            const originalToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {
                return originalToBlob.call(this, function(blob) {
                    callback(blob);
                }, ...args);
            };

            // === WebGL Spoofing ===
            const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {
                if (param === 37445) return "Intel Inc.";
                if (param === 37446) return "Intel Iris OpenGL Engine";
                return originalGetParameter.apply(this, arguments);
            };

            // === Font Fingerprinting Spoofing ===
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = originalMeasureText.apply(this, arguments);
                metrics.width += Math.random(); // subpixel alteration
                return metrics;
            };

            const originalComputedStyle = window.getComputedStyle;
            window.getComputedStyle = function(el, pseudo) {
                const style = originalComputedStyle.call(this, el, pseudo);
                Object.defineProperty(style, "fontFamily", {
                    get: function() { return "Arial, sans-serif"; }
                });
                return style;
            };

            // === Audio Fingerprinting Obfuscation ===
            const originalCreateAnalyser = AudioContext.prototype.createAnalyser;
            AudioContext.prototype.createAnalyser = function() {
                const analyser = originalCreateAnalyser.apply(this, arguments);
                const original = analyser.getFloatFrequencyData;
                analyser.getFloatFrequencyData = function(array) {
                    for (let i = 0; i < array.length; i++) {
                        array[i] = -100 + Math.random() * 5;
                    }
                    return original.apply(this, arguments);
                };
                return analyser;
            };

            // === Screen/Locale/Timezone Spoofing ===
            Object.defineProperty(navigator, "language", {
                get: () => ["en-US", "fr-FR", "de-DE"][Math.floor(Math.random() * 3)]
            });
            Object.defineProperty(navigator, "languages", {
                get: () => ["en-US", "en"]
            });

            Object.defineProperty(screen, "width", {
                get: () => 1280 + Math.floor(Math.random() * 160)
            });
            Object.defineProperty(screen, "height", {
                get: () => 720 + Math.floor(Math.random() * 160)
            });
            Object.defineProperty(screen, "colorDepth", {
                get: () => 24
            });

            Object.defineProperty(navigator, "hardwareConcurrency", {
                get: () => [2, 4, 8][Math.floor(Math.random() * 3)]
            });

            // === Timezone Spoofing ===
            const originalDateToString = Date.prototype.toString;
            Date.prototype.toString = function() {
                return originalDateToString.apply(new Date('1970-01-01T00:00:00Z'), arguments);
            };

            // === Media Devices ===
            Object.defineProperty(navigator, "mediaDevices", {
                get: () => undefined
            });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def protect_fonts(self):
        script = """
        (function() {
            const original = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = original.call(this, text);
                metrics.width += (Math.random() * 5 - 2.5);
                return metrics;
            };

            const originalComputed = window.getComputedStyle;
            window.getComputedStyle = function(el, pseudo) {
                const cs = originalComputed.call(window, el, pseudo);
                const modified = new Proxy(cs, {
                    get(target, prop) {
                        if (prop === "fontFamily") return "Arial";
                        return Reflect.get(target, prop);
                    }
                });
                return modified;
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def spoof_canvas_api(self):

        # Generate session-specific noise seed
        seed = random.randint(1000, 9999) + int(time.time()) % 10000

        script = f"""
        (function () {{
            const seed = {seed};
            const getNoise = () => Math.floor(Math.sin(seed * 1000 + performance.now()) * 10) % 5;

            // getImageData override
            const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {{
                const imageData = originalGetImageData.call(this, x, y, w, h);
                for (let i = 0; i < imageData.data.length; i += 4) {{
                    imageData.data[i] += getNoise();
                    imageData.data[i + 1] += getNoise();
                    imageData.data[i + 2] += getNoise();
                }}
                return imageData;
            }};

            // toDataURL override
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {{
                const ctx = this.getContext("2d");
                if (ctx) ctx.fillRect(getNoise(), getNoise(), 1, 1);
                return originalToDataURL.apply(this, arguments);
            }};

            // measureText spoof
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {{
                const metrics = originalMeasureText.call(this, text);
                metrics.width += getNoise();
                return metrics;
            }};

            // toBlob override
            const originalToBlob = HTMLCanvasElement.prototype.toBlob;
            HTMLCanvasElement.prototype.toBlob = function(callback, ...args) {{
                const ctx = this.getContext("2d");
                if (ctx) ctx.fillRect(getNoise(), getNoise(), 1, 1);
                return originalToBlob.call(this, callback, ...args);
            }};
        }})();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)
        
    def stealth_webrtc_block(self):
        script = """
        (() => {
            const block = (target, key) => {
                try {
                    Object.defineProperty(target, key, {
                        get: () => undefined,
                        set: () => {},
                        configurable: false
                    });
                    delete target[key];
                } catch (e) {
                    // Silently ignore expected errors (e.g. non-configurable)
                }
            };

            const targets = [
                [window, 'RTCPeerConnection'],
                [window, 'webkitRTCPeerConnection'],
                [window, 'mozRTCPeerConnection'],
                [window, 'RTCDataChannel'],
                [navigator, 'mozRTCPeerConnection'],
                [navigator, 'mediaDevices']
            ];

            targets.forEach(([obj, key]) => block(obj, key));

            // Iframe defense
            new MutationObserver((muts) => {
                for (const m of muts) {
                    m.addedNodes.forEach((node) => {
                        if (node.tagName === 'IFRAME') {
                            try {
                                const w = node.contentWindow;
                                targets.forEach(([obj, key]) => block(w, key));
                                targets.forEach(([obj, key]) => block(w.navigator, key));
                            } catch (e) {}
                        }
                    });
                }
            }).observe(document, { childList: true, subtree: true });

            console.log('[DarkelfAI] WebRTC APIs neutralized.');
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def block_etag_and_cache_tracking(self):
        script = """
        (function() {
            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                this.addEventListener('readystatechange', function() {
                    if (this.readyState === 1) {
                        try {
                            this.setRequestHeader('If-None-Match', '');
                            this.setRequestHeader('Cache-Control', 'no-store');
                            this.setRequestHeader('Pragma', 'no-cache');
                        } catch (e) {
                            console.warn("Header blocking error:", e);
                        }
                    }
                });
                return originalOpen.apply(this, arguments);
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.headers = Object.assign({}, init.headers || {}, {
                    'If-None-Match': '',
                    'Cache-Control': 'no-store',
                    'Pragma': 'no-cache'
                });
                return originalFetch(resource, init);
            };
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def setup_csp(self):
        script = """
        (function() {
            const meta = document.createElement('meta');
            meta.httpEquiv = "Content-Security-Policy";
            meta.content = "default-src 'self', script-src 'self' 'nonce-12345' 'strict-dynamic' https:, style-src 'self' 'unsafe-inline', img-src 'self' http: https: data: blob:, frame-src 'self' blob: data: https://account-api.proton.me https://account-api.tuta.io https://app.tuta.com/login, object-src 'self' blob:, child-src 'self' data: blob:, report-uri https://reports.proton.me/reports/csp, frame-ancestors 'self', base-uri 'self'";
            document.head.appendChild(meta);
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation, subframes=False)

# Custom Web Engine View
class CustomWebEngineView(QWebEngineView):
    def __init__(self, browser, parent=None):
        super().__init__(parent)
        self.browser = browser
        custom_page = CustomWebEnginePage(self.browser, self)
        self.setPage(custom_page)
        self.configure_sandbox()
        self.configure_channel()
        profile = custom_page.profile()
        self.inject_crypto_script(profile)
        self.inject_crypto_prng_script(profile)

    def configure_channel(self):
        self.channel = QWebChannel(self.page())
        self.pqcrypto = PQCryptoAPI()
        self.channel.registerObject("darkelfCrypto", self.pqcrypto)
        self.page().setWebChannel(self.channel)

    def inject_crypto_script(self, profile: QWebEngineProfile):
        js = """
        (function() {
            var script = document.createElement('script');
            script.src = "qrc:///qtwebchannel/qwebchannel.js";
            script.onload = function() {
                new QWebChannel(qt.webChannelTransport, function(channel) {
                    const crypto = channel.objects.darkelfCrypto;
                    crypto.generateKeyPair().then(function(pubkey) {
                        console.log("Public Key:", pubkey);
                        crypto.encrypt(pubkey, "Post-quantum web crypto!").then(function(enc) {
                            console.log("Encrypted:", enc);
                            crypto.decrypt(enc).then(function(plain) {
                                console.log("Decrypted:", plain);
                            });
                        });
                    });
                });
            };
            document.head.appendChild(script);
        })();
        """
        script_obj = QWebEngineScript()
        script_obj.setSourceCode(js)
        script_obj.setInjectionPoint(QWebEngineScript.DocumentReady)
        script_obj.setWorldId(QWebEngineScript.MainWorld)
        script_obj.setRunsOnSubFrames(False)
        profile.scripts().insert(script_obj)

    def inject_crypto_prng_script(self, profile: QWebEngineProfile):
        js = """
        (function() {
            async function getRandomBytes(length) {
                return window.crypto.getRandomValues(new Uint8Array(length));
            }
            window.cryptoPRNG = {
                getRandomBytes: getRandomBytes
            };
        })();
        """
        script_obj = QWebEngineScript()
        script_obj.setSourceCode(js)
        script_obj.setInjectionPoint(QWebEngineScript.DocumentCreation)
        script_obj.setWorldId(QWebEngineScript.MainWorld)
        script_obj.setRunsOnSubFrames(True)
        profile.scripts().insert(script_obj)

    def configure_sandbox(self):
        settings = self.settings()
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, False)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, False)
        settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AllowRunningInsecureContent, False)

    def contextMenuEvent(self, event):
        menu = self.page().createStandardContextMenu()
        new_tab_action = QAction('Open Link in New Tab', self)
        new_tab_action.triggered.connect(self.open_link_in_new_tab)
        menu.addAction(new_tab_action)
        new_window_action = QAction('Open Link in New Window', self)
        new_window_action.triggered.connect(self.open_link_in_new_window)
        menu.addAction(new_window_action)
        menu.exec_(event.globalPos())

    def open_link_in_new_tab(self):
        url = self.page().contextMenuData().linkUrl()
        if url.isValid():
            self.browser.create_new_tab(url.toString())

    def open_link_in_new_window(self):
        url = self.page().contextMenuData().linkUrl()
        if url.isValid():
            self.browser.create_new_window(url.toString())
            
class DoHResolverWorker(QThread):
    result_ready = Signal(str)
    error = Signal(str)

    def __init__(self, domain: str, record_type: str = "A", proxies: str = None):
        super().__init__()
        self.domain = domain
        self.record_type = record_type.upper()
        self.proxies = proxies

    def run(self):
        try:
            result = asyncio.run(self._resolve_doh(self.domain, self.record_type))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(f"DoH DNS Resolution Failed: {str(e)}")

    async def _resolve_doh(self, domain: str, record_type: str) -> str:
        url = "https://cloudflare-dns.com/dns-query"
        headers = {"accept": "application/dns-json"}
        params = {"name": domain, "type": record_type}

        async with httpx.AsyncClient(timeout=10, proxies=self.proxies) as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            answers = data.get("Answer", [])
            records = [a["data"] for a in answers if str(a.get("type")) == self._dns_type_to_code(record_type)]
            return ", ".join(records) if records else "No matching DNS records found."

    def _dns_type_to_code(self, record_type: str) -> str:
        dns_type_map = {"A": "1", "AAAA": "28", "CNAME": "5", "MX": "15", "TXT": "16", "NS": "2"}
        return dns_type_map.get(record_type.upper(), "1")

class DoTResolverWorker(QThread):
    result_ready = Signal(str)
    error = Signal(str)

    def __init__(self, domain: str, record_type: str = "A", use_proxy: bool = True):
        super().__init__()
        self.domain = domain
        self.record_type = record_type.upper()
        self.use_proxy = use_proxy

    def run(self):
        try:
            query = dns.message.make_query(self.domain, self.record_type)

            # Create a SOCKS5-wrapped socket if proxy is enabled
            if self.use_proxy:
                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9052)  # Tor's SOCKS port
                sock.settimeout(5)
                sock.connect(("1.1.1.1", 853))  # Cloudflare DoT endpoint
            else:
                sock = socket.create_connection(("1.1.1.1", 853), timeout=5)

            # Send DNS query over TLS using the wrapped socket
            response = dns.query.tls(query, sock, timeout=5, server_hostname="cloudflare-dns.com")

            records = [r.to_text() for r in response.answer[0]] if response.answer else []
            result = ", ".join(records) if records else "No matching DNS records found."
            self.result_ready.emit(result)

        except Exception as e:
            self.error.emit(f"DoT DNS Resolution Failed: {str(e)}")

class Darkelf(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Darkelf Browser")
        self.showMaximized()
        self.monitor_timer = None
        
        # --- Synchronous ML-KEM 768 key manager ---
        self.kyber_manager = MLKEM768Manager(sync=False)
        # Print confirmation in main thread
        print("MLKEM768Manager created in Darkelf.")

        self.log_path = os.path.join(os.path.expanduser("~"), ".darkelf_log")
        self._init_stealth_log()
        
        self.phishing_detector = PhishingDetectorZeroTrace()
                
        self.disable_system_swap()  # Disable swap early
        self.init_settings()
        self.init_security()
        self.init_ui()
        self.init_theme()
        self.init_download_manager()
        self.history_log = []
        self.init_shortcuts()

        QTimer.singleShot(8000, self.start_forensic_tool_monitor)
        
        # Fallback DNS resolution only if Tor is not working
        if self.tor_connection_failed():
            self.log_stealth("Tor unavailable — using DoH/DoT fallback")
            self.resolve_domain_doh("cloudflare.com", "A")
            self.resolve_domain_dot("cloudflare.com", "A")
        else:
            self.log_stealth("Tor active — fallback not triggered")
    
    def _init_stealth_log(self):
        try:
            with open(self.log_path, "a") as f:
                os.chmod(self.log_path, 0o600)
                f.write(f"--- Stealth log started: {datetime.utcnow()} UTC ---\n")
        except Exception:
            pass

    def log_stealth(self, message):
        try:
            with open(self.log_path, "a") as f:
                f.write(f"[{datetime.utcnow()}] {message}\n")
        except Exception:
            pass

    def tor_connection_failed(self) -> bool:
        try:
            if not getattr(self, "tor_network_enabled", False):
                return True
            with socket.create_connection(("127.0.0.1", 9052), timeout=3):
                return False
        except Exception:
            return True

    def resolve_domain_doh(self, domain: str, record_type: str = "A"):
        proxies = "socks5h://127.0.0.1:9052" if getattr(self, "tor_enabled", False) else None
        self.doh_worker = DoHResolverWorker(domain, record_type, proxies)
        self.doh_worker.result_ready.connect(self.handle_doh_result)
        self.doh_worker.error.connect(self.handle_doh_error)
        self.doh_worker.start()

    def handle_doh_result(self, result: str):
        self.log_stealth(f"DoH Success: {result}")

    def handle_doh_error(self, error_msg: str):
        self.log_stealth(f"DoH Error: {error_msg}")

    def resolve_domain_dot(self, domain: str, record_type: str = "A"):
        self.dot_worker = DoTResolverWorker(domain, record_type, use_proxy=True)
        self.dot_worker.result_ready.connect(self.handle_dot_result)
        self.dot_worker.error.connect(self.handle_dot_error)
        self.dot_worker.start()

    def handle_dot_result(self, result: str):
        self.log_stealth(f"DoT Success: {result}")

    def handle_dot_error(self, error_msg: str):
        self.log_stealth(f"DoT Error: {error_msg}")

    def disable_system_swap(self):
        """Disable swap memory to enhance security and optimize for SSD."""
        os_type = platform.system()
        try:
            if os_type == "Linux":
                self._disable_swap_linux()
            elif os_type == "Windows":
                self._disable_swap_windows()
            elif os_type == "Darwin":  # macOS
                self._disable_swap_macos()
            else:
                print(f"Unsupported OS type: {os_type}")
        except Exception as e:
            print(f"Error while disabling system swap: {e}")

    def _disable_swap_linux(self):
        """Disable swap on Linux and optimize for SSD."""
        print("Disabling swap on Linux...")
    
        # Ensure sudo and swapoff are available
        sudo_path = shutil.which("sudo") or "/usr/bin/sudo"
        swapoff_path = shutil.which("swapoff") or "/sbin/swapoff"
    
        # Disable swap
        subprocess.run([sudo_path, swapoff_path, "-a"], check=True, shell=False)
    
        # Set swappiness to 0 to prevent swap usage
        with open('/proc/sys/vm/swappiness', 'w') as f:
            f.write("0")
    
        # Optimize I/O scheduler for SSDs (use noop or deadline)
        with open('/sys/block/sda/queue/scheduler', 'w') as f:
            f.write('noop')  # Using noop scheduler reduces writes on SSDs
    
        print("Swap disabled, swappiness set to 0, and SSD-optimized scheduler applied.")

    def _disable_swap_windows(self):
        """Disable swap on Windows and optimize for SSD."""
        print("Disabling swap on Windows...")
    
        # Disable memory compression (may reduce swap file use)
        powershell_path = shutil.which("powershell.exe") or "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        subprocess.run([powershell_path, "-Command", "Disable-MMAgent -MemoryCompression"], check=True, shell=False)
    
        # Optionally reduce the size of the pagefile
        subprocess.run([powershell_path, "-Command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management' -Name 'PagingFiles' -Value ''"], check=True, shell=False)
    
        print("Memory compression disabled, and pagefile size reduced on Windows (optional).")

    def _disable_swap_macos(self):
        """Disable swap on macOS and optimize for SSD."""
        print("Disabling swap on macOS...")
    
        # Ensure sudo and launchctl are available
        sudo_path = shutil.which("sudo") or "/usr/bin/sudo"
        launchctl_path = shutil.which("launchctl") or "/bin/launchctl"
    
        # First attempt: Unload dynamic pager using launchctl bootout (for macOS 10.15+)
        try:
            print("Attempting to unload dynamic pager with launchctl bootout...")
            subprocess.run([sudo_path, launchctl_path, "bootout", "system", "/System/Library/LaunchDaemons/com.apple.dynamic_pager.plist"], check=True, shell=False)
            print("Dynamic pager service unloaded successfully using launchctl bootout.")
        except subprocess.CalledProcessError as e:
            print(f"Error unloading dynamic pager with bootout: {e}")
    
        # Fallback for older macOS versions: Use launchctl unload
        try:
            print("Attempting to unload dynamic pager with launchctl unload...")
            subprocess.run([sudo_path, launchctl_path, "unload", "-w", "/System/Library/LaunchDaemons/com.apple.dynamic_pager.plist"], check=True, shell=False)
            print("Dynamic pager service unloaded successfully using launchctl unload.")
        except subprocess.CalledProcessError as e:
            print(f"Error unloading dynamic pager with unload: {e}")
    
        # Optionally, you can attempt to disable pagefile or reduce the system swap further.
        print("Swap disable process completed.")
    def check_forensic_environment(self):
        self.log_stealth("Checking forensic environment...")
        try:
            hits = []
            if self._is_suspicious_user(): hits.append("user")
            if self._is_suspicious_hostname(): hits.append("hostname")
            if self._is_vm_mac_address(): hits.append("MAC")
            if self._is_hypervisor_present(): hits.append("hypervisor")
            if self._check_env_indicators(): hits.append("env vars")

            if hits:
                self.log_stealth(f"Env suspicion: {', '.join(hits)}")
                self.self_destruct()
        except Exception as e:
            self.log_stealth(f"Forensic env check error: {e}")

    def _check_env_indicators(self):
        indicators = ["VBOX", "VMWARE", "SANDBOX", "CUCKOO"]
        for k, v in os.environ.items():
            if any(ind.lower() in k.lower() or ind.lower() in str(v).lower() for ind in indicators):
                return True
        return False

    def _is_suspicious_user(self):
        user = getpass.getuser().lower()
        return user in {"sandbox", "cuckoo", "analyst", "malware"}

    def _is_suspicious_hostname(self):
        hostname = socket.gethostname().lower()
        return any(k in hostname for k in {"sandbox", "vm", "cuckoo", "test"})

    def _is_vm_mac_address(self):
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        return any(mac.startswith(p) for p in {"00:05:69", "00:0C:29", "00:1C:14", "00:50:56"})

    def _is_hypervisor_present(self):
        try:
            lscpu = shutil.which("lscpu")
            if lscpu:
                result = subprocess.run([lscpu], capture_output=True, text=True, check=True)
                return "hypervisor" in result.stdout.lower()
        except Exception as e:
            self.log_stealth(f"Hypervisor check error: {e}")
        return False

    def start_forensic_tool_monitor(self):
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_for_forensic_tools)
        interval = 5000 + secrets.randbelow(1000)
        self.monitor_timer.start(interval)
        self.log_stealth(f"Forensic monitor started: {interval}ms")

    def check_for_forensic_tools(self):
        tools = self._get_forensic_tools_list()
        try:
            for proc in psutil.process_iter(['name', 'exe']):
                name = (proc.info.get('name') or '').lower()
                path = proc.info.get('exe') or ''
                if any(tool in name for tool in tools):
                    self.log_stealth(f"Tool detected: {name}")
                    self.self_destruct()
                elif self._check_process_hash(path):
                    self.log_stealth(f"Hash match: {path}")
                    self.self_destruct()
        except Exception as e:
            self.log_stealth(f"Error checking tools: {e}")

    def _check_process_hash(self, path):
        known_hashes = {
            "9f1c43e4d7a33f0a1350d6b73d7f2e...": "IDA Pro",
            "1d0b6abf5c1358e034d8faec5bafc...": "x64dbg"
        }
        if not os.path.isfile(path):
            return False
        try:
            with open(path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
            return sha in known_hashes
        except:
            return False

    def self_destruct(self):
        self.log_stealth("Self-destruct triggered")
        for file in ["private_key.pem", "kyber1024_private_key.pem"]:
            self.secure_delete(file)
        os._exit(1)

    def secure_delete(self, file_path, overwrite_count=7):
        try:
            if os.path.exists(file_path):
                with open(file_path, "ba+", buffering=0) as f:
                    length = f.tell()
                    for _ in range(overwrite_count):
                        f.seek(0)
                        f.write(secrets.token_bytes(length))
                os.remove(file_path)
                self.log_stealth(f"Deleted: {file_path}")
        except Exception as e:
            self.log_stealth(f"Error deleting {file_path}: {e}")

    def _get_forensic_tools_list(self):
        return []
        
    def init_settings(self):
        self.settings = QSettings("DarkelfBrowser", "Darkelf")
        self.load_settings()

    def load_settings(self):
        self.download_path = self.settings.value("download_path", os.path.expanduser("~"), type=str)
        self.homepage_mode = self.settings.value("homepage_mode", "dark", type=str)  # Initialize homepage_mode
        self.javascript_enabled = self.settings.value("javascript_enabled", False, type=bool)  # Load JavaScript setting

    def save_settings(self):
        self.settings.setValue("download_path", self.download_path)
        
    def init_security(self):

        # Initialize settings
        self.anti_fingerprinting_enabled = self.settings.value("anti_fingerprinting_enabled", True, type=bool)
        self.tor_network_enabled = self.settings.value("tor_network_enabled", False, type=bool)
        self.https_enforced = self.settings.value("https_enforced", True, type=bool)
        self.cookies_enabled = self.settings.value("cookies_enabled", False, type=bool)
        self.geolocation_enabled = self.settings.value("geolocation_enabled", False, type=bool)
        self.block_device_orientation = self.settings.value("block_device_orientation", True, type=bool)
        self.block_media_devices = self.settings.value("block_media_devices", True, type=bool)

        # Configure web engine profile
        self.configure_web_engine_profile()

        # Initialize Tor if enabled
        self.init_tor()
        
        # Configure user agent to mimic Firefox ESR
        self.configure_user_agent()
    
    def configure_tls(self):
        ssl_configuration = QSslConfiguration.defaultConfiguration()

        # Mimic Firefox ESR cipher suites
        firefox_cipher_suites = [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
        ]

        # Convert the cipher suite strings to QSslCipher objects
        cipher_objects = [QSslCipher(cipher) for cipher in firefox_cipher_suites]
        ssl_configuration.setCiphers(cipher_objects)

        # Set the modified configuration as the default
        QSslConfiguration.setDefaultConfiguration(ssl_configuration)

        # Mimic Firefox ESR TLS versions
        ssl_configuration.setProtocol(QSsl.TlsV1_2OrLater)
        QSslSocket.setDefaultSslConfiguration(ssl_configuration)
        
    def configure_user_agent(self):
        profile = QWebEngineProfile.defaultProfile()
        # Mimic Firefox ESR user agent string
        firefox_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0"
        profile.setHttpUserAgent(firefox_user_agent)
        
    def configure_web_engine_profile(self):
        self.ram_path = tempfile.mkdtemp()
        profile = QWebEngineProfile(self)
        profile.setCachePath(self.ram_path)
        profile.setPersistentStoragePath(self.ram_path)
        profile.setHttpCacheType(QWebEngineProfile.NoCache)
        profile.setPersistentCookiesPolicy(QWebEngineProfile.NoPersistentCookies)
        profile.setPersistentStoragePath("")
        profile.setHttpCacheMaximumSize(0)
        profile.setSpellCheckEnabled(False)
        profile.setHttpAcceptLanguage("en")
        settings = profile.settings()
        settings.setAttribute(QWebEngineSettings.LocalStorageEnabled, False)
        settings.setAttribute(QWebEngineSettings.JavascriptEnabled, False)  # Ensure JavaScript is disabled by default
        settings.setAttribute(QWebEngineSettings.JavascriptCanOpenWindows, False)
        settings.setAttribute(QWebEngineSettings.JavascriptCanAccessClipboard, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        settings.setAttribute(QWebEngineSettings.XSSAuditingEnabled, True)
        settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebGLEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebRTCPublicInterfacesOnly, False)
        settings.setAttribute(QWebEngineSettings.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.PluginsEnabled, False)
        settings.setAttribute(QWebEngineSettings.HyperlinkAuditingEnabled, False)
        settings.setAttribute(QWebEngineSettings.FullScreenSupportEnabled, True)
        settings.setAttribute(QWebEngineSettings.SpatialNavigationEnabled, False)
        settings.setAttribute(QWebEngineSettings.AllowWindowActivationFromJavaScript, False)
        settings.setAttribute(QWebEngineSettings.ScreenCaptureEnabled, False)
        settings.setAttribute(QWebEngineSettings.PdfViewerEnabled, False)
        settings.setAttribute(QWebEngineSettings.LocalContentCanAccessFileUrls, False)

        # ✅ Create the web view and pass the profile correctly to CustomWebEnginePage
        self.web_view = QWebEngineView()
        page = CustomWebEnginePage(profile, self.web_view)
        self.web_view.setPage(page)

        # Optional signal
        # self.web_view.loadFinished.connect(page.inject_ad_removal_js)

    def setup_encrypted_cookie_store(self, profile):
        cookie_store = profile.cookieStore()
        self.encrypted_store = ObfuscatedEncryptedCookieStore(cookie_store)

    def init_tor(self):
        self.tor_process = None
        if self.tor_network_enabled:
            self.start_tor()
            if self.is_tor_running():
                self.configure_tor_proxy()
                self.configure_tor_dns()

    def start_tor(self):
        try:
            if self.tor_process:
                print("Tor is already running.")
                return

            tor_path = shutil.which("tor")

            if not tor_path or not os.path.exists(tor_path):
                QMessageBox.critical(self, "Tor Error", "Tor executable not found! Install it using 'brew install tor'.")
                return

            # Optimized Tor configuration
            tor_config = {
                'SocksPort': '9052',
                'ControlPort': '9053',
                'DNSPort': '9054',
                'AutomapHostsOnResolve': '1',
                'VirtualAddrNetworkIPv4': '10.192.0.0/10',
                'CircuitBuildTimeout': '10',
                'MaxCircuitDirtiness': '180',
                'NewCircuitPeriod': '120',
                'NumEntryGuards': '2',
                'AvoidDiskWrites': '1',
                'CookieAuthentication': '1',
                'DataDirectory': '/tmp/darkelf-tor-data',
                'Log': 'notice stdout'
            }

            self.tor_process = stem.process.launch_tor_with_config(
                tor_cmd=tor_path,
                config=tor_config,
                init_msg_handler=lambda line: print("[tor]", line)
                #init_msg_handler=lambda line: print(line) if 'Bootstrapped ' in line else None
            )  # <== THIS closes the call properly

            self.controller = Controller.from_port(port=9053)
            cookie_path = os.path.join('/tmp/darkelf-tor-data', 'control_auth_cookie')
            authenticate_cookie(self.controller, cookie_path=cookie_path)
            print("[Darkelf] Tor authenticated via cookie.")
            
            print("Tor started successfully.")

            # Optional SOCKS test with ML-KEM wrapping (if used in your stack)
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.connect(("127.0.0.1", 9052))
                protector = NetworkProtector(test_sock)  # Assuming this wraps ML-KEM
                protector.send_protected(b"[Darkelf] Tor SOCKS test with PQC")
                test_sock.close()
            except Exception as e:
                print(f"[Darkelf] Failed test connection through Tor SOCKS: {e}")

        except OSError as e:
            QMessageBox.critical(None, "Tor Error", f"Failed to start Tor: {e}")

    def is_tor_running(self):
        try:
            with Controller.from_port(port=9053) as controller:
                controller.authenticate()
                print("Tor is running.")
                return True
        except Exception as e:
            print(f"Tor is not running: {e}")
            return False

    def configure_tor_proxy(self):
        proxy = QNetworkProxy(QNetworkProxy.Socks5Proxy, '127.0.0.1', 9052)
        QNetworkProxy.setApplicationProxy(proxy)
        print("Configured QWebEngineView to use Tor SOCKS proxy.")

    def configure_tor_dns(self):
        os.environ['DNSPORT'] = '127.0.0.1:9054'
        print("Configured Tor DNS.")

    def stop_tor(self):
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process = None
            print("Tor stopped.")

    def close(self):
        self.stop_tor()
        super().close()

    def init_theme(self):
        self.black_theme_enabled = True
        self.apply_theme()

    def apply_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(40, 40, 40))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
        palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        palette.setColor(QPalette.Text, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(45, 45, 45))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        self.setPalette(palette)

    def init_download_manager(self):
        self.download_manager = DownloadManager(self)
        profile = QWebEngineProfile.defaultProfile()
        profile.downloadRequested.connect(self.download_manager.handle_download)

    def init_ui(self):
        self.setWindowTitle("Darkelf Browser")
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.setMovable(True)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 0;
            }
            QTabBar::tab {
                background: #333;
                color: #fff;
                padding: 5px 10px;
                border-radius: 10px;
                margin: 2px;
            }
            QTabBar::tab:selected, QTabBar::tab:hover {
                background: #34C759;
                color: #000;
                border-radius: 10px;
            }
        """)
        self.create_toolbar()
        self.create_menu_bar()
        self.create_new_tab("home")

    def create_toolbar(self):
        toolbar = QToolBar()
        self.addToolBar(toolbar)
        back_button = self.create_button('◄', self.go_back)
        toolbar.addWidget(back_button)
        forward_button = self.create_button('►', self.go_forward)
        toolbar.addWidget(forward_button)
        reload_button = self.create_button('↺', self.reload_page)
        toolbar.addWidget(reload_button)
        home_button = self.create_button('⏻', self.load_homepage)  # Unicode character for power button
        toolbar.addWidget(home_button)
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Search or enter URL")
        self.search_bar.returnPressed.connect(self.search_or_load_url)
        self.style_line_edit(self.search_bar)
        toolbar.addWidget(self.search_bar)
        zoom_in_button = self.create_button('+', self.zoom_in)
        toolbar.addWidget(zoom_in_button)
        zoom_out_button = self.create_button('-', self.zoom_out)
        toolbar.addWidget(zoom_out_button)
        full_screen_button = self.create_button('⛶', self.toggle_full_screen)
        toolbar.addWidget(full_screen_button)

    def create_button(self, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        self.style_button(button)
        return button

    def style_button(self, button):
        button.setStyleSheet("""
            QPushButton {
                border: 1px solid #ccc;
                border-radius: 10px;
                padding: 5px;
                margin: 3px;
                font-size: 12px;
                background-color: #333;
                color: #fff;
            }
            QPushButton:hover {
                color: #34C759;
            }
        """)

    def style_line_edit(self, line_edit):
        line_edit.setStyleSheet("""
            QLineEdit {
                border: 1px solid #ccc;
                border-radius: 10px;
                padding: 5px;
                margin: 3px;
                font-size: 12px;
                background-color: #333;
                color: #fff;
            }
        """)

    def load_homepage(self):
        current_tab = self.tab_widget.currentWidget()
        web_view = current_tab.findChild(QWebEngineView)
        if web_view:
            web_view.setHtml(self.custom_homepage_html())

    def custom_homepage_html(self):
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Darkelf</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
            <style id="theme-style">
                body {
                    font-family: Arial, sans-serif;
                    background-color: #000;
                    color: #ddd;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    flex-direction: column;
                    height: 100vh;
                    align-items: center;
                    justify-content: center;
                }
                .content {
                    flex: 1;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                }
                h1 {
                    font-size: 36px;
                    margin-bottom: 20px;
                    color: #34C759; /* Same green as the tab */
                }
                form {
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin-top: 20px;
                }
                input[type="text"] {
                    padding: 10px;
                    width: 500px;
                    margin-right: 10px;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    background-color: #333;
                    color: #ddd;
                }
                button[type="submit"] {
                    padding: 10px 20px;
                    background-color: #333;
                    border: none;
                    color: white;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 16px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                button[type="submit"]:hover {
                    color: #34C759;
                }
            </style>
        </head>
        <body>
            <div class="content">
                <h1>Darkelf Browser</h1>
                <p>Your privacy is our priority.</p>
                <form id="searchForm" action="https://lite.duckduckgo.com/lite/" method="get">
                    <input type="text" id="searchInput" name="q" placeholder="Search DuckDuckGo">
                    <button type="submit"><i class="bi bi-search"></i></button>
                </form>
            </div>
        </body>
        </html>
        """
        return html_content
        
    def current_web_view(self):
        return self.tab_widget.currentWidget().findChild(QWebEngineView)

    def update_tab_title(self):
        web_view = self.current_web_view()
        if web_view:
            self.tab_widget.setTabText(self.tab_widget.currentIndex(), web_view.page().title())

    def update_url_bar(self, url):
        self.search_bar.setText(url.toString())

    def create_menu_bar(self):
        menu_bar = QMenuBar(self)

        # Create menus
        navigation_menu = menu_bar.addMenu("Navigation")
        self.add_navigation_actions(navigation_menu)
        security_menu = menu_bar.addMenu("Security")
        self.set_up_security_actions(security_menu)
        settings_menu = menu_bar.addMenu("Settings")
        self.add_settings_actions(settings_menu)
        history_menu = menu_bar.addMenu("History")
        view_history_action = QAction("View History", self)
        view_history_action.triggered.connect(self.view_history)
        history_menu.addAction(view_history_action)
        clear_history_action = QAction("Clear History", self)
        clear_history_action.triggered.connect(self.clear_history)
        history_menu.addAction(clear_history_action)
        osint_menu = menu_bar.addMenu("OSINT")
        self.add_osint_actions(osint_menu)
        mapping_menu = menu_bar.addMenu("Mapping")
        self.add_mapping_actions(mapping_menu)
        tools_menu = menu_bar.addMenu("Tools")
        self.add_tools_actions(tools_menu)
        about_menu = menu_bar.addMenu("About")
        about_privacy_action = QAction("Privacy Policy", self)
        about_privacy_action.triggered.connect(self.show_privacy_policy)
        about_menu.addAction(about_privacy_action)
        about_terms_action = QAction("Terms of Service", self)
        about_terms_action.triggered.connect(self.show_terms_of_service)
        about_menu.addAction(about_terms_action)
    
        self.setMenuBar(menu_bar)

    # Method to show Privacy Policy
    def show_privacy_policy(self):
        self.create_new_tab("https://github.com/Darkelf2024/Darkelf-Browser/blob/main/Privacy%20Policy.md")

    # Method to show Terms of Service
    def show_terms_of_service(self):
        self.create_new_tab("https://github.com/Darkelf2024/Darkelf-Browser/blob/main/Terms.md")
        
    def open_new_tab(self, url):
        new_tab = QWebEngineView()
        new_tab.setUrl(QUrl(url))
        self.tabs.addTab(new_tab, "New Tab")
        self.tabs.setCurrentWidget(new_tab)
        self.setMenuBar(menu_bar)

    def add_navigation_actions(self, navigation_menu):
        back_action = QAction("Back", self)
        back_action.triggered.connect(self.go_back)
        navigation_menu.addAction(back_action)
        forward_action = QAction("Forward", self)
        forward_action.triggered.connect(self.go_forward)
        navigation_menu.addAction(forward_action)
        reload_action = QAction("Reload", self)
        reload_action.triggered.connect(self.reload_page)
        navigation_menu.addAction(reload_action)
        home_action = QAction("Home", self)
        home_action.triggered.connect(self.load_homepage)
        navigation_menu.addAction(home_action)
        new_tab_action = QAction("New Tab", self)
        new_tab_action.triggered.connect(lambda: self.create_new_tab())
        navigation_menu.addAction(new_tab_action)
        close_tab_action = QAction("Close Tab", self)
        close_tab_action.triggered.connect(lambda: self.close_tab(self.tab_widget.currentIndex()))
        navigation_menu.addAction(close_tab_action)
        close_window_action = QAction("Close Window", self)
        close_window_action.triggered.connect(self.close)
        navigation_menu.addAction(close_window_action)

    def set_up_security_actions(self, security_menu):
        javascript_action = QAction("Enable JavaScript", self, checkable=True)
        javascript_action.setChecked (False) # Ensure it is unchecked at startup
        javascript_action.triggered.connect(lambda: self.toggle_javascript(javascript_action.isChecked()))
        security_menu.addAction(javascript_action)
        fingerprinting_action = QAction("Enable Anti-Fingerprinting", self, checkable=True)
        fingerprinting_action.setChecked(self.anti_fingerprinting_enabled)
        fingerprinting_action.triggered.connect(self.toggle_anti_fingerprinting)
        security_menu.addAction(fingerprinting_action)
        tor_action = QAction("Enable Tor Network", self, checkable=True)
        tor_action.setChecked(self.tor_network_enabled)
        tor_action.triggered.connect(self.toggle_tor_network)
        security_menu.addAction(tor_action)
        firefox_user_agent_action = QAction("Enable Firefox Agent", self, checkable=True)
        firefox_user_agent_action.setChecked(True)
        firefox_user_agent_action.triggered.connect(lambda: self.toggle_firefox_user_agent(firefox_user_agent_action.isChecked()))
        security_menu.addAction(firefox_user_agent_action)
        clear_cache_action = QAction("Clear Cache", self)
        clear_cache_action.triggered.connect(self.clear_cache)
        security_menu.addAction(clear_cache_action)
        clear_cookies_action = QAction("Clear Cookies", self)
        clear_cookies_action.triggered.connect(self.clear_cookies)
        security_menu.addAction(clear_cookies_action)

    def add_settings_actions(self, settings_menu):
        https_action = QAction("Enforce HTTPS", self, checkable=True)
        https_action.setChecked(self.https_enforced)
        https_action.triggered.connect(self.toggle_https_enforcement)
        settings_menu.addAction(https_action)
        cookies_action = QAction("Enable Cookies", self, checkable=False)
        cookies_action.setChecked(not self.cookies_enabled)
        cookies_action.triggered.connect(self.toggle_cookies)
        settings_menu.addAction(cookies_action)
        geolocation_action = QAction("Enable Geolocation", self, checkable=True)
        geolocation_action.setChecked(self.geolocation_enabled)
        geolocation_action.triggered.connect(self.toggle_geolocation)
        settings_menu.addAction(geolocation_action)
        orientation_action = QAction("Block Device Orientation", self, checkable=True)
        orientation_action.setChecked(self.block_device_orientation)
        orientation_action.triggered.connect(self.toggle_device_orientation)
        settings_menu.addAction(orientation_action)
        media_devices_action = QAction("Block Media Devices", self, checkable=True)
        media_devices_action.setChecked(self.block_media_devices)
        media_devices_action.triggered.connect(self.toggle_media_devices)
        settings_menu.addAction(media_devices_action)
        
    def open_url(self, url):
        """
        Open the specified URL in a new tab or in the current tab.
        """
        self.create_new_tab(url)

    def add_osint_actions(self, osint_menu):
        urls = [
            ("Apify", "https://www.apify.com/"),
            ("Graph.tips", "https://graph.tips/"),
            ("Intelx.io", "https://intelx.io/"),
            ("Lookup-id.com", "https://lookup-id.com/"),
            ("Sowsearch.info", "https://sowsearch.info/"),
            ("Whopostedwhat.com", "https://whopostedwhat.com/"),
            ("Hunchly", "https://www.hunch.ly/"),
            ("OSINT Combine", "https://www.osintcombine.com/"),
            ("Internet Archive", "https://archive.org/"),
            ("InfoGalactic", "https://infogalactic.com/info/Main_Page"),
            ("Maltego", "https://www.maltego.com/"),
            ("HackerOne", "https://www.hackerone.com/"),
            ("OSINT Framework", "https://osintframework.com/"),
            ("Censys", "https://censys.io/"),
            ("LeakCheck", "https://leakcheck.io/"),
            ("MX ToolBox", "https://mxtoolbox.com/whois.aspx"),
            ("PublicWWW", "https://publicwww.com/"),
            ("W3Techs", "https://w3techs.com/sites/"),
            ("Social Search", "https://social-searcher.com/"),
            ("GeoIP Lookup", "https://ipinfo.io/"),
            ("DomainTools", "https://www.domaintools.com/"),
            ("Zoom Earth", "https://zoom.earth/"),
            ("NASA Worldview", "https://worldview.earthdata.nasa.gov/"),
            ("Yeti", "https://yeti-platform.github.io/"),
            ("MISP", "https://www.misp-project.org/"),
            ("Dork's Collection List", "https://github.com/cipher387/Dorks-collections-list")
        ]
        for name, url in urls:
            action = QAction(name, self)
            action.triggered.connect(lambda checked, u=url: self.open_url(u))
            osint_menu.addAction(action)

    def add_mapping_actions(self, mapping_menu):
        urls = [
            ("OpenStreetMap", "https://www.openstreetmap.org/"),
            ("MapLibre", "https://maplibre.org/"),
            ("OpenMapTiles", "https://openmaptiles.org/"),
            ("Leaflet", "https://leafletjs.com/")
        ]
        for name, url in urls:
            action = QAction(name, self)
            action.triggered.connect(lambda checked, u=url: self.open_url(u))
            mapping_menu.addAction(action)

    def add_tools_actions(self, tools_menu):
        urls = [
            # OSINT Tools that can be installed via Homebrew
            ("Sherlock", "sherlock"),
            ("Shodan", "shodan"),
            ("Recon-ng", "recon-ng"),
            ("The Harvester", "theharvester"),
            ("Nmap", "nmap"),
            ("Yt-Dlp", "yt-dlp"),
            ("Maltego", "maltego"),
            ("Masscan", "masscan"),
            ("Amass", "amass"),
            ("Subfinder", "subfinder"),
            ("Exiftool", "exiftool"),
            ("Mat2", "mat2"),
            ("Neomutt", "neomutt"),
            ("Thunderbird", "thunderbird"),
        ]
        
        def open_tool(url):
            system = platform.system()

            def run_command(command):
                # Ensure command is a list of arguments
                if isinstance(command, list) and all(isinstance(arg, str) for arg in command):
                    subprocess.run(command, check=True)  # nosec B602
                else:
                    raise ValueError("Invalid command format")
                    
            # Define a list of allowed tools
            allowed_tools = ["sherlock", "shodan", "recon-ng", "theharvester", "nmap", "yt-dlp", "maltego", "masscan", "amass", "subfinder", "exiftool", "mat2", "Neomutt", "Thunderbird"]

            # Ensure the provided url is in the list of allowed tools
            if url in allowed_tools:
                sanitized_url = shlex.quote(url)

                # Execute platform-specific commands to open the too
                if system == "Darwin":  # macOS
                    apple_script = f'''
                    tell application "Terminal"
                        do script "brew install {sanitized_url} && exec $SHELL"
                        activate
                    end tell
                    '''
                    run_command(["osascript", "-e", apple_script]) # nosec B603
                elif system == "Linux":
                    run_command(["gnome-terminal", "--", "sh", "-c", f"brew install {sanitized_url} && exec bash"])
                elif system == "Windows":
                    run_command(["cmd.exe", "/c", "start", "cmd.exe", "/k", f"brew install {sanitized_url}"])
                else:
                    raise OSError("Unsupported operating system: " + system)
            else:
                self.open_url(url)

        def open_url(self, url):
            """
            Open the specified URL in a new tab or in the current tab.
            """
            self.create_new_tab(url)
        
        for tool_name, tool_url in urls:
            action = QAction(tool_name, self)
            action.triggered.connect(lambda checked, url=tool_url: open_tool(url))
            tools_menu.addAction(action)
                
    def init_shortcuts(self):
        # Shortcut for creating a new tab (Cmd+T on macOS, Ctrl+T on other systems)
        QShortcut(QKeySequence("Ctrl+T" if sys.platform != 'darwin' else "Meta+T"), self, self.create_new_tab)

        # Shortcut for closing the current tab (Cmd+W on macOS, Ctrl+W on other systems)
        QShortcut(QKeySequence("Ctrl+W" if sys.platform != 'darwin' else "Meta+W"), self, lambda: self.close_tab(self.tab_widget.currentIndex()))

        # Shortcut for reloading the current page (Cmd+R on macOS, Ctrl+R on other systems)
        QShortcut(QKeySequence("Ctrl+R" if sys.platform != 'darwin' else "Meta+R"), self, self.reload_page)

        # Shortcut for going back (Cmd+Left on macOS, Ctrl+Left on other systems)
        QShortcut(QKeySequence("Ctrl+Left" if sys.platform != 'darwin' else "Meta+Left"), self, self.go_back)

        # Shortcut for going forward (Cmd+Right on macOS, Ctrl+Right on other systems)
        QShortcut(QKeySequence("Ctrl+Right" if sys.platform != 'darwin' else "Meta+Right"), self, self.go_forward)

        # Shortcut for toggling full screen (F11)
        QShortcut(QKeySequence("F11"), self, self.toggle_full_screen)

        # Shortcut for viewing history (Cmd+H on macOS, Ctrl+H on other systems)
        QShortcut(QKeySequence("Ctrl+H" if sys.platform != 'darwin' else "Meta+H"), self, self.view_history)

        # Shortcut for zooming in (Cmd++ on macOS, Ctrl++ on other systems)
        QShortcut(QKeySequence("Ctrl++" if sys.platform != 'darwin' else "Meta++"), self, self.zoom_in)

        # Shortcut for zooming out (Cmd+- on macOS, Ctrl+- on other systems)
        QShortcut(QKeySequence("Ctrl+-" if sys.platform != 'darwin' else "Meta+-"), self, self.zoom_out)
        
    def create_new_tab(self, url="home"):
        web_view = QWebEngineView()
        web_view.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, self.javascript_enabled)  # Apply JavaScript setting
        web_view.loadFinished.connect(self.update_tab_title)
        web_view.urlChanged.connect(self.update_url_bar)
        if url == "home":
            web_view.setHtml(self.custom_homepage_html())
            tab_title = "Darkelf"
        else:
            web_view.setUrl(QUrl(url))
            tab_title = "New Tab"

        index = self.tab_widget.addTab(web_view, tab_title)
        self.tab_widget.setCurrentIndex(index)
        return web_view

    def load_url(self, url):
        return QUrl(url)

    def create_new_window(self, url=None):
        new_window = Darkelf()
        if url:
            new_window.create_new_tab(url)
        new_window.show()
        return new_window

    def close_tab(self, index):
        if self.tab_widget.count() < 2:
            return
        widget = self.tab_widget.widget(index)
        widget.deleteLater()
        self.tab_widget.removeTab(index)
        self.clear_cache_and_history()

    def go_back(self):
        if self.tab_widget.currentWidget():
            self.tab_widget.currentWidget().back()

    def go_forward(self):
        if self.tab_widget.currentWidget():
            self.tab_widget.currentWidget().forward()

    def reload_page(self):
        if self.tab_widget.currentWidget():
            self.tab_widget.currentWidget().reload()

    def update_tab_title(self):
        index = self.tab_widget.currentIndex()
        web_view = self.tab_widget.widget(index)
        title = web_view.page().title()
        self.tab_widget.setTabText(index, title)

    def update_url_bar(self, q):
        url_str = q.toString()
        if not url_str.startswith("data:text/html"):
            self.search_bar.setText(url_str)
            self.history_log.append(url_str)

    def load_homepage(self):
        index = self.tab_widget.currentIndex()
        web_view = self.tab_widget.widget(index)
        web_view.setHtml(self.custom_homepage_html())

    def zoom_in(self):
        current_tab = self.tab_widget.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.setZoomFactor(current_tab.zoomFactor() + 0.1)

    def zoom_out(self):
        current_tab = self.tab_widget.currentWidget()
        if isinstance(current_tab, QWebEngineView):
            current_tab.setZoomFactor(current_tab.zoomFactor() - 0.1)

    def analyze_page_content(self, web_view, url):
        web_view.page().toHtml(lambda html: self.check_html_for_phishing(url, html))

    def check_html_for_phishing(self, url, html):
        is_phish, reason = self.phishing_detector.analyze_page_content(html)
        if is_phish:
            self.phishing_detector.flag_url_ephemeral(url)
            self.phishing_detector.show_warning_dialog(self, reason)
    
    def toggle_full_screen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def clear_cache(self):
        profile = QWebEngineProfile.defaultProfile()
        profile.clearHttpCache()
        QMessageBox.information(self, "Cache Cleared", "The cache has been successfully cleared.")

    def clear_cookies(self):
        profile = QWebEngineProfile.defaultProfile()
        profile.cookieStore().deleteAllCookies()
        QMessageBox.information(self, "Cookies Cleared", "All cookies have been successfully cleared.")

    def search_or_load_url(self):
        text = self.search_bar.text()
        if text.startswith(('http://', 'https://')):
            self.create_new_tab(text)
        else:
            self.create_new_tab(f"https://lite.duckduckgo.com/lite/?q={text}")

    def toggle_javascript(self, enabled):
        self.javascript_enabled = enabled
        self.settings.setValue("javascript_enabled", enabled)
        index = self.tab_widget.currentIndex()
        if index != -1:
            web_view = self.tab_widget.widget(index)
            web_view.settings().setAttribute(QWebEngineSettings.JavascriptEnabled, enabled)

            
    def toggle_anti_fingerprinting(self, enabled):
        self.anti_fingerprinting_enabled = enabled
        self.settings.setValue("anti_fingerprinting_enabled", enabled)

    def toggle_tor_network(self, enabled):
        self.tor_network_enabled = enabled
        self.settings.setValue("tor_network_enabled", enabled)
        if enabled:
            self.start_tor()
        else:
            self.stop_tor()

    def toggle_https_enforcement(self, enabled):
        self.https_enforced = enabled
        self.settings.setValue("https_enforced", enabled)

    def toggle_cookies(self, enabled):
        self.cookies_enabled = enabled
        self.settings.setValue("cookies_enabled", enabled)
        self.configure_web_engine_profile()

    def toggle_geolocation(self, enabled):
        self.geolocation_enabled = enabled
        self.settings.setValue("geolocation_enabled", enabled)

    def toggle_device_orientation(self, enabled):
        self.block_device_orientation = enabled
        self.settings.setValue("block_device_orientation", enabled)

    def toggle_media_devices(self, enabled):
        self.block_media_devices = enabled
        self.settings.setValue("block_media_devices", enabled)

    def closeEvent(self, event):
        """Secure shutdown with memory wipe, file deletion, and anti-forensics measures."""
        try:
            if hasattr(self, 'log_path') and os.path.exists(self.log_path):
                self.log_stealth("Initiating clean shutdown...")

            self.check_forensic_environment()

            # Stop Tor if active
            if hasattr(self, 'tor_manager') and callable(getattr(self.tor_manager, 'stop_tor', None)):
                self.tor_manager.stop_tor()

            # Wipe memory-based encrypted cookie store
            if hasattr(self, 'encrypted_store'):
                self.encrypted_store.wipe_memory()

            self.save_settings()
            self.secure_clear_cache_and_history()

            # Stop download timers
            if hasattr(self, 'download_manager') and hasattr(self.download_manager, 'timers'):
                for timer in self.download_manager.timers.values():
                    try:
                        timer.stop()
                    except Exception:
                        pass

            # Close all tabs
            if hasattr(self, 'tab_widget'):
                for i in reversed(range(self.tab_widget.count())):
                    widget = self.tab_widget.widget(i)
                    if isinstance(widget, QWebEngineView):
                        try:
                            page = widget.page()
                            if page:
                                page.setParent(None)
                                widget.setPage(None)
                                page.deleteLater()
                        except RuntimeError:
                            pass
                        widget.close()
                    self.tab_widget.removeTab(i)
                    widget.setParent(None)
                    widget.deleteLater()

            # Close popouts
            if hasattr(self, 'web_views'):
                for view in self.web_views:
                    try:
                        page = view.page()
                        if page:
                            page.setParent(None)
                            view.setPage(None)
                            page.deleteLater()
                    except RuntimeError:
                        pass
                    view.close()
                    view.setParent(None)
                    view.deleteLater()

            # Close main view
            if hasattr(self, 'web_view'):
                try:
                    page = self.web_view.page()
                    if page:
                        page.setParent(None)
                        self.web_view.setPage(None)
                        page.deleteLater()
                except RuntimeError:
                    pass
                self.web_view.close()
                self.web_view.setParent(None)
                self.web_view.deleteLater()

            QApplication.processEvents()
            QApplication.processEvents()

            if hasattr(self, 'web_profile') and self.web_profile:
                QTimer.singleShot(5000, lambda: self.web_profile.deleteLater())

            # Clean RAM-based directory
            if hasattr(self, 'ram_path') and os.path.exists(self.ram_path):
                self.secure_delete_ram_disk_directory(self.ram_path)

            # Clean temp folder
            temp_subdir = os.path.join(tempfile.gettempdir(), "darkelf_temp")
            if os.path.exists(temp_subdir):
                shutil.rmtree(temp_subdir, ignore_errors=True)
                self.log_stealth(f"[✓] Securely deleted temp folder via rmtree: {temp_subdir}")

            # Cryptographic keys
            for keyfile in ["private_key.pem", "ecdh_private_key.pem"]:
                if os.path.exists(keyfile):
                    self.secure_delete(keyfile)

            # --- Begin: ML-KEM 768 (Kyber) key memory and file wipe ---
            try:
                if hasattr(self, 'kyber_manager') and self.kyber_manager:
                    # Overwrite private key in memory
                    if hasattr(self.kyber_manager, 'kyber_private_key') and self.kyber_manager.kyber_private_key:
                        priv = self.kyber_manager.kyber_private_key
                        if isinstance(priv, (bytearray, bytes)):
                            try:
                                for i in range(len(priv)):
                                    if isinstance(priv, bytearray):
                                        priv[i] = 0
                            except Exception:
                                pass
                        self.kyber_manager.kyber_private_key = None
                    # Overwrite public key in memory
                    if hasattr(self.kyber_manager, 'kyber_public_key') and self.kyber_manager.kyber_public_key:
                        pub = self.kyber_manager.kyber_public_key
                        if isinstance(pub, (bytearray, bytes)):
                            try:
                                for i in range(len(pub)):
                                    if isinstance(pub, bytearray):
                                        pub[i] = 0
                            except Exception:
                                pass
                        self.kyber_manager.kyber_public_key = None
                    self.kyber_manager.kem = None

                # Secure erase Kyber key files if ever saved
                for kyber_file in ["kyber_private.key", "kyber_public.key"]:
                    if os.path.exists(kyber_file):
                        self.secure_delete(kyber_file)
            except Exception as e:
                if hasattr(self, 'log_path') and os.path.exists(self.log_path):
                    self.log_stealth(f"Error wiping ML-KEM keys: {e}")
            # --- End: ML-KEM 1024 key wipe ---

            # Final: log
            if hasattr(self, 'log_path') and os.path.exists(self.log_path):
                self.secure_delete(self.log_path)

        except Exception as e:
            if hasattr(self, 'log_path') and os.path.exists(self.log_path):
                self.log_stealth(f"Error during shutdown: {e}")
        finally:
            super().closeEvent(event)

    def secure_delete_directory(self, directory_path):
        try:
            if not os.path.exists(directory_path):
                self.log_stealth(f"[!] Directory not found: {directory_path}")
                return

            for root, dirs, files in os.walk(directory_path, topdown=False):
                for name in files:
                    self.secure_delete(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception as e:
                        self.log_stealth(f"[!] Error removing subdir {name}: {e}")

            os.rmdir(directory_path)
            self.log_stealth(f"[✓] Securely deleted directory: {directory_path}")
        except Exception as e:
            self.log_stealth(f"[!] Error deleting directory {directory_path}: {e}")

    def secure_delete_temp_memory_file(self, file_path):
        try:
            if not isinstance(file_path, (str, bytes, os.PathLike)):
                self.log_stealth(f"[!] Invalid temp file path: {type(file_path)}")
                return

            if not os.path.exists(file_path):
                self.log_stealth(f"[!] Temp file not found: {file_path}")
                return

                file_size = os.path.getsize(file_path)

                with open(file_path, "r+b", buffering=0) as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(secrets.token_bytes(file_size))
                        f.flush()
                        os.fsync(f.fileno())

            os.remove(file_path)
            self.log_stealth(f"[✓] Securely deleted temp file: {file_path}")
        except Exception as e:
            self.log_stealth(f"[!] Error deleting temp file {file_path}: {e}")

    def secure_delete_ram_disk_directory(self, ram_dir_path):
        try:
            if not os.path.exists(ram_dir_path):
                self.log_stealth(f"[!] RAM disk not found: {ram_dir_path}")
                return

            for root, dirs, files in os.walk(ram_dir_path, topdown=False):
                for name in files:
                    self.secure_delete_temp_memory_file(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception as e:
                        self.log_stealth(f"[!] Error removing RAM subdir {name}: {e}")

            os.rmdir(ram_dir_path)
            self.log_stealth(f"[✓] Wiped RAM disk: {ram_dir_path}")
        except Exception as e:
            self.log_stealth(f"[!] Error wiping RAM disk: {e}")

    def handle_download(self, download_item):
        self.download_manager.handle_download(download_item)

    def clear_cache_and_history(self):
        profile = QWebEngineProfile.defaultProfile()
        profile.clearHttpCache()
        profile.clearAllVisitedLinks()
        self.history_log.clear()

    def view_history(self):
        dialog = HistoryDialog(self.history_log, self)
        dialog.exec()

    def clear_history(self):
        self.history_log.clear()
        self.clear_cache_and_history()
        QMessageBox.information(self, "Clear History", "Browsing history cleared.")

class HistoryDialog(QDialog):
    def __init__(self, history_log, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Browsing History")
        
        layout = QVBoxLayout()
        self.history_list = QListWidget()
        self.history_list.addItems(history_log)
        layout.addWidget(self.history_list)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
        
        self.setLayout(layout)

def main():
    # Apply correct High DPI scaling
    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    # Set Chromium flags to disable WebRTC, WebGL, Canvas API, GPU, etc.
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--disable-webrtc "
        "--disable-webgl "
        "--disable-3d-apis "
        "--disable-rtc-sctp-data-channels "
        "--disable-rtc-multiple-routes "
        "--disable-rtc-stun-origin "
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp "
        "--disable-rtc-event-log "
        "--disable-rtc-sdp-logs "
        "--disable-webgl-2 "
        "--disable-gpu "
        "--disable-d3d11 "
        "--disable-accelerated-2d-canvas "
        "--disable-software-rasterizer "
        "--disable-features=Canvas2DImageChromium,WebGLImageChromium "
        "--disable-reading-from-canvas "
        "--disable-offscreen-canvas "
        "--use-angle=none "
        "--disable-extensions "
        "--disable-sync "
        "--disable-translate "
        "--disable-plugins "
        "--disable-features=CookiesWithoutSameSiteMustBeSecure,AutofillServerCommunication "
        "--disable-client-side-phishing-detection "
        "--disable-font-subpixel-positioning "
        "--disable-kerning "
        "--disable-web-fonts "
        "--disable-background-networking "
        "--disable-sync "
        "--disable-translate "
        "--disable-speech-api "
        "--disable-sensor "
        "--disable-features=InterestCohortAPI,PrivacySandboxAdsAPIs "
        "--disable-javascript-harmony "
        "--no-referrers "
        "--disable-features=AudioServiceSandbox "
        "--enable-features=StrictOriginIsolation,PartitionedCookies "
        "--disable-renderer-backgrounding "
        "--disable-background-timer-throttling "
        "--disable-third-party-cookies "
        "--disable-webrtc-hw-encoding "
        "--disable-webrtc-hw-decoding "
        "--disable-webrtc-cpu-overuse-detection "
        "--disable-features=WebRTCMediaDevices "
        "--disable-blink-features=NavigatorOnLine,UserAgentClientHint,WebAuthn "
        "--disable-features=HTMLImports "
        "--disable-features=AudioContext "
        "--disable-features=HardwareConcurrency "
        "--disable-backgrounding-occluded-windows "
        "--disable-lcd-text "
        "--disable-accelerated-video "
        "--disable-gpu-compositing "
        "--disable-features=IndexedDB "
        "--disable-webgl-image-chromium "
        "--disable-text-autosizing "
        "--disable-peer-connection "
        "--disable-javascript"
        "--incognito --disable-logging --no-first-run --disable-breakpad "
        "--disable-features=NetworkService,TranslateUI "
        "--disk-cache-dir=/dev/null"
    )
    
    # Start kernel state monitor
    kernel_monitor = DarkelfKernelMonitor(check_interval=5)
    kernel_monitor.start()
    
    # Create the application
    app = QApplication.instance() or QApplication(sys.argv)

    # Initialize and show the browser
    darkelf_browser = Darkelf()
    darkelf_browser.show()

    # Run the application
    sys.exit(app.exec())

if __name__ == '__main__':
    main()



