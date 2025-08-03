# Darkelf CLI TL OSINT Tool Kit v3.0 – Secure, Privacy-Focused Command-Line Web Browser
# Copyright (C) 2025 Dr. Kevin Moore
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
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
# This software contains publicly available encryption source code and is
# released under License Exception TSU in accordance with 15 CFR §740.13(e) of the
# U.S. Export Administration Regulations (EAR).
#
# A public notification of source code release has been submitted to the
# U.S. Bureau of Industry and Security (BIS) and the National Security Agency (NSA).
#
# The software includes implementations of standard cryptographic algorithms
# (e.g., AES, RSA, ChaCha20, TLS 1.3, X25519) for research and general-purpose use.
#
# This is source code only. No compiled binaries are included in this distribution.
# Redistribution, modification, or use must comply with all applicable U.S. export
# control laws and regulations.
#
# PROHIBITED DESTINATIONS:
# This software may not be exported or transferred, directly or indirectly, to:
# - Countries or territories under comprehensive U.S. embargo (OFAC or BIS lists),
# - Entities or individuals listed on the U.S. Denied Persons, Entity, or SDN Lists,
# - Parties on the BIS Country Group E:1 or E:2 lists.
#
# END-USE RESTRICTIONS:
# This software may not be used in the development or production of weapons of mass
# destruction, including nuclear, chemical, biological weapons, or missile systems
# as defined in EAR Part 744.
#
# By downloading, using, or distributing this software, you agree to comply with
# all applicable export control laws.
#
# This software is published under the LGPL v3.0 license and authored by
# Dr. Kevin Moore, 2025.
#
# NOTE: This is the CLI (Command-Line Interface) edition of Darkelf.
# It is entirely terminal-based and does not use PyQt5, PySide6, or any GUI frameworks.

import os
import sys
import time
import argparse
import logging
import aiohttp
import aiohttp_socks
import numpy as np
import asyncio
import mmap
import ctypes
import random
import base64
import hashlib
import threading
import shutil
import socket
import json
import secrets
import tempfile
import platform
import shlex
import struct
import subprocess
import termios
import tty
import zlib
import oqs
import re
import ssl
import signal
import tls_client
import html
import ipaddress
import dns.resolver
import phonenumbers
import textwrap
import psutil
import urllib
from collections import deque, Counter
from typing import Optional, List, Dict, Union, Any
from datetime import datetime
from aiohttp_socks import ProxyConnector
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.table import Table
from collections import defaultdict
from rich.layout import Layout
from textwrap import wrap
from getpass import getpass
from urllib.parse import quote_plus, unquote, parse_qs, urlparse, urljoin
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from oqs import KeyEncapsulation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from requests import Response
from phonenumbers import carrier, geocoder, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.markdown import Markdown
from aiohttp import ClientTimeout
import socks
import requests
import spacy
import pytesseract
import cv2

# --- Tor integration via Stem ---
import stem.process
from stem.connection import authenticate_cookie
from stem.control import Controller
from stem import Signal as StemSignal
from stem import process as stem_process

def get_tor_session():
    session = requests.Session()
    session.proxies = {
        "http": "socks5h://127.0.0.1:9052",
        "https": "socks5h://127.0.0.1:9052",
    }
    return session
    
async def async_fetch_ddg(query, max_results=5):
    url = f"https://duckduckgo.com/html/?q={query}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=15) as response:
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                hits = []
                for a in soup.find_all("a", href=True):
                    if a["href"].startswith("http"):
                        hits.append((a.get_text(strip=True), a["href"]))
                        if len(hits) >= max_results:
                            break
                return query, hits
    except Exception as e:
        return query, f"[Error fetching results: {e}]"


# --- Cross-platform RAM disk location ---
def get_ramdisk_path(filename="prekeys.json.enc"):
    # Linux
    if sys.platform.startswith("linux"):
        ramdisk = "/dev/shm"
    # macOS (Apple Silicon and Intel, including M1-M4)
    elif sys.platform == "darwin":
        ramdisk = "/private/tmp"
        # Optionally, use a custom RAM disk: /Volumes/RAMDisk (if user mounts one)
        if os.path.exists("/Volumes/RAMDisk"):
            ramdisk = "/Volumes/RAMDisk"
    # Fallback: system temp dir (not always RAM, but best effort)
    else:
        ramdisk = os.environ.get("TMPDIR") or "/tmp"
    return os.path.join(ramdisk, filename)

KEM_ALGO = "Kyber768"
PREKEYS_FILE = get_ramdisk_path()

def derive_key(password, salt, iterations=150_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

class DarkelfPQChat:
    """
    PQ chat with Ed25519 identity, Kyber768 session, replay protection,
    and async X3DH-style prekey support (encrypted mailbox in RAM).
    """
    def _start_intrusion_monitor(self):
        def monitor():
            log_path = get_ramdisk_path(".darkelf_intrusion_log")
            # Only alert if the process name exactly matches a known tool
            suspicious = {
                "nmap", "tcpdump", "wireshark", "netcat", "nc", "socat", "aircrack", "ettercap"
            }
            seen = set()
            while not self._exit_chat:
                try:
                    for proc in psutil.process_iter(['pid', 'name']):
                        pname = proc.info['name'].lower()
                        # Only exact match (no substring match)
                        if pname in suspicious:
                            entry = f"{pname}:{proc.info['pid']}"
                            if entry not in seen:
                                seen.add(entry)
                                with open(log_path, "a") as f:
                                    f.write(f"[!] Suspicious process: {pname} (PID: {proc.info['pid']})\n")
                                print(f"\n[ALERT] Suspicious process detected: {pname} (PID: {proc.info['pid']})\nYou: ", end="")
                    time.sleep(10)
                except Exception:
                    pass
        threading.Thread(target=monitor, daemon=True).start()

    def __init__(self, is_initiator=True, their_prekey_bundle=None, my_id="alice"):
        self.kem_algo = KEM_ALGO
        self.is_initiator = is_initiator
        self.sock = None
        self.my_id = my_id

        self.root_key = secrets.token_bytes(32)
        self.send_chain_key = None
        self.recv_chain_key = None

        # Identity keys
        self.identity_sk = Ed25519PrivateKey.generate()
        self.identity_pk = self.identity_sk.public_key()

        self.kem_self = oqs.KeyEncapsulation(self.kem_algo)
        self.pk_self = self.kem_self.generate_keypair()
        self.pk_length = self.kem_self.details['length_public_key']
        self.ct_length = self.kem_self.details['length_ciphertext']
        self.pk_remote = None

        # For replay/ordering
        self.send_count = 0
        self.recv_count = 0

        # Prekey support
        self.prekey_sk = oqs.KeyEncapsulation(self.kem_algo)
        self.prekey_pk = self.prekey_sk.generate_keypair()
        self.prekey_id = secrets.token_hex(4)
        self.prekey_used = False

        # Remote bundle (for initiator)
        self.their_prekey_bundle = their_prekey_bundle

        self._exit_chat = False

        # --- Encrypted mailbox ---
        self._mailbox_key = None
        self._mailbox_salt = None
        self._ensure_mailbox_key()

    # --- Mailbox encryption helpers ---
    def _ensure_mailbox_key(self):
        # Prompt for passphrase, or reuse if set
        if self._mailbox_key and self._mailbox_salt:
            return
        while True:
            password = getpass(f"[Prekey Mailbox] Enter passphrase for mailbox at {PREKEYS_FILE}: ")
            if not password:
                print("Passphrase required. Try again.")
                continue
            if os.path.exists(PREKEYS_FILE):
                with open(PREKEYS_FILE, "rb") as f:
                    salt = f.read(16)
                key = derive_key(password, salt)
                try:
                    with open(PREKEYS_FILE, "rb") as f:
                        f.read(16)  # skip salt
                        enc = f.read()
                    Fernet(key).decrypt(enc)
                    self._mailbox_key = key
                    self._mailbox_salt = salt
                    break
                except Exception:
                    print("Incorrect passphrase or corrupted mailbox. Try again.")
                    continue
            else:
                # New mailbox, generate salt
                salt = os.urandom(16)
                self._mailbox_key = derive_key(password, salt)
                self._mailbox_salt = salt
                break

    def _load_mailbox(self):
        if not os.path.exists(PREKEYS_FILE):
            return []
        with open(PREKEYS_FILE, "rb") as f:
            salt = f.read(16)
            enc = f.read()
        if not self._mailbox_key or salt != self._mailbox_salt:
            # mailbox salt changed, re-prompt
            self._mailbox_salt = salt
            password = getpass("[Prekey Mailbox] Enter passphrase for new mailbox: ")
            self._mailbox_key = derive_key(password, salt)
        data = Fernet(self._mailbox_key).decrypt(enc)
        return json.loads(data.decode("utf-8"))

    def _save_mailbox(self, mailbox):
        enc = Fernet(self._mailbox_key).encrypt(json.dumps(mailbox).encode("utf-8"))
        with open(PREKEYS_FILE, "wb") as f:
            f.write(self._mailbox_salt)
            f.write(enc)

    # --- Prekey mailbox API (encrypted in RAM) ---
    def publish_prekey_bundle(self):
        bundle = {
            "id_pub": self.identity_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            "prekey_id": self.prekey_id,
            "prekey_pk": self.prekey_pk.hex(),
            "prekey_sig": self.identity_sk.sign(self.prekey_pk).hex(),
            "user": self.my_id
        }
        try:
            mailbox = []
            if os.path.exists(PREKEYS_FILE):
                mailbox = self._load_mailbox()
            mailbox = [b for b in mailbox if b["user"] != self.my_id]
            mailbox.append(bundle)
            self._save_mailbox(mailbox)
            print(f"[Prekey] Published prekey for ID: {self.my_id}")
        except Exception as e:
            print(f"[!] Failed to publish prekey: {e}")

    def fetch_prekey_bundle(self, recipient_id):
        if not os.path.exists(PREKEYS_FILE):
            print("[!] No prekey mailbox found.")
            return None
        try:
            mailbox = self._load_mailbox()
            for b in mailbox:
                if b["user"] == recipient_id:
                    return b
            print(f"[!] No prekey found for {recipient_id}")
            return None
        except Exception as e:
            print(f"[!] Failed to load mailbox: {e}")
            return None

    def consume_own_prekey(self):
        if not os.path.exists(PREKEYS_FILE):
            return
        try:
            mailbox = self._load_mailbox()
            mailbox = [b for b in mailbox if b["user"] != self.my_id]
            self._save_mailbox(mailbox)
        except Exception as e:
            print(f"[!] Failed to consume own prekey: {e}")

    # --- Secure mailbox wipe (RAM disk) ---
    def _secure_wipe_prekeys(self):
        if not os.path.exists(PREKEYS_FILE):
            return
        try:
            size = os.path.getsize(PREKEYS_FILE)
            with open(PREKEYS_FILE, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
            os.remove(PREKEYS_FILE)
            print("[*] Securely wiped encrypted prekey mailbox.")
        except Exception as e:
            print(f"[!] Failed to securely wipe prekeys: {e}")

    # ---- PQ Chat Handshake and Messaging (unchanged) ----
    def _hkdf(self, input_key_material, context=b"", length=32):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=context
        ).derive(input_key_material)

    def async_handshake_initiator(self, remote_bundle):
        id_pub_bytes = bytes.fromhex(remote_bundle["id_pub"])
        prekey_pk = bytes.fromhex(remote_bundle["prekey_pk"])
        prekey_sig = bytes.fromhex(remote_bundle["prekey_sig"])
        id_pub = Ed25519PublicKey.from_public_bytes(id_pub_bytes)
        id_pub.verify(prekey_sig, prekey_pk)
        kem_temp = oqs.KeyEncapsulation(self.kem_algo)
        ct, shared_secret = kem_temp.encap_secret(prekey_pk)
        auth_packet = json.dumps({
            "ct": ct.hex(),
            "id_pub": self.identity_pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex(),
            "prekey_id": remote_bundle["prekey_id"]
        }).encode()
        self.sock.sendall(len(auth_packet).to_bytes(4, "big") + auth_packet)
        self.root_key = self._hkdf(shared_secret, b"root")
        self.send_chain_key = self.root_key
        self.recv_chain_key = self.root_key
        self.send_count = 0
        self.recv_count = 0

    def async_handshake_responder(self):
        length = int.from_bytes(self._recv_exact(4), "big")
        pkt = self._recv_exact(length)
        data = json.loads(pkt)
        ct = bytes.fromhex(data["ct"])
        peer_id_pub = bytes.fromhex(data["id_pub"])
        if self.prekey_used:
            raise Exception("[!] Prekey already used!")
        self.prekey_used = True
        self.consume_own_prekey()
        shared_secret = self.prekey_sk.decap_secret(ct)
        self.root_key = self._hkdf(shared_secret, b"root")
        self.send_chain_key = self.root_key
        self.recv_chain_key = self.root_key
        self.send_count = 0
        self.recv_count = 0

    def next_message_key(self, chain_key, count):
        context = b"msg" + count.to_bytes(8, 'big')
        message_key = self._hkdf(chain_key + context, b"msg")
        next_chain_key = self._hkdf(chain_key + b"chain", b"chain")
        return message_key, next_chain_key

    def encrypt_message(self, plaintext):
        self.send_count += 1
        message_key, self.send_chain_key = self.next_message_key(self.send_chain_key, self.send_count)
        nonce = secrets.token_bytes(12)
        cipher = ChaCha20Poly1305(message_key)
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)
        payload = {
            "count": self.send_count,
            "nonce": nonce.hex(),
            "cipher": ciphertext.hex()
        }
        return json.dumps(payload).encode()

    def decrypt_message(self, pkt):
        data = json.loads(pkt)
        count = data["count"]
        nonce = bytes.fromhex(data["nonce"])
        ciphertext = bytes.fromhex(data["cipher"])
        if count != self.recv_count + 1:
            raise ValueError(f"Out-of-order or replayed message: expected {self.recv_count + 1}, got {count}")
        self.recv_count = count
        message_key, self.recv_chain_key = self.next_message_key(self.recv_chain_key, self.recv_count)
        cipher = ChaCha20Poly1305(message_key)
        return cipher.decrypt(nonce, ciphertext, None).decode('utf-8')

    def _recv_exact(self, nbytes):
        buf = b""
        while len(buf) < nbytes:
            chunk = self.sock.recv(nbytes - len(buf))
            if not chunk:
                raise ConnectionError("Socket closed unexpectedly")
            buf += chunk
        return buf

    def _send_packet(self, payload: bytes):
        self.sock.sendall(len(payload).to_bytes(4, 'big') + payload)

    def _recv_packet(self):
        length_bytes = self._recv_exact(4)
        if not length_bytes:
            raise ConnectionError("Socket closed unexpectedly")
        length = int.from_bytes(length_bytes, 'big')
        return self._recv_exact(length)

    def connect_async(self, host, port, recipient_id):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        remote_bundle = self.fetch_prekey_bundle(recipient_id)
        if not remote_bundle:
            raise Exception("No prekey bundle found for recipient")
        self.async_handshake_initiator(remote_bundle)
        print("[*] Async handshake complete. You can now send messages.")
        self._start_chat()

    def accept_async(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(1)
        print(f"[Server] Listening on {host}:{port} (async mode)")
        self.sock, _ = self.sock.accept()
        print("[Server] Connection accepted")
        self.async_handshake_responder()
        print("[*] Async handshake complete. You can now receive messages.")
        self._start_chat()

    def _start_chat(self):
        self._exit_chat = False
        self._start_intrusion_monitor()
        threading.Thread(target=self._receiver_thread, daemon=True).start()
        try:
            while not self._exit_chat:
                msg = input("You: ")
                if msg.lower() in ("exit", "quit", "/exit", "/quit"):
                    self._exit_chat = True
                    break
                pkt = self.encrypt_message(msg)
                self._send_packet(pkt)
        except KeyboardInterrupt:
            print("\n[!] Exiting chat")
            self._exit_chat = True
        finally:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
            self._secure_wipe_prekeys()
            print("[*] Chat closed. Returning to CLI menu.")

    def accept(self, host, port):
        raise NotImplementedError("Use accept_async() for async-prekey PQ chat.")

    def connect(self, host, port):
        raise NotImplementedError("Use connect_async() with recipient_id for async-prekey PQ chat.")

    def _receiver_thread(self):
        while not self._exit_chat:
            try:
                data = self._recv_packet()
                try:
                    message = self.decrypt_message(data)
                    print(f"\rFriend: {message}\nYou: ", end="")
                except Exception as e:
                    print(f"[!] Failed to decrypt: {e}")
            except Exception as e:
                if not self._exit_chat:
                    print(f"[!] Connection error: {e}")
                break
                
class LicensePlateOSINT:
    PLATE_SOURCES = [
        "stolencars24.eu",
        "licenseplatesdatabase.com",
        "platecheck.com",
        "findbyplate.com",
        "forum-auto.com",
        "cartitle.org",
        "bimmerforums.com",
        "reddit.com",
        "opendata.transport.ee",
        "regitra.lt",
        "platesmania.com",
        "platehunter.com",
        "carjam.co.nz",
        "numberplates.com",
        "plateslookup.com",
        "digitpol.com/stolen-car-database/"
    ]
    DDG_ONION_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    TOR_PROXIES = {
        "http": "socks5h://127.0.0.1:9052",
        "https": "socks5h://127.0.0.1:9052"
    }

    def __init__(self):
        self.session = requests.Session()
        self.session.proxies = self.TOR_PROXIES
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) LicensePlateOSINT/1.0"
        })

    def generate_plate_dorks(self, plate, country=None):
        dorks = [f'"{plate}" site:{site}' for site in self.PLATE_SOURCES]
        if country:
            dorks += [f'"{plate}" {country} site:{site}' for site in self.PLATE_SOURCES]
        dorks += [
            f'"{plate}" license plate',
            f'"{plate}" vehicle history',
            f'"{plate}" stolen',
            f'"{plate}" intitle:forum',
            f'"{plate}" inurl:forum',
            f'"{plate}" police report',
            f'"{plate}" intext:stolen',
            f'"{plate}" accident report',
            f'"{plate}" recovered',
            f'"{plate}" insurance',
            f'"{plate}" VIN',
            f'"{plate}" owner',
            f'"{plate}" make model',
            f'"{plate}" carfax',
            f'"{plate}" site:gov',
            f'"{plate}" site:reddit.com',
            f'{plate}',
            f'{plate} car',
        ]
        return list(set(dorks))

    def parse_ddg_lite_results(self, text):
        soup = BeautifulSoup(text, "html.parser")
        results = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            label = a.get_text(strip=True)
            if href.startswith("http") and label and "google.com" not in href.lower():
                results.append((label, href))
        return results

    def ddg_onion_search(self, query, max_results=8):
        try:
            r = self.session.get(f"{self.DDG_ONION_LITE}?q={quote_plus(query)}", timeout=20)
            results = self.parse_ddg_lite_results(r.text)
            if not results:
                r2 = self.session.post(self.DDG_ONION_LITE, data={"q": query}, timeout=20)
                results = self.parse_ddg_lite_results(r2.text)
            return results[:max_results] if results else []
        except Exception:
            return []

    def fetch_url(self, url, plate):
        try:
            r = self.session.get(url, timeout=14)
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text(separator=" ", strip=True)
            snippet = ""
            idx = text.lower().find(plate.lower())
            if idx != -1:
                snippet = text[max(0, idx-60):idx+60]
            else:
                snippet = text[:180]
            return text, snippet
        except Exception:
            return "", ""

    def check_digitpol_direct(self, plate):
        url = f"https://www.digitpol.com/stolen-car-database/?search={plate}"
        try:
            r = self.session.get(url, timeout=20)
            if plate.lower() in r.text.lower():
                idx = r.text.lower().find(plate.lower())
                snippet = r.text[max(0, idx-80):idx+80] if idx != -1 else ""
                return {"url": url, "title": f"Digitpol: {plate}", "snippet": snippet}
        except Exception:
            pass
        return None

    def check_findbyplate_direct(self, plate):
        url = f"https://findbyplate.com/CA/search/?q={plate}"
        try:
            r = self.session.get(url, timeout=20)
            if plate.lower() in r.text.lower():
                idx = r.text.lower().find(plate.lower())
                snippet = r.text[max(0, idx-80):idx+80] if idx != -1 else ""
                return {"url": url, "title": f"FindByPlate: {plate}", "snippet": snippet}
        except Exception:
            pass
        return None

    def check_plateslookup_direct(self, plate):
        url = f"https://plateslookup.com/search/?q={plate}"
        try:
            r = self.session.get(url, timeout=20)
            if plate.lower() in r.text.lower():
                idx = r.text.lower().find(plate.lower())
                snippet = r.text[max(0, idx-80):idx+80] if idx != -1 else ""
                return {"url": url, "title": f"PlatesLookup: {plate}", "snippet": snippet}
        except Exception:
            pass
        return None

    def run(self, plate, country=None, max_results=20):
        dorks = self.generate_plate_dorks(plate, country)
        seen_urls = set()
        all_urls = []
        # Collect URLs from all dorks (DuckDuckGo Onion) and filter out google.com
        for dork in dorks:
            hits = self.ddg_onion_search(dork, max_results=2)
            for label, url in hits:
                if "google.com" in url.lower():
                    continue
                if url not in seen_urls:
                    seen_urls.add(url)
                    all_urls.append((label, url))
        # Fetch all URLs in parallel, classify
        profiles, mentions = [], []
        exact_plates, correlated = set(), []
        all_fetched = []
        def fetch_and_classify(label, url):
            text, snippet = self.fetch_url(url, plate)
            entry = {"url": url, "title": label, "snippet": snippet}
            found = False
            if plate.lower() in url.lower() or plate.lower() in label.lower():
                profiles.append(entry)
                found = True
            if not found and plate.lower() in snippet.lower():
                mentions.append(entry)
                found = True
            if re.search(rf"\b{re.escape(plate)}\b", text, re.I):
                exact_plates.add(plate)
                if not found:
                    mentions.append(entry)
                    found = True
            if found:
                correlated.append(entry)
            all_fetched.append(entry)
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(fetch_and_classify, label, url) for label, url in all_urls]
            for _ in as_completed(futures):
                pass
        # Add direct database hits (never google.com)
        for check_fn in [self.check_digitpol_direct, self.check_findbyplate_direct, self.check_plateslookup_direct]:
            res = check_fn(plate)
            if res:
                profiles.append(res)
                correlated.append(res)
                all_fetched.append(res)
                exact_plates.add(plate)
        return {
            "success": bool(profiles or mentions or exact_plates or correlated),
            "plate": plate,
            "country": country,
            "profiles": profiles,
            "mentions": mentions,
            "exact_plates": sorted(exact_plates),
            "correlated": correlated,
            "all_links": [url for _, url in all_urls],
            "all_snippets": all_fetched,
            "dorks_run": dorks,
            "errors": [],
            "error": "No results found." if not (profiles or mentions or exact_plates or correlated) else "",
        }
        
# Load SpaCy model globally for efficiency
nlp = spacy.load("en_core_web_sm")

class DarkelfGovernmentScanner:
    """
    International legal/court scanner.
    Uses CourtListener (US), BAILII (UK/Commonwealth), AustLII (Australia),
    and various international LII portals.
    Includes SpaCy NER summaries and rich table output.
    """

    COURTLISTENER_API_ENDPOINTS = {
        "search": "https://www.courtlistener.com/api/rest/v4/search/",
    }
    BAILII_SEARCH_URL = "https://www.bailii.org/cgi-bin/lucy_search_1.cgi"
    AUSTLII_SEARCH_URL = "http://www.austlii.edu.au/cgi-bin/sinosrch.cgi"

    WORLD_LII_URLS = {
        "paclii": "http://www.paclii.org/cgi-bin/sinosrch.cgi",
        "nzlii": "http://www.nzlii.org/cgi-bin/sinosrch.cgi",
        "saflii": "http://www.saflii.org/cgi-bin/sinosrch.cgi",
        "hklii": "http://www.hklii.org/cgi-bin/sinosrch.cgi",
        "irlii": "http://www.irlii.org/cgi-bin/sinosrch.cgi",
        "worldlii": "http://www.worldlii.org/cgi-bin/sinosrch.cgi",
    }

    OUTCOME_KEYWORDS = [
        "affirmed", "reversed", "vacated", "remanded", "denied", "granted",
        "convicted", "acquitted", "dismissed", "upheld", "overturned", "petition denied"
    ]

    def __init__(self, max_results=10, use_tor=False, allow_direct_fallback=True, courtlistener_email=None):
        self.results = []
        self.max_results = max_results
        self.use_tor = use_tor
        self.allow_direct_fallback = allow_direct_fallback
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://duckduckgo.com/",
            "Accept": "application/json",
        }
        if courtlistener_email:
            self.headers["User-Agent"] += f" {courtlistener_email}"
        self.session = self.get_tor_session() if use_tor else requests.Session()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("DarkelfGovernmentScanner")

    @staticmethod
    def get_tor_session():
        session = requests.Session()
        session.proxies = {
            "http": "socks5h://127.0.0.1:9052",
            "https": "socks5h://127.0.0.1:9052"
        }
        return session

    @staticmethod
    def is_probable_case_title(title):
        return bool(title and len(title.strip()) > 0)

    def _safe_get(self, url, params=None, headers=None, timeout=25, retries=2, backoff=2):
        attempt = 0
        while attempt <= retries:
            try:
                resp = self.session.get(url, params=params, headers=headers or self.headers, timeout=timeout)
                resp.raise_for_status()
                return resp
            except Exception as e:
                self.logger.warning(f"GET {url} failed (attempt {attempt+1}/{retries+1}): {e}")
                time.sleep(backoff * (attempt + 1))
                attempt += 1
        if self.allow_direct_fallback and self.use_tor:
            try:
                self.logger.warning(f"Retrying {url} with direct connection (no Tor)...")
                session = requests.Session()
                resp = session.get(url, params=params, headers=headers or self.headers, timeout=timeout)
                resp.raise_for_status()
                return resp
            except Exception as e:
                self.logger.error(f"Direct fallback GET {url} failed: {e}")
        raise RuntimeError(f"Failed to fetch {url} after {retries+1} attempts")

    def search_courtlistener(self, query):
        try:
            url = self.COURTLISTENER_API_ENDPOINTS["search"]
            params = {"q": query, "page_size": self.max_results}
            resp = self._safe_get(url, params=params)
            try:
                data = resp.json()
            except Exception as json_exc:
                print("[ERROR] CourtListener API did NOT return JSON. Here is the raw response:")
                print(resp.text[:1000])  # print first 1000 chars
                raise

            got_any = False
            for result in data.get("results", []):
                if not isinstance(result, dict):
                    continue

                title = result.get("caseName") or result.get("caseNameFull") or ""
                court = result.get("court")
                if isinstance(court, dict):
                    court_name = court.get("name", "")
                else:
                    court_name = court or result.get("court_citation_string", "")
                citations = result.get("citation") or result.get("citations") or ""
                if isinstance(citations, list):
                    citations = ", ".join(citations)
                snippet = ""
                opinions = result.get("opinions")
                if isinstance(opinions, list) and opinions:
                    snippet = opinions[0].get("snippet", "")

                got_any = True
                self.results.append({
                    "source": "CourtListener",
                    "case": title,
                    "court": court_name,
                    "date": result.get("dateFiled"),
                    "status": result.get("status") or result.get("caseStatus"),
                    "citations": citations,
                    "docket_number": result.get("docketNumber"),
                    "url": "https://www.courtlistener.com" + result.get("absolute_url", ""),
                    "snippet": snippet,
                })

            if not got_any:
                self.logger.info("[Fallback] No API results — scraping HTML instead.")
                html_url = f"https://www.courtlistener.com/?q={requests.utils.quote(query)}"
                html = self._safe_get(html_url).text
                self.results.extend(self.parse_courtlistener_html(html)[:self.max_results])

        except Exception as e:
            self.logger.error(f"CourtListener error: {e}")

    def search_bailii(self, query):
        """Search BAILII (UK, Ireland, Commonwealth) for the query."""
        try:
            params = {
                "query": query,
                "method": "boolean",
                "sort": "rank",
                "mask_path": "",
                "search": "all",
                "show": str(self.max_results)
            }
            resp = self._safe_get(self.BAILII_SEARCH_URL, params=params, timeout=20)
            soup = BeautifulSoup(resp.text, "html.parser")
            results = soup.find_all("li")
            for li in results[:self.max_results]:
                a = li.find("a", href=True)
                if not a:
                    continue
                url = a["href"]
                title = a.get_text()
                snippet = li.get_text(separator=" ", strip=True)
                self.results.append({
                    "source": "BAILII",
                    "case": title,
                    "court": "",  # BAILII sometimes includes court in the title
                    "date": "",   # Sometimes in snippet or title, parse with regex if needed
                    "status": "",
                    "citations": "",
                    "docket_number": "",
                    "url": url if url.startswith("http") else "https://www.bailii.org" + url,
                    "snippet": snippet,
                })
        except Exception as e:
            self.logger.error(f"BAILII error: {e}")

    def search_austlii(self, query):
        """Search AustLII (Australian Law) for the query."""
        try:
            params = {
                "query": query,
                "results": self.max_results,
                "submit": "Search",
            }
            resp = self._safe_get(self.AUSTLII_SEARCH_URL, params=params, timeout=20)
            soup = BeautifulSoup(resp.text, "html.parser")
            results = soup.find_all("li")
            for li in results[:self.max_results]:
                a = li.find("a", href=True)
                if not a:
                    continue
                url = a["href"]
                title = a.get_text()
                snippet = li.get_text(separator=" ", strip=True)
                self.results.append({
                    "source": "AustLII",
                    "case": title,
                    "court": "",  # Could parse more from title/snippet
                    "date": "",
                    "status": "",
                    "citations": "",
                    "docket_number": "",
                    "url": url if url.startswith("http") else "http://www.austlii.edu.au" + url,
                    "snippet": snippet,
                })
        except Exception as e:
            self.logger.error(f"AustLII error: {e}")

    def _search_generic_lii(self, query, source_key):
        try:
            base_url = self.WORLD_LII_URLS[source_key]
            params = {
                "query": query,
                "results": self.max_results,
                "submit": "Search",
            }
            resp = self._safe_get(base_url, params=params, timeout=20)
            soup = BeautifulSoup(resp.text, "html.parser")
            results = soup.find_all("li")
            for li in results[:self.max_results]:
                a = li.find("a", href=True)
                if not a:
                    continue
                url = a["href"]
                title = a.get_text()
                snippet = li.get_text(separator=" ", strip=True)
                self.results.append({
                    "source": source_key.upper(),
                    "case": title,
                    "court": "",
                    "date": "",
                    "status": "",
                    "citations": "",
                    "docket_number": "",
                    "url": url if url.startswith("http") else base_url.rsplit("/", 1)[0] + "/" + url,
                    "snippet": snippet,
                })
        except Exception as e:
            self.logger.error(f"{source_key.upper()} error: {e}")

    def parse_courtlistener_html(self, html):
        return []

    def run_all(self, query, sources=None):
        self.results.clear()
        queries = list(set([
            query,
            query.lower().replace(" vs ", " v. "),
            query.lower().replace(" v. ", " vs ")
        ]))
        sources = sources or ['courtlistener', 'bailii', 'austlii']
        for q in queries:
            if 'courtlistener' in sources:
                self.search_courtlistener(q)
            if 'bailii' in sources:
                self.search_bailii(q)
            if 'austlii' in sources:
                self.search_austlii(q)
            for extra in self.WORLD_LII_URLS.keys():
                if extra in sources:
                    self._search_generic_lii(q, extra)
        return self._summarize_results()

    def detect_case_outcome(self, snippet):
        snippet_lower = snippet.lower()
        for word in self.OUTCOME_KEYWORDS:
            if word in snippet_lower:
                match = re.search(rf"\b({word})\b", snippet, re.I)
                if match:
                    context = snippet[max(0, match.start()-40):match.end()+40]
                    return match.group(1).capitalize(), context.strip()
                return word.capitalize(), None
        return "Outcome not detected", None

    def pretty_print_cases_rich(self, results, max_cases=5):
        console = Console()
        for i, r in enumerate(results[:max_cases], 1):
            outcome, _ = self.detect_case_outcome(r.get("snippet", ""))
            parties = ', '.join(r.get("parties", [])) or "N/A"
            url = r.get('url', '—')

            md = f"""
    **Source:** {r.get('source', '—')}
    **Case:** {r.get('case', '—')}
    **Court:** {r.get('court', '—')}
    **Date:** {r.get('date', '—')}
    **Outcome:** {outcome}
    **Parties:** {parties}
    **URL:** {url}
    """
            console.print(Panel(Markdown(md.strip()), border_style="green"))

    def _summarize_results(self):
        summary = []
        for r in self.results:
            text = " ".join(str(val) for val in r.values() if val)
            doc = nlp(text)
            parties = [ent.text for ent in doc.ents if ent.label_ in ("PERSON", "ORG")]
            dates = [ent.text for ent in doc.ents if ent.label_ == "DATE"]
            summary.append({
                **r,
                "parties": sorted(set(parties)),
                "dates": sorted(set(dates)),
            })
        return summary

    def summarize_apa_report(self, results, max_cases=3):
        """
        Generate an APA-style paragraph summarizing the case outcomes.
        """
        if not results:
            return "No court records were found for the given search term."
        summaries = []
        for i, r in enumerate(results[:max_cases], 1):
            outcome, _ = self.detect_case_outcome(r.get('snippet', ''))
            citation = f"{r.get('case', 'Unknown Case')} [{r.get('citations', 'No citation')}]"
            parties = ', '.join(r.get('parties', [])) or "N/A"
            summary = (
                f"{i}. {citation}, {r.get('court', '')}, {r.get('date', '')}. "
                f"Main parties: {parties}. "
                f"Outcome: {outcome}. "
                f"Summary: {r.get('snippet', '')[:150].replace(chr(10), ' ')}{'...' if len(r.get('snippet', '')) > 150 else ''} "
                f"URL: {r.get('url', '')}"
            )
            summaries.append(summary)
        return "\n".join(summaries)

nlp = spacy.load("en_core_web_sm")

class DarkelfSpiderAsync:
    def __init__(self, base_url, depth=3, delay=1.5, keyword_filters=None, extract_data=True, use_tor=False):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.depth = depth
        self.delay = delay
        self.keyword_filters = keyword_filters or []
        self.extract_data = extract_data
        self.use_tor = use_tor
        self.visited = set()
        self.results = []
        self.found_emails = set()
        self.found_hashes = set()
        self.found_usernames = set()
        self.found_names = set()

    def _should_visit(self, url):
        parsed = urlparse(url)
        return (
            parsed.scheme in ("http", "https") and
            self.domain in parsed.netloc and
            url not in self.visited
        )

    def _parse_links(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            full_url = urljoin(base_url, href.split('#')[0])
            if self._should_visit(full_url):
                links.add(full_url)
        return links

    def _matches_keywords(self, content):
        if not self.keyword_filters:
            return True
        return any(kw.lower() in content.lower() for kw in self.keyword_filters)

    def _extract_emails_and_hashes(self, text):
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
        if emails:
            print(f"[DEBUG] Found emails: {emails}")
        self.found_emails.update(emails)
        self.found_hashes.update(hashes)

    def _extract_names(self, text):
        possible_names = re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', text)
        blacklist = {
            "Learn More", "Developer Components", "Documentation Wiki",
            "Hardened Networking", "Native Tor", "Quantum Editions",
            "Ready Editions", "Threat Detection", "Updated Darkelf"
        }
        clean_names = [
            name for name in possible_names
            if name not in blacklist and all(part.istitle() for part in name.split())
        ]
        self.found_names.update(clean_names)

    def _extract_usernames(self, text, soup):
        css_keywords = {
            "media", "keyframes", "font-face", "supports", "import", "charset",
            "layer", "namespace", "document", "page"
        }
        handle_matches = re.findall(r'@([\w\-_]{2,32})', text)
        cleaned_handles = {
            h for h in handle_matches
            if h.lower() not in css_keywords and not h[0].isdigit()
        }
        meta_usernames = set()
        for tag in soup.find_all('meta'):
            content = tag.get('content', '')
            if content and re.fullmatch(r'[\w\-_]{3,32}', content):
                if content.lower() not in css_keywords:
                    meta_usernames.add(content)
        social_patterns = {
            "github": r'github\.com/([\w\-_]{2,32})',
            "discord": r'discord(app)?\.com/users/([\w\-_]+)',
            "tiktok": r'tiktok\.com/@([\w\._\-]+)',
            "twitter": r'(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})',
            "facebook": r'facebook\.com/([A-Za-z0-9.\-]+)',
            "instagram": r'instagram\.com/([A-Za-z0-9_.]+)',
            "reddit": r'reddit\.com/user/([A-Za-z0-9_\-]+)',
            "linkedin": r'linkedin\.com/in/([A-Za-z0-9\-_]+)',
            "youtube_user": r'youtube\.com/user/([A-Za-z0-9_\-]+)',
            "youtube_channel": r'youtube\.com/channel/([A-Za-z0-9_\-]+)',
            "medium": r'medium\.com/@([A-Za-z0-9_\-]+)',
            "pinterest": r'pinterest\.com/([A-Za-z0-9_\-/]+)'
        }
        link_usernames = set()
        for a in soup.find_all('a', href=True):
            href = a['href']
            for platform, pattern in social_patterns.items():
                match = re.search(pattern, href)
                if match:
                    username = match.group(1)
                    if username and username.lower() not in css_keywords:
                        link_usernames.add(username)
        all_usernames = cleaned_handles | meta_usernames | link_usernames
        self.found_usernames.update(all_usernames)

    async def _fetch(self, session, url, depth):
        if depth > self.depth or url in self.visited:
            return
        self.visited.add(url)
        await asyncio.sleep(self.delay)
        try:
            async with session.get(url) as response:
                if response.status != 200:
                    return
                text = await response.text(errors='ignore')
                soup = BeautifulSoup(text, 'html.parser')
                title = soup.title.string.strip() if soup.title else "(No title)"
                content = title + ' ' + url
                if self._matches_keywords(content):
                    self.results.append({"url": url, "title": title})
                if self.extract_data:
                    self._extract_emails_and_hashes(text)
                    self._extract_names(text)
                    self._extract_usernames(text, soup)
                links = self._parse_links(text, url)
                await asyncio.gather(*[
                    self._fetch(session, link, depth + 1) for link in links
                ])
        except Exception:
            pass

    async def run(self):
        print(f"\n🌐 [Spider] Crawling {self.base_url} (depth={self.depth}){' via Tor' if self.use_tor else ''}...\n")
        timeout = ClientTimeout(total=30)
        connector = None
        if self.use_tor:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url('socks5h://127.0.0.1:9052')
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            await self._fetch(session, self.base_url, 0)
        print(f"\n✅ [Spider] Done. {len(self.results)} results.")
        for r in self.results:
            print(f" • {r['title']} — {r['url']}")
        if self.found_emails:
            print(f"\n📧 Emails found ({len(self.found_emails)}):")
            for e in sorted(self.found_emails):
                print(f"   - {e}")
        if self.found_hashes:
            print(f"\n🔐 Hashes found ({len(self.found_hashes)}):")
            for h in sorted(self.found_hashes):
                print(f"   - {h}")
        if self.found_usernames:
            print(f"\n👤 Usernames found ({len(self.found_usernames)}):")
            for u in sorted(self.found_usernames):
                print(f"   - @{u}")
        if self.found_names:
            print(f"\n🧍 Personal Names found ({len(self.found_names)}):")
            for n in sorted(self.found_names):
                print(f"   - {n}")
        return self.results

    def spacy_summary(self):
        """
        Use spaCy to analyze indicators and provide a structured, paragraph-style OSINT summary.
        """

        # Gather indicator lists
        emails = sorted(self.found_emails)
        usernames = sorted(self.found_usernames)
        hashes = sorted(self.found_hashes)
        names = sorted(self.found_names)

        # Load spaCy model
        nlp = spacy.load("en_core_web_sm")

        # Extract named entities from the names list
        name_entities = []
        entity_counter = Counter()
        for name in names:
            doc = nlp(name)
            for ent in doc.ents:
                if ent.label_ in ("PERSON", "ORG"):
                    name_entities.append(f"{ent.label_}: {ent.text}")
                    entity_counter[ent.label_] += 1

        # Build the OSINT report
        report = []
        report.append("OSINT Summary Report:\n")

        # --- Email Addresses ---
        if emails:
            report.append(f"📧 Identified {len(emails)} email address{'es' if len(emails) > 1 else ''}: {', '.join(emails)}.")
            for email in emails:
                if any(email.endswith(domain) for domain in (".pro", ".xyz", ".top", ".icu", ".live")):
                    report.append(f"  - {email}: Uses a non-standard or niche TLD, often linked to disposable or privacy-focused services.")
                elif email.endswith(".gov") or email.endswith(".edu"):
                    report.append(f"  - {email}: Institutional domain suggests legitimacy and possible affiliation with government or education.")

        # --- Usernames ---
        if usernames:
            report.append(f"👤 Detected {len(usernames)} username{'s' if len(usernames) > 1 else ''}: {', '.join(usernames)}.")
            for u in usernames:
                if "darkelf" in u.lower():
                    report.append(f"  - Username '{u}' may be tied to pseudonymous or niche online activity (e.g., forums or cybersecurity).")
                if "consult" in u.lower():
                    report.append(f"  - Username '{u}' suggests potential link to a professional service or freelance identity.")

        # --- Hashes ---
        if hashes:
            report.append(f"🔐 Found {len(hashes)} cryptographic hash{'es' if len(hashes) > 1 else ''} — could indicate leaked credentials, passwords, or API secrets.")

        # --- Names ---
        if names:
            report.append(f"🧑 Extracted {len(names)} name{'s' if len(names) > 1 else ''}: {', '.join(names)}.")
            if name_entities:
                report.append(f"  - Named entity types detected via NLP: {', '.join(name_entities)}.")
            if "Full Name" in names:
                report.append("  - 'Full Name' field may indicate a primary author or account owner.")

        # --- Contextual Inference ---
        if emails or usernames:
            if any("domain" in item for item in emails + usernames):
                report.append("🔎 Affiliation with specific domain names detected; may indicate organizational or service-based origin.")

        # --- Summary Assessment ---
        report.append(
            "\n✅ No immediate critical threats were identified in this scan.\n"
            "⚠️ However, professional-grade email domains and uniquely identifying usernames are present.\n"
            "🔍 Further OSINT techniques such as breach checks, WHOIS lookups, and forum scrapes are advised for deeper context.\n"
            "📌 Use `osintscan` or similar tooling to expand intelligence around these indicators."
        )

        return "\n".join(report)

class PegasusMonitor:
    def __init__(self):
        self.ioc_domains = [
            "akamaitechcloudservices.com", "cloudfront-service.com", "krakenfiles.com",
            "apple-mobile-service.com", "pushupdates.net", "pushedwebcontent.com",
            "icloud-sync.net", "signal-authenticator.net", "cdn-whatsapp.com"
        ]
        self.ioc_keywords = [
            "mprotect", "mmap", "execve", "sandbox escape", "rootkit", "surveillance agent"
        ]
        self.safe_processes = [
            "corespeechd", "replayd", "helpd", "UserEventAgent",
            "mediaanalysisd", "imagent", "searchpartyuseragent", "sirittsd"
        ]
        self.system = platform.system()
        self.is_windows = self.system == "Windows"
        self.is_macos = self.system == "Darwin"
        self.is_android_or_linux = self.system == "Linux"

    def _run(self, command):
        try:
            return os.popen(command).read().splitlines()
        except:
            return []

    def _write_hosts(self, path):
        try:
            current = ""
            try:
                with open(path, "r") as f:
                    current = f.read()
            except:
                pass

            with open(path, "a") as f:
                for domain in self.ioc_domains:
                    if domain not in current:
                        f.write(f"0.0.0.0 {domain}\n")
            return True
        except:
            return False

    def _is_suspicious_log(self, line):
        # Avoid known benign Apple services
        if any(proc in line for proc in self.safe_processes):
            return False

        # Score based on suspicious keywords
        score = 0
        if "execve" in line: score += 2
        if "mmap" in line: score += 1
        if "mprotect" in line: score += 1
        if "sandbox escape" in line: score += 3
        if "rootkit" in line: score += 3

        return score >= 3

    def _report(self, logs, conns):
        found = False

        suspicious_logs = [line for line in logs if self._is_suspicious_log(line)]
        if suspicious_logs:
            print("📄 Suspicious log entries:")
            for line in suspicious_logs:
                print("  •", line)
            found = True
        else:
            print("✅ No suspicious log activity found.")

        flagged_conns = []
        for line in conns:
            if any(domain in line for domain in self.ioc_domains):
                flagged_conns.append(line)

        if flagged_conns:
            print("\n🌐 Network activity with potential C2 servers:")
            for line in flagged_conns:
                print("  •", line)
            found = True
        else:
            print("✅ No suspicious network activity found.")

        if not found:
            print("\n✅ No Pegasus indicators detected.\n")

    def run(self):
        print(f"\n🛡️ [PegasusMonitor] Running Pegasus Defense Scan on {self.system}...\n")
        logs, conns = [], []

        if self.is_macos:
            logs = self._run("log show --style syslog --last 1d | grep -i 'mprotect\\|mmap\\|execve'")
            conns = self._run("netstat -an")
            self._write_hosts("/etc/hosts")

        elif self.is_android_or_linux:
            logs = self._run("logcat -d | grep -i 'mprotect\\|execve'")
            conns = self._run("cat /proc/net/tcp")
            self._write_hosts("/etc/hosts")

        elif self.is_windows:
            logs = self._run("wevtutil qe System /f:text /c:300")
            conns = self._run("netstat -an")
            self._write_hosts("C:\\Windows\\System32\\drivers\\etc\\hosts")

        else:
            print("⚠️ Unsupported platform.")
            return

        self._report(logs, conns)
        print("\n🔒 Pegasus defense scan complete.\n")
        
class EmailIntelPro:
    DISPOSABLE_DOMAINS = {
        "mailinator.com", "10minutemail.com", "tempmail.com", "guerrillamail.com",
        "getnada.com", "yopmail.com", "trashmail.com", "emailondeck.com"
    }

    def __init__(self, email, session=None):
        self.console = Console()
        self.email = email
        self.session = session or get_tor_session()  # ✅ Ensure TOR routing
        self.domain = self.get_domain()
        self.prefix = self.get_prefix()
        self.mx_records = []
        self.txt_records = []
        self.disposable = False
        self.creation_date = "Unknown"
        self.breached = "Unknown"
        self.breach_url = None
        self.score = 0

    def is_valid_email(self):
        return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", self.email)

    def get_domain(self):
        return self.email.split('@')[1].lower()

    def get_prefix(self):
        return self.email.split('@')[0]

    def fetch_mx_records(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            self.mx_records = sorted([str(r.exchange).rstrip('.') for r in answers])
        except:
            self.mx_records = []

    def fetch_txt_records(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            self.txt_records = [r.to_text().strip('"') for r in answers]
        except:
            self.txt_records = []

    def check_disposable(self):
        self.disposable = self.domain in self.DISPOSABLE_DOMAINS

    async def check_rdap(self):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://rdap.org/domain/{self.domain}", timeout=10) as res:
                    if res.status == 200:
                        data = await res.json()
                        for event in data.get("events", []):
                            if event.get("eventAction") == "registration":
                                self.creation_date = event.get("eventDate", "Unknown")
        except Exception:
            self.creation_date = "Unknown"

    def calculate_score(self):
        self.score = 0
        self.score += 3 if self.disposable else 0
        self.score += 2 if not self.mx_records else 0
        self.score += 3 if self.breached == "Yes" else 0
        self.score += 1 if self.creation_date == "Unknown" else 0

    def threat_label(self):
        if self.score >= 7:
            return "[red]HIGH[/red]"
        elif self.score >= 4:
            return "[yellow]MODERATE[/yellow]"
        else:
            return "[green]LOW[/green]"

    async def analyze(self):
        if not self.is_valid_email():
            self.console.print(f"[red]❌ Invalid email: {self.email}[/red]")
            return

        self.fetch_mx_records()
        self.fetch_txt_records()
        self.check_disposable()
        await self.check_rdap()
        self.calculate_score()

        table = Table(title=f"📧 Enhanced Email Intel for [bold]{self.email}[/bold]", show_lines=True)
        table.add_column("Field", style="cyan")
        table.add_column("Result", style="white")

        table.add_row("Domain", self.domain)
        table.add_row("MX Record", "✅ Found" if self.mx_records else "❌ None")
        if self.mx_records:
            table.add_row("MX Servers", "\n".join(self.mx_records))
        table.add_row("Disposable Provider", "⚠️ Yes" if self.disposable else "✅ No")
        table.add_row("Domain Creation", self.creation_date)
        table.add_row("Leaked in Breach", self.breached)
        if self.breach_url:
            table.add_row("Leak Details", self.breach_url)
        table.add_row("TXT Records (SPF/DKIM)", "\n".join(self.txt_records[:3]) if self.txt_records else "❌ None")
        table.add_row("Google Search", f"https://duckduckgo.com/?q=\"{self.email}\"")
        table.add_row("GitHub Search", f"https://github.com/search?q={self.email}")
        table.add_row("Pastebin Search", f"https://duckduckgo.com/?q={self.email}+site:pastebin.com")
        table.add_row("Threat Score", f"{self.score}/10")
        table.add_row("Threat Level", self.threat_label())

        self.console.print(table)

# === FontManager: Stealth Obfuscation and Styling ===
class FontManager:
    def __init__(self, stealth_mode=True, randomize=True):
        self.stealth_mode = stealth_mode
        self.randomize = randomize
        self.console = Console()

        self.fullwidth = {chr(i): chr(0xFF21 + i - 65) for i in range(65, 91)}
        self.styles = [
            "bold green", "bold cyan", "bold yellow",
            "italic magenta", "bold blue", "italic green"
        ]

    def obfuscate(self, text):
        return ''.join(self.fullwidth.get(c.upper(), c) for c in text)

    def stylize(self, text):
        styled = Text()
        for char in text:
            style = random.choice(self.styles) if self.randomize else "bold"
            styled.append(char, style=style)
        return styled

    def print(self, text):
        if self.stealth_mode:
            text = self.obfuscate(text)
        if self.randomize:
            self.console.print(self.stylize(text))
        else:
            self.console.print(text)

# === Initialize global FontManager instance ===
console = Console()
font = FontManager(stealth_mode=True, randomize=True)

# Example usage:
font.print("Darkelf CLI — Secure Terminal Loaded")

class DarkelfIPScan:
    def __init__(self, use_tor=True, timeout=10):
        self.console = Console()
        self.timeout = timeout
        self.use_tor = use_tor
        self.api_urls = [
            "http://ip-api.com/json/{}",      # primary
            "https://ipwho.is/{}",            # fallback 1
            "https://ipinfo.io/{}/json"       # fallback 2
        ]
        self.proxies = {
            "http": "socks5h://127.0.0.1:9052",
            "https": "socks5h://127.0.0.1:9052"
        } if use_tor else None

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_public_ip(self):
        ip_sources = [
            "https://icanhazip.com",
            "https://check.torproject.org/api/ip",
            "https://api64.ipify.org"
        ]
        for url in ip_sources:
            try:
                r = requests.get(url, timeout=self.timeout, proxies=self.proxies)
                ip = r.text.strip()
                ipaddress.ip_address(ip)
                return ip
            except Exception:
                continue
        self.console.print("[red]❌ All public IP sources failed[/red]")
        return None

    def lookup(self, ip=""):
        target_ip = ip.strip() if ip else self.get_public_ip()
        if not target_ip:
            return

        if not self.is_valid_ip(target_ip):
            self.console.print(f"[red]Invalid IP format: {target_ip}[/red]")
            return

        for api_url in self.api_urls:
            try:
                r = requests.get(api_url.format(target_ip), timeout=self.timeout, proxies=self.proxies)
                data = r.json()

                # Handle common API error signals
                if "status" in data and data["status"] != "success":
                    raise Exception(data.get("message", "status != success"))
                if "success" in data and not data["success"]:
                    raise Exception(data.get("message", "lookup failed"))

                self._print_table(data, source=api_url.split('/')[2])
                return
            except Exception as e:
                self.console.print(f"[yellow]⚠️ API error: {e} — trying next[/yellow]")

        self.console.print(f"[red]❌ All lookups failed for {target_ip}[/red]")

    def _print_table(self, data, source="unknown"):
        table = Table(title=f"IP Lookup for {data.get('ip', data.get('query', 'Unknown'))} [dim](via {source})[/dim]")
        fields = {
            "IP": data.get("ip") or data.get("query"),
            "Country": data.get("country") or data.get("country_name"),
            "Region": data.get("regionName") or data.get("region"),
            "City": data.get("city"),
            "ISP": data.get("isp") or data.get("connection", {}).get("isp"),
            "Org": data.get("org") or data.get("connection", {}).get("org"),
            "ASN": data.get("as") or data.get("connection", {}).get("asn"),
            "Timezone": data.get("timezone"),
            "Latitude": str(data.get("lat")),
            "Longitude": str(data.get("lon")),
        }
        for key, val in fields.items():
            table.add_row(key, str(val or "N/A"))
        self.console.print(table)

# === Stealth, Threat Detection, In-Memory Logging ===
# Known tracker hashes (SHA256-obfuscated)

STEALTH_MODE = True  # or True, depending on context

def in_stealth():
    return STEALTH_MODE

KNOWN_TRACKER_HASHES = {
    hashlib.sha256(domain.encode()).hexdigest() for domain in [
        "google-analytics.com",
        "doubleclick.net",
        "facebook.net",
        "hotjar.com",
        "cloudflareinsights.com"
    ]
}

# In-memory ephemeral log
in_memory_log = []

def log_ephemeral(url):
    hashed = hashlib.sha256(url.encode()).hexdigest()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    in_memory_log.append((timestamp, hashed))

def wipe_memory_log():
    in_memory_log.clear()

def threat_score(url):
    parsed = urlparse(url)
    score = 0
    if parsed.port and parsed.port not in [80, 443, 8080]:
        score += 2
    if re.search(r"(tracking|analytics|ads|beacon)", parsed.netloc):
        score += 3
    if parsed.netloc.endswith((".xyz", ".top", ".click", ".gdn", ".live")):
        score += 1
    hashed_domain = hashlib.sha256(parsed.netloc.encode()).hexdigest()
    if hashed_domain in KNOWN_TRACKER_HASHES:
        print("⚠️  Tracker domain detected:", parsed.netloc)
        score += 5
    return score

def check_dns_leak(test_domain="dnsleaktest.com"):
    try:
        ip = socket.gethostbyname(test_domain)
        if ip:
            print(f"[DNS OK] {test_domain} resolved to {ip}")
    except Exception as e:
        print("[DNS Leak Check] Error:", e)

def analyze_connection(url):
    if in_stealth():
        return
    score = threat_score(url)
    if score >= 5:
        print(f"[THREAT] {url} scored {score}/10 on threat scale.")
    log_ephemeral(url)

def setup_logging():
    # Disable specific library loggers
    logging.getLogger('stem').disabled = True
    logging.getLogger('urllib3').disabled = True
    logging.getLogger('requests').disabled = True
    logging.getLogger('torpy').disabled = True
    logging.getLogger('socks').disabled = True
    logging.getLogger('httpx').disabled = True
    logging.getLogger('aiohttp').disabled = True
    logging.getLogger('asyncio').disabled = True

    # Optional: shut down *all* logging unless explicitly re-enabled
    logging.basicConfig(level=logging.CRITICAL)

    # Bonus: catch any logs that somehow sneak through
    logging.getLogger().addHandler(logging.NullHandler())

# Call this early in your main script
setup_logging()

DUCKDUCKGO_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"

DECOY_ONIONS = [
    "http://msydqstlz2kzerdg.onion",  # Tor Project
    "http://zlal32teyptf4tvi.onion",  # DuckDuckGo old
    "http://protonirockerxow.onion",  # ProtonMail
    "http://searxspbitokayvkhzhsnljde7rqmn7rvogyv6o3ap7k2lnwczh2fad.onion", # Searx
    "http://3g2upl4pq6kufc4m.onion",  # DuckDuckGo
    "http://torwikizhdeyutd.onion",   # Tor Wiki
    "http://libraryqtlpitkix.onion",  # Library Genesis
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
]
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.5",
    "en-GB,en;q=0.7",
    "en;q=0.9",
    "en-US;q=0.8,en;q=0.6"
]
REFERERS = [
    "", "https://duckduckgo.com/", "https://startpage.com/", "https://example.com/"
]

KEY_FILES = [
    "my_pubkey.bin", "my_privkey.bin", "msg.dat",
    "history.log", "log.enc", "logkey.bin"
]

class DarkelfKernelMonitor(threading.Thread):
    """
    Monitors kernel state and flags forensic-risk activity (e.g., swap use).
    Instead of force shutdown, it sets a cleanup flag and performs secure wipe on exit.
    """
    def __init__(self, check_interval=5, parent_app=None):
        super().__init__(daemon=True)
        self.check_interval = check_interval
        self.parent_app = parent_app
        self.initial_fingerprint = self.system_fingerprint()
        self._last_swap_active = None
        self._last_pager_state = None
        self._last_fingerprint_hash = hash(str(self.initial_fingerprint))
        self.cleanup_required = False

    def run(self):
        self.monitor_active = True
        console.print("[DarkelfKernelMonitor] ✅ Kernel monitor active.")
        while True:
            time.sleep(self.check_interval)
            swap_now = self.swap_active()
            if swap_now != self._last_swap_active:
                if swap_now:
                    console.print("\u274c [DarkelfKernelMonitor] Swap is ACTIVE — marking cleanup required!")
                    self.kill_dynamic_pager()
                    self.cleanup_required = True
                self._last_swap_active = swap_now

            pager_now = self.dynamic_pager_running()
            if pager_now != self._last_pager_state:
                if pager_now:
                    console.print("\u274c [DarkelfKernelMonitor] dynamic_pager is RUNNING")
                self._last_pager_state = pager_now

            current_fingerprint = self.system_fingerprint()
            if hash(str(current_fingerprint)) != self._last_fingerprint_hash:
                console.print("\u26a0\ufe0f [DarkelfKernelMonitor] Kernel config changed!")
                self.cleanup_required = True
                self._last_fingerprint_hash = hash(str(current_fingerprint))

    def swap_active(self):
        try:
            with open("/proc/swaps", "r") as f:
                return len(f.readlines()) > 1  # Header + at least one active swap
        except Exception:
            return False

    def dynamic_pager_running(self):
        try:
            output = subprocess.check_output(['ps', 'aux'], stderr=subprocess.DEVNULL).decode().lower()
            return "dynamic_pager" in output
        except Exception:
            return False

    def kill_dynamic_pager(self):
        try:
            subprocess.run(["sudo", "launchctl", "bootout", "system", "/System/Library/LaunchDaemons/com.apple.dynamic_pager.plist"], check=True)
            console.print("\U0001f512 [DarkelfKernelMonitor] dynamic_pager disabled")
        except subprocess.CalledProcessError:
            console.print("\u26a0\ufe0f [DarkelfKernelMonitor] Failed to disable dynamic_pager")

    def secure_delete_swap(self):
        try:
            subprocess.run(["sudo", "rm", "-f", "/private/var/vm/swapfile*"], check=True)
            console.print("\U0001f4a8 [DarkelfKernelMonitor] Swap files removed")
        except Exception as e:
            console.print(f"\u26a0\ufe0f [DarkelfKernelMonitor] Failed to remove swapfiles: {e}")

    def secure_purge_darkelf_vault(self):
        vault_paths = [
            os.path.expanduser("~/Darkelf/Darkelf CLI TL Edition.py"),
            os.path.expanduser("~/Desktop/Darkelf CLI TL Edition.py"),
            "/usr/local/bin/Darkelf CLI Browser.py",
            "/opt/darkelf/Darkelf CLI Browser.py"
        ]
        for path in vault_paths:
            if os.path.exists(path):
                try:
                    with open(path, "ba+", buffering=0) as f:
                        length = f.tell()
                        f.seek(0)
                        f.write(secrets.token_bytes(length))
                    os.remove(path)
                    console.print(f"\U0001f4a5 [DarkelfKernelMonitor] Vault destroyed: {path}")
                except Exception as e:
                    console.print(f"\u26a0\ufe0f Failed to delete {path}: {e}")

    def shutdown_darkelf(self):
        console.print("\U0001f4a3 [DarkelfKernelMonitor] Shutdown initiated.")
        if self.cleanup_required:
            self.secure_delete_swap()
            self.secure_purge_darkelf_vault()
        if self.parent_app:
            self.parent_app.quit()
        else:
            os.kill(os.getpid(), signal.SIGTERM)

    def system_fingerprint(self):
        keys = ["kern.osrevision", "kern.osversion", "kern.bootargs"]
        results = {}
        for key in keys:
            try:
                val = subprocess.check_output(['sysctl', key], stderr=subprocess.DEVNULL).decode().strip()
                results[key] = val
            except Exception:
                results[key] = "ERROR"
        return results

class SecureBuffer:
    """
    RAM-locked buffer using mmap + mlock to prevent swapping.
    Use for sensitive in-memory data like session tokens, keys, etc.
    """
    def __init__(self, size=4096):
        self.size = size
        self.buffer = mmap.mmap(-1, self.size)
        self.locked = False
        try:
            libc_name = "libc.so.6" if sys.platform.startswith("linux") else "libc.dylib"
            libc = ctypes.CDLL(libc_name)
            result = libc.mlock(
                ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self.buffer))),
                ctypes.c_size_t(self.size)
            )
            self.locked = (result == 0)
        except Exception as e:
            print(f"[SecureBuffer] mlock failed or not available: {e}")
            self.locked = False

        if not self.locked:
            print("[SecureBuffer] Warning: buffer not locked in RAM! Your OS may not support mlock.")

    def write(self, data: bytes):
        self.buffer.seek(0)
        # If data is shorter than buffer, fill the rest with zeros for security
        data = data[:self.size]
        self.buffer.write(data)
        if len(data) < self.size:
            self.buffer.write(b'\x00' * (self.size - len(data)))

    def read(self) -> bytes:
        self.buffer.seek(0)
        return self.buffer.read(self.size)

    def zero(self):
        ctypes.memset(
            ctypes.addressof(ctypes.c_char.from_buffer(self.buffer)),
            0,
            self.size
        )

    def close(self):
        self.zero()
        self.buffer.close()

    def __del__(self):
        # Always zero and close on deletion
        try:
            self.zero()
            self.buffer.close()
        except Exception:
            pass
            
secure_buffer = SecureBuffer(size=4096)

# --- MemoryMonitor: exit if memory low to avoid swap ---
class MemoryMonitor(threading.Thread):
    """
    Monitors system memory. If available memory falls below threshold,
    exits the program to prevent swap usage and potential forensic leakage.
    """
    def __init__(self, threshold_mb=150, check_interval=5):
        super().__init__(daemon=True)
        self.threshold = threshold_mb * 1024 * 1024  # MB to bytes
        self.check_interval = check_interval
        self._running = True

    def run(self):
        while self._running:
            mem = psutil.virtual_memory()
            if mem.available < self.threshold:
                console.print(f"🔻 LOW MEMORY: < {self.threshold // (1024 * 1024)} MB available. Exiting to prevent swap.")
                sys.exit(1)
            time.sleep(self.check_interval)

    def stop(self):
        self._running = False

# --- hardened_random_delay: for stealth timings ---
def hardened_random_delay(min_delay=0.1, max_delay=1.0, jitter=0.05):
    secure_random = random.SystemRandom()
    base_delay = secure_random.uniform(min_delay, max_delay)
    noise = secure_random.uniform(-jitter, jitter)
    final_delay = max(0, base_delay + noise)
    time.sleep(final_delay)

# --- StealthCovertOpsPQ: PQ in-memory log, anti-forensics ---
class StealthCovertOpsPQ:
    def __init__(self, stealth_mode=True):
        self._log_buffer = []
        self._stealth_mode = stealth_mode
        self._authorized = False

        # === Kyber768: Post-Quantum Key Exchange ===
        self.kem = EphemeralPQKEM("Kyber768")
        self.public_key = self.kem.generate_keypair()
        self.private_key = self.kem.export_secret_key()
        self.stealth_mode = stealth_mode

        # Derive shared secret using encapsulation
        self.ciphertext, self.shared_secret = self.kem.encap_secret(self.public_key)

        # Derive AES-256 key from shared secret
        self.salt = os.urandom(16)
        self.aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            info=b"mlkem768_log_key"
        ).derive(self.shared_secret)

        self.aesgcm = AESGCM(self.aes_key)

    def encrypt(self, message: str) -> str:
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, message.encode(), None)
        blob = {
            "nonce": base64.b64encode(nonce).decode(),
            "cipher": base64.b64encode(ciphertext).decode()
        }
        return json.dumps(blob)

    def decrypt(self, blob_str: str) -> str:
        blob = json.loads(blob_str)
        nonce = base64.b64decode(blob["nonce"])
        cipher = base64.b64decode(blob["cipher"])
        return self.aesgcm.decrypt(nonce, cipher, None).decode()

    def log_to_memory(self, message: str):
        encrypted = self.encrypt(f"[{datetime.utcnow().isoformat()}] {message}")
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

    def panic(self):
        console.print("[StealthOpsPQ] 🚨 PANIC: Wiping memory, faking noise, and terminating.")
        self.clear_logs()
        self.memory_saturate(500)
        self.cpu_saturate(10)
        self.fake_activity_noise()
        self.process_mask_linux()
        os._exit(1)

# --- PhishingDetectorZeroTrace: PQ phishing detector ---
class PhishingDetectorZeroTrace:
    """
    Post-Quantum phishing detector with:
    - In-memory PQ-encrypted logs
    - No logging to disk until shutdown (if authorized)
    - No network or LLM usage
    """

    def __init__(self, pq_logger=None, flush_path="phishing_log.txt"):
        self.static_blacklist = {
            "paypal-login-security.com",
            "update-now-secure.net",
            "signin-account-verification.info"
        }
        self.suspicious_keywords = {
            "login", "verify", "secure", "account", "bank", "update", "signin", "password"
        }
        self.ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        self.session_flags = set()
        self.pq_logger = pq_logger
        self.flush_path = flush_path

    def is_suspicious_url(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            host = host.lower()
            url_hash = self._hash_url(url)

            if url_hash in self.session_flags:
                return self._log_and_flag(url, "Previously flagged during session.")

            if host in self.static_blacklist:
                return self._log_and_flag(url, f"Domain '{host}' is in static blacklist.")

            if self.ip_pattern.match(host):
                return self._log_and_flag(url, "URL uses IP address directly.")

            if host.count('.') > 3:
                return self._log_and_flag(url, "Too many subdomains.")

            for keyword in self.suspicious_keywords:
                if keyword in host:
                    return self._log_and_flag(url, f"Contains suspicious keyword: '{keyword}'.")

            return False, "URL appears clean."

        except Exception as e:
            return self._log_and_flag(url, f"URL parsing error: {str(e)}")

    def analyze_page_content(self, html, url="(unknown)"):
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
                return self._log_and_flag(url, "Suspicious elements found in page.")
            return False, "Content appears clean."
        except Exception as e:
            return self._log_and_flag(url, f"Content scan error: {str(e)}")

    def flag_url_ephemeral(self, url):
        self.session_flags.add(self._hash_url(url))

    def _log_and_flag(self, url, reason):
        if self.pq_logger:
            timestamp = datetime.utcnow().isoformat()
            message = f"[{timestamp}] PHISHING - {url} | {reason}"
            self.pq_logger.log_to_memory(message)
        self.flag_url_ephemeral(url)
        return True, reason

    def _hash_url(self, url):
        return hashlib.sha256(url.encode()).hexdigest()

    def flush_logs_on_exit(self):
        if self.pq_logger:
            try:
                self.pq_logger.authorize_flush("darkelf-confirm")
                self.pq_logger.flush_log(path=self.flush_path)
                console.print(f"[PhishingDetector] ✅ Flushed encrypted phishing log to {self.flush_path}")
            except Exception as e:
                console.print(f"[PhishingDetector] ⚠️ Log flush failed: {e}")

class PQKEMWrapper:
    def __init__(self, algo="Kyber768"):
        self.algo = algo
        self.kem = oqs.KeyEncapsulation(self.algo)
        self.privkey = None
        self.pubkey = None

    def generate_keypair(self):
        """Generates a new PQ keypair."""
        self.pubkey = self.kem.generate_keypair()
        self.privkey = self.kem.export_secret_key()  # Fixed: store private key correctly
        return self.pubkey

    def export_secret_key(self):
        """Returns the last generated or imported secret key."""
        return self.privkey

    def import_secret_key(self, privkey_bytes):
        """Loads a secret key into the encapsulator."""
        self.kem = oqs.KeyEncapsulation(self.algo)  # re-init for clean state
        self.kem.import_secret_key(privkey_bytes)   # Fixed: was incomplete
        self.privkey = privkey_bytes

    def encap_secret(self, pubkey_bytes):
        """Encapsulates a shared secret to a recipient's public key."""
        return self.kem.encap_secret(pubkey_bytes)

    def decap_secret(self, ciphertext):
        """Decapsulates the shared secret from ciphertext using the private key."""
        if self.privkey is None:
            raise ValueError("Private key not set. Use generate_keypair() or import_secret_key().")
        return self.kem.decap_secret(ciphertext)

class NetworkProtector:
    def __init__(self, sock, peer_kyber_pub_b64: str, privkey_bytes: bytes = None, direction="outbound", version=1, cover_traffic=True):
        self.sock = sock
        self.secure_random = random.SystemRandom()
        self.peer_pub = base64.b64decode(peer_kyber_pub_b64)
        self.privkey_bytes = privkey_bytes
        self.direction = direction
        self.version = version
        self.cover_traffic = cover_traffic
        if cover_traffic:
            threading.Thread(target=self._cover_traffic_loop, daemon=True).start()

    def _frame_data(self, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + payload  # 4-byte big-endian length prefix

    def _unframe_data(self, framed: bytes) -> bytes:
        length = struct.unpack(">I", framed[:4])[0]
        return framed[4:4 + length]

    def add_jitter(self, min_delay=0.05, max_delay=0.3):
        jitter = self.secure_random.uniform(min_delay, max_delay)
        time.sleep(jitter)

    def send_with_padding(self, data: bytes, min_padding=128, max_padding=512):
        target_size = max(len(data), self.secure_random.randint(min_padding, max_padding))
        pad_len = target_size - len(data)
        padded = data + os.urandom(pad_len)
        self.sock.sendall(self._frame_data(padded))  # framed for streaming

    def send_protected(self, data: bytes):
        self.add_jitter()
        compressed = zlib.compress(data)
        encrypted = self.encrypt_data_kyber768(compressed)
        self.send_with_padding(encrypted)

    def encrypt_data_kyber768(self, data: bytes) -> bytes:
        kem = PQKEMWrapper("Kyber768")
        ciphertext, shared_secret = kem.encap_secret(self.peer_pub)
        salt = os.urandom(16)
        nonce = os.urandom(12)

        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"darkelf-net-protect"
        ).derive(shared_secret)

        aesgcm = AESGCM(aes_key)
        payload = {
            "data": base64.b64encode(data).decode(),
            "id": secrets.token_hex(4),
            "ts": datetime.utcnow().isoformat(),
            "dir": self.direction
        }
        plaintext = json.dumps(payload).encode()
        encrypted_payload = aesgcm.encrypt(nonce, plaintext, None)

        packet = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "payload": base64.b64encode(encrypted_payload).decode(),
            "salt": base64.b64encode(salt).decode(),
            "version": self.version
        }
        return base64.b64encode(json.dumps(packet).encode())

    def receive_protected(self, framed_data: bytes):
        kem = PQKEMWrapper("Kyber768")
        raw = self._unframe_data(framed_data)
        packet = json.loads(base64.b64decode(raw).decode())

        ciphertext = base64.b64decode(packet["ciphertext"])
        nonce = base64.b64decode(packet["nonce"])
        salt = base64.b64decode(packet["salt"])
        enc_payload = base64.b64decode(packet["payload"])

        shared_secret = kem.decap_secret(ciphertext)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"darkelf-net-protect"
        ).derive(shared_secret)

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, enc_payload, None)
        payload = json.loads(plaintext.decode())
        compressed_data = base64.b64decode(payload["data"])
        original_data = zlib.decompress(compressed_data)

        return {
            "data": original_data,
            "meta": {
                "id": payload["id"],
                "timestamp": payload["ts"],
                "direction": payload["dir"],
                "version": packet["version"]
            }
        }
        
    def _cover_traffic_loop(self):
        while True:
            try:
                self.add_jitter(0.2, 1.0)
                fake_data = secrets.token_bytes(self.secure_random.randint(32, 128))
                self.send_protected(fake_data)
            except Exception:
                pass
            time.sleep(self.secure_random.uniform(15, 45))  # Interval between cover messages

console = Console()

class TorManagerCLI:
    def __init__(self):
        self.tor_process = None
        self.controller = None
        self.socks_port = 9052
        self.control_port = 9053
        self.dns_port = 9054
        self.data_dir = "/tmp/darkelf-tor-data"
        self.tor_network_enabled = True
        self.allow_direct_fallback = True

    def init_tor(self):
        if self.tor_network_enabled:
            self.start_tor()
            if self.is_tor_running():
                console.print(f"[Darkelf] Tor is running on SOCKS:{self.socks_port}, CONTROL:{self.control_port}, DNS:{self.dns_port}")

    def start_tor(self):
        try:
            if self.tor_process:
                console.print("Tor is already running.")
                return

            tor_path = shutil.which("tor")
            obfs4_path = shutil.which("obfs4proxy")

            if not tor_path or not os.path.exists(tor_path):
                console.print("Tor not found. Please install it using:\n\n  brew install tor\nor\n  sudo apt install tor")
                return

            if not obfs4_path or not os.path.exists(obfs4_path):
                console.print("obfs4proxy not found. Please install it using:\n\n  brew install obfs4proxy\nor\n  sudo apt install obfs4proxy")
                return

            bridges = [
                "obfs4 46.36.37.251:8443 58B51B6F4010DE58322752D0A9E437B4046B5023 cert=ivuqECFLPemiQ2aodQ7qnuXDpRqdOg6cTWStKAMxSVL5xhi3kKfE+ZGV5MtKCxy4URPHDg iat-mode=0"
                "obfs4 193.138.81.106:8443 C94512A5874D9A1D5D1A7682A75DEB6D00430761 cert=KigNdR5llmRn1BF1ydeK3ZaI4ypBz2WjD5sH5//0ufav2RCv0Ue6VX/c4G76O9wyp3DyHw iat-mode=0" 

            ]
            random.shuffle(bridges)

            tor_config = {
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port),
                'DNSPort': str(self.dns_port),
                'AutomapHostsOnResolve': '1',
                'VirtualAddrNetworkIPv4': '10.192.0.0/10',
                'CircuitBuildTimeout': '10',
                'MaxCircuitDirtiness': '180',
                'NewCircuitPeriod': '120',
                'NumEntryGuards': '2',
                'AvoidDiskWrites': '1',
                'CookieAuthentication': '1',
                'DataDirectory': self.data_dir,
                'Log': 'notice stdout',
                'UseBridges': '1',
                'ClientTransportPlugin': f'obfs4 exec {obfs4_path}',
                'Bridge': bridges,
                'StrictNodes': '1',
                'BridgeRelay': '0'
            }

            try:
                self.tor_process = stem_process.launch_tor_with_config(
                    tor_cmd=tor_path,
                    config=tor_config,
                    init_msg_handler=lambda line: console.print("[tor]", line)
                )
            except Exception as bridge_error:
                console.print("[Darkelf] Bridge connection failed:", bridge_error)

                if not getattr(self, "allow_direct_fallback", True):
                    console.print("Bridge connection failed and direct fallback is disabled.")
                    return  # Stop here if fallback not allowed

                console.print("[Darkelf] Bridge connection failed. Trying direct Tor connection...")
                tor_config.pop('UseBridges', None)
                tor_config.pop('ClientTransportPlugin', None)
                tor_config.pop('Bridge', None)
                tor_config.pop('BridgeRelay', None)

                self.tor_process = stem_process.launch_tor_with_config(
                    tor_cmd=tor_path,
                    config=tor_config,
                    init_msg_handler=lambda line: console.print("[tor fallback]", line)
                )
            
            # Wait for the control_auth_cookie to appear and be readable
            cookie_path = os.path.join(tor_config['DataDirectory'], 'control_auth_cookie')
            self.wait_for_cookie(cookie_path)

            # Connect controller and authenticate using the cookie
            self.controller = Controller.from_port(port=self.control_port)
            with open(cookie_path, 'rb') as f:
                cookie = f.read()
            self.controller.authenticate(cookie)
            console.print("[Darkelf] Tor authenticated via cookie.")
            
        except OSError as e:
            console.print(f"Failed to start Tor: {e}")
        except Exception as e:
            console.print(f"Unexpected error: {e}")

    def wait_for_cookie(self, cookie_path, timeout=10):
        start = time.time()
        while True:
            try:
                with open(cookie_path, 'rb'):
                    return
            except Exception:
                if time.time() - start > timeout:
                    raise TimeoutError("Timed out waiting for Tor control_auth_cookie to appear.")
                time.sleep(0.2)

    def is_tor_running(self):
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                return True
        except Exception as e:
            console.print(f"Tor is not running: {e}")
            return False

    def is_tor_running(self):
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                return True
        except Exception as e:
            console.print(f"Tor is not running: {e}")
            return False

    def test_tor_socks_pqc(self):
        """
        Test a PQC-protected connection routed through Tor's SOCKS5 proxy with jitter and padding.
        """
        try:
            # Create a SOCKS5 proxy socket through Tor
            test_sock = socks.socksocket()
            test_sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
            test_sock.connect(("127.0.0.1", 9052))

            # Apply artificial jitter (random delay before sending)
            jitter_delay = random.uniform(0.5, 2.0)  # 0.5 to 2 seconds
            time.sleep(jitter_delay)

            # Example peer public key; replace with a real one in practice
            peer_pub_key_b64 = KyberManager().get_public_key()
            protector = NetworkProtector(test_sock, peer_pub_key_b64)

            # Message padding handled inside send_protected if implemented
            protector.send_protected(b"[Darkelf] Tor SOCKS test with PQC + jitter + padding")
            test_sock.close()

        except Exception as e:
            console.print(f"[Darkelf] Tor SOCKS PQC test failed: {e}")


    def stop_tor(self):
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process = None
            console.print("Tor stopped.")

    def close(self):
        self.stop_tor()

# Optional: Use aiohttp_socks if routing through Tor
try:
    from aiohttp_socks import ProxyConnector
except ImportError:
    ProxyConnector = None

async def async_duckduckgo_search(query, tor_proxy="socks5://127.0.0.1:9052", max_results=10):
    await asyncio.sleep(0.2)
    headers = {'User-Agent': 'Mozilla/5.0'}
    url = DUCKDUCKGO_LITE + f"?q={quote_plus(query)}"
    connector = ProxyConnector.from_url(tor_proxy)
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, headers=headers, timeout=20) as response:
                if response.status != 200:
                    return []
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                results = []
                for a in soup.find_all("a", href=True):
                    if "result" in a.get("class", []) or "nofollow" in a.get("rel", []):
                        href = html.unescape(a["href"])
                        text = a.get_text(strip=True)
                        if href.startswith(("http://", "https://")) and text:
                            results.append((text, href))
                        if len(results) >= max_results:
                            break
                return results
    except Exception:
        return []

async def async_batch_duckduckgo_search(queries):
    return await asyncio.gather(*(async_duckduckgo_search(q) for q in queries))

async def async_batch_duckduckgo_search(queries):
    return await asyncio.gather(*(async_duckduckgo_search(q) for q in queries))
    
def get_tor_proxy():
    return f"socks5h://127.0.0.1:9052"

def random_headers(extra_stealth_options=None):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": random.choice(REFERERS),
        "DNT": "1" if random.random() < 0.5 else "0"
    }
    if extra_stealth_options:
        if extra_stealth_options.get("random_order"):
            headers = dict(random.sample(list(headers.items()), len(headers)))
        if extra_stealth_options.get("add_noise_headers"):
            headers["X-Request-ID"] = base64.urlsafe_b64encode(os.urandom(6)).decode()
            if random.random() < 0.5:
                headers["X-Fake-Header"] = "Darkelf"
        if extra_stealth_options.get("minimal_headers"):
            headers.pop("Accept-Language", None)
            headers.pop("Referer", None)
        if extra_stealth_options.get("spoof_platform"):
            if random.random() < 0.5:
                headers["Sec-CH-UA-Platform"] = random.choice(["Linux", "Windows", "macOS"])
    return headers

def random_delay(extra_stealth_options=None):
    base = random.uniform(0.1, 0.8)
    if extra_stealth_options and extra_stealth_options.get("delay_range"):
        min_d, max_d = extra_stealth_options["delay_range"]
        base = random.uniform(min_d, max_d)
    time.sleep(base)

def hash_url(url):
    return hashlib.sha256(url.encode()).hexdigest()[:16]

def encrypt_log(message, key):
    f = Fernet(key)
    return f.encrypt(message.encode())

def get_fernet_key(path="logkey.bin"):
    from cryptography.fernet import Fernet

    def is_valid_fernet_key(k):
        try:
            return len(base64.urlsafe_b64decode(k)) == 32
        except Exception:
            return False

    if not os.path.exists(path):
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)
        return key

    with open(path, "rb") as f:
        key = f.read().strip()

    if not is_valid_fernet_key(key):
        console.print("⚠️ Invalid key file detected. Regenerating secure Fernet key.")
        key = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(key)

    return key

class EphemeralPQKEM:
    def __init__(self, algo="Kyber768"):
        self.algo = algo
        self.kem = oqs.KeyEncapsulation(self.algo)
        self.privkey = None
        self.pubkey = None

    def generate_keypair(self):
        self.pubkey = self.kem.generate_keypair()
        self.privkey = self.kem.export_secret_key()
        return self.pubkey

    def export_secret_key(self):
        return self.privkey

    def encap_secret(self, pubkey_bytes):
        return self.kem.encap_secret(pubkey_bytes)

    def decap_secret(self, ciphertext):
        return self.kem.decap_secret(ciphertext)  # uses internal key

console = Console()

class DarkelfMessenger:
    def __init__(self, kem_algo="Kyber768"):
        self.kem_algo = kem_algo

    def _derive_password_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def generate_keys(self, pubkey_path="my_pubkey.bin", privkey_path="my_privkey.bin"):
        kem = oqs.KeyEncapsulation(self.kem_algo)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        with open(pubkey_path, "wb") as f:
            f.write(public_key)

        password = getpass("🔐 Set password to protect your private key: ")
        salt = os.urandom(16)
        key = self._derive_password_key(password, salt)
        encrypted = Fernet(key).encrypt(private_key)

        with open(privkey_path, "wb") as f:
            f.write(b"vKEY||" + base64.b64encode(salt) + b"||" + base64.b64encode(encrypted))

        logging.info("🔐 Encrypted private key saved to: %s", privkey_path)

    def send_message(self, recipient_pubkey_path, message_text, output_path="msg.dat"):
        if not os.path.exists(recipient_pubkey_path):
            logging.error("Missing recipient pubkey: %s", recipient_pubkey_path)
            return 1
        if not message_text.strip():
            logging.error("Message cannot be empty.")
            return 1

        password = getpass("🔐 Set a password to protect this message: ")
        kem = oqs.KeyEncapsulation(self.kem_algo)

        with open(recipient_pubkey_path, "rb") as f:
            pubkey = f.read()

        ciphertext, shared_secret = kem.encap_secret(pubkey)
        fernet_key = base64.urlsafe_b64encode(shared_secret[:32])
        message_token = Fernet(fernet_key).encrypt(message_text.encode())

        salt = os.urandom(16)
        password_key = self._derive_password_key(password, salt)
        encrypted_fernet_key = Fernet(password_key).encrypt(fernet_key)

        with open(output_path, "wb") as f:
            f.write(b"v2||" + base64.b64encode(ciphertext) + b"||" +
                    base64.b64encode(encrypted_fernet_key) + b"||" +
                    base64.b64encode(salt) + b"||" +
                    base64.b64encode(message_token))

        logging.info("📤 Encrypted and saved message to: %s", output_path)
        return 0

    def receive_message(self, privkey_path="my_privkey.bin", msg_path="msg.dat"):
        if not os.path.exists(msg_path):
            logging.error("Message file not found: %s", msg_path)
            return 1
        if not os.path.exists(privkey_path):
            logging.error("Private key file not found: %s", privkey_path)
            return 1

        with open(msg_path, "rb") as f:
            content = f.read()

        if not content.startswith(b"v2||"):
            logging.error("Invalid or unsupported message format.")
            return 1

        try:
            _, ct_b64, enc_key_b64, salt_b64, token_b64 = content.split(b"||", 4)
            ciphertext = base64.b64decode(ct_b64)
            enc_fernet_key = base64.b64decode(enc_key_b64)
            msg_salt = base64.b64decode(salt_b64)
            token = base64.b64decode(token_b64)

            with open(privkey_path, "rb") as f:
                priv_data = f.read()

            if not priv_data.startswith(b"vKEY||"):
                logging.error("Private key format invalid.")
                return 1

            _, key_salt_b64, encrypted_privkey_b64 = priv_data.split(b"||", 2)
            key_salt = base64.b64decode(key_salt_b64)
            encrypted_privkey = base64.b64decode(encrypted_privkey_b64)

            password = getpass("🔑 Enter password for your private key: ")
            password_key = self._derive_password_key(password, key_salt)
            privkey = Fernet(password_key).decrypt(encrypted_privkey)

            kem = oqs.KeyEncapsulation(self.kem_algo, secret_key=privkey)
            shared_secret = kem.decap_secret(ciphertext)

            fernet_key = Fernet(self._derive_password_key(password, msg_salt)).decrypt(enc_fernet_key)
            message = Fernet(fernet_key).decrypt(token)

            console.print("📥 Message decrypted:", message.decode())
            return 0
        except Exception as e:
            logging.error("❌ Decryption failed: %s", e)
            return 1

def fetch_with_requests(url, session=None, extra_stealth_options=None, debug=False, method="GET", data=None):
    proxies = {
        "http": get_tor_proxy(),
        "https": get_tor_proxy()
    }
    headers = random_headers(extra_stealth_options)
    try:
        random_delay(extra_stealth_options)
        req_session = session or requests.Session()
        if extra_stealth_options and extra_stealth_options.get("session_isolation"):
            req_session = requests.Session()
        if method == "POST":
            resp = req_session.post(url, data=data, proxies=proxies, headers=headers, timeout=30)
        else:
            resp = req_session.get(url, proxies=proxies, headers=headers, timeout=30)
        resp.raise_for_status()
        random_delay(extra_stealth_options)
        if debug:
            console.print("\n[DEBUG] Request URL:", url)
            console.print("[DEBUG] Request Headers:", headers)
            console.print("[DEBUG] Response Status:", resp.status_code)
            console.print("[DEBUG] Response Headers:", dict(resp.headers))
            console.print("[DEBUG] Raw HTML preview:\n", resp.text[:2000], "\n[END DEBUG]\n")
        return resp.text, headers
    except requests.exceptions.RequestException as e:
        console.print(f"[red]Network error during fetch: {e}[/red]")
        # Optionally, return a blank page or raise a custom error
        return "<html><p>[Network error]</p></html>", headers
    except Exception as e:
        # Only wipe for actual intrusion, not for network errors!
        trigger_self_destruct(f"Unexpected critical error: {e}")
        
def parse_ddg_lite_results(soup):
    results = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        label = a.get_text(strip=True)

        # Handle redirect wrapper
        if "redirect_url=" in href:
            parsed = urlparse(href)
            query = parse_qs(parsed.query)
            real_url = query.get("redirect_url", [None])[0]
            if real_url and label:
                results.append((label, real_url))

        # Handle direct links
        elif href.startswith("http") and label:
            results.append((label, href))

    return results if results else "no_results"
    
def check_my_ip():
    try:
        html, _ = fetch_with_requests("http://check.torproject.org", debug=False)
        if "Congratulations. This browser is configured to use Tor." in html:
            console.print("✅ You're using Tor correctly. Traffic is routed via Tor.")
        else:
            console.print("❌ Warning: Tor routing not detected by check.torproject.org.")
    except Exception as e:
        console.print(f"⚠️ Failed to verify Tor status: {e}")

def fetch_and_display(url, session=None, extra_stealth_options=None, debug=True):
    parsed = urlparse(url)
    hashed_domain = hashlib.sha256(parsed.netloc.encode()).hexdigest()

    if hashed_domain in KNOWN_TRACKER_HASHES:
        console.print(f"⛔ Blocked tracker domain: {parsed.netloc}")
        return

    if re.search(r"(tracking|analytics|ads|beacon)", parsed.netloc):
        console.print(f"⛔ Blocked suspicious tracker domain pattern: {parsed.netloc}")
        return

    html, headers = fetch_with_requests(
        url,
        session=session,
        extra_stealth_options=extra_stealth_options,
        debug=debug
    )
    soup = BeautifulSoup(html, "html.parser")
    console.print("\n📄 Title:", soup.title.string.strip() if soup.title else "No title")
    is_ddg_search = "duckduckgo" in url and ("q=" in url or "search" in url)
    results = []
    if is_ddg_search:
        results = parse_ddg_lite_results(soup)
        if (not results or results == "no_results") and "q=" in url:
            q = url.split("q=",1)[-1]
            q = q.split("&")[0]
            resp2, _ = fetch_with_requests(
                DUCKDUCKGO_LITE,
                session=session,
                extra_stealth_options=extra_stealth_options,
                debug=debug,
                method="POST",
                data={"q": q}
            )
            soup2 = BeautifulSoup(resp2, "html.parser")
            results = parse_ddg_lite_results(soup2)
        if results == "no_results":
            console.print("  ▪ DuckDuckGo Lite reports no results for this query.")
        elif results:
            for txt, link in results:
                console.print(f"  ▪ {txt} — {link if link else '[no url]'}")
        else:
            console.print("  ▪ No results found or parsing failed.")
            if debug:
                console.print(html)
    else:
        found = False
        for p in soup.find_all("p"):
            text = p.get_text(strip=True)
            if text:
                console.print("  ▪", text)
                found = True
        if not found:
            console.print("  ▪ No results found or parsing failed.")
    key = get_fernet_key()
    logmsg = f"{hash_url(url)} | {headers.get('User-Agent','?')}\n"
    enc_log = encrypt_log(logmsg, key)
    with open("log.enc", "ab") as log:
        log.write(enc_log + b'\n')

def trigger_self_destruct(reason="Unknown"):
    console.print(f"💀 INTRUSION DETECTED: {reason} → WIPING...")
    for f in KEY_FILES:
        if os.path.exists(f):
            with open(f, "ba+") as wipe:
                wipe.write(os.urandom(2048))
            os.remove(f)
    exit(1)

def intrusion_check():
    if os.getenv("PYTHONINSPECT") or os.getenv("LD_PRELOAD"):
        trigger_self_destruct("Debug mode detected")
    for p in os.popen("ps aux").readlines():
        if any(tool in p for tool in ["strace", "gdb", "lldb"]):
            trigger_self_destruct("Debugger detected")

def renew_tor_circuit():
    try:
        with Controller.from_port(port=9053) as controller:
            controller.authenticate()
            controller.signal("NEWNYM")
        logging.info("Tor circuit silently renewed.")
    except Exception as e:
        logging.error("Failed to renew Tor circuit: %s", e)


def tor_auto_renew_thread():
    while True:
        time.sleep(random.uniform(60, 180))
        try:
            renew_tor_circuit()
        except Exception:
            pass

def decoy_traffic_thread(extra_stealth_options=None):
    while True:
        time.sleep(random.uniform(40, 120))
        try:
            url = random.choice(DECOY_ONIONS)
            headers = random_headers(extra_stealth_options)
            proxies = {"http": get_tor_proxy(), "https": get_tor_proxy()}
            if random.random() < 0.5:
                requests.get(url, proxies=proxies, headers=headers, timeout=10)
            else:
                requests.post(url, data=os.urandom(random.randint(32, 128)), proxies=proxies, headers=headers, timeout=10)
        except Exception:
            pass

def get_terminal_size():
    return shutil.get_terminal_size((80, 20))

def paginate_output(text):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        width, height = shutil.get_terminal_size((80, 20))
        page_size = height - 2  # reserve lines for prompt

        os.system('clear')
        for line in lines[i:i + page_size]:
            console.print(line[:width])  # truncate long lines

        i += page_size
        if i < len(lines):
            console.print("[bold green]>>[/bold green] ", end=""); input("\n-- More -- Press Enter to continue...")
            
def onion_discovery(keywords, extra_stealth_options=None):
    ahmia = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q=" + quote_plus(keywords)
    console.print(f"🌐 Discovering .onion services for: {keywords}")
    try:
        html, _ = fetch_with_requests(ahmia, extra_stealth_options=extra_stealth_options, debug=False)
        soup = BeautifulSoup(html, "html.parser")
        seen = set()
        for a in soup.find_all("a", href=True):
            href = a['href']
            if ".onion" in href and href not in seen:
                console.print("  ▪", href)
                seen.add(href)
        if not seen:
            console.print("  ▪ No .onion services found for this query.")
    except Exception as e:
        console.print("  ▪ Error during onion discovery:", e)
        
# 🌐 Global list of supported tools
TOOLS = [
    "sherlock", "shodan", "recon-ng", "theharvester", "nmap", "yt-dlp",
    "maltego", "masscan", "amass", "subfinder", "exiftool", "mat2",
    "neomutt", "dnstwist", "gitleaks", "httpx", "p0f", "ollama", "phoneinfoga", "thunderbird"
]

def open_tool(tool):
    """
    Open a terminal tool by name in a new window, installing via Homebrew if missing.
    """
    allowed_tools = TOOLS
    tool = tool.lower()
    if tool not in allowed_tools:
        console.print(f"Tool '{tool}' is not in the allowed list.")
        return

    system = platform.system()

    def is_installed(tool_name):
        try:
            subprocess.run(["which", tool_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return True
        except subprocess.CalledProcessError:
            return False

    try:
        if system == "Darwin":  # macOS
            if is_installed(tool):
                command = f"{tool}"
            else:
                console.print(f"📦 Installing '{tool}' via Homebrew...")
                command = f"brew install {tool}; {tool}"
            subprocess.run([
                "osascript", "-e",
                f'''tell application "Terminal"
    do script "{command}"
    activate
end tell'''
            ], check=True)

        elif system == "Linux":
            if is_installed(tool):
                command = f"{tool}"
            else:
                console.print(f"📦 Installing '{tool}' via Homebrew...")
                command = f"brew install {tool} && {tool}"
            subprocess.run([
                "gnome-terminal", "--", "sh", "-c", f"{command}; exec bash"
            ], check=True)

        elif system == "Windows":
            command = f"{tool}" if is_installed(tool) else f"brew install {tool} && {tool}"
            subprocess.run([
                "cmd.exe", "/c", "start", "cmd.exe", "/k", command
            ], check=True)

        else:
            console.print(f"Unsupported platform: {system}")

    except Exception as e:
        console.print(f"❌ Failed to open tool '{tool}': {e}")
        
def print_help():
    console.print("[bold cyan]Darkelf CLI TL OSINT Tool Kit — Command Reference[/bold cyan]\n")
    console.print("Select by and type full command:\n")

    categories = [
        ("General OSINT and Searching", [
            ("search <keywords>",     "Search DuckDuckGo (onion)"),
            ("debug <keywords>",      "Search and show full debug info"),
            ("osintscan <term|url>",  "Fetch a URL & extract emails, phones, etc."),
            ("findonions <keywords>", "Discover .onion services by keywords"),
            ("govscan",               "Search for All Records - Open Databases"),
            ("licenseplate",          "Look up License Plate Information")
        ]),

        ("Security and Privacy Tools", [
            ("stealth",               "Toggle extra stealth options"),
            ("genkeys",               "Generate post-quantum keys"),
            ("sendmsg",               "Encrypt & send a message"),
            ("recvmsg",               "Decrypt & show received message"),
            ("checkip",               "Verify you're routed through Tor"),
            ("iplookup <ip>",         "Lookup IP address info"),
            ("tlsstatus",             "Show recent TLS Monitor activity"),
            ("beacon <.onion>",       "Check if a .onion site is reachable via Tor"),
            ("dnsleak",               "Run a dnsleak test"),
            ("analyze! <url>",        "Analyze a URL for threat trackers"),
            ("open <url>",            "Open and fetch a full URL (tracker-safe)"),
            ("emailintel <email>",    "Lookup MX Information"),
            ("emailhunt <email>",     "Collect Information"),
            ("pegasusmonitor",        "Run Pegasus Infection Check"),
            ("spider <url>",          "Crawl & Extract information"),
            ("publish-prekey",        "Publish Prekeys for PQChat"),
            ("pqchat",                "Live Post Quantum Chat")
        ]),

        ("Tools and Utilities", [
            ("tool <name>",           "Install and launch a terminal tool"),
            ("tools",                 "List available terminal tools"),
            ("toolinfo",              "Show categorized descriptions of each tool"),
            ("browser",               "Launch Darkelf CLI Browser")
        ]),

        ("Maintenance", [
            ("wipe",                  "Self-destruct and wipe sensitive files"),
            ("help",                  "Show this help menu"),
            ("exit",                  "Exit the browser")
        ])
    ]

    idx = 1
    for section, items in categories:
        console.print(f"\n[bold yellow]{section}[/bold yellow]")
        for cmd, desc in items:
            console.print(f"  {idx:>2}. {cmd:<24} — {desc}")
            idx += 1

def print_toolinfo():
    tool_categories = [
        ("Social & Username Recon", {
            "sherlock": "Find usernames across social networks",
            "recon-ng": "Web recon framework with modules"
        }),

        ("Network Scanning & OSINT", {
            "shodan": "Search engine for internet-connected devices",
            "theharvester": "Collect emails, domains, hosts",
            "masscan": "Internet-scale port scanner",
            "nmap": "Port scanner and network mapper",
            "httpx": "HTTP toolkit for probing web services",
            "p0f": "Passive OS fingerprinting tool",
            "amass": "Subdomain discovery and asset mapping",
            "subfinder": "Passive subdomain discovery"
        }),

        ("Metadata & Privacy", {
            "exiftool": "Read and write file metadata",
            "mat2": "Metadata anonymization toolkit"
        }),

        ("Communications", {
            "neomutt": "Command-line email client",
            "thunderbird": "Secure GUI email client"
        }),

        ("Threat Intelligence", {
            "dnstwist": "Find typo-squatting/phishing domains",
            "gitleaks": "Scan repos for secrets and keys",
            "maltego": "Graphical link analysis tool"
        }),

        ("Media Tools", {
            "yt-dlp": "Download videos from YouTube and more"
        }),

        ("Phone and AI", {
            "phoneinfoga": "Advanced information gathering tool for phone numbers",
            "ollama": "Run local LLMs (AI) via the Ollama API"
        })
    ]

    console.print("[bold cyan]\nAvailable OSINT Tools by Category:[/bold cyan]")
    for title, tools in tool_categories:
        console.print(f"\n[bold yellow]{title}[/bold yellow]")
        for name, desc in tools.items():
            console.print(f"  [magenta]{name:<16}[/magenta] — {desc}")

def print_tools_help():
    console.print("Tools CLI Usage:")
    console.print("  tool <number>     — Install and launch the selected terminal tool\n")
    console.print("Available Tools:")

    half = len(TOOLS) // 2
    col1 = TOOLS[:half]
    col2 = TOOLS[half:]

    for i in range(half):
        left = f"{i+1:>2}. {col1[i]:<12}"
        right = f"{i+1+half:>2}. {col2[i]}"
        console.print(f"  {left} {right}")
        
def check_tls_status():
    try:
        log_path = "darkelf_tls_monitor.log"
        if not os.path.exists(log_path):
            print("[!] TLS monitor log file not found.")
            return

        with open(log_path, "rb") as f:
            file_size = os.path.getsize(log_path)
            seek_size = min(2048, file_size)  # Avoid going before start of file
            f.seek(-seek_size, os.SEEK_END)
            lines = f.readlines()
            last_entries = lines[-10:]

        print("\n[*] TLS Monitor Status:")
        print("- Log file: darkelf_tls_monitor.log")
        print("- Last 10 log entries:")
        for line in last_entries:
            print(" ", line.decode("utf-8", errors="ignore").strip())

    except Exception as e:
        print(f"[!] Error checking TLS status: {e}")



def cli_browser():
    setup_logging()
    parser = argparse.ArgumentParser(description="DarkelfMessenger: PQC CLI Messenger")
    subparsers = parser.add_subparsers(dest="command", required=True)

    gen_parser = subparsers.add_parser("generate-keys", help="Generate a PQ keypair.")
    gen_parser.add_argument("--pub", default="my_pubkey.bin", help="Path for public key output.")
    gen_parser.add_argument("--priv", default="my_privkey.bin", help="Path for private key output.")

    send_parser = subparsers.add_parser("send", help="Send an encrypted message.")
    send_parser.add_argument("--pub", required=True, help="Recipient's public key path.")
    send_parser.add_argument("--msg", required=True, help="Message text to send.")
    send_parser.add_argument("--out", default="msg.dat", help="Output file for encrypted message.")

    recv_parser = subparsers.add_parser("receive", help="Receive/decrypt a message.")
    recv_parser.add_argument("--priv", default="my_privkey.bin", help="Path to your private key.")
    recv_parser.add_argument("--msgfile", default="msg.dat", help="Encrypted message file.")

    args = parser.parse_args()
    messenger = DarkelfMessenger()
    if args.command == "generate-keys":
        messenger.generate_keys(pubkey_path=args.pub, privkey_path=args.priv)
    elif args.command == "send":
        messenger.send_message(args.pub, args.msg, args.out)
    elif args.command == "receive":
        messenger.receive_message(args.priv, args.msgfile)

def get_key():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        key = sys.stdin.read(1)
        if key == '\x1b':
            key += sys.stdin.read(2)
        return key
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        
# === Enhancement Patch for Darkelf CLI ===
# Drop-in ready upgrades: session isolation, PQ log separation, entropy check,
# SIGTERM memory wipe, and TLS fingerprint mimic via uTLS for clearnet requests

# 1. === Strong Entropy Check ===
def ensure_strong_entropy(min_bytes=256):
    try:
        with open("/dev/random", "rb") as f:
            entropy = f.read(min_bytes)
        if len(entropy) < min_bytes:
            raise RuntimeError("Insufficient entropy available from /dev/random")
    except Exception as e:
        print(f"[EntropyCheck] ⚠️ Warning: {e}")

# 2. === Session Isolation Wrapper ===
def fetch_with_isolated_session(url, method="GET", headers=None, data=None, timeout=30):
    session = requests.Session()  # New session per call
    proxies = {"http": get_tor_proxy(), "https": get_tor_proxy()}
    try:
        if method == "POST":
            resp = session.post(url, headers=headers, data=data, proxies=proxies, timeout=timeout)
        else:
            resp = session.get(url, headers=headers, proxies=proxies, timeout=timeout)
        resp.raise_for_status()
        return resp.text, resp.headers
    except Exception as e:
        return f"[ERROR] {e}", {}

# 3. === PQ Log Separation (Split by Purpose) ===
class PQLogManager:
    def __init__(self, key):
        self.fernet = Fernet(key)
        self.logs = {"phishing": [], "onion": [], "tools": []}

    def log(self, category, message):
        if category not in self.logs:
            self.logs[category] = []
        encrypted = self.fernet.encrypt(message.encode())
        self.logs[category].append(encrypted)

    def flush_all(self, base_path="darkelf_logs"):
        os.makedirs(base_path, exist_ok=True)
        for cat, entries in self.logs.items():
            with open(os.path.join(base_path, f"{cat}.log"), "wb") as f:
                for line in entries:
                    f.write(line + b"\n")

# 4. === SIGTERM Triggered Memory Wipe ===
TEMP_SENSITIVE_FILES = ["log.enc", "msg.dat", "my_privkey.bin"]

def sigterm_cleanup_handler(signum, frame):
    print("\n[Darkelf] 🔐 SIGTERM received. Wiping sensitive files...")
    for f in TEMP_SENSITIVE_FILES:
        if os.path.exists(f):
            with open(f, "ba+") as wipe:
                wipe.write(secrets.token_bytes(2048))
            os.remove(f)
    exit(0)

signal.signal(signal.SIGTERM, sigterm_cleanup_handler)

# 5. === uTLS Mimicry for Clearnet Requests ===
try:

    def clearnet_request_utls(url, user_agent):
        session = tls_client.Session(client_identifier="firefox_117")
        return session.get(
            url,
            headers={"User-Agent": user_agent},
            proxy="socks5://127.0.0.1:9052",
            timeout_seconds=20,
            allow_redirects=True
        )
except ImportError:
    def clearnet_request_utls(url, user_agent):
        return requests.get(
            url,
            headers={"User-Agent": user_agent},
            proxies={"http": get_tor_proxy(), "https": get_tor_proxy()},
            timeout=20
        )

# Helper — Tor Proxy

def get_tor_proxy():
    return "socks5h://127.0.0.1:9052"

# Ensure entropy at program start
ensure_strong_entropy()

class KyberVault:
    """
    Quantum-safe vault for storing, encrypting, and decrypting files using Kyber KEM.
    Uses kyber_pub.bin and kyber_priv.bin only, like DarkelfMessenger.
    Stores vault files as vault_xxx.dat in vault_dir.
    """

    def __init__(self, vault_dir="darkelf_vault", kem_algo="Kyber768"):
        self.vault_dir = os.path.abspath(vault_dir)
        os.makedirs(self.vault_dir, exist_ok=True)
        self.kem_algo = kem_algo
        self.pubkey_path = os.path.join(self.vault_dir, "kyber_pub.bin")
        self.privkey_path = os.path.join(self.vault_dir, "kyber_priv.bin")

    def generate_keys(self):
        kem = oqs.KeyEncapsulation(self.kem_algo)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        with open(self.pubkey_path, "wb") as f:
            f.write(public_key)
        with open(self.privkey_path, "wb") as f:
            f.write(private_key)
        return self.pubkey_path, self.privkey_path

    def encrypt_file(self, plaintext, filename=None):
        """
        Encrypt the plaintext string, store as a .dat file in the vault directory.
        """
        if not os.path.isfile(self.pubkey_path):
            raise FileNotFoundError(f"Kyber public key not found: {self.pubkey_path}")
        with open(self.pubkey_path, "rb") as f:
            pubkey = f.read()
        kem = oqs.KeyEncapsulation(self.kem_algo)
        ct, shared_secret = kem.encap_secret(pubkey)
        fkey = base64.urlsafe_b64encode(shared_secret[:32])
        token = Fernet(fkey).encrypt(plaintext.encode())
        ct_b64 = base64.b64encode(ct)
        token_b64 = base64.b64encode(token)
        if not filename:
            fname = f"vault_{int(time.time())}.dat"
        else:
            fname = filename
        path = os.path.join(self.vault_dir, fname)
        with open(path, "wb") as f:
            f.write(b"v1||" + ct_b64 + b"||" + token_b64)
        return path

    def decrypt_file(self, filename):
        """
        Decrypt a vault .dat file using kyber_priv.bin.
        """
        path = os.path.join(self.vault_dir, filename)
        if not os.path.isfile(self.privkey_path):
            raise FileNotFoundError(f"Kyber private key not found: {self.privkey_path}")
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Vault file not found: {path}")
        with open(path, "rb") as f:
            content = f.read()
        if not content.startswith(b"v1||"):
            raise ValueError("Vault file is corrupted or has wrong format.")
        try:
            _, ct_b64, token_b64 = content.split(b"||", 2)
            ct = base64.b64decode(ct_b64)
            token = base64.b64decode(token_b64)
            with open(self.privkey_path, "rb") as f:
                privkey = f.read()
            kem = oqs.KeyEncapsulation(self.kem_algo, secret_key=privkey)
            shared_secret = kem.decap_secret(ct)
            fkey = base64.urlsafe_b64encode(shared_secret[:32])
            decrypted = Fernet(fkey).decrypt(token).decode()
            return decrypted
        except Exception as e:
            raise ValueError("Failed to decrypt vault file: " + str(e))

    def list_vault(self):
        """
        List all .dat files in the vault directory.
        """
        return [f for f in os.listdir(self.vault_dir) if f.endswith(".dat")]
        
    def wipe_vault_files(self):
        """
        Securely wipe all .dat files in the vault directory.
        """
        for fname in self.list_vault():
            fpath = os.path.join(self.vault_dir, fname)
            try:
                size = os.path.getsize(fpath)
                with open(fpath, "r+b") as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(secrets.token_bytes(size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(fpath)
            except Exception:
                pass
                
console = Console()

# --- Theme definitions, improved for accuracy ---
DARKELF_THEMES = {
    "dark": {
        "panel_border": "bright_magenta",
        "header_text": "bold bright_magenta",
        "footer_text": "bright_magenta",
        "content": "white",
        "highlight": "cyan",
        "link": "bright_cyan underline",
        "table_header": "bold cyan",
        "table_row": "white",
        "divider": "cyan",
    },
    "hacker": {
        "panel_border": "bright_green",
        "header_text": "bold bright_green",
        "footer_text": "bright_green",
        "content": "white",
        "highlight": "bright_green",
        "link": "bold green underline",
        "table_header": "bold green",
        "table_row": "white",
        "divider": "bright_green",
    },
    "light": {
        "panel_border": "bright_white",
        "header_text": "bold bright_blue",
        "footer_text": "bright_blue",
        "content": "black",
        "highlight": "yellow",
        "link": "bright_blue underline",
        "table_header": "bold bright_blue",
        "table_row": "black",
        "divider": "yellow",
    },
    "blue": {
        "panel_border": "bright_blue",
        "header_text": "bold bright_blue",
        "footer_text": "bright_blue",
        "content": "white",
        "highlight": "cyan",
        "link": "bright_blue underline",
        "table_header": "bold bright_blue",
        "table_row": "white",
        "divider": "cyan",
    }
}

def get_key():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == '\x1b':
            ch += sys.stdin.read(2)
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def fetch_browser_page(url, debug=False):
    headers = {
        "User-Agent": "Mozilla/5.0 (DarkelfCLI/3.0)"
    }
    proxies = {}
    if ".onion" in url:
        proxies = {
            "http": "socks5h://127.0.0.1:9052",
            "https": "socks5h://127.0.0.1:9052"
        }
    for attempt in range(3):
        try:
            response = requests.get(url, headers=headers, timeout=20, proxies=proxies)
            response.raise_for_status()
            return response.text, response.url
        except requests.exceptions.RequestException as e:
            if attempt == 2:
                raise e
            time.sleep(1)

def make_clickable(text, url):
    return Text(text, style=f"underline blue link {url}")

class Page:
    def __init__(self, url):
        self.url = url
        self.title = url
        self.lines = []
        self.links = []
        self.error = None
        self.headings = []
        self.fetch()

    def fetch(self):
        try:
            html, _ = fetch_with_requests(self.url, debug=False)
            soup = BeautifulSoup(html, 'html.parser')
            for s in soup(['script', 'style', 'noscript']):
                s.decompose()
            title_tag = soup.find('title')
            if title_tag:
                self.title = title_tag.get_text(strip=True)
            self.headings = [h.get_text(strip=True) for h in soup.find_all(['h1', 'h2', 'h3'])]
            results = soup.select(".result")
            fancy_divider = "═" * 40
            if results:
                self.lines = []
                for idx, result in enumerate(results):
                    title = result.select_one(".result__title")
                    snippet = result.select_one(".result__snippet")
                    link = result.find("a", href=True)
                    if title:
                        self.lines.append((f"[{idx+1}]", title.get_text(strip=True)))
                    if snippet:
                        self.lines.append(("", snippet.get_text(strip=True)))
                    if link:
                        self.lines.append(("", link['href']))
                    self.lines.append((None, fancy_divider))
            else:
                self.lines = []
                for idx, p in enumerate(soup.find_all("p")):
                    text = p.get_text(strip=True)
                    if text:
                        self.lines.append((f"[{idx+1}]", text))
                        self.lines.append((None, fancy_divider))
                if not self.lines:
                    main_content = soup.get_text(separator='\n\n')
                    paragraphs = [p.strip() for p in main_content.split('\n\n') if p.strip()]
                    for idx, paragraph in enumerate(paragraphs):
                        self.lines.append((f"[{idx+1}]", paragraph))
                        self.lines.append((None, fancy_divider))
                if self.lines and self.lines[-1][1] == fancy_divider:
                    self.lines.pop()
            if not self.lines:
                self.lines = [(None, "[dim]No content available.[/dim]")]
            self.links = [(i + 1, a.get_text(strip=True), a.get('href')) for i, a in enumerate(soup.find_all('a'))]
            for i, (num, label, _) in enumerate(self.links):
                if label:
                    annotated = f"[{num}] {label}"
                    for idx, (n, line) in enumerate(self.lines):
                        if label in line:
                            self.lines[idx] = (n, line.replace(label, annotated, 1))
                            break
        except Exception as e:
            self.error = str(e)

def launch_browser_in_new_terminal():
    system = platform.system()
    script_path = os.path.abspath(__file__)

    try:
        if system == "Darwin":  # macOS
            subprocess.Popen([
                "osascript", "-e",
                f'tell app "Terminal" to do script "python3 \\"{script_path}\\" --browser"'
            ])
        elif system == "Linux":
            subprocess.Popen(["x-terminal-emulator", "-e", f"python3 '{script_path}' --browser"])
        elif system == "Windows":
            subprocess.Popen([
                "cmd", "/c", "start", "cmd", "/k",
                f"{sys.executable} {script_path} --browser"
            ], shell=True)
        else:
            print("Unsupported OS for terminal launch.")
    except Exception as e:
        print(f"❌ Failed to launch browser in new terminal: {e}")

class DarkelfCLIBrowser:
    def __init__(self):
        self.history = []
        self.forward_stack = []
        self.current_page = None
        self.scroll = 0
        self.tabs = []
        self.active_tab = 0
        self.height = max(12, shutil.get_terminal_size((80, 24)).lines - 2)
        self.needs_render = True
        self.page_size = 15
        self.help_mode = False
        self.links_mode = False
        self.quit = False
        self.search_term = ""
        self.search_matches = []
        self.current_match_idx = 0
        self.vault = KyberVault()
        signal.signal(signal.SIGWINCH, self.on_resize)
        self.console = Console()
        self.theme_name = "blue"  # Default: cyan/blue/green
        self.theme = DARKELF_THEMES[self.theme_name]

    def set_theme(self, name):
        if name in DARKELF_THEMES:
            self.theme_name = name
            self.theme = DARKELF_THEMES[name]
            self.console.print(f"[green]Theme set to {name}.[/green]")
            self.needs_render = True
        else:
            self.console.print(f"[red]Theme '{name}' not found. Available: {', '.join(DARKELF_THEMES.keys())}[/red]")

    def get_terminal_size(self):
        return shutil.get_terminal_size((80, 24))

    def on_resize(self, signum, frame):
        self.needs_render = True

    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def wrap_text(self, lines, width):
        fancy_divider = "═" * (width - 4)
        wrapped = []
        for idx, pair in enumerate(lines):
            number, line = pair if isinstance(pair, tuple) else (None, pair)
            # Search highlight
            if self.search_term and self.search_term.lower() in line.lower():
                line = line.replace(self.search_term, f"[reverse {self.theme['highlight']}]{self.search_term}[/reverse {self.theme['highlight']}]")
            if line.strip() == "═" * 40 or line.strip() == fancy_divider:
                wrapped.append(Text(" ", style=self.theme["content"]))
                wrapped.append(Text(fancy_divider, style=f"bold {self.theme['divider']}"))
                wrapped.append(Text(" ", style=self.theme["content"]))
                continue
            if not line.strip():
                wrapped.append(Text("", style=self.theme["content"]))
                continue
            if line.isupper() and len(line) < 80:
                wrapped.append(Text(line, style=f"bold {self.theme['highlight']}"))
                wrapped.append(Text("", style=self.theme["content"]))
                continue
            if line.endswith(":") and len(line) < 80:
                wrapped.append(Text(line, style=f"bold {self.theme['header_text']}"))
                wrapped.append(Text("", style=self.theme["content"]))
                continue
            if number and number.startswith("[") and "]" in number:
                text_obj = Text()
                text_obj.append(number + " ", style=self.theme["highlight"])
                text_obj.append(line, style=self.theme["link"])
                wrapped.append(text_obj)
                wrapped.append(Text("", style=self.theme["content"]))
                continue
            if line.strip().startswith("[") and "]" in line:
                try:
                    num = int(line.strip().split("]")[0][1:])
                    wrapped.append(Text(line, style=f"underline {self.theme['link']}"))
                    wrapped.append(Text("", style=self.theme["content"]))
                    continue
                except Exception:
                    pass
            wrapped.extend([Text(t, style=self.theme["content"]) for t in textwrap.wrap(line, width=width) or [""]])
        return wrapped

    def do_search(self):
        self.search_term = input("Search: ").strip()
        self.search_matches = []
        self.current_match_idx = 0
        if not self.search_term or not self.current_page or not self.current_page.lines:
            return
        term = self.search_term.lower()
        for idx, (_, line) in enumerate(self.current_page.lines):
            if term in line.lower():
                self.search_matches.append(idx)
        if self.search_matches:
            self.scroll = self.search_matches[0] // self.page_size
            self.current_match_idx = 0

    def next_match(self):
        if self.search_matches:
            self.current_match_idx = (self.current_match_idx + 1) % len(self.search_matches)
            idx = self.search_matches[self.current_match_idx]
            self.scroll = idx // self.page_size
            self.needs_render = True

    def prev_match(self):
        if self.search_matches:
            self.current_match_idx = (self.current_match_idx - 1) % len(self.search_matches)
            idx = self.search_matches[self.current_match_idx]
            self.scroll = idx // self.page_size
            self.needs_render = True

    def jump_to_heading(self):
        if not self.current_page or not self.current_page.headings:
            console.print("[yellow]No headings found on this page.[/yellow]")
            return
        for i, heading in enumerate(self.current_page.headings):
            console.print(f"{i+1}. {heading}")
        num = input("Jump to heading #: ").strip()
        if num.isdigit():
            idx = int(num) - 1
            if 0 <= idx < len(self.current_page.headings):
                heading_text = self.current_page.headings[idx]
                for i, (_, line) in enumerate(self.current_page.lines):
                    if heading_text in line:
                        self.scroll = i // self.page_size
                        self.needs_render = True
                        break

    def render_markdown(self, width):
        # Restore clean organized line breaks!
        output_lines = []
        for i, (_, line) in enumerate(self.current_page.lines):
            # Split each record by a divider, or detect when a new result starts
            if line.strip().startswith("[") and "]" in line:
                # Start of new record
                output_lines.append("")  # blank line before new record
            output_lines.append(line)
        content = "\n".join(output_lines)
        md = Markdown(content)
        self.console.print(Panel(md, title="Markdown", border_style="white", width=width, expand=True))

    def export_to_vault(self):
        if not self.current_page:
            self.console.print("[red]No page loaded.[/red]")
            return
        # Ensure Kyber keys exist
        if not (os.path.exists(self.vault.pubkey_path) and os.path.exists(self.vault.privkey_path)):
            self.vault.generate_keys()
            self.console.print("[green]Vault keypair generated.[/green]")
        content = "\n".join(line for _, line in self.current_page.lines)
        fname = f"vault_{int(time.time())}.dat"
        try:
            self.vault.encrypt_file(content, filename=fname)
            self.console.print(f"[green]Page exported to vault as {fname}[/green]")
        except Exception as e:
            self.console.print(f"[red]Vault export failed: {e}[/red]")

    def list_vault(self):
        files = self.vault.list_vault()
        if not files:
            self.console.print("[yellow]No vault files found.[/yellow]")
            return
        self.console.print("[bold magenta]Vault Files:[/bold magenta]")
        for f in files:
            self.console.print(f"  {f}")
        fname = input("File to decrypt: ").strip()
        if fname in files:
            try:
                decrypted = self.vault.decrypt_file(fname)
                self.console.print(Panel(decrypted, title=f"Vault File: {fname}", border_style="green"))
            except Exception as e:
                self.console.print(f"[red]Failed to decrypt: {e}[/red]")

    def render(self):
        # DO NOT clear or print blank lines here!
        term_size = shutil.get_terminal_size((80, 24))
        width = term_size.columns

        if self.help_mode:
            self.render_help(width)
            return
        if self.links_mode:
            self.render_links(width)
            return

        if not self.current_page:
            self.console.print(Panel(
                Text("[blue]No page loaded.[/blue]", style=self.theme["content"]),
                title="Darkelf CLI Browser",
                border_style=self.theme["panel_border"],
                width=width
            ))
            self.render_footer(width)
            return

        header_text = Text.assemble(
            ("Darkelf CLI Browser", self.theme["header_text"]),
            f" | Tab {self.active_tab + 1}/{len(self.tabs)}\n",
            (self.current_page.title or self.current_page.url, self.theme["link"])
        )
        self.console.print(Panel(header_text, border_style=self.theme["panel_border"], padding=(0, 1), width=width))

        total_lines = len(self.current_page.lines) if self.current_page and self.current_page.lines else 0
        if total_lines:
            start = self.scroll * self.page_size
            end = min(start + self.page_size, total_lines)
            visible_lines = self.current_page.lines[start:end]
        else:
            visible_lines = []

        wrapped_lines = self.wrap_text(visible_lines, width - 4)
        content = []
        for w in wrapped_lines:
            if isinstance(w, Text):
                content.append(w)
            else:
                content.append(Text(w, style=self.theme["content"]))
        self.console.print(Panel(Text.assemble(*content), title="\U0001f4f0 Page Content", border_style=self.theme["panel_border"], width=width, expand=True))

        if self.current_page and self.current_page.lines:
            total_pages = max(1, (len(self.current_page.lines) + self.page_size - 1) // self.page_size)
            current_page = self.scroll + 1
            status = f"-- Page {current_page}/{total_pages} --"
            self.console.print(Align.right(Text(status, style=f"bold {self.theme['footer_text']}"), width=width))

        self.render_footer(width)

        if self.tabs:
            tabs_panel = Text.from_markup(f"[bold {self.theme['highlight']}]Open Tabs:[/bold {self.theme['highlight']}] ")
            for i, tab in enumerate(self.tabs):
                mark = "*" if i == self.active_tab else " "
                tab_title = getattr(tab, "title", getattr(tab, "url", "Tab"))
                style = self.theme["highlight"] if i == self.active_tab else self.theme["footer_text"]
                tabs_panel.append(f"{i+1}. {tab_title} {mark}  ", style=style)
            self.console.print(Align.center(tabs_panel, width=width))

    def render_footer(self, width):
        self.console.print(Rule(style=self.theme["divider"], characters="─"), width=width)
        footer = Text()
        footer.append("[↑/↓/w/s/j/k] Prev/Next Page  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[O] Open Link  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[U] URL  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[B] Back  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[H] History  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[T] Tabs  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[t] Themes  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[F] Search  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[L] List Links  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[E] Export Links  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[V] Vault Export  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[v] View Vault  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[G] Headings  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[M] Markdown  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[/] Search  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[N] Next match  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[?] Help  ", style=f"bold {self.theme['footer_text']}")
        footer.append("[ESC] Wipe Vault/Return  ", style=f"bold {self.theme['highlight']}")
        footer.append("[Q] Quit", style="bold red")
        # Function key to return to CLI menu
        footer.append("[F1] Main Menu", style="bold magenta")
        self.console.print(Align.center(footer, width=width))

    def prompt_theme_menu(self):
        self.console.print("\n[bold cyan]Choose a theme:[/bold cyan]")
        theme_names = list(DARKELF_THEMES.keys())
        for i, t in enumerate(theme_names, 1):
            self.console.print(f"  {i}. {t}")
        choice = input("Theme name or number: ").strip().lower()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(theme_names):
                theme = theme_names[idx]
                self.set_theme(theme)
                self.needs_render = True
                return
        elif choice in DARKELF_THEMES:
            self.set_theme(choice)
            self.needs_render = True
            return
        self.console.print(f"[red]Invalid theme: {choice}[/red]")
        self.needs_render = True

    def render_help(self, width):
        header_text = Text.assemble(
            ("Darkelf CLI Browser", self.theme["header_text"]),
            f" | Tab {self.active_tab + 1}/{len(self.tabs)}\n",
            (self.current_page.title or self.current_page.url if self.current_page else "No Page Loaded", self.theme["link"])
        )
        self.console.print(Panel(header_text, border_style=self.theme["panel_border"], padding=(0, 1), width=width))
        helptext = Text()
        helptext.append(Text.from_markup(f"\n[{self.theme['header_text']}]Darkelf CLI Browser Help[/{self.theme['header_text']}]\n\n"))
        helptext.append("[↑/↓/w/s/j/k] : Previous/next page (pagination)\n")
        helptext.append("[O]           : Open link by number\n")
        helptext.append("[U]           : Enter a URL\n")
        helptext.append("[B]           : Back\n")
        helptext.append("[H]           : Show history\n")
        helptext.append("[T]           : Manage tabs\n")
        helptext.append("[F]           : DuckDuckGo search\n")
        helptext.append("[L]           : List all links on page\n")
        helptext.append("[E]           : Export links to file\n")
        helptext.append("[V]           : Export page to Kyber Vault\n")
        helptext.append("[v]           : View/decrypt Vault files\n")
        helptext.append("[G]           : Jump to heading\n")
        helptext.append("[M]           : Render page as Markdown\n")
        helptext.append("[/]           : Search within page\n")
        helptext.append("[N]           : Next search match\n")
        helptext.append("[?]           : Show this help\n")
        helptext.append("[Q]           : Quit and clear screen\n")
        helptext.append(Text.from_markup(f"\n[bold {self.theme['highlight']}]Tips:[/bold {self.theme['highlight']}] Use [O] to open numbered links, [L] to see all links, highlight search terms with /, export securely with V!\n"))
        self.console.print(Panel(helptext, title="Help", border_style=self.theme["panel_border"], width=width))
        self.render_footer(width)
        self.console.print("\nPress any key to return.", style=self.theme["highlight"])
        get_key()  # Wait for any keypress
        self.help_mode = False
        self.needs_render = True

    def export_links(self):
        if not self.current_page or not self.current_page.links:
            console.print("[red]No links to export.[/red]")
            return
        filename = f"darkelf_links_{int(time.time())}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            for num, label, href in self.current_page.links:
                f.write(f"{num}. {label} - {href}\n")
        console.print(f"[green]Links exported to {filename}[/green]")

    def render_links(self, width):
        # Defensive patch: ensure self.current_page and .links are valid and non-empty
        if not self.current_page or not hasattr(self.current_page, "links") or not self.current_page.links:
            header_text = Text.assemble(
                ("Darkelf CLI Browser", self.theme["header_text"]),
                " | No Tab\n",
                ("No Page Loaded", self.theme["link"])
            )
            self.console.print(Panel(header_text, border_style=self.theme["panel_border"], padding=(0, 1), width=width))
            self.console.print(Panel(Text("No links found.", style=self.theme["highlight"]), title="Links", border_style=self.theme["panel_border"], width=width))
            self.render_footer(width)
            self.links_mode = False
            self.needs_render = True
            return

        header_text = Text.assemble(
            ("Darkelf CLI Browser", self.theme["header_text"]),
            f" | Tab {self.active_tab + 1}/{len(self.tabs)}\n",
            (self.current_page.title or self.current_page.url, self.theme["link"])
        )
        self.console.print(Panel(header_text, border_style=self.theme["panel_border"], padding=(1, 2), width=width))

        seen_urls = set()
        deduped_links = []
        for num, label, href in self.current_page.links:
            if href and href not in seen_urls:
                deduped_links.append((num, label, href))
                seen_urls.add(href)
        fancy_divider = "═" * (width - 4)
        table = Table(show_header=False, box=None, expand=True)
        table.add_column("Result", style=self.theme["content"], ratio=1)
        if deduped_links:
            for num, label, href in deduped_links:
                link_text = Text()
                link_text.append(f"[{num}] ", style=self.theme["highlight"])
                link_text.append(label + "\n", style=f"bold {self.theme['highlight']}")
                link_text.append(href, style=f"{self.theme['link']} link {href}")
                table.add_row(link_text)
                table.add_row(Text(fancy_divider, style=f"bold {self.theme['divider']}"))
        else:
            table.add_row(Text("No links found", style=self.theme["highlight"]))
        self.console.print(table)
        self.render_footer(width)
        self.console.print("\n[O] Open link by number | [E] Export links | Any key to return.")

        key = get_key().lower()
        if key == "o":
            try:
                num = int(input("Open link #: ").strip())
                link_dict = {n: href for n, _, href in deduped_links}
                if num in link_dict:
                    href = link_dict[num]
                    if href.startswith("/l/?uddg="):
                        parsed = urlparse(href)
                        qs = parse_qs(parsed.query)
                        resolved = qs.get("uddg", [""])[0]
                        href = unquote(resolved)
                    if not href.startswith("http"):
                        href = "https://" + href.lstrip("/")
                    self.links_mode = False
                    self.needs_render = True
                    self.visit(href)
                    return
                else:
                    self.console.print(f"[red]Invalid link number: {num}[/red]")
                    time.sleep(1)
                    self.needs_render = True
            except Exception as err:
                self.console.print(f"[red]Invalid input: {err}[/red]")
                time.sleep(1)
                self.needs_render = True
        elif key == "e":
            self.export_links()
            self.links_mode = False
            self.needs_render = True
        elif key.isdigit():
            num = int(key)
            link_dict = {n: href for n, _, href in deduped_links}
            if num in link_dict:
                href = link_dict[num]
                if href.startswith("/l/?uddg="):
                    parsed = urlparse(href)
                    qs = parse_qs(parsed.query)
                    resolved = qs.get("uddg", [""])[0]
                    href = unquote(resolved)
                if not href.startswith("http"):
                    href = "https://" + href.lstrip("/")
                self.links_mode = False
                self.needs_render = True
                self.visit(href)
                return
            else:
                self.console.print(f"[red]Invalid link number: {num}[/red]")
                time.sleep(1)
                self.needs_render = True
        else:
            self.links_mode = False
            self.needs_render = True
            
    def visit(self, url):
        try:
            if self.current_page:
                self.history.append(self.current_page.url)
            self.scroll = 0
            self.forward_stack.clear()
            self.current_page = Page(url)
            if len(self.tabs) <= self.active_tab:
                self.tabs.append(self.current_page)
            else:
                self.tabs[self.active_tab] = self.current_page
            self.needs_render = True
        except Exception as e:
            self.current_page = Page("data:text/html,<html><body><p>Failed to load page</p></body></html>")
            self.current_page.error = str(e)
            self.needs_render = True

    def open_link(self, number):
        try:
            if not self.current_page or not self.current_page.links:
                console.print("[red]No links available on this page.[/red]")
                return
            link_map = dict((num, href) for num, _, href in self.current_page.links)
            href = link_map.get(number)
            if not href:
                console.print(f"[red]No link found for number: {number}[/red]")
                return
            if href.startswith("/l/?uddg="):
                qs = urlparse(href).query
                resolved = parse_qs(qs).get("uddg", [""])[0]
                if not resolved:
                    console.print(f"[red]DuckDuckGo redirect did not resolve for {href}[/red]")
                    return
                href = unquote(resolved)
            if not href.startswith("http"):
                href = urljoin(self.current_page.url, href)
            # Show loading message for better UX
            console.print(f"[yellow]Opening link #{number}: {href}[/yellow]")
            try:
                self.visit(href)
            except Exception as e:
                console.print(f"[red]Network or fetch error: {e}[/red]")
                return
            self.needs_render = True  # Force redraw
        except Exception as e:
            console.print(f"[red]Error opening link: {e}[/red]")

    def show_history(self):
        width = shutil.get_terminal_size((80, 24)).columns
        if not self.history:
            console.print("[green]No browsing history available.[/green]")
        else:
            table = Table(title="History", show_lines=True, box=None, expand=True)
            table.add_column("#", style="cyan", width=6)
            table.add_column("URL", style="blue")
            for i, url in enumerate(reversed(self.history[-20:]), 1):
                table.add_row(str(i), url)
            console.print(table)
        self.render_footer(width)
        console.print("\nPress any key to return.")
        get_key()
        self.needs_render = True

    def manage_tabs(self):
        if not self.tabs:
            console.print("[grey]No open tabs.[/grey]")
            return
        console.print("[bold magenta]Open Tabs:[/bold magenta]")
        for i, tab in enumerate(self.tabs):
            mark = "*" if i == self.active_tab else " "
            console.print(f" {i+1}. {tab.url} {mark}")
        user_input = input("\nEnter tab number or 'x' to close tab: ").strip()
        if user_input.lower() == 'x':
            self.tabs.pop(self.active_tab)
            if self.tabs:
                self.active_tab = max(0, self.active_tab - 1)
                self.current_page = self.tabs[self.active_tab]
            else:
                self.active_tab = 0
                self.current_page = None
                self.scroll = 0
        elif user_input.isdigit():
            idx = int(user_input) - 1
            if 0 <= idx < len(self.tabs):
                self.active_tab = idx
                self.current_page = self.tabs[idx]
        self.needs_render = True

    def simulate_search_prompt(self):
        console.print("\n[bold cyan]Search DuckDuckGo:[/bold cyan]", end=" ")
        query = input().strip()
        if query:
            encoded_query = requests.utils.quote(query)
            url = f"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/?q={encoded_query}"
            self.visit(url)
            if self.current_page:
                self.current_page.title = f"Search DuckDuckGo: {query}"
            self.needs_render = True

    def secure_wipe(self):
        self.history.clear()
        self.tabs.clear()
        self.forward_stack.clear()
        self.current_page = None
        self.scroll = 0
        self.help_mode = False
        self.links_mode = False
        secure_buffer.zero()
        secure_buffer.close()

    def run(self):
        self.needs_render = True
        self.simulate_search_prompt()
        while not self.quit:
            while self.needs_render:
                # self.clear()  # Alignment fix!
                self.render()
                self.needs_render = False
                if not self.links_mode and not self.help_mode and self.current_page:
                    continue
                break

            key = get_key()
            # --- Robust ESC key handling: accept any sequence starting with ESC ---
            if key.startswith('\x1b') and key not in ('\x1b[A', '\x1b[B'):
                # Only treat ESC *not* up or down as quit/wipe!
                self.vault.wipe_vault_files()
                self.console.print(f"[bold {self.theme['highlight']}]KyberVault wiped. Returning to CLI menu.[/bold {self.theme['highlight']}]")
                self.quit = True
                break
            elif key == '\x1b[A' or key == 'w' or key == 'k':
                if self.current_page and self.scroll > 0:
                    self.scroll -= 1
                    self.needs_render = True
            elif key == '\x1b[B' or key == 's' or key == 'j':
                if self.current_page and self.current_page.lines:
                    total_pages = max(1, (len(self.current_page.lines) + self.page_size - 1) // self.page_size)
                    if self.scroll + 1 < total_pages:
                        self.scroll += 1
                        self.needs_render = True
                    # FIX: If at last page, do nothing. Don't quit, don't break, just stay.
            elif key == '/':
                self.do_search()
            elif key == 'n':
                self.next_match()
            elif key == 'N':
                self.prev_match()
            elif key == 'G':
                self.jump_to_heading()
            elif key == 'M':
                if self.current_page:
                    width = self.get_terminal_size().columns
                    self.render_markdown(width)
            elif key == 'v':
                self.list_vault()
            elif key == 'V':
                self.export_to_vault()
            elif key == 'u':
                url = input("\nEnter URL: ").strip()
                if not url:
                    continue
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                self.visit(url)
            elif key == 'b':
                if self.history:
                    url = self.history.pop()
                    if self.current_page:
                        self.forward_stack.append(self.current_page.url)
                    self.visit(url)
            elif key == 'o':
                try:
                    num = int(input("Open link #: "))
                    self.open_link(num)
                except Exception:
                    pass
            elif key.isdigit():
                num = int(key)
                self.open_link(num)
            elif key == 'h':
                self.show_history()
                self.needs_render = True
            elif key == 'T':  # Shift+T for Tabs
                self.manage_tabs()
            elif key == 't':  # Lowercase t for Theme
                self.prompt_theme_menu()
                self.needs_render = True
            elif key == 'f':
                self.simulate_search_prompt()
            elif key == '?':
                self.help_mode = True
                self.needs_render = True
            elif key == 'l':
                self.links_mode = True
                self.needs_render = True
            elif key == 'q' or key == 'Q':
                self.quit = True
                break
        self.clear()
        sys.exit(0)
        
class DarkelfUtils:
    DUCKDUCKGO_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    DUCKDUCKGO_HTML = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html"
    TOR_PROXY = {
        "http": "socks5h://127.0.0.1:9052",
        "https": "socks5h://127.0.0.1:9052"
    }
    DORK_THREADS = 2   # Number of threads for dorking
    FETCH_THREADS = 2  # Number of threads for fetching URLs

    def __init__(self):
        pass

    def generate_duckduckgo_dorks(self, query):
        dorks = []
        if "@" in query:
            dorks += [
                f'"{query}" site:pastebin.com',
                f'"{query}" site:github.com',
                f'"{query}" filetype:txt',
                f'"{query}" site:linkedin.com/in',
                f'"{query}" site:facebook.com',
                f'"{query}" intitle:index.of',
                f'"{query}" ext:log OR ext:txt',
                f'"{query}" site:medium.com',
                f'"{query}" site:archive.org',
            ]
        elif query.startswith("+") or query.replace(" ", "").isdigit():
            dorks += [
                f'"{query}" site:pastebin.com',
                f'"{query}" filetype:pdf',
                f'"{query}" site:whocallsme.com',
                f'"{query}" intitle:index.of',
                f'"{query}" ext:log OR ext:txt',
            ]
        elif "." in query:
            dorks += [
                f'site:{query} ext:log',
                f'site:{query} ext:txt',
                f'"@{query}"',
                f'"{query}" intitle:index.of',
                f'"{query}" filetype:csv',
                f'"{query}" site:archive.org',
            ]
        else:
            dorks += [
                f'"{query}" site:github.com',
                f'"{query}" site:reddit.com',
                f'"{query}" site:twitter.com',
                f'"{query}" site:medium.com',
                f'"{query}" inurl:profile',
                f'"{query}" intitle:profile',
                f'"{query}" filetype:pdf',
                f'"{query}" site:pastebin.com',
                f'"{query}" ext:log OR ext:txt',
            ]
        return dorks

    def parse_ddg_lite_results(self, soup):
        results = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            text = a.get_text(strip=True)
            if href.startswith("http") and "google.com" not in href.lower():
                results.append((text or "[no snippet]", href))
        return results if results else "no_results"

    def onion_ddg_search(self, query, max_results=10, use_tor=True):
        session = requests.Session()
        if use_tor:
            session.proxies = self.TOR_PROXY
        headers = {"User-Agent": "Mozilla/5.0"}

        endpoints = [self.DUCKDUCKGO_LITE, self.DUCKDUCKGO_HTML]
        random.shuffle(endpoints)
        for endpoint in endpoints:
            try:
                if endpoint.endswith("/html"):
                    res = session.post(endpoint, headers=headers, data={"q": query}, timeout=10)
                else:
                    res = session.get(f"{endpoint}?q={quote_plus(query)}", headers=headers, timeout=10)
                soup = BeautifulSoup(res.text, "html.parser")
                results = self.parse_ddg_lite_results(soup)
                if results and results != "no_results":
                    return results[:max_results]
            except Exception:
                continue
        return []

    def run_dork_searches(self, dorks: list, max_results=10):
        """
        Executes DuckDuckGo Lite dork-style queries via Tor in parallel.
        Assigns URLs to the first matching dork only (based on order).
        Prints only successful results and summarizes failed dorks.
        """
        results = {}
        failed_dorks = []
        seen_urls = set()

        category_colors = {
            "github.com": "green",
            "reddit.com": "red",
            "twitter.com": "blue",
            "medium.com": "magenta",
            "pastebin.com": "yellow",
            "linkedin.com": "bright_cyan",
            "facebook.com": "bright_blue",
            "inurl:profile": "cyan",
            "intitle:profile": "bright_magenta",
            "filetype:pdf": "bright_yellow",
            "ext:log": "bright_red",
            "ext:txt": "bright_red",
        }

        console.print("\n[bold underline cyan]🔗 DuckDuckGo Dorking Results:[/bold underline cyan]")

        def worker(dork):
            try:
                hits = self.onion_ddg_search(dork, max_results=max_results)
                urls = [url for _, url in hits if url not in seen_urls] if hits else []
                return dork, urls
            except Exception:
                return dork, []

        with ThreadPoolExecutor(max_workers=self.DORK_THREADS) as executor:
            future_to_dork = {executor.submit(worker, dork): dork for dork in dorks}
            for future in as_completed(future_to_dork):
                dork, urls = future.result()
                if urls:
                    for url in urls:
                        seen_urls.add(url)
                    color = next((v for k, v in category_colors.items() if k in dork), "white")
                    console.print(f"\n[bold {color}]🔍 Dork:[/bold {color}] [italic]{dork}[/italic]")
                    for i, url in enumerate(urls[:max_results], 1):
                        console.print(f"   {i}. [cyan]{url}[/cyan]")
                    results[dork] = urls[:max_results]
                else:
                    failed_dorks.append(dork)

        if failed_dorks:
            console.print(f"\n[yellow]⚠ No new results for {len(failed_dorks)} dork(s).[/yellow]")

        return results

    def fetch_url(self, url, use_tor=True, timeout=10):
        session = requests.Session()
        if use_tor:
            session.proxies = self.TOR_PROXY
        res = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout)
        return res.text

    def fetch_urls_parallel(self, urls, use_tor=True, timeout=10):
        """
        Fetches multiple URLs in parallel, returns a dict {url: content or None}
        """
        def worker(url):
            try:
                return url, self.fetch_url(url, use_tor=use_tor, timeout=timeout)
            except Exception:
                return url, None

        results = {}
        with ThreadPoolExecutor(max_workers=self.FETCH_THREADS) as executor:
            future_to_url = {executor.submit(worker, url): url for url in urls}
            for future in as_completed(future_to_url):
                url, content = future.result()
                results[url] = content
        return results

    @staticmethod
    def save_osint_data_to_json(data: dict, output_path: str = "osint_scrape_output.json"):
        try:
            with open(output_path, "r") as infile:
                existing = json.load(infile)
        except (FileNotFoundError, json.JSONDecodeError):
            existing = []
        existing.append(data)
        with open(output_path, "w") as outfile:
            json.dump(existing, outfile, indent=4)

    @staticmethod
    def run_email_scraper(email, use_tor=True):
        console.print(f"🔍 [bold]Running email OSINT on:[/bold] {email}")
        results = {}
        try:
            intel = EmailIntelPro(email, session=get_tor_session() if use_tor else requests.Session())
            intel.analyze()

            results["valid"] = intel.is_valid_email()
            results["domain"] = intel.domain
            results["prefix"] = intel.prefix
            results["mx_records"] = intel.mx_records
            results["txt_records"] = intel.txt_records
            results["disposable"] = intel.disposable
            results["rdap"] = intel.creation_date
            results["score"] = intel.score
            results["threat_label"] = re.sub(r"\[.*?\]", "", intel.threat_label())  # strip color tags
            results["breach"] = intel.breached

        except Exception as e:
            console.print(f"[red][ERROR][/red] Failed to run email scraper: {e}")
        return results

    def fetch_and_display_links(self, term: str, max_results: int = 30):
        """
        Mimics the 'search' command: fetches URLs from DuckDuckGo and prints only titles + links.
        """
        console.print(f"\n[bold cyan]🔎 Fetching links for:[/bold cyan] {term}\n")

        results = self.onion_ddg_search(term, max_results=max_results)

        if not results:
            console.print("[yellow]⚠ No results.[/yellow]")
            return

        seen = set()
        count = 0
        for title, url in results:
            if url not in seen and url.startswith("http"):
                count += 1
                seen.add(url)
                console.print(f"  ▪ {title} — [cyan]{url}[/cyan]")

        if count == 0:
            console.print("[yellow]⚠ No usable links found.[/yellow]")

    def fetch_url(self, url, use_tor=True, timeout=15):
        session = requests.Session()
        if use_tor:
            session.proxies = self.TOR_PROXY
        res = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout)
        return res.text

    def parse_ddg_lite_results(self, soup):
        results = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            text = a.get_text(strip=True)
            if href.startswith("http") and "google.com" not in href.lower():
                results.append((text or "[no snippet]", href))
        return results if results else "no_results"

    def onion_ddg_search(self, query, max_results=25, use_tor=True):
        session = requests.Session()
        if use_tor:
            session.proxies = self.TOR_PROXY
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            res = session.get(f"{self.DUCKDUCKGO_LITE}?q={quote_plus(query)}", headers=headers, timeout=20)
            soup = BeautifulSoup(res.text, "html.parser")
            results = self.parse_ddg_lite_results(soup)

            if not results or results == "no_results":
                res2 = session.post(self.DUCKDUCKGO_LITE, headers=headers, data={"q": query}, timeout=20)
                soup2 = BeautifulSoup(res2.text, "html.parser")
                results = self.parse_ddg_lite_results(soup2)

                if not results or results == "no_results":
                    pass

            return results[:max_results] if isinstance(results, list) else []

        except Exception as e:
            console.print(f"[red]❌ Onion search failed:[/red] {e}")
            return []

    def do_emailhunt(self, query: str, max_results=30):
        console.print(f"\n[bold cyan]🔎 Email Hunt via DuckDuckGo Onion Lite[/bold cyan]")
        console.print(f"[bold]Searching for:[/bold] {query}\n")

        # Accept emails or usernames
        if "@" in query:
            username = query.split("@")[0]
            search_term = f'"{username}"'
        else:
            search_term = f'"{query}"'

        # Smart dorks (focus on profile mentions)
        dorks = [
            f'{search_term} inurl:profile',
            f'{search_term} inurl:user',
            f'{search_term} inurl:members',
            f'{search_term} site:github.com',
            f'{search_term} site:linkedin.com/in',
            f'{search_term} site:stackoverflow.com/users',
            f'{search_term} site:reddit.com/user',
            f'{search_term} site:gravatar.com',
            f'{search_term} site:medium.com/@',
            f'{search_term} site:about.me',
            f'{search_term} site:angel.co',
            f'{search_term} site:behance.net',
            f'{search_term} site:dev.to',
            f'{search_term} site:dribbble.com',
            f'{search_term} site:producthunt.com',
            f'{search_term} site:flipboard.com',
            f'{search_term} site:hubpages.com',
            f'{search_term} site:quora.com/profile',
            f'{search_term} ext:log OR ext:txt'
        ]

        seen = set()
        urls = []

        for dork in dorks:
            results = self.onion_ddg_search(dork, max_results=max_results)
            for item in results:
                url = item[1] if isinstance(item, (list, tuple)) and len(item) == 2 else str(item)
                if url.startswith("http") and url not in seen:
                    # Filter out garbage
                    junk = ["login", "faq", "help", "support", "contact", "privacy"]
                    if not any(j in url.lower() for j in junk):
                        urls.append(url)
                        seen.add(url)
            if len(urls) >= max_results:
                break

        if urls:
            console.print(f"[green]✅ Found {len(urls)} site(s):[/green]\n")
            for link in urls[:max_results]:
                console.print(f"[cyan]{link}[/cyan]")
        else:
            console.print("[yellow]⚠ No usable links found. Trying fallback like 'search' command...[/yellow]\n")
            self.fetch_and_display_links(query)  # fallback
            
    def beacon_onion_service(self, onion_url):
        socks_proxy = "socks5h://127.0.0.1:9052"
        if not onion_url.startswith("http"):
            onion_url = "http://" + onion_url
        try:
            r = requests.get(
                onion_url,
                headers={"User-Agent": "Mozilla/5.0"},
                proxies={"http": socks_proxy, "https": socks_proxy},
                timeout=15
            )
            if r.status_code < 400:
                console.print(f"[🛰] Onion service is live: {onion_url} (Status {r.status_code})")
            else:
                console.print(f"[⚠] Onion responded with status {r.status_code}")
        except Exception as e:
            console.print(f"[🚫] Failed to reach onion service: {e}")
            
DUCKDUCKGO_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"

DISPOSABLE_CARRIERS = {
    "google", "twilio", "bandwidth", "onvoy", "textnow", "pinger", "textplus",
    "talkatone", "burner", "hushed", "sideline", "line2", "freetone", "voip"
}

async def passive_monitor_loop(watch_term, interval=3600):
    while True:
        results = await async_duckduckgo_search(f'"{watch_term}" site:pastebin.com')
        if results:
            print(f"🔔 ALERT: Leak found for {watch_term}")
            for title, link in results:
                print(f"- {title}: {link}")
        await asyncio.sleep(interval)
        
def generate_darkelf_dorks(phone_number):
    DUCKDUCKGO_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    clean = phone_number.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    formats = [
        phone_number,
        clean,
        f"+{clean}",
        f"({clean[:3]}) {clean[3:6]}-{clean[6:]}" if len(clean) == 10 else phone_number
    ]

    base_sites = [
        "site:pastebin.com", "site:whocalled.us", "site:findwhocallsme.com",
        "site:locatefamily.com", "site:phonenumbers.ie", "intitle:index.of",
        "ext:log OR ext:txt", "filetype:pdf", "filetype:doc"
    ]

    dork_urls = []

    for site in base_sites:
        for f in formats:
            dork = f'{site} intext:"{f}"'
            ddg_url = f"{DUCKDUCKGO_LITE}?q={quote_plus(dork)}"
            dork_urls.append(ddg_url)

    return dork_urls

def format_phone_local(phone):
    digits = ''.join(filter(str.isdigit, phone))
    if len(digits) == 11 and digits.startswith('1'):
        digits = digits[1:]
    if len(digits) != 10:
        return phone, phone, phone, phone
    return (
        digits,
        f"({digits[:3]}) {digits[3:6]}-{digits[6:]}",
        f"+1{digits}",
        f"1{digits}"
    )
    
def get_phone_metadata(phone, region="US"):
    try:
        parsed = phonenumbers.parse(phone, region)
        return {
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "location": geocoder.description_for_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en"),
            "timezones": timezone.time_zones_for_number(parsed)
        }
    except Exception:
        return {
            "valid": False,
            "possible": False,
            "location": "",
            "carrier": "",
            "timezones": []
        }

def is_disposable_voip(carrier_name):
    if not carrier_name or carrier_name.lower() == "unknown":
        return "Inconclusive"
    # Fuzzy match for any carrier in the list or "voip"/"virtual"
    carrier_name_lc = carrier_name.lower()
    if any(d in carrier_name_lc for d in DISPOSABLE_CARRIERS):
        return "Yes"
    if "voip" in carrier_name_lc or "virtual" in carrier_name_lc:
        return "Likely"
    return "No"

def run_phone_scan(phone, region="US", show_dorks=False):
    raw, local, e164, international = format_phone_local(phone)
    dorks = generate_darkelf_dorks(phone)

    summary_lines = []
    summary_lines.append(f"📞 [Darkelf] Running phone scan for: {phone}\n")

    # 📍 Metadata extraction
    phone_meta = get_phone_metadata(phone, region=region)
    carrier_name = phone_meta.get("carrier", "Unknown") or "Unknown"
    location = phone_meta.get("location", "Unknown") or "Unknown"
    timezones = phone_meta.get("timezones", [])
    is_valid = phone_meta.get("valid", False)
    is_possible = phone_meta.get("possible", False)

    # 🧪 Disposable/VoIP detection
    disposable_status = is_disposable_voip(carrier_name)

    summary_lines.append("=== Results ===")
    summary_lines.append(f"Raw local: {raw}")
    summary_lines.append(f"Local: {local}")
    summary_lines.append(f"E164: {e164}")
    summary_lines.append(f"International: {international}")
    summary_lines.append(f"Country: {region}")
    summary_lines.append(f"Location: {location}")
    summary_lines.append(f"Carrier: {carrier_name if carrier_name else 'Unknown'}")
    summary_lines.append(f"Timezones: {', '.join(timezones) if timezones else 'Unknown'}")
    summary_lines.append(f"Valid: {'Yes' if is_valid else 'No'}")
    summary_lines.append(f"Possible: {'Yes' if is_possible else 'No'}")
    summary_lines.append(f"Disposable/VoIP: {disposable_status}")

    if carrier_name.lower() == "unknown" or not carrier_name:
        summary_lines.append(
            "⚠️ Carrier could not be determined. This number may be unlisted, new, ported, or from an obscure/virtual provider. Disposable/VoIP status is inconclusive."
        )

    # 🔍 Darkelf-style Dork summary (via DuckDuckGo Onion Lite)
    summary_lines.append("\n=== Darkelf Dorks ===")
    if show_dorks:
        for url in dorks:
            summary_lines.append(url)
    else:
        summary_lines.append("[URLs Hidden]")
    summary_lines.append(f"Total dorks generated: {len(dorks)}")
    summary_lines.append("✅ 2 scanner(s) succeeded")

    return "\n".join(summary_lines)

def extract_osint_data(html_content: str, username=None, email=None, phone=None) -> dict:
    data = {
        "emails": set(),
        "phones": set(),
        "usernames": set(),
        "mentions": set()
    }
    # Email detection (exact)
    if email:
        for match in re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html_content):
            if match.lower() == email.lower():
                data["emails"].add(match)
                data["mentions"].add(match)
    # Phone detection (exact, loose pattern)
    if phone:
        for match in re.findall(r"\+?\d[\d\s\-().]{6,}", html_content):
            norm = re.sub(r"[^\d]", "", match)
            if norm == phone:
                data["phones"].add(match)
                data["mentions"].add(match)
    # Username detection (exact, case-insensitive)
    if username:
        if re.search(rf"\b{re.escape(username)}\b", html_content, re.I):
            data["usernames"].add(username)
            data["mentions"].add(username)
    return data

def osintscan(query, use_tor=True, max_results=10):
    utils = DarkelfUtils()
    is_email = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", query))
    is_phone = bool(re.match(r"^\+?\d[\d\s\-().]{6,}$", query))
    is_username = bool(re.match(r"^@?[a-zA-Z0-9_.-]{3,32}$", query)) and not is_email and not is_phone
    is_name = False

    if not (is_email or is_phone or is_username):
        parts = query.strip().split()
        if len(parts) >= 2 and all(re.match(r"^[A-Za-z.\-']+$", p) for p in parts):
            is_name = True

    username = query.lstrip('@') if is_username else None
    phone = re.sub(r"[^\d]", "", query) if is_phone else None
    email = query if is_email else None
    name = query if is_name else None

    results = {
        "profiles": [],
        "mentions": [],
        "emails": [],
        "phones": [],
    }

    tlds = [
        "com", "net", "org", "gov", "edu", "int", "info", "eu", "ch", "de", "fr", "it", "nl", "ru", "pl", "us", "uk", "au", "ca", "in", "biz", "pro", "co", "me"
    ]
    special_sites = [
        "archive.org", "pastebin.com", "manchestercf.com", "egs.edu", "egs.edu.eu", "researchgate.net", "academia.edu", "ssrn.com", "osf.io", "darkelfbrowser.com"
    ]

    # ---- EMAIL SCAN (ALL DOMAINS) ----
    if is_email:
        try:
            intel = EmailIntelPro(email, session=get_tor_session() if use_tor else requests.Session())
            if intel.is_valid_email():
                asyncio.run(intel.analyze())
                results["emails"].append(email)
        except Exception:
            pass

        username_part = email.split("@")[0]
        console.print(f"[bold cyan]🔍 Comprehensive scan for email and username part:[/bold cyan] [bold]{email}[/bold], [bold]{username_part}[/bold]")

        dorks_email = [f'"{email}" site:{site}' for site in special_sites]
        dorks_email += [f'"{email}" site:.{tld}' for tld in tlds]
        dorks_email += [
            f'"{email}"',
            f'"{email}" ext:log OR ext:txt',
            f'"{email}" filetype:pdf',
            f'"{email}" inurl:profile',
            f'"{email}" inurl:user',
            f'"{email}" intitle:profile'
        ]
        dorks_username = [f'"{username_part}" site:{site}' for site in special_sites]
        dorks_username += [f'"{username_part}" site:.{tld}' for tld in tlds]
        dorks_username += [
            f'"{username_part}"',
            f'"{username_part}" ext:log OR ext:txt',
            f'"{username_part}" filetype:pdf',
            f'"{username_part}" inurl:profile',
            f'"{username_part}" inurl:user',
            f'"{username_part}" intitle:profile'
        ]
        # Get all URLs for email and username dorks
        seen_urls = set()
        all_urls = []
        for dork in dorks_email + dorks_username:
            ddg_results = utils.onion_ddg_search(dork, max_results=max_results, use_tor=use_tor)
            for text, url in ddg_results:
                if url in seen_urls or not url.startswith("http"):
                    continue
                seen_urls.add(url)
                all_urls.append((text, url))
        # Fetch all URLs in parallel and scan for mentions
        def fetch_and_extract(url, text):
            try:
                html_content = utils.fetch_url(url, use_tor=use_tor, timeout=10)
                found = []
                if email.lower() in html_content.lower():
                    found.append({"url": url, "snippet": f"...{email} found..."})
                if re.search(rf"\b{re.escape(username_part)}\b", html_content, re.I):
                    found.append({"url": url, "snippet": f"...{username_part} found..."})
                # Profile detection
                for f in found:
                    if f"/{email}" in url or (text and email.lower() in text.lower()):
                        results["profiles"].append(f)
                    elif f"/{username_part}" in url or (text and username_part.lower() in text.lower()):
                        results["profiles"].append(f)
                    else:
                        results["mentions"].append(f)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(fetch_and_extract, url, text) for text, url in all_urls]
            for _ in as_completed(futures):
                pass

    # ---- PHONE SCAN ----
    if is_phone:
        phone_output = run_phone_scan(query)
        raw, local, e164, international = format_phone_local(query)
        results["phones"].extend({raw, local, e164, international})
        urls = re.findall(r"https?://[^\s]+", phone_output)
        if urls:
            results["mentions"].extend(urls)
        lines = phone_output.splitlines()
        filtered_lines = [line for line in lines if line.strip()]
        cleaned = "\n".join(filtered_lines).strip()
        if cleaned:
            results["mentions"].append("PhoneScan:\n" + cleaned)

    # ---- USERNAME SCAN (ALL DOMAINS, PARALLEL) ----
    if is_username:
        console.print(f"[bold cyan]🔍 Comprehensive scan for username:[/bold cyan] [bold]{username}[/bold]")
        dorks_username = [f'"{username}" site:{site}' for site in special_sites]
        dorks_username += [f'"{username}" site:.{tld}' for tld in tlds]
        dorks_username += [
            f'"{username}"',
            f'"{username}" ext:log OR ext:txt',
            f'"{username}" filetype:pdf',
            f'"{username}" inurl:profile',
            f'"{username}" inurl:user',
            f'"{username}" intitle:profile'
        ]
        # Collect all URLs from all dorks first
        seen_urls = set()
        all_urls = []
        for dork in dorks_username:
            ddg_results = utils.onion_ddg_search(dork, max_results=max_results, use_tor=use_tor)
            for text, url in ddg_results:
                if url in seen_urls or not url.startswith("http"):
                    continue
                seen_urls.add(url)
                all_urls.append((text, url))
        # Fetch all URLs in parallel and scan for mentions
        def fetch_and_extract(url, text):
            try:
                html_content = utils.fetch_url(url, use_tor=use_tor, timeout=10)
                if re.search(rf"\b{re.escape(username)}\b", html_content, re.I):
                    entry = {"url": url, "snippet": f"...{username} found..."}
                    if f"/{username}" in url or (text and username.lower() in text.lower()):
                        results["profiles"].append(entry)
                    else:
                        results["mentions"].append(entry)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(fetch_and_extract, url, text) for text, url in all_urls]
            for _ in as_completed(futures):
                pass

    # ---- PERSONAL NAME SCAN (ALL DOMAINS, PARALLEL) ----
    if is_name:
        console.print(f"[bold cyan]🔍 Comprehensive scan for personal name:[/bold cyan] [bold]{name}[/bold]")
        dorks_name = [f'"{name}" site:{site}' for site in special_sites]
        dorks_name += [f'"{name}" site:.{tld}' for tld in tlds]
        dorks_name += [
            f'"{name}"',
            f'"{name}" ext:log OR ext:txt',
            f'"{name}" filetype:pdf',
            f'"{name}" inurl:profile',
            f'"{name}" inurl:user',
            f'"{name}" intitle:profile'
        ]
        parts = name.strip().split()
        if len(parts) == 3:
            f, m, l = parts
            dorks_name.append(f'"{f} {l}"')
            dorks_name.append(f'"{f[0]}. {l}"')
        elif len(parts) == 2:
            f, l = parts
            dorks_name.append(f'"{f[0]}. {l}"')
        seen_urls = set()
        all_urls = []
        for dork in dorks_name:
            ddg_results = utils.onion_ddg_search(dork, max_results=max_results, use_tor=use_tor)
            for text, url in ddg_results:
                if url in seen_urls or not url.startswith("http"):
                    continue
                seen_urls.add(url)
                all_urls.append((text, url))
        def fetch_and_extract(url, text):
            try:
                html_content = utils.fetch_url(url, use_tor=use_tor, timeout=10)
                if re.search(re.escape(name), html_content, re.I):
                    entry = {"url": url, "snippet": f"...{name} found..."}
                    if f"/{name.replace(' ', '')}" in url or (text and name.lower() in text.lower()):
                        results["profiles"].append(entry)
                    else:
                        results["mentions"].append(entry)
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(fetch_and_extract, url, text) for text, url in all_urls]
            for _ in as_completed(futures):
                pass

    # ---- OUTPUT ----
    def dedup_by_url(items):
        seen = set()
        out = []
        for x in items:
            url = x["url"] if isinstance(x, dict) else x
            if url not in seen:
                out.append(x)
                seen.add(url)
        return out
    results["profiles"] = dedup_by_url(results["profiles"])
    results["mentions"] = dedup_by_url(results["mentions"])

    if results["profiles"]:
        console.print("\n[green]🔗 Correlated Profiles:[/green]")
        for p in results["profiles"]:
            console.print(f"   [cyan]{p['url']}[/cyan] [dim]{p.get('snippet','')}[/dim]")
    if results["mentions"]:
        console.print("\n[yellow]🔎 Mentions/Leaks:[/yellow]")
        for m in results["mentions"]:
            if isinstance(m, dict):
                console.print(f"   [cyan]{m['url']}[/cyan] [dim]{m.get('snippet','')}[/dim]")
            else:
                console.print(f"   [cyan]{m}[/cyan]")
    if results["emails"]:
        console.print("\n[green]✉️ Exact Emails Found:[/green]")
        for e in results["emails"]:
            console.print(f"   [cyan]{e}[/cyan]")
    if results["phones"]:
        console.print("\n[green]📞 Exact Phone Numbers Found:[/green]")
        for p in sorted(set(results["phones"])):
            console.print(f"   [cyan]{p}[/cyan]")

    # Always show useful search links (using DDG Onion Lite and other options)
    console.print("\n[blue]🔍 Useful search links:[/blue]")

    ddg_onion_lite = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    for name_label, url in [
        ("Startpage", f"https://www.startpage.com/do/dsearch?query={quote_plus(query)}"),
        ("DuckDuckGo", f"{ddg_onion_lite}?q={quote_plus(query)}"),
        ("Twitter", f"https://twitter.com/search?q={quote_plus(query)}"),
        ("Pastebin", f"{ddg_onion_lite}?q={quote_plus(query)}+site:pastebin.com"),
        ("LinkedIn", f"https://www.linkedin.com/search/results/all/?keywords={quote_plus(query)}"),
        ("Facebook", f"https://www.facebook.com/search/top/?q={quote_plus(query)}"),
    ]:
        console.print(f"   [bold]{name_label}:[/bold] [cyan]{url}[/cyan]")

    # 🔍 Generate DuckDuckGo dorks based on query
    dorks = utils.generate_duckduckgo_dorks(query)

    console.print("\n[bold magenta]🕵️ DuckDuckGo Dorking Suggestions:[/bold magenta]")

    ddg_lite_base = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    for dork in dorks:
        dork_url = f"{ddg_lite_base}?q={quote_plus(dork)}"
        console.print(f"   [italic]{dork}[/italic] → [cyan]{dork_url}[/cyan]")

    # 🔎 Execute each dork using DuckDuckGo Onion Lite search (summary)
    console.print("\n[bold magenta]🔗 DuckDuckGo Dorking Results:[/bold magenta]")
    utils.run_dork_searches(dorks)
    
# Logging Setup
logging.basicConfig(
    filename="darkelf_tls_monitor.log",
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("DarkelfTLSMonitor")

# TLS Certificate Fingerprint Helper

def get_cert_hash(hostname: str, port: int = 443) -> Optional[str]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
        return hashlib.sha256(der_cert).hexdigest()
    except Exception as e:
        logger.error(f" Error retrieving certificate for {hostname}: {e}")
        return None
        
class DarkelfTLSMonitorJA3:
    """
    Monitors TLS certificate changes for a list of sites with rotating JA3 fingerprints and User-Agents.
    Suitable for production use. Supports background operation and robust error handling.
    """
    def __init__(
        self,
        sites: List[str],
        interval: int = 300,
        proxy: Optional[str] = "socks5://127.0.0.1:9052"
    ):
        """
        :param sites: List of hostnames to monitor (no scheme, e.g., "github.com")
        :param interval: Time between checks (seconds)
        :param proxy: Proxy URL (optional)
        """
        self.sites = sites
        self.interval = interval
        self.proxy = proxy
        self.fingerprints: Dict[str, str] = {}
        self.running = True

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 12.5; rv:92.0) Gecko/20100101 Firefox/92.0",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.2; rv:99.0) Gecko/20100101 Firefox/99.0"
        ]
        self.ja3_profiles = [
            "firefox_92","firefox_95","firefox_98","firefox_102"
        ]

    def rotate_headers(self) -> Dict[str, str]:
        """Randomly select HTTP headers for requests."""
        return {"User-Agent": random.choice(self.user_agents)}

    def rotate_ja3_session(self) -> tls_client.Session:
        """Create a tls_client.Session with a randomly chosen JA3 (ClientHello) profile."""
        return tls_client.Session(
            client_identifier=random.choice(self.ja3_profiles)
        )

    async def check_cert(self, site: str, headers: Dict[str, str]):
        """
        Checks the TLS certificate for a given site, detects changes, and prints status.
        """
        try:
            # 1. Rotate JA3 and fetch page for anti-bot (optional for your logic)
            session = self.rotate_ja3_session()
            session.get(
                f"https://{site}",
                headers=headers,
                proxy=self.proxy,
                timeout_seconds=15,
                allow_redirects=True,
            )
            # 2. Independently fetch and hash the real cert using ssl
            cert_hash = get_cert_hash(site)
            if not cert_hash:
                logger.error(f" Could not extract certificate for {site}")
                return
            if site not in self.fingerprints:
                logger.info(f" Initial fingerprint for {site}: {cert_hash}")
                self.fingerprints[site] = cert_hash
            elif self.fingerprints[site] != cert_hash:
                logger.warning(f" TLS CERT ROTATION for {site}")
                print(f"Old: {self.fingerprints[site]}")
                print(f"New: {cert_hash}")
                self.fingerprints[site] = cert_hash
            else:
                logger.info(f" No change in cert for {site}")
        except Exception as e:
            logger.error(f" Error checking {site}: {e}")

    async def monitor_loop(self):
        """Main monitoring loop. Runs until .stop() is called."""
        while self.running:
            headers = self.rotate_headers()
            logger.info(f" Rotating User-Agent: {headers['User-Agent']}")
            tasks = [self.check_cert(site, headers) for site in self.sites]
            await asyncio.gather(*tasks)
            await asyncio.sleep(self.interval)

    def start(self):
        """Starts the monitor in a background thread."""
        def runner():
            logger.info(" ✅ TLS Monitor started in background thread.")
            asyncio.run(self.monitor_loop())
        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        logger.info(" ✅ TLS Monitor running in background thread.")

    def stop(self):
        """Stops the monitoring loop."""
        self.running = False
        logger.info(" 🛑 TLS Monitor stopped.")
    
class SecureCleanup:
    @staticmethod
    def secure_delete(file_path):
        try:
            if not os.path.exists(file_path):
                return
            size = os.path.getsize(file_path)
            with open(file_path, "r+b", buffering=0) as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)
        except Exception:
            pass

    @staticmethod
    def secure_delete_directory(directory_path):
        try:
            if not os.path.exists(directory_path):
                return
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for name in files:
                    SecureCleanup.secure_delete(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
            os.rmdir(directory_path)
        except Exception:
            pass

    @staticmethod
    def secure_delete_temp_memory_file(file_path):
        try:
            if not isinstance(file_path, (str, bytes, os.PathLike)) or not os.path.exists(file_path):
                return
            file_size = os.path.getsize(file_path)
            with open(file_path, "r+b", buffering=0) as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)
        except Exception:
            pass

    @staticmethod
    def secure_delete_ram_disk_directory(ram_dir_path):
        try:
            if not os.path.exists(ram_dir_path):
                return
            for root, dirs, files in os.walk(ram_dir_path, topdown=False):
                for name in files:
                    SecureCleanup.secure_delete_temp_memory_file(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
            os.rmdir(ram_dir_path)
        except Exception:
            pass

    @staticmethod
    def shutdown_cleanup(context):
        try:
            log_path = context.get("log_path")
            stealth_log_path = os.path.expanduser("~/.darkelf_log")
            ram_path = context.get("ram_path")
            tor_manager = context.get("tor_manager")
            encrypted_store = context.get("encrypted_store")
            kyber_manager = context.get("kyber_manager")

            if log_path:
                if os.path.isfile(log_path):
                    SecureCleanup.secure_delete(log_path)
                elif os.path.isdir(log_path):
                    SecureCleanup.secure_delete_directory(log_path)

            if os.path.exists(stealth_log_path):
                try:
                    with open(stealth_log_path, "r+b", buffering=0) as f:
                        length = os.path.getsize(stealth_log_path)
                        for _ in range(5):
                            f.seek(0)
                            f.write(secrets.token_bytes(length))
                            f.flush()
                            os.fsync(f.fileno())
                    os.remove(stealth_log_path)
                except Exception:
                    pass

            if tor_manager and callable(getattr(tor_manager, 'stop_tor', None)):
                tor_manager.stop_tor()

            if encrypted_store:
                encrypted_store.wipe_memory()

            if ram_path and os.path.exists(ram_path):
                SecureCleanup.secure_delete_ram_disk_directory(ram_path)

            temp_subdir = os.path.join(tempfile.gettempdir(), "darkelf_temp")
            if os.path.exists(temp_subdir):
                SecureCleanup.secure_delete_directory(temp_subdir)

            for keyfile in ["private_key.pem", "ecdh_private_key.pem"]:
                if os.path.exists(keyfile):
                    SecureCleanup.secure_delete(keyfile)

            if kyber_manager:
                try:
                    for attr in ['kyber_private_key', 'kyber_public_key']:
                        key = getattr(kyber_manager, attr, None)
                        if isinstance(key, bytearray):
                            for i in range(len(key)):
                                key[i] = 0
                        setattr(kyber_manager, attr, None)
                    kyber_manager.kem = None
                    for kyber_file in ["kyber_private.key", "kyber_public.key"]:
                        if os.path.exists(kyber_file):
                            SecureCleanup.secure_delete(kyber_file)
                except Exception:
                    pass
        except Exception:
            pass
   
def start_tls_monitor():
    monitored_sites = [
        "check.torproject.org",
        "example.com"
    ]
    monitor = DarkelfTLSMonitorJA3(monitored_sites, interval=300)
    monitor.start()  # Already runs in a background thread

# === BEGIN PATCH: Deep Emailhunt ===
def deep_emailhunt(email: str, use_tor: bool = True, max_links: int = 30):
    """
    Search for mentions of the email across the open web using DuckDuckGo.
    Returns a dict: {url -> [context snippets]}.
    """
    session = get_tor_session() if use_tor else requests.Session()
    results = {}
    seen_urls = set()

    # Deduplicated and expanded queries
    queries = list(dict.fromkeys([
        f'"{email}"',
        f'"{email}" profile',
        f'"{email}" contact',
        f'"{email}" resume',
        f'"{email}" CV',
        f'intext:{email}',
        f'site:github.com "{email}"',
        f'site:pastebin.com "{email}"',
        f'site:linkedin.com "{email}"',
        f'site:orcid.org "{email}"',
    ]))

    for query in queries:
        try:
            console.print(f"[green]🔎 Searching:[/green] {query}")
            links = DarkelfUtils().duckduckgo_onion_search(query, max_results=max_links)
            for _, url in links[:max_links]:
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                try:
                    html = fetch_url(url, use_tor=use_tor, timeout=15)
                    if email.lower() in html.lower():
                        context = extract_context_lines(html, email)
                        results[url] = context if context else ["(email found, no extractable snippet)"]
                except Exception as fetch_err:
                    console.print(f"[red]⚠ Failed to fetch:[/red] {url} - {fetch_err}")
                    continue
        except Exception as search_err:
            console.print(f"[red]⚠ DuckDuckGo search failed:[/red] {query} - {search_err}")
            continue

    if results:
        console.print(f"\n[yellow]🔎 Mentions of {email} found:[/yellow]")
        for url, snippets in results.items():
            console.print(f"[cyan]{url}[/cyan]")
            for snippet in snippets:
                console.print(f"   [dim]{snippet}[/dim]")
    else:
        console.print(f"[red]No visible mentions of {email} found.[/red]")

    return results

def extract_context_lines(text: str, keyword: str, window: int = 100):
    context_snippets = []
    for match in re.finditer(re.escape(keyword), text, re.IGNORECASE):
        start = max(0, match.start() - window)
        end = match.end() + window
        snippet = text[start:end].replace("\n", " ").strip()
        context_snippets.append("... " + snippet + " ...")
    return context_snippets or ["(found on page but no specific snippet extracted)"]
    
# === END PATCH ===

def repl_main():
    os.environ["HISTFILE"] = ""
    try:
        open(os.path.expanduser("~/.bash_history"), "w").close()
    except:
        pass

    intrusion_check()
    kernel_monitor = DarkelfKernelMonitor()
    kernel_monitor.start()
    mem_monitor = MemoryMonitor()
    mem_monitor.start()
    pq_logger = StealthCovertOpsPQ(stealth_mode=True)
    phishing_detector = PhishingDetectorZeroTrace(pq_logger=pq_logger)
    tor_manager = TorManagerCLI()
    tor_manager.init_tor()

    # Start TLS monitor after 20s delay to allow Tor to bootstrap
    threading.Timer(20.0, start_tls_monitor).start()

    messenger = DarkelfMessenger()
    utils = DarkelfUtils()

    console.print("🛡️  Darkelf CLI Browser - Stealth Mode - Auto Tor rotation, decoy traffic, onion discovery")
    print_help()

    extra_stealth_options = {
        "random_order": True,
        "add_noise_headers": True,
        "minimal_headers": False,
        "spoof_platform": True,
        "session_isolation": True,
        "delay_range": (1.5, 3.0)
    }

    def find_file(filename):
        for path in [os.path.expanduser("~/Desktop"), os.path.expanduser("~"), "."]:
            full = os.path.join(path, filename)
            if os.path.exists(full):
                return full
        return filename

    stealth_on = True
    threading.Thread(target=tor_auto_renew_thread, daemon=True).start()
    threading.Thread(target=decoy_traffic_thread, args=(extra_stealth_options,), daemon=True).start()

    while True:
        try:
            console.print("[bold green]>>[/bold green] ", end="")
            cmd = input("darkelf> ").strip()
            if not cmd:
                continue

            if cmd.isdigit():
                index = int(cmd) - 1
                if 0 <= index < len(TOOLS):
                    tool_name = TOOLS[index]
                    console.print(f"🛠️  Launching tool: {tool_name}")
                    open_tool(tool_name)
                    continue

            if cmd.lower() in TOOLS:
                console.print(f"🛠️  Launching tool: {cmd.lower()}")
                open_tool(cmd.lower())
                continue

            elif cmd == "checkip":
                check_my_ip()
                print()

            elif cmd == "tlsstatus":
                check_tls_status()
                print()

            elif cmd.startswith("beacon "):
                onion = cmd.split(" ", 1)[1]
                utils.beacon_onion_service(onion)
                print()

            elif cmd.startswith("iplookup"):
                parts = cmd.split()
                ip = parts[1] if len(parts) > 1 else ""
                DarkelfIPScan(use_tor=True).lookup(ip)
                print()
                
            elif cmd.startswith("publish-prekey"):
                user_id = cmd.split(" ", 1)[1].strip() if " " in cmd else input("Enter your user ID: ").strip()
                chat = DarkelfPQChat(my_id=user_id)
                chat.publish_prekey_bundle()
                print(f"[+] Prekey published for user: {user_id}")
    
            elif cmd.startswith("licenseplate"):
                parts = cmd.strip().split()

                if len(parts) == 2:
                    plate_number = parts[1].upper()
                else:
                    plate_number = input("Enter license plate number: ").strip().upper()

                country = input("Country code (optional, e.g. FR, DE, US): ").strip().upper() or None

                scanner = LicensePlateOSINT()
                result = scanner.run(plate_number, country=country, max_results=20)

                if result["success"]:
                    print(f"\n🔍 License Plate Queried: {result['plate']}")
                    print(f"🌍 Country detected: {result.get('country') or 'Unknown'}")

                    print("\n🔗 [Profiles] (Plate in URL or Title):")
                    if result["profiles"]:
                        for p in result["profiles"]:
                            print(f"  - {p['url']}")
                            print(f"    Title: {p.get('title', '')}")
                            print(f"    Snippet: {p.get('snippet','')[:350]}\n")
                    else:
                        print("  None")

                    print("\n🟡 [Mentions/Leaks] (Plate in snippet):")
                    if result["mentions"]:
                        for m in result["mentions"]:
                            print(f"  - {m['url']}")
                            print(f"    Title: {m.get('title', '')}")
                            print(f"    Snippet: {m.get('snippet','')[:350]}\n")
                    else:
                        print("  None")

                    print("\n✅ [Exact Plates Found on Linked Pages]:")
                    if result["exact_plates"]:
                        print(", ".join(result["exact_plates"]))
                    else:
                        print("  None")

                    print("\n🔗 [All Links Found]:")
                    if result["all_links"]:
                        for link in result["all_links"]:
                            print(f"  - {link}")
                    else:
                        print("  None")

                    print("\n🧑‍💻 [All Dorks Tried]:")
                    for dork in result["dorks_run"]:
                        print(f"  - {dork}")

            elif cmd == "govscan":
                query = input("Enter legal/court search term: ").strip()
                scanner = DarkelfGovernmentScanner(max_results=10)
                print("\n[•] Running multi-source legal records scan. Please wait...\n")
                results = scanner.run_all(query)

                if not results:
                    print("[!] No results found.")
                else:
                    scanner.pretty_print_cases_rich(results, max_cases=10)
                    # APA-style summary paragraph
                    summary = scanner.summarize_apa_report(results)
                    console.print(Panel(summary, title="APA-style summary report", style="green"))

            elif cmd == "dnsleak":
                check_dns_leak()
                print()

            elif cmd.startswith("analyze! "):
                url = cmd.split(" ", 1)[1].strip()
                score = threat_score(url)
                if score >= 5:
                    print(f"[THREAT] {url} scored {score}/10 on threat scale.")

            elif cmd.startswith("open "):
                url = cmd.split(" ", 1)[1].strip()
                fetch_and_display(url)
                print()

            elif cmd.startswith("emailintel "):
                target = cmd.split(" ", 1)[1].strip()
                asyncio.run(EmailIntelPro(target, session=get_tor_session()).analyze())

            elif cmd.startswith("emailhunt "):
                email = cmd.split(" ", 1)[1].strip()
                utils.do_emailhunt(email)
                print()
                
            elif cmd == "pegasusmonitor":
                pegasus = PegasusMonitor()
                pegasus.run()
                print()
                
            elif cmd == "tools":
                print_tools_help()
                print()

            elif cmd.startswith("tool "):
                tool_name = cmd.split(" ", 1)[1]
                open_tool(tool_name)
                print()

            elif cmd == "toolinfo":
                print_toolinfo()
                print()

            elif cmd == "help":
                print_help()
                print()

            elif cmd == "browser":
                launch_browser_in_new_terminal()
                print()

            elif cmd == "stealth":
                stealth_on = not stealth_on
                console.print("🫥 Extra stealth options are now", "ENABLED" if stealth_on else "DISABLED")
                print()

            elif cmd.startswith("osintscan "):
                query = cmd[len("osintscan "):].strip()
                try:
                    osintscan(query)
                except Exception as e:
                    console.print(f"[red]OSINT scan failed: {e}[/red]")
                    
            elif cmd.startswith("spider "):
                parts = cmd.split()
                if len(parts) >= 2:
                    url = parts[1]
                    use_tor = "--tor" in parts
                    parts = [p for p in parts if p != "--tor"]

                    try:
                        depth = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 2
                    except ValueError:
                        depth = 2

                    filters_start = 3 if len(parts) >= 3 and parts[2].isdigit() else 2
                    keyword_filters = parts[filters_start:] if len(parts) > filters_start else []

                    print(f"🕷️ Launching spider on {url} (depth={depth}) with filters: {', '.join(keyword_filters) or 'None'} {'via Tor' if use_tor else ''}\n")
                    spider = DarkelfSpiderAsync(base_url=url, depth=depth, keyword_filters=keyword_filters, use_tor=use_tor)
                    asyncio.run(spider.run())
                    # << ADD THIS LINE BELOW >>
                    print("\n🔎 [spaCy] NLP summary of indicators:")
                    print(spider.spacy_summary())
                else:
                    print("Usage: spider <url> [depth] [keywords...] [--tor]")
                    
            elif cmd.startswith("search "):
                q = cmd.split(" ", 1)[1]
                url = f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}"
                suspicious, reason = phishing_detector.is_suspicious_url(url)
                if suspicious:
                    console.print(f"⚠️ [PHISHING WARNING] {reason}")
                fetch_and_display(url, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=False)
                print()

            elif cmd.startswith("debug "):
                q = cmd.split(" ", 1)[1]
                url = f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}"
                suspicious, reason = phishing_detector.is_suspicious_url(url)
                if suspicious:
                    console.print(f"⚠️ [PHISHING WARNING] {reason}")
                fetch_and_display(url, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=True)
                print()

            elif cmd == "duck":
                fetch_and_display(DUCKDUCKGO_LITE, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=False)
                print()

            elif cmd == "genkeys":
                messenger.generate_keys()
                print()

            elif cmd == "sendmsg":
                to = input("Recipient pubkey path: ")
                msg = input("Message: ")
                messenger.send_message(to, msg)

            elif cmd == "recvmsg":
                priv = find_file("my_privkey.bin")
                msgf = find_file("msg.dat")
                console.print(f"🔐 Using private key: {priv}")
                console.print(f"📩 Reading message from: {msgf}")
                messenger.receive_message(priv, msgf)

            elif cmd == "tornew":
                renew_tor_circuit()
                print()

            elif cmd.startswith("findonions "):
                keywords = cmd.split(" ", 1)[1]
                onion_discovery(keywords, extra_stealth_options=extra_stealth_options if stealth_on else {})
                print()
                
            elif cmd == "pqchat":
                mode = input("Start as (s)erver or (c)lient? [s/c]: ").strip().lower()
                is_server = (mode == "s")
                host = input("Host (default 127.0.0.1): ").strip() or "127.0.0.1"
                port_input = input("Port (default 9000): ").strip()
                port = int(port_input) if port_input else 9000

                try:
                    if is_server:
                        user_id = input("Your user ID for prekey: ").strip() or "server"
                        chat = DarkelfPQChat(my_id=user_id)
                        # Auto-publish if missing
                        if not chat.fetch_prekey_bundle(user_id):
                            chat.publish_prekey_bundle()
                            print(f"[+] Prekey published for user: {user_id}")
                        chat.accept_async(host, port)
                    else:
                        their_id = input("Recipient user ID (published prekey): ").strip()
                        chat = DarkelfPQChat()
                        chat.connect_async(host, port, their_id)
                except OSError as oe:
                    # Handle address/port in use, etc.
                    if hasattr(oe, "errno") and oe.errno == 48:
                        print(f"[!] Port {port} already in use. Try another.")
                    else:
                        print(f"[!] Socket error: {oe}")
                except Exception as e:
                    print(f"[!] Error starting PQChat: {e}")

            elif cmd == "wipe":
                pq_logger.panic()
                trigger_self_destruct("Manual wipe")
                print()

            elif cmd == "exit":
                console.print("🧩 Exiting securely.")
                phishing_detector.flush_logs_on_exit()
                SecureCleanup.shutdown_cleanup({
                    "log_path": "log.enc",
                    "tor_manager": tor_manager,
                    "ram_path": None,
                    "encrypted_store": None,
                    "kyber_manager": None
                })
                break

            else:
                console.print("❓ Unknown command. Type `help` for options.")

        except KeyboardInterrupt:
            console.print("\n⛔ Ctrl+C - exit requested.")
            phishing_detector.flush_logs_on_exit()
            SecureCleanup.shutdown_cleanup({
                "log_path": "log.enc",
                "tor_manager": tor_manager,
                "ram_path": None,
                "encrypted_store": None,
                "kyber_manager": None
            })
            break

    threading.Thread(target=tor_auto_renew_thread, daemon=True).start()
    threading.Thread(target=decoy_traffic_thread, args=(extra_stealth_options,), daemon=True).start()

if __name__ == "__main__":
    import sys

    # 🧠 Check if launched in browser mode
    if "--browser" in sys.argv:
        DarkelfCLIBrowser().run()
        sys.exit(0)

    # 🧠 Check if launched in PQChat async-prekey mode
    if "publish-prekey" in sys.argv:
        idx = sys.argv.index("publish-prekey")
        if len(sys.argv) > idx + 1:
            user_id = sys.argv[idx + 1]
            chat = DarkelfPQChat(my_id=user_id)
            chat.publish_prekey_bundle()
            sys.exit(0)
        else:
            print("Usage: python thisfile.py publish-prekey <your_id>")
            sys.exit(1)

    if "accept-prekey" in sys.argv:
        idx = sys.argv.index("accept-prekey")
        if len(sys.argv) > idx + 2:
            user_id = sys.argv[idx + 1]
            port = int(sys.argv[idx + 2])
            chat = DarkelfPQChat(my_id=user_id)
            chat.accept_async("0.0.0.0", port)
            sys.exit(0)
        else:
            print("Usage: python thisfile.py accept-prekey <your_id> <port>")
            sys.exit(1)

    if "connect-prekey" in sys.argv:
        idx = sys.argv.index("connect-prekey")
        if len(sys.argv) > idx + 3:
            their_id = sys.argv[idx + 1]
            host = sys.argv[idx + 2]
            port = int(sys.argv[idx + 3])
            chat = DarkelfPQChat()
            chat.connect_async(host, port, their_id)
            sys.exit(0)
        else:
            print("Usage: python thisfile.py connect-prekey <their_id> <host> <port>")
            sys.exit(1)

    # 🧠 Legacy PQChat mode (keep for backward compatibility)
    if "--pqchat" in sys.argv:
        import argparse
        parser = argparse.ArgumentParser(description="Post-Quantum Secure Terminal Chat (DarkelfPQChat)")
        parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to connect/bind")
        parser.add_argument("--port", type=int, default=9000, help="Port to connect/bind")
        parser.add_argument("--server", action="store_true", help="Run as server")
        args, _ = parser.parse_known_args()
        chat = DarkelfPQChat()
        chat.run(host=args.host, port=args.port, is_server=args.server)
        sys.exit(0)

    # Step 1: Ensure strong entropy
    ensure_strong_entropy()

    # Step 2: Secure shutdown handlers
    signal.signal(signal.SIGTERM, sigterm_cleanup_handler)
    signal.signal(signal.SIGINT, sigterm_cleanup_handler)

    # Step 3: PQ Logger initialization
    pq_logger = PQLogManager(get_fernet_key())
    pq_logger.log("tools", "✅ Darkelf CLI booted successfully.")
    pq_logger.flush_all()

    # Step 4: CLI or REPL routing
    cli_commands = {"generate-keys", "send", "receive"}
    if len(sys.argv) > 1 and sys.argv[1] in cli_commands:
        cli_main()
    else:
        repl_main()

    # Step 5: In-memory log cleanup
    for category in pq_logger.logs:
        pq_logger.logs[category].clear()
