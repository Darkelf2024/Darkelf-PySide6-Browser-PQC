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
import signal
import ssl
import struct
import zlib
import nacl.public
import ctypes.util
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import CryptoError
from typing import Optional, List, Dict
from urllib.parse import urlparse
from base64 import urlsafe_b64encode, urlsafe_b64decode
from collections import defaultdict
from datetime import datetime
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.kem import ml_kem_768 as kyber
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from bs4 import BeautifulSoup
from oqs import KeyEncapsulation
from PIL import Image
import piexif
import tls_client  # Requires: pip install tls-client
import subprocess  # nosec - All run through sanitizing and validation
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

# Tor + Stem
import stem.process
from stem.connection import authenticate_cookie
from stem.control import Controller
from stem import Signal as StemSignal
from stem import process as stem_process


from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

# PyQt5 Imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QLineEdit, QVBoxLayout,
    QMenuBar, QToolBar, QDialog, QMessageBox, QFileDialog, QProgressDialog, QTextEdit,
    QListWidget, QMenu, QWidget, QLabel, QShortcut, QAction, QActionGroup, QSizePolicy, QToolButton, QHBoxLayout
)
from PyQt5.QtGui import QPalette, QColor, QKeySequence, QGuiApplication, QIcon, QPainter, QPixmap
from PyQt5.QtWebChannel import QWebChannel

from PyQt5.QtWebEngineWidgets import (
    QWebEngineView, QWebEngineSettings, QWebEnginePage,
    QWebEngineProfile, QWebEngineScript, QWebEngineDownloadItem
)
from PyQt5.QtWebEngineCore import (
    QWebEngineUrlRequestInterceptor,
    QWebEngineCookieStore
)
from PyQt5.QtNetwork import QNetworkProxy, QSslConfiguration, QSslSocket, QSsl, QSslCipher
from PyQt5.QtCore import (
    QUrl, QSettings, Qt, QObject, pyqtSlot, QTimer, QCoreApplication,
    pyqtSignal, QThread, QSize
)

# --- Darkelf theme helpers ---
THEME = {
    "bg":        "#0b0f14",   # app background
    "surface":   "#11161d",   # toolbar surface
    "stroke":    "#1f2937",   # borders / dividers
    "muted":     "#93a4b3",   # secondary text
    "text":      "#e6f0f7",
    "accent":    "#18f77a",   # neon green
    "accentDim": "#0ed967",
}

def make_text_icon(char: str, fg: str = "#e6f0f7", size: int = 18) -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing, True)
    p.setPen(QColor(fg))
    p.setFont(p.font())
    p.drawText(pm.rect(), Qt.AlignCenter, char)
    p.end()
    return QIcon(pm)
    
def apply_darkelf_menu_theme():
    qApp = QApplication.instance()
    if not qApp:
        return
    qApp.setStyleSheet(qApp.styleSheet() + f"""
        QMenu {{
            background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                        stop:0 {THEME['surface']}, stop:1 {THEME['bg']});
            border: 1px solid {THEME['stroke']};
            border-radius: 12px;
            padding: 6px;
        }}
        QMenu::separator {{
            height: 1px;
            background: {THEME['stroke']};
            margin: 6px 8px;
        }}
        QMenu::item {{
            color: {THEME['text']};
            padding: 8px 12px;
            border-radius: 8px;
        }}
        QMenu::item:selected {{
            background: rgba(24, 247, 122, 0.14);
        }}
        QMenu::icon {{ margin-right: 8px; }}

        QToolTip {{
            background: {THEME['surface']};
            color: {THEME['text']};
            border: 1px solid {THEME['stroke']};
            border-radius: 8px;
            padding: 6px 8px;
        }}
    """)
    
class SignalWrapper(QObject):
    osint_result_signal = pyqtSignal(object)
    
class EmailIntelPro:
    def __init__(self, email, session=None):
        self.email = email
        self.session = session or requests.Session()
        self.domain = email.split("@")[-1] if "@" in email else ""
        self.prefix = email.split("@")[0] if "@" in email else ""
        self.mx_records = []
        self.txt_records = []
        self.creation_date = None
        self.disposable = False
        self.score = 0
        self.breached = False

    def is_valid_email(self):
        return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", self.email))

    async def analyze(self):
        # Dummy: Add real DNS and breach checks here
        try:
            self.mx_records = ["mx1." + self.domain]
            self.txt_records = ["v=spf1 include:" + self.domain]
            self.creation_date = "2022-01-01"
            self.disposable = "mailinator" in self.domain
            self.score = 100 if not self.disposable else 60
            self.breached = False
        except Exception as e:
            print(f"Initialization failed: {e}")

class DarkelfUtils:
    DUCKDUCKGO_LITE = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite"
    DUCKDUCKGO_HTML = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html"
    TOR_PROXY = {
        "http": "socks5h://127.0.0.1:9052",
        "https": "socks5h://127.0.0.1:9052"
    }
    DORK_THREADS = 2
    FETCH_THREADS = 2

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
                    results[dork] = urls[:max_results]
                else:
                    failed_dorks.append(dork)

        return results

    def fetch_url(self, url, use_tor=True, timeout=15):
        session = requests.Session()
        if use_tor:
            session.proxies = self.TOR_PROXY
        res = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=timeout)
        return res.text

    def fetch_urls_parallel(self, urls, use_tor=True, timeout=10):
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

    def osintscan(self, query, use_tor=True, max_results=10):
        import re
        is_email = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", query))
        is_username = bool(re.match(r"^@?[a-zA-Z0-9_.-]{3,32}$", query)) and not is_email
        is_name = False

        if not (is_email or is_username):
            parts = query.strip().split()
            if len(parts) >= 2 and all(re.match(r"^[A-Za-z.\-']+$", p) for p in parts):
                is_name = True

        username = query.lstrip('@') if is_username else None
        email = query if is_email else None
        name = query if is_name else None

        results = {
            "emails": [],
            "profiles": [],
            "mentions": [],
            "summary": []
        }

        tlds = ["com", "net", "org", "gov", "edu", "int", "info", "eu", "ch", "de", "fr", "it", "nl", "ru", "pl", "us", "uk", "au", "ca", "in", "biz", "pro", "co", "me"]
        special_sites = ["archive.org", "pastebin.com", "manchestercf.com", "egs.edu", "researchgate.net", "academia.edu", "ssrn.com", "osf.io", "darkelfbrowser.com"]

        if is_email:
            username_part = email.split("@")[0]
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
                f'"{username_part}" inurl:profile',
                f'"{username_part}" site:github.com',
                f'"{username_part}" site:linkedin.com/in',
                f'"{username_part}" site:reddit.com/user'
            ]
            dorks = dorks_email + dorks_username
        elif is_username:
            dorks = [
                f'"{username}" inurl:profile',
                f'"{username}" site:github.com',
                f'"{username}" site:reddit.com/user',
                f'"{username}" site:stackoverflow.com/users',
                f'"{username}" site:about.me'
            ]
        elif is_name:
            dorks = [f'"{name}" site:{site}' for site in special_sites]
            dorks += [f'"{name}" site:.{tld}' for tld in tlds]
        else:
            dorks = [f'"{query}"']

        seen = set()
        urls = []

        for dork in dorks:
            hits = self.onion_ddg_search(dork, max_results=max_results)
            for item in hits:
                url = item[1] if isinstance(item, (list, tuple)) and len(item) == 2 else str(item)
                if url.startswith("http") and url not in seen:
                    urls.append(url)
                    seen.add(url)
            if len(urls) >= max_results:
                break

        results["profiles"].extend(urls)
        results["mentions"].extend(list(seen))

        summary = []
        summary.append("=== OSINT Summary ===")
        if email:
            summary.append(f"[📧] Email scanned: {email}")
        if username:
            summary.append(f"[🧑] Username scanned: {username}")
        if name:
            summary.append(f"[👤] Name scanned: {name}")
        if urls:
            summary.append(f"[🌐] Dorked URLs: {len(urls)}")
            for u in urls[:max_results]:
                summary.append(f"  - {u}")
        else:
            summary.append("[!] No URLs found.")
        summary.append("✅ OSINT scan complete.")
        results["summary"] = summary

        return results

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
        while True:
            time.sleep(self.check_interval)

            # Swap monitoring
            swap_now = self.swap_active()
            if swap_now != self._last_swap_active:
                if swap_now:
                    print("❌ [DarkelfKernelMonitor] Swap is ACTIVE — marking cleanup required!")
                    self.kill_dynamic_pager()
                    self.cleanup_required = True
                else:
                    print("✅ [DarkelfKernelMonitor] Swap is OFF")
                self._last_swap_active = swap_now

            # Dynamic pager monitoring
            pager_now = self.dynamic_pager_running()
            if pager_now != self._last_pager_state:
                if pager_now:
                    print("❌ [DarkelfKernelMonitor] dynamic_pager is RUNNING — potential memory leak risk!")
                else:
                    print("✅ [DarkelfKernelMonitor] dynamic_pager is not running")
                self._last_pager_state = pager_now

            # Kernel fingerprint monitoring
            current_fingerprint = self.system_fingerprint()
            if hash(str(current_fingerprint)) != self._last_fingerprint_hash:
                print("⚠️ [DarkelfKernelMonitor] Kernel config changed — setting cleanup required!")
                self.cleanup_required = True
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

    def kill_dynamic_pager(self):
        try:
            subprocess.run(["sudo", "launchctl", "bootout", "system", "/System/Library/LaunchDaemons/com.apple.dynamic_pager.plist"], check=True)
            print("🔒 [DarkelfKernelMonitor] dynamic_pager disabled")
        except subprocess.CalledProcessError:
            print("⚠️ [DarkelfKernelMonitor] Failed to disable dynamic_pager")

    def secure_delete_swap(self):
        try:
            subprocess.run(["sudo", "rm", "-f", "/private/var/vm/swapfile*"], check=True)
            print("🧨 [DarkelfKernelMonitor] Swap files removed")
        except Exception as e:
            print(f"⚠️ [DarkelfKernelMonitor] Failed to remove swapfiles: {e}")

    def secure_purge_darkelf_vault(self):
        # Securely overwrite and delete known vault scripts
        vault_paths = [
            os.path.expanduser("~/Darkelf/Darkelf Vault TL Edition.py"),
            os.path.expanduser("~/Desktop/Darkelf Vault TL Edition.py"),
            "/usr/local/bin/Darkelf Vault Browser.py",
            "/usr/local/bin/Darkelf Vault TL Edition.py",
            "/opt/darkelf/Darkelf Vault Browser.py",
            "/opt/darkelf/Darkelf Vault TL Edition.py"
        ]
        for path in vault_paths:
            if os.path.exists(path):
                try:
                    with open(path, "ba+", buffering=0) as f:
                        length = f.tell()
                        f.seek(0)
                        f.write(secrets.token_bytes(length))
                    os.remove(path)
                    print(f"💥 [DarkelfKernelMonitor] Vault destroyed: {path}")
                except Exception as e:
                    print(f"⚠️ Failed to delete {path}: {e}")
                    
    def shutdown_darkelf(self):
        print("💣 [DarkelfKernelMonitor] Darkelf app shutdown initiated.")
        if self.cleanup_required:
            self.secure_delete_swap()
            self.secure_purge_darkelf_vault()

        if self.parent_app:
            QTimer.singleShot(0, self.parent_app.quit)
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
        
class HeaderInterceptor(QWebEngineUrlRequestInterceptor):
    def interceptRequest(self, info):
        # Spoofed or poisoned headers
        poison_headers = {
            b'referer': b'null',
            b'user-agent': b'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0',
            b'sec-ch-ua': b'"Not_A_Brand";v="99", "Chromium";v="120", "FakeBrand";v="1"',
            b'sec-ch-ua-mobile': b'?0',
            b'sec-ch-ua-platform': b'"Windows"'
        }

        for header, value in poison_headers.items():
            if info.requestHeader(header):
                info.setHttpHeader(header, value)

        # Add noise headers
        info.setHttpHeader(b'x-poison-null', b'0')
        info.setHttpHeader(b'x-random-noop', b'noop')

# TLS Certificate Fingerprint Helper

def get_cert_hash(hostname: str, port: int = 443) -> Optional[str]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
        return hashlib.sha256(der_cert).hexdigest()
    except Exception as e:
        print(f"[DarkelfAI] ❌ Error retrieving certificate for {hostname}: {e}")
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
                print(f"[DarkelfAI] ❌ Could not extract certificate for {site}")
                return
            if site not in self.fingerprints:
                print(f"[DarkelfAI] 📌 Initial fingerprint for {site}: {cert_hash}")
                self.fingerprints[site] = cert_hash
            elif self.fingerprints[site] != cert_hash:
                print(f"[DarkelfAI] ⚠️ TLS CERT ROTATION for {site}")
                print(f"Old: {self.fingerprints[site]}")
                print(f"New: {cert_hash}")
                self.fingerprints[site] = cert_hash
            else:
                print(f"[DarkelfAI] ✅ No change in cert for {site}")
        except Exception as e:
            print(f"[DarkelfAI] ❌ Error checking {site}: {e}")

    async def monitor_loop(self):
        """Main monitoring loop. Runs until .stop() is called."""
        while self.running:
            headers = self.rotate_headers()
            print(f"[DarkelfAI] 🔁 Rotating User-Agent: {headers['User-Agent']}")
            tasks = [self.check_cert(site, headers) for site in self.sites]
            await asyncio.gather(*tasks)
            await asyncio.sleep(self.interval)

    def start(self):
        """Starts the monitor in a background thread."""
        def runner():
            print("[DarkelfAI] ✅ TLS Monitor started in background thread.")
            asyncio.run(self.monitor_loop())
        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        print("[DarkelfAI] ✅ TLS Monitor running in background thread.")

    def stop(self):
        """Stops the monitoring loop."""
        self.running = False
        print("[DarkelfAI] 🛑 TLS Monitor stopped.")
        
# 🔐 SecureBuffer + 🧠 MemoryMonitor (Embedded for Darkelf Browser)

class SecureBuffer:
    def __init__(self, size=4096):
        self.size = size
        self.buffer = mmap.mmap(-1, self.size)
        self.locked = False
        self._lock_memory()

    def _lock_memory(self):
        try:
            if sys.platform.startswith("win"):
                self.locked = ctypes.windll.kernel32.VirtualLock(
                    ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self.buffer))),
                    ctypes.c_size_t(self.size)
                )
            else:
                libc_name = ctypes.util.find_library("c")
                libc = ctypes.CDLL(libc_name)
                if hasattr(libc, "madvise"):
                    libc.madvise(
                        ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self.buffer))),
                        ctypes.c_size_t(self.size),
                        16  # MADV_DONTDUMP
                    )
                self.locked = (libc.mlock(
                    ctypes.c_void_p(ctypes.addressof(ctypes.c_char.from_buffer(self.buffer))),
                    ctypes.c_size_t(self.size)
                ) == 0)
        except Exception as e:
            print(f"[SecureBuffer] Lock failed: {e}")
            self.locked = False

    def write(self, data: bytes):
        self.buffer.seek(0)
        data = data[:self.size]
        self.buffer.write(data)
        if len(data) < self.size:
            self.buffer.write(b'\x00' * (self.size - len(data)))

    def read(self) -> bytes:
        self.buffer.seek(0)
        return self.buffer.read(self.size)

    def zero(self):
        self.buffer.seek(0)
        self.buffer.write(secrets.token_bytes(self.size))
        self.buffer.seek(0)
        self.buffer.write(b"\x00" * self.size)

    def close(self):
        self.zero()
        self.buffer.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
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

    def show_warning_dialog(self, parent_widget, reason):
        msg = QMessageBox(parent_widget)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Phishing Warning")
        msg.setText("Blocked suspicious site")
        msg.setInformativeText(reason)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec()

    def flush_logs_on_exit(self):
        if self.pq_logger:
            try:
                self.pq_logger.authorize_flush("darkelf-confirm")
                self.pq_logger.flush_log(path=self.flush_path)
                print(f"[PhishingDetector] ✅ Flushed encrypted phishing log to {self.flush_path}")
            except Exception as e:
                print(f"[PhishingDetector] ⚠️ Log flush failed: {e}")

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

class StealthCovertOpsPQ:
    def __init__(self, stealth_mode=True):
        self._log_buffer = []
        self._stealth_mode = stealth_mode
        self._authorized = False

        # === ML-KEM-768: Post-Quantum Key Exchange ===
        self.kem = oqs.KeyEncapsulation("ML-KEM-768")
        self.public_key = self.kem.generate_keypair()
        self.private_key = self.kem.export_secret_key()

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
        print("[StealthOpsPQ] 🚨 PANIC: Wiping memory, faking noise, and terminating.")
        self.clear_logs()
        self.memory_saturate(500)
        self.cpu_saturate(10)
        self.fake_activity_noise()
        self.process_mask_linux()
        os._exit(1)

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

def hardened_random_delay(min_s: float, max_s: float):
    time.sleep(random.uniform(min_s, max_s))

class ObfuscatedEncryptedCookieStore:
    def __init__(self, qt_cookie_store: QWebEngineCookieStore):
        self.store = {}  # {enc_name: (enc_value, kem_ciphertext)}
        self.qt_cookie_store = qt_cookie_store
        self.qt_cookie_store.cookieAdded.connect(self.intercept_cookie)

        # Post-quantum keypair for values
        self.master_public_key, self.master_private_key = kyber.generate_keypair()

        # 🔐 Secret for encrypting cookie names
        obf_key = hashlib.sha256(b"obfuscation_secret_42").digest()
        self.name_crypto = Fernet(base64.urlsafe_b64encode(obf_key[:32]))

    def obfuscate_name(self, name: str) -> str:
        return self.name_crypto.encrypt(name.encode()).decode()

    def deobfuscate_name(self, enc_name: str) -> str:
        return self.name_crypto.decrypt(enc_name.encode()).decode()

    def intercept_cookie(self, cookie):
        hardened_random_delay(0.2, 1.5)
        name = bytes(cookie.name()).decode(errors='ignore')
        value = bytes(cookie.value()).decode(errors='ignore')
        self.set_cookie(name, value)

    def set_cookie(self, real_name: str, value: str):
        hardened_random_delay(0.2, 1.5)
        enc_name = self.obfuscate_name(real_name)

        kem_ct, shared = kyber.encrypt(self.master_public_key)
        key = hashlib.sha256(shared).digest()
        fkey = base64.urlsafe_b64encode(key[:32])
        cipher = Fernet(fkey)
        enc_value = cipher.encrypt(value.encode())
        self.store[enc_name] = (enc_value, kem_ct)
        del cipher, key, fkey

    def get_cookie(self, real_name: str) -> str:
        hardened_random_delay(0.1, 1.0)
        enc_name = self.obfuscate_name(real_name)
        entry = self.store.get(enc_name)
        if not entry:
            return None
        enc_value, kem_ct = entry
        shared = kyber.decrypt(self.master_private_key, kem_ct)
        key = hashlib.sha256(shared).digest()
        fkey = base64.urlsafe_b64encode(key[:32])
        cipher = Fernet(fkey)
        val = cipher.decrypt(enc_value).decode()
        del cipher
        return val

    def clear(self):
        hardened_random_delay(0.3, 1.0)
        self._secure_erase()
        self.qt_cookie_store.deleteAllCookies()

    def wipe_memory(self):
        hardened_random_delay(0.2, 0.8)
        self._secure_erase()

    def _secure_erase(self):
        for enc_name in list(self.store.keys()):
            enc_value, kem_ct = self.store[enc_name]
            self.store[enc_name] = (
                secrets.token_bytes(len(enc_value)),
                secrets.token_bytes(len(kem_ct))
            )
            del self.store[enc_name]
        self.store.clear()

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
        kem = KeyEncapsulation("ML-KEM-768")
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
        kem = KeyEncapsulation("ML-KEM-768")
        kem.import_secret_key(self.privkey_bytes)
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
        
class EncryptedLoggerMLKEM768:
    def __init__(self):
        self.lock = threading.Lock()

    def log(self, message: str):
        encrypted = self.encrypt_with_mlkem(message)
        print(encrypted)

    def encrypt_with_mlkem(self, plaintext: str) -> str:
        try:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            ciphertext, shared_secret = kem.encap_secret(public_key)

            salt = os.urandom(16)
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"mlkem768_aes_key"
            ).derive(shared_secret)

            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            encrypted_payload = aesgcm.encrypt(nonce, plaintext.encode(), None)

            encrypted_blob = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "payload": base64.b64encode(encrypted_payload).decode(),
                "salt": base64.b64encode(salt).decode(),
            }

            encoded = base64.b64encode(json.dumps(encrypted_blob).encode()).decode()
            return f"[EncryptedMLKEM768]::{encoded}"
        except Exception as e:
            return f"[EncryptionError]::{str(e)}"

class PQCryptoAPI(QObject):
    def __init__(self):
        super().__init__()
        self.kyber = MLKEM768Manager()

    @pyqtSlot(result=str)
    def generateKeyPair(self) -> str:
        return self.kyber.get_public_key_b64()

    @pyqtSlot(str, str, result=str)
    def encrypt(self, peer_public_key_b64: str, message: str) -> str:
        try:
            return self.kyber.encrypt_with_peer_key(peer_public_key_b64, message)
        except Exception as e:
            return f"Error: {str(e)}"

    @pyqtSlot(str, result=str)
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

    @pyqtSlot(QWebEngineDownloadItem)
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

        if download_item.state() == QWebEngineDownloadItem.DownloadCompleted:
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
        self._inject_user_agent()

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
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
                "screen": (1920, 1080),
                "language": "en-GB",
                "timezone": "Europe/London"
            },
            {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
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
        # Use Tor-like letterboxing resolution (e.g., 1000x1000)
        tor_width = 1000
        tor_height = 1000

        js = f"""
        // [DarkelfAI] Spoof screen and window dimensions to mimic Tor Letterboxing (1000x1000)
        Object.defineProperty(window, 'innerWidth', {{ get: () => {tor_width} }});
        Object.defineProperty(window, 'innerHeight', {{ get: () => {tor_height} }});

        Object.defineProperty(window, 'outerWidth', {{ get: () => {tor_width} }});
        Object.defineProperty(window, 'outerHeight', {{ get: () => {tor_height} }});

        Object.defineProperty(screen, 'width', {{ get: () => {tor_width} }});
        Object.defineProperty(screen, 'height', {{ get: () => {tor_height} }});
        Object.defineProperty(screen, 'availWidth', {{ get: () => {tor_width - 20} }});
        Object.defineProperty(screen, 'availHeight', {{ get: () => {tor_height - 40} }});
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
        self.inject_stealth_profile()
        self.block_shadow_dom_inspection()
        self.block_tracking_requests()
        self.protect_fingerprinting()
        self.spoof_canvas_api()
        self.stealth_webrtc_block()
        self.block_webrtc_sdp_logging()
        self.block_supercookies()
        self.block_etag_and_cache_tracking()
        self.block_referrer_headers()
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
        self.inject_useragentdata_kill()
        #self.inject_webgl_spoof()
        self.inject_iframe_override()
        self.setup_csp()

    def inject_geolocation_override(self):
        script = """
        (function() {
            // Completely remove navigator.geolocation
            Object.defineProperty(navigator, "geolocation", {
                get: function () {
                    return undefined;
                },
                configurable: true
            });

            // Fake permissions API to return denied
            if (navigator.permissions && navigator.permissions.query) {
                const originalQuery = navigator.permissions.query;
                navigator.permissions.query = function(parameters) {
                    if (parameters.name === "geolocation") {
                        return Promise.resolve({ state: "denied" });
                    }
                    return originalQuery(parameters);
                };
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def inject_iframe_override(self):
        script = """
        (function() {
            const poisonIframe = (frame) => {
                try {
                    if (frame.contentWindow && frame.contentWindow.navigator) {
                        frame.contentWindow.navigator.geolocation = undefined;
                        Object.defineProperty(frame.contentWindow.navigator, 'platform', { value: 'unknown', configurable: true });
                        Object.defineProperty(frame.contentWindow.navigator, 'vendor', { value: '', configurable: true });
                    }
                } catch (e) {
                    // Ignore cross-origin issues
                }
            };

            // Poison existing iframes
            document.querySelectorAll('iframe').forEach(poisonIframe);

            // Observe for dynamically added iframes
            const observer = new MutationObserver(function(mutations) {
                for (let mutation of mutations) {
                    for (let node of mutation.addedNodes) {
                        if (node.tagName === 'IFRAME') {
                            poisonIframe(node);
                        }
                    }
                }
            });

            observer.observe(document, { childList: true, subtree: true });
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def inject_webgl_spoof(self):
        script = """
        (function () {
            const spoofedVendor = "Intel Inc.";
            const spoofedRenderer = "Intel Iris Xe Graphics";

            function spoofGL(context) {
                const originalGetParameter = context.getParameter;
                context.getParameter = function (param) {
                    if (param === 37445) return spoofedVendor;   // UNMASKED_VENDOR_WEBGL
                    if (param === 37446) return spoofedRenderer; // UNMASKED_RENDERER_WEBGL
                    return originalGetParameter.call(this, param);
                };
            }

            const originalGetContext = HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext = function(type, attrs) {
                const ctx = originalGetContext.call(this, type, attrs);
                if (type === "webgl" || type === "webgl2") {
                    spoofGL(ctx);
                }
                return ctx;
            };

            // Spoof WebGLRenderingContext extensions
            WebGLRenderingContext.prototype.getSupportedExtensions = function () {
                return [
                    "OES_texture_float", 
                    "OES_standard_derivatives", 
                    "OES_element_index_uint"
                ];
            };

            // Spoof shader precision to reduce entropy
            const origPrecision = WebGLRenderingContext.prototype.getShaderPrecisionFormat;
            WebGLRenderingContext.prototype.getShaderPrecisionFormat = function() {
                return { rangeMin: 127, rangeMax: 127, precision: 23 };
            };

            // Prevent detection of overridden functions
            const hideOverride = (obj, name) => {
                if (obj[name]) {
                    Object.defineProperty(obj[name], 'toString', {
                        value: () => `function ${name}() { [native code] }`
                    });
                }
            };

            hideOverride(WebGLRenderingContext.prototype, "getParameter");
            hideOverride(HTMLCanvasElement.prototype, "getContext");
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def inject_useragentdata_kill(self):
        script = """
        (function() {
            try {
                // Remove or override navigator.userAgentData
                if ("userAgentData" in navigator) {
                    Object.defineProperty(navigator, "userAgentData", {
                        get: function () {
                            return undefined;
                        },
                        configurable: true
                    });
                }

                // If it's still there, override the method
                if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
                    navigator.userAgentData.getHighEntropyValues = async function() {
                        return {};
                    };
                }

                // Remove Client Hint headers from fetch()
                const spoofUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0";
                const originalFetch = window.fetch;
                window.fetch = function(resource, init = {}) {
                    init.headers = new Headers(init.headers || {});
                    init.headers.set("sec-ch-ua", "");
                    init.headers.set("sec-ch-ua-mobile", "?0");
                    init.headers.set("sec-ch-ua-platform", "");
                    init.headers.set("user-agent", spoofUA);
                    return originalFetch(resource, init);
                };

                // Also scrub headers from XHR
                const originalOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(...args) {
                    this.addEventListener("readystatechange", function() {
                        if (this.readyState === 1) {
                            try {
                                this.setRequestHeader("sec-ch-ua", "");
                                this.setRequestHeader("sec-ch-ua-mobile", "?0");
                                this.setRequestHeader("sec-ch-ua-platform", "");
                                this.setRequestHeader("user-agent", spoofUA);
                            } catch (_) {}
                        }
                    });
                    return originalOpen.apply(this, args);
                };

                console.log("[Darkelf] userAgentData & Client Hints neutralized.");
            } catch (err) {
                console.warn("Darkelf stealth injection error:", err);
            }
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def inject_stealth_profile(self):
        script = """
        (() => {
            const spoofUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/78.0";

            const spoofedNavigator = {
                userAgent: spoofUA,
                appVersion: "5.0 (Windows NT 10.0)",
                platform: "Win32",
                vendor: "",
                language: "en-US",
                languages: ["en-US", "en"],
                webdriver: false,
                doNotTrack: "1",
                maxTouchPoints: 0,
                deviceMemory: 4,
                hardwareConcurrency: 4,
                connection: undefined,
                bluetooth: undefined
            };

            for (const [key, value] of Object.entries(spoofedNavigator)) {
                try {
                    Object.defineProperty(navigator, key, {
                        get: () => value,
                        configurable: true
                    });
                } catch (_) {}
            }

            try {
                navigator.__defineGetter__('userAgentData', () => undefined);
                Object.defineProperty(window, 'chrome', { get: () => undefined });
                Object.defineProperty(document, 'cookie', {
                    get: () => '',
                    set: () => {},
                    configurable: true
                });
            } catch (_) {}

            const fakeHeaders = {
                'sec-ch-ua': '',
                'sec-ch-ua-platform': '',
                'sec-ch-ua-mobile': '',
                'user-agent': spoofUA,
                'referer': '',
                'referrer-policy': 'no-referrer'
            };

            const patchHeaders = (headers) => {
                for (const h in fakeHeaders) {
                    try { headers.set(h, fakeHeaders[h]); } catch (_) {}
                }
            };

            const originalFetch = window.fetch;
            window.fetch = function(resource, init = {}) {
                init.headers = new Headers(init.headers || {});
                patchHeaders(init.headers);
                init.referrer = '';
                init.referrerPolicy = 'no-referrer';
                return originalFetch(resource, init);
            };

            const originalOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(...args) {
                this.addEventListener("readystatechange", function() {
                    if (this.readyState === 1) {
                        try {
                            for (const h in fakeHeaders) {
                                this.setRequestHeader(h, fakeHeaders[h]);
                            }
                        } catch (_) {}
                    }
                });
                return originalOpen.apply(this, args);
            };

            console.log("[Darkelf StealthInjector] Spoofing applied.");
        })();
        """
        self.inject_script(script, injection_point=QWebEngineScript.DocumentCreation)

    def _inject_font_protection(self):
        js = """
        // [DarkelfAI] Font fingerprinting protection with .onion whitelist

        (function() {
            const isOnion = window.location.hostname.endsWith(".onion");
            if (isOnion) {
                console.warn("[DarkelfAI] .onion site detected — skipping font spoofing.");
                return;
            }

            // Slight noise added to disrupt precise fingerprinting
            const randomize = (val, factor = 0.03) => val + (Math.random() * val * factor);

            // Override measureText to return slightly randomized width
            const originalMeasureText = CanvasRenderingContext2D.prototype.measureText;
            CanvasRenderingContext2D.prototype.measureText = function(text) {
                const metrics = originalMeasureText.call(this, text);
                metrics.width = randomize(metrics.width);
                return metrics;
            };

            // Spoof getComputedStyle to alter only font properties
            const originalGetComputedStyle = window.getComputedStyle;
            window.getComputedStyle = function(...args) {
                const style = originalGetComputedStyle.apply(this, args);
                return new Proxy(style, {
                    get(target, prop) {
                        if (typeof prop === 'string' && prop.toLowerCase().includes('font')) {
                            return '16px "Noto Sans"';
                        }
                        return target[prop];
                    }
                });
            };

            // Slightly randomized offsetWidth/offsetHeight
            const offsetNoise = () => Math.floor(90 + Math.random() * 10);
            Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
                get: function () { return offsetNoise(); },
                configurable: true
            });
            Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
                get: function () { return offsetNoise(); },
                configurable: true
            });

            console.log('[DarkelfAI] Soft font fingerprinting vectors spoofed.');
        })();
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
            meta.content = `
                default-src 'none';
                script-src 'self' 'unsafe-inline' https:;
                connect-src 'self' https: wss:;
                img-src 'self' data: https:;
                style-src 'self' 'unsafe-inline';
                font-src 'self' https:;
                media-src 'none';
                object-src 'none';
                frame-ancestors 'none';
                base-uri 'self';
                form-action 'self';
                upgrade-insecure-requests;
                block-all-mixed-content;
            `.replace(/\\s+/g, ' ').trim();
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
    result_ready = pyqtSignal(str)
    error = pyqtSignal(str)

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
    result_ready = pyqtSignal(str)
    error = pyqtSignal(str)

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
        self.signals = SignalWrapper()
        
        # --- Synchronous ML-KEM 768 key manager ---
        self.kyber_manager = MLKEM768Manager(sync=False)
        # Print confirmation in main thread
        print("MLKEM768Manager created in Darkelf.")

        self.log_path = os.path.join(os.path.expanduser("~"), ".darkelf_log")
        self._init_stealth_log()
        
        stealth_logger = StealthCovertOpsPQ()
        phishing_detector = PhishingDetectorZeroTrace(pq_logger=stealth_logger)
                
        self.disable_system_swap()  # Disable swap early
        self.init_settings()
        self.init_security()
        self.init_ui()
        self.init_theme()
        self.init_download_manager()
        self.history_log = []
        self.init_shortcuts()
        
        interceptor = HeaderInterceptor()
        profile = QWebEngineProfile.defaultProfile()
        profile.setUrlRequestInterceptor(interceptor)
        
        # --- Inject JavaScript to strip DOM ads (banners, iframes, etc) ---
        #script = create_dom_cleaner_script()
        #profile.scripts().insert(script)
        
        QTimer.singleShot(8000, self.start_forensic_tool_monitor)
        
        # Launch JA3 spoofing proxy
        self.start_mitmproxy_proxy()
        
        # Fallback DNS resolution only if Tor is not working
        if self.tor_connection_failed():
            self.log_stealth("Tor unavailable — using DoH/DoT fallback")
            self.resolve_domain_doh("cloudflare.com", "A")
            self.resolve_domain_dot("cloudflare.com", "A")
        else:
            self.log_stealth("Tor active — fallback not triggered")
            
    def close_tab(self, index=None):
        """
        Closes the tab at the specified index. If no index is given, closes current tab.
        """
        if index is None:
            index = self.tab_widget.currentIndex()
        if self.tab_widget.count() < 2:
            return
        widget = self.tab_widget.widget(index)
        widget.deleteLater()
        self.tab_widget.removeTab(index)
        self.clear_cache_and_history()
        
    def start_mitmproxy_proxy(self):
        try:
            self.log_stealth("Starting mitmproxy with JA3 rotation...")
            self.mitmproxy_process = subprocess.Popen([
                "mitmdump",
                "--mode", "upstream:socks5://127.0.0.1:9052",
                "-p","8080",
                "-s", os.path.join(os.path.dirname(__file__), "rotate_tls.py")
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.log_stealth(f"Failed to launch mitmproxy: {e}")

    def close(self):
        self.stop_tor()
        if self.mitmproxy_process:
            self.mitmproxy_process.terminate()
            self.mitmproxy_process.wait()
        super().close()
    
    def _init_stealth_log(self):
        try:
            with open(self.log_path, "a") as f:
                os.chmod(self.log_path, 0o600)
                f.write(f"--- Stealth log started: {datetime.utcnow()} UTC ---\n")
        except Exception:
            pass

    def log_stealth(self, message):
        try:
            if not self.log_path or not os.path.exists(self.log_path):
                return  # Don't recreate log files once deleted
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

    def _is_tracelabs_ova(self):
        try:
            hostname = socket.gethostname().lower()
            if "tracelabs" in hostname or "parrot" in hostname:
                return True

            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    os_release = f.read().lower()
                    if "kali" in os_release or "parrot" in os_release:
                        return True

            uname_release = os.uname().release.lower()
            if "kali" in uname_release or "parrot" in uname_release:
                return True

        except Exception as e:
            self.log_stealth(f"Error checking OVA environment: {e}")

        return False

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
        return [
            "wireshark", "volatility", "autopsy", "tcpdump", "sysinternals", "processhacker",
            "networkminer", "bulk_extractor", "sleuthkit", "xplico", "oxygen", "magnetaxiom",
            "chainsaw", "cape", "redline", "dumpzilla", "mftdump", "regshot", "nkprocmgr",
            "cyberchef", "prodiscover", "xways", "hexeditor", "binwalk", "foremost",
            "regripper", "plaso", "timesketch", "arkime",
            "gdb", "lldb", "ida", "ollydbg", "windbg", "radare2", "x64dbg", "immunitydebugger",
            "debugdiag", "strace", "ltrace"
        ]
        
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
        self.tor_network_enabled = self.settings.value("tor_network_enabled", True, type=bool)
        self.https_enforced = self.settings.value("https_enforced", True, type=bool)
        self.cookies_enabled = self.settings.value("cookies_enabled", False, type=bool)
        self.block_geolocation = self.settings.value("block_geolocation", True, type=bool)
        self.block_device_orientation = self.settings.value("block_device_orientation", True, type=bool)
        self.block_media_devices = self.settings.value("block_media_devices", True, type=bool)

        # Configure web engine profile
        self.configure_web_engine_profile()
        
        self.logger = EncryptedLoggerMLKEM768()

        # Initialize Tor if enabled
        self.init_tor()
        
        # Configure user agent to mimic Firefox ESR
        self.configure_user_agent()
    
    def configure_tls(self):
        ssl_configuration = QSslConfiguration.defaultConfiguration()

        # Mimic Firefox ESR cipher suites
        firefox_cipher_suites = []

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
        self.web = self.web_view
        self.web.setContextMenuPolicy(Qt.CustomContextMenu)
        self.web.customContextMenuRequested.connect(self.show_darkelf_context_menu)

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
            obfs4_path = shutil.which("obfs4proxy")

            if not tor_path or not os.path.exists(tor_path):
                QMessageBox.critical(self, "Tor Error", "Tor not found. Please install it using:\n\n  brew install tor\nor\n  sudo apt install tor")
                return

            if not obfs4_path or not os.path.exists(obfs4_path):
                QMessageBox.critical(self, "Tor Error", "obfs4proxy not found. Please install it using:\n\n  brew install obfs4proxy\nor\n  sudo apt install obfs4proxy")
                return

            bridges = [
                "obfs4 185.177.207.158:8443 B9E39FA01A5C72F0774A840F91BC72C2860954E5 cert=WA1P+AQj7sAZV9terWaYV6ZmhBUcj89Ev8ropu/IED4OAtqFm7AdPHB168BPoW3RrN0NfA iat-mode=0",
                "obfs4 91.227.77.152:465 42C5E354B0B9028667CFAB9705298F8C3623A4FB cert=JKS4que9Waw8PyJ0YRmx3QrSxv/YauS7HfxzmR51rCJ/M9jCKscJu7SOuz//dmzGJiMXdw iat-mode=2"
            ]

            random.shuffle(bridges)

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
                    init_msg_handler=lambda line: print("[tor]", line)
                )
            except Exception as bridge_error:
                print("[Darkelf] Bridge connection failed:", bridge_error)

                if not getattr(self, "allow_direct_fallback", True):
                    QMessageBox.critical(self, "Tor Bridge Error", "Bridge connection failed and direct fallback is disabled.")
                    return  # Stop here if fallback not allowed

                # FALLBACK TO DIRECT CONNECTION
                QMessageBox.warning(self, "Tor Fallback", "Bridge connection failed. Trying direct Tor connection...")

                tor_config.pop('UseBridges', None)
                tor_config.pop('ClientTransportPlugin', None)
                tor_config.pop('Bridge', None)
                tor_config.pop('BridgeRelay', None)

                self.tor_process = stem_process.launch_tor_with_config(
                    tor_cmd=tor_path,
                    config=tor_config,
                    init_msg_handler=lambda line: print("[tor fallback]", line)
                )

                # Authenticate controller
                self.controller = Controller.from_port(port=9053)
                cookie_path = os.path.join(tor_config['DataDirectory'], 'control_auth_cookie')
            
                with open(cookie_path, 'rb') as f:
                    cookie = f.read()
                
                self.controller.authenticate(password=None, cookie=cookie)
                print("[Darkelf] Tor authenticated via cookie.")

            # Optional PQC test
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_sock.connect(("127.0.0.1", 9052))

                # Example peer public key; replace with a real one in practice
                peer_pub_key_b64 = KyberManager().get_public_key()
                protector = NetworkProtector(test_sock, peer_pub_key_b64)
                protector.send_protected(b"[Darkelf] Tor SOCKS test with PQC")
                test_sock.close()
            except Exception as e:
                print(f"[Darkelf] Failed test connection through Tor SOCKS: {e}")

        except OSError as e:
            QMessageBox.critical(None, "Tor Error", f"Failed to start Tor: {e}")
        except Exception as e:
            QMessageBox.critical(None, "Tor Error", f"Unexpected error: {e}")

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
        
    def _apply_shortcuts(self):
        QShortcut(QKeySequence("Alt+Left"),  self, activated=self.go_back)
        QShortcut(QKeySequence("Alt+Right"), self, activated=self.go_forward)
        QShortcut(QKeySequence("Ctrl+R"),    self, activated=self.reload_page)
        QShortcut(QKeySequence("F11"),       self, activated=self.toggle_full_screen)
        QShortcut(QKeySequence("Ctrl+="),    self, activated=self.zoom_in)
        QShortcut(QKeySequence("Ctrl+-"),    self, activated=self.zoom_out)

    def create_toolbar(self):
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setIconSize(QSize(18, 18))
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
                            stop:0 {THEME['surface']},
                            stop:1 {THEME['bg']});
                border: 0px;
                padding: 6px 10px;
                spacing: 6px;
            }}
            QToolBar::separator {{
                background: {THEME['stroke']};
                width: 1px; height: 24px; margin: 0 8px;
            }}
            QToolButton {{
                color: {THEME['text']};
                background: rgba(255,255,255,0.02);
                border: 1px solid {THEME['stroke']};
                border-radius: 10px;
                padding: 6px 10px;
            }}
            QToolButton:hover {{
                background: rgba(255,255,255,0.06);
                border-color: {THEME['accentDim']};
            }}
            QToolButton:pressed {{
                background: rgba(24, 247, 122, 0.14);
                border-color: {THEME['accent']};
            }}
            QLineEdit#omni {{
                color: {THEME['text']};
                background: {THEME['bg']};
                border: 1px solid {THEME['stroke']};
                border-radius: 16px;
                padding: 8px 14px;
                selection-background-color: {THEME['accent']};
                selection-color: #000;
            }}
            QLineEdit#omni:focus {{
                border-color: {THEME['accent']};
            }}
        """)

        # Left controls
        back_button    = self.create_button('', self.go_back,    icon=make_text_icon('◄'))
        back_button.setToolTip("Back  (Alt+Left)")
        forward_button = self.create_button('', self.go_forward, icon=make_text_icon('►'))
        forward_button.setToolTip("Forward  (Alt+Right)")
        reload_button  = self.create_button('', self.reload_page,icon=make_text_icon('↺'))
        reload_button.setToolTip("Reload  (Ctrl+R)")
        home_button    = self.create_button('', self.load_homepage, icon=make_text_icon('⏻', fg=THEME['accent']))
        home_button.setToolTip("Home")

        toolbar.addWidget(back_button)
        toolbar.addWidget(forward_button)
        toolbar.addWidget(reload_button)
        toolbar.addSeparator()
        toolbar.addWidget(home_button)

        # Search bar (longer, no icon)
        self.search_bar = QLineEdit(self)
        self.search_bar.setObjectName("omni")
        self.search_bar.setPlaceholderText("Search or enter URL")
        self.search_bar.returnPressed.connect(self.search_or_load_url)
        self.search_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        toolbar.addWidget(self.search_bar)

        # Right controls
        zoom_in_button  = self.create_button('', self.zoom_in,  icon=make_text_icon('+'))
        zoom_in_button.setToolTip("Zoom In  (Ctrl+=)")
        zoom_out_button = self.create_button('', self.zoom_out, icon=make_text_icon('−'))
        zoom_out_button.setToolTip("Zoom Out  (Ctrl+-)")
        full_button     = self.create_button('', self.toggle_full_screen, icon=make_text_icon('⛶'))
        full_button.setToolTip("Toggle Full Screen  (F11)")

        toolbar.addSeparator()
        toolbar.addWidget(zoom_out_button)
        toolbar.addWidget(zoom_in_button)
        toolbar.addWidget(full_button)

        self.addToolBar(toolbar)
        if hasattr(self, "_apply_shortcuts"):
            self._apply_shortcuts()
        return toolbar

    def create_button(self, text, slot, icon=None):
        btn = QToolButton(self)
        if icon is not None:
            btn.setIcon(icon)
        else:
            btn.setText(text)
        btn.clicked.connect(slot)
        btn.setAutoRaise(True)
        return btn

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
        
    def show_darkelf_context_menu(self, pos):
        view = self.web
        global_pos = view.mapToGlobal(pos)

        data = view.page().contextMenuData()
        menu = QMenu(self)

        shadow = QGraphicsDropShadowEffect(menu)
        shadow.setBlurRadius(24)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(0, 0, 0, 160))
        menu.setGraphicsEffect(shadow)

        # Navigation
        act_back    = menu.addAction(make_text_icon('◄', size=16), "Back",    self.go_back)
        act_forward = menu.addAction(make_text_icon('►', size=16), "Forward", self.go_forward)
        act_reload  = menu.addAction(make_text_icon('↺', size=16), "Reload",  self.reload_page)
        act_back.setEnabled(view.history().canGoBack())
        act_forward.setEnabled(view.history().canGoForward())
        menu.addSeparator()

        # Link actions if clicking a link
        if data.linkUrl().isValid():
            menu.addAction(make_text_icon('⤴', size=16), "Open Link in New Tab",
                        lambda url=data.linkUrl(): self.open_in_new_tab(url))
            menu.addAction("Copy Link Address",
                        lambda url=data.linkUrl(): self.copy_to_clipboard(url.toString()))
            menu.addSeparator()

        # Edit
        page = view.page()
        menu.addAction("Copy",  page.action(page.Copy).trigger) \
            .setEnabled(bool(data.selectedText()))
        menu.addAction("Paste", page.action(page.Paste).trigger)
        menu.addAction("Select All", page.action(page.SelectAll).trigger)
        menu.addSeparator()

        # Zoom / View
        menu.addAction(make_text_icon('+', size=16), "Zoom In",  self.zoom_in)
        menu.addAction(make_text_icon('−', size=16), "Zoom Out", self.zoom_out)
        menu.addAction(make_text_icon('⛶', size=16), "Full Screen", self.toggle_full_screen)

        menu.exec_(global_pos)
        
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
    
    def enable_light_mode(self):
        self.homepage_mode = "light"
        self.load_homepage()

    def enable_grey_mode(self):
        self.homepage_mode = "grey"
        self.load_homepage()

    def enable_dark_mode(self):
        self.homepage_mode = "dark"
        self.load_homepage()

    def custom_homepage_html(self):
        return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Darkelf Browser — Post-Quantum, Private, Hardened</title>
  <link rel="icon" href="/Images/favicon.png" type="image/png" />
  <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">

  <style>
    :root{
      --bg: #0a0b10;
      --accent: #34C759;
      --accent-2: #04A8C8;
      --border: rgba(255,255,255,.10);
      --input-bg: #12141b;
      --input-text: #e5e7eb;
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      background: radial-gradient(1200px 600px at 20% -10%, rgba(4,168,200,.25), transparent 60%),
                  radial-gradient(1000px 600px at 120% 10%, rgba(52,199,89,.18), transparent 60%),
                  var(--bg);
      color:#eef2f6;
      display:flex; flex-direction:column; justify-content:center; align-items:center;
    }
    header{display:none;}

    .center-container{text-align:center;}

    .brand{
      display:flex; gap:10px; align-items:center; justify-content:center;
      font-weight:700; letter-spacing:.3px; font-size:2rem;
    }
    .brand i{color:var(--accent);}

    .tagline{
      font-size:.95rem; font-weight:700; letter-spacing:.18em;
      text-transform:uppercase; color:#cfd8e3; margin:6px 0 20px;
    }

    .search-wrap{
      display:flex; align-items:stretch; gap:10px; flex-wrap:nowrap; justify-content:center;
    }
    .search-wrap input[type="text"]{
      height:48px;
      padding:0 16px;
      width:min(720px, 92vw);
      border-radius:12px;
      border:1px solid var(--border);
      background:var(--input-bg);
      color:var(--input-text);
      font-size:16px; outline:none;
    }
    .search-wrap input[type="text"]::placeholder{color:#9aa3ad;}
    .search-wrap input[type="text"]:focus{
      box-shadow:0 0 0 3px rgba(52,199,89,.30);
      border-color:transparent;
    }

    .search-wrap button[type="submit"]{
      width:48px; height:48px;
      border-radius:12px;
      border:none; cursor:pointer; font-size:20px;
      display:inline-flex; align-items:center; justify-content:center;
      color:#fff; background:var(--accent);
    }
    .search-wrap button[type="submit"]:hover{filter:brightness(1.05);}

    @media (max-width:520px){
      .search-wrap{flex-wrap:wrap;}
      .search-wrap button[type="submit"]{width:100%;}
    }
  </style>
</head>
<body>
  <div class="center-container">
    <div class="brand" aria-label="Darkelf Browser home">
      <i class="bi bi-shield-lock"></i>
      <span style="color: var(--accent);">Darkelf Browser</span>
    </div>

    <div class="tagline">Post-Quantum • Private • Hardened</div>

    <form class="search-wrap" action="https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/" method="get" role="search" aria-label="Search DuckDuckGo">
      <input type="text" name="q" placeholder="Search DuckDuckGo" aria-label="Search query" />
      <button type="submit" aria-label="Search"><i class="bi bi-search"></i></button>
    </form>
  </div>
</body>
</html>
"""

        
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
        recon_menu = menu_bar.addMenu("Recon")
        self.add_recon_actions(recon_menu)
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
        geolocation_action = QAction("Block Geolocation", self, checkable=True)
        geolocation_action.setChecked(self.block_geolocation)  # Reflect actual state
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
        run_osint_action = QAction("Run OSINT Scan", self)
        run_osint_action.triggered.connect(self.launch_osint_scanner)  # ✅ must match your actual method name
        osint_menu.addAction(run_osint_action)

    def launch_osint_scanner(self):
        self.osint_window = QWidget()
        self.osint_window.setWindowTitle("Darkelf OSINT Scanner")
        self.osint_window.setGeometry(300, 200, 600, 500)

        layout = QVBoxLayout()

        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Enter email, username, phone, or .onion")

        self.scan_button = QPushButton("Run OSINT Scan")
        self.export_button = QPushButton("Export Results")
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)

        layout.addWidget(self.query_input)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.export_button)
        layout.addWidget(self.output_box)

        self.osint_window.setLayout(layout)
        self.scan_button.clicked.connect(self.run_osint_query)
        self.export_button.clicked.connect(self.export_results)

        self.last_result = None
        self.osint_window.show()

    def run_osint_query(self):
        query = self.query_input.text().strip()
        if not query:
            QMessageBox.warning(self.osint_window, "Missing Input", "Enter a query to scan.")
            return

        self.output_box.clear()
        self.output_box.append(f"[INFO] Running OSINT scan for: {query}\n")

        # Connect the signal once
        try:
            self.signals.osint_result_signal.disconnect()
        except Exception:
            pass
        self.signals.osint_result_signal.connect(self.display_osint_result)

        def threaded_task(query_copy):
            try:
                utils = DarkelfUtils()
                result = utils.osintscan(query_copy, use_tor=True, max_results=10)
                self.last_result = result
                self.signals.osint_result_signal.emit(result)
            except Exception as e:
                self.last_result = None
                self.signals.osint_result_signal.emit({"error": str(e)})

        threading.Thread(target=threaded_task, args=(query,), daemon=True).start()

    def export_results(self):
        if not self.last_result:
            QMessageBox.information(self.osint_window, "Nothing to export", "Run a scan first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self.osint_window,
            "Save OSINT Results",
            "osint_results.json",
            "JSON Files (*.json)"
        )
        if path:
            try:
                with open(path, "w") as f:
                    json.dump(self.last_result, f, indent=4)
                QMessageBox.information(self.osint_window, "Export Successful", f"Saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self.osint_window, "Export Failed", f"Error: {e}")

    def display_osint_result(self, result):
        if "error" in result:
            self.output_box.append(f"[ERROR] Scan failed: {result['error']}")
            return

        self.output_box.append("[✅] Scan complete.\n")
        for line in result.get("summary", []):
            self.output_box.append(str(line))

    def add_recon_actions(self, recon_menu):
        urls = [
            ("Ahmia", "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"),
            ("Archive Today", "http://archiveiya74codqgiixo33q62qlrqtkgmcitqx5u2oeqnmn5bpcbiyd.onion/"),
            ("Dark Fail", "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/"),
            ("Dread", "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/"),
            ("Keys OpenPGP", "http://zkaan2xfbuxia2wpf7ofnkbz6r5zdbbvxbunvp5g2iebopbfc4iqmbad.onion/"),
            ("Hidden Wiki", "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki/index.php/Main_Page"),
            ("Internet Archive", "https://archive.org/"),
            ("IntelX", "https://intelx.io/"),
            ("OnionLand", "https://onionland.io/"),
            ("OnionLinks", "http://jaz45aabn5vkemy4jkg4mi4syheisqn2wn2n4fsuitpccdackjwxplad.onion/"),
            ("Secure Drop", "http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion/"),
            ("Torbox Email", "http://torbox36ijlcevujx7mjb4oiusvwgvmue7jfn2cvutwa6kl6to3uyqad.onion/"),
            ("ZeroBin", "http://zerobinftagjpeeebbvyzjcqyjpmjvynj5qlexwyxe7l3vqejxnqv5qd.onion/")
        ]
        for name, url in urls:
            action = QAction(name, self)
            action.triggered.connect(lambda checked, u=url: self.open_url(u))
            recon_menu.addAction(action)
            
    def add_tools_actions(self, tools_menu):

        urls = [
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
        """Navigate back in the current tab."""
        current_webview = self.tab_widget.currentWidget()
        if hasattr(current_webview, "back"):
            current_webview.back()

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
            self.create_new_tab(f"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/?q={text}")

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
        self.block_geolocation = enabled
        self.settings.setValue("block_geolocation", enabled)

    def toggle_device_orientation(self, enabled):
        self.block_device_orientation = enabled
        self.settings.setValue("block_device_orientation", enabled)

    def toggle_media_devices(self, enabled):
        self.block_media_devices = enabled
        self.settings.setValue("block_media_devices", enabled)

    def closeEvent(self, event):
        """Secure shutdown with memory wipe, file deletion, and anti-forensics measures."""
        try:
            # Secure delete logs FIRST and disable logging
            if hasattr(self, 'log_path'):
                if os.path.isfile(self.log_path):
                    self.secure_delete(self.log_path)
                elif os.path.isdir(self.log_path):
                    self.secure_delete_directory(self.log_path)

            stealth_log_path = os.path.expanduser("~/.darkelf_log")
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

            # Disable logging after logs are deleted
            self.log_stealth = lambda *args, **kwargs: None

            self.check_forensic_environment()

            if hasattr(self, 'tor_manager') and callable(getattr(self.tor_manager, 'stop_tor', None)):
                self.tor_manager.stop_tor()

            if hasattr(self, 'encrypted_store'):
                self.encrypted_store.wipe_memory()

            self.save_settings()
            self.secure_clear_cache_and_history()

            if hasattr(self, 'download_manager') and hasattr(self.download_manager, 'timers'):
                for timer in self.download_manager.timers.values():
                    try:
                        timer.stop()
                    except Exception:
                        pass

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

            if hasattr(self, 'ram_path') and os.path.exists(self.ram_path):
                self.secure_delete_ram_disk_directory(self.ram_path)

            temp_subdir = os.path.join(tempfile.gettempdir(), "darkelf_temp")
            if os.path.exists(temp_subdir):
                self.secure_delete_directory(temp_subdir)

            for keyfile in ["private_key.pem", "ecdh_private_key.pem"]:
                if os.path.exists(keyfile):
                    self.secure_delete(keyfile)

            try:
                if hasattr(self, 'kyber_manager') and self.kyber_manager:
                    for attr in ['kyber_private_key', 'kyber_public_key']:
                        key = getattr(self.kyber_manager, attr, None)
                        if isinstance(key, bytearray):
                            for i in range(len(key)):
                                key[i] = 0
                        setattr(self.kyber_manager, attr, None)
                    self.kyber_manager.kem = None

                    for kyber_file in ["kyber_private.key", "kyber_public.key"]:
                        if os.path.exists(kyber_file):
                            self.secure_delete(kyber_file)
            except Exception:
                pass

            if hasattr(self, 'phishing_detector'):
                try:
                    self.phishing_detector.flush_logs_on_exit()
                except Exception:
                    pass

        except Exception:
            pass
        finally:
            super().closeEvent(event)

    def secure_delete(self, file_path):
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
            pass  # Avoid any logging


    def secure_delete_directory(self, directory_path):
        try:
            if not os.path.exists(directory_path):
                return
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for name in files:
                    self.secure_delete(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
            os.rmdir(directory_path)
        except Exception:
            pass

    def secure_delete_temp_memory_file(self, file_path):
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

    def secure_delete_ram_disk_directory(self, ram_dir_path):
        try:
            if not os.path.exists(ram_dir_path):
                return
            for root, dirs, files in os.walk(ram_dir_path, topdown=False):
                for name in files:
                    self.secure_delete_temp_memory_file(os.path.join(root, name))
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
            os.rmdir(ram_dir_path)
        except Exception:
            pass
            
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

def start_tls_monitor():
    monitored_sites = [
        "check.torproject.org",
        "example.com"
    ]
    monitor = DarkelfTLSMonitorJA3(monitored_sites, interval=300)
    monitor.start()  # Already runs in a background thread

    print("[DarkelfAI] ✅ TLS Monitor started in background thread.")

def main():
    os.environ["QT_SCALE_FACTOR_ROUNDING_POLICY"] = "PassThrough"
    # Apply correct High DPI scaling

    # Set Chromium flags to disable WebRTC, WebGL, Canvas API, GPU, etc.
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        "--disable-webrtc "
        "--disable-http2 "
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
        "--disable-breakpad "
        "--disable-blink-features=ClientHints,UserAgentClientHint,UserAgentClient "
        "--disable-features=UserAgentClientHint,ClientHints,UserAgentReduction "
        "--disable-features=NetworkService,PrefetchPrivacyChanges "
        "--force-major-version-to-minor "  # Sends random or shifted UA strings
        "--user-agent=\"Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0 "
        "--disable-http=cache "
        "--cipher-suite-blacklist=0x0004,0x0005,0x002f,0x0035 "
        '--proxy-server="http://127.0.0.1:8080"'
        "--disk-cache-dir=/dev/null"
    )

    QCoreApplication.setAttribute(Qt.AA_ShareOpenGLContexts)

    # Create the application only ONCE
    app = QApplication.instance() or QApplication(sys.argv)
    apply_darkelf_menu_theme()

    # Start the kernel monitor
    monitor = DarkelfKernelMonitor(parent_app=app)
    monitor.start()
    app.aboutToQuit.connect(monitor.shutdown_darkelf)

    # Start the main browser
    darkelf_browser = Darkelf()
    darkelf_browser.show()

    # Start TLS monitor after Tor bootstrap delay
    QTimer.singleShot(20000, start_tls_monitor)

    # Optionally: Launch the OSINT GUI in parallel (if desired)

    # Start the event loop
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
