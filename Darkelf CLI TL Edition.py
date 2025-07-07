# Darkelf CLI Browser v3.0 – Secure, Privacy-Focused Command-Line Web Browser
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
from urllib.parse import quote_plus
from collections import deque
from typing import Optional, List, Dict
from datetime import datetime
import psutil
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.align import Align
from rich.table import Table
from urllib.parse import quote_plus, unquote, parse_qs, urlparse
from bs4 import BeautifulSoup
from oqs import KeyEncapsulation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
from requests import Response
from dotenv import load_dotenv
import requests

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

load_dotenv()  # Loads HIBP_API_KEY from .env if present

LAST_REQUEST_TIME = 0
REQUEST_INTERVAL = 1.6  # seconds (adjust based on API limits)

def safe_get(session, url, **kwargs) -> Response:
    global LAST_REQUEST_TIME
    elapsed = time.time() - LAST_REQUEST_TIME
    if elapsed < REQUEST_INTERVAL:
        time.sleep(REQUEST_INTERVAL - elapsed)
    LAST_REQUEST_TIME = time.time()
    return session.get(url, **kwargs)

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
        self.gravatar = False
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

    def check_rdap(self):
        try:
            res = self.session.get(f"https://rdap.org/domain/{self.domain}", timeout=10)
            if res.ok:
                data = res.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        self.creation_date = event.get("eventDate", "Unknown")
        except:
            self.creation_date = "Unknown"

    def check_breach(self):
        try:
            api_key = os.getenv("HIBP_API_KEY")
            if not api_key:
                self.console.print("[red]❌ HIBP API key not set. Please set HIBP_API_KEY in your environment or .env file.[/red]")
                self.breached = "Unknown"
                return

            headers = {
                "hibp-api-key": api_key,
                "user-agent": "DarkelfCLI-TL-OSINT/1.0"
            }

            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}?truncateResponse=true"
            res = self.session.get(url, headers=headers, timeout=10)

            if res.status_code == 200:
                self.breached = "Yes"
                self.breach_url = f"https://haveibeenpwned.com/account/{self.email}"
            elif res.status_code == 404:
                self.breached = "No"
            else:
                self.breached = "Unknown"

            time.sleep(1.6)  # Respect free-tier API rate limit
        except Exception as e:
            self.console.print(f"[red]❌ Error checking HIBP breach: {e}[/red]")
            self.breached = "Unknown"

    def check_gravatar(self):
        h = hashlib.md5(self.email.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{h}?d=404"
        try:
            self.gravatar = self.session.get(url, timeout=5).status_code == 200
        except:
            self.gravatar = False

    def calculate_score(self):
        self.score = 0
        self.score += 3 if self.disposable else 0
        self.score += 2 if not self.mx_records else 0
        self.score += 3 if self.breached == "Yes" else 0
        self.score += 1 if self.creation_date == "Unknown" else 0
        self.score += 1 if not self.gravatar else 0

    def threat_label(self):
        if self.score >= 7:
            return "[red]HIGH[/red]"
        elif self.score >= 4:
            return "[yellow]MODERATE[/yellow]"
        else:
            return "[green]LOW[/green]"

    def analyze(self):
        if not self.is_valid_email():
            self.console.print(f"[red]❌ Invalid email: {self.email}[/red]")
            return

        self.fetch_mx_records()
        self.fetch_txt_records()
        self.check_disposable()
        self.check_rdap()
        self.check_breach()
        self.check_gravatar()
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
        table.add_row("Gravatar Profile", "👤 Yes" if self.gravatar else "🙈 None")
        table.add_row("Leaked in Breach", self.breached)
        if self.breach_url:
            table.add_row("Leak Details", self.breach_url)
        table.add_row("TXT Records (SPF/DKIM)", "\n".join(self.txt_records[:3]) if self.txt_records else "❌ None")
        table.add_row("Google Search", f"https://www.google.com/search?q=\"{self.email}\"")
        table.add_row("GitHub Search", f"https://github.com/search?q={self.email}")
        table.add_row("Pastebin Search", f"https://www.google.com/search?q={self.email}+site:pastebin.com")
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

class IPLookup:
    def __init__(self, use_tor=False, timeout=10):
        self.console = Console()
        self.timeout = timeout
        self.use_tor = use_tor
        self.api_url_primary = "http://ip-api.com/json/{}"
        self.api_url_fallback = "https://ipwho.is/{}"
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
        try:
            r = requests.get("https://api.ipify.org", timeout=self.timeout, proxies=self.proxies)
            return r.text.strip()
        except Exception as e:
            self.console.print(f"[red]Failed to fetch public IP: {e}[/red]")
            return None

    def lookup(self, ip=""):
        target_ip = ip.strip() if ip else self.get_public_ip()
        if not target_ip:
            return

        if not self.is_valid_ip(target_ip):
            self.console.print(f"[red]Invalid IP format: {target_ip}[/red]")
            return

        # Try primary API
        try:
            r = requests.get(self.api_url_primary.format(target_ip), timeout=self.timeout, proxies=self.proxies)
            if r.status_code == 429:
                self.console.print("[yellow]Rate limit exceeded on ip-api.com. Trying fallback...[/yellow]")
                return self._lookup_fallback(target_ip)

            data = r.json()
            if data.get("status") != "success":
                self.console.print(f"[yellow]Primary API failed: {data.get('message', 'unknown error')}[/yellow]")
                return self._lookup_fallback(target_ip)

            self._print_table(data, source="ip-api.com")
        except Exception as e:
            self.console.print(f"[yellow]Primary API error: {e} — trying fallback...[/yellow]")
            self._lookup_fallback(target_ip)

    def _lookup_fallback(self, ip):
        try:
            r = requests.get(self.api_url_fallback.format(ip), timeout=self.timeout, proxies=self.proxies)
            data = r.json()
            if not data.get("success", False):
                self.console.print(f"[red]Fallback lookup failed for {ip}: {data.get('message', 'unknown error')}[/red]")
                return

            self._print_table(data, source="ipwho.is")
        except Exception as e:
            self.console.print(f"[red]Fallback API error: {e}[/red]")

    def _print_table(self, data, source="ip-api.com"):
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
        
# --- SecureBuffer: RAM-locked buffer for sensitive data ---
class SecureBuffer:
    """
    RAM-locked buffer using mmap + mlock to prevent swapping.
    Use for sensitive in-memory data like session tokens, keys, etc.
    """
    def __init__(self, size=4096):
        self.size = size
        self.buffer = mmap.mmap(-1, self.size)
        libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else "libc.dylib")
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
        ctypes.memset(
            ctypes.addressof(ctypes.c_char.from_buffer(self.buffer)),
            0,
            self.size
        )

    def close(self):
        self.zero()
        self.buffer.close()

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
               # "obfs4 185.177.207.158:8443 B9E39FA01A5C72F0774A840F91BC72C2860954E5 cert=WA1P+AQj7sAZV9terWaYV6ZmhBUcj89Ev8ropu/IED4OAtqFm7AdPHB168BPoW3RrN0NfA iat-mode=0",
                "obfs4 91.227.77.152:465 42C5E354B0B9028667CFAB9705298F8C3623A4FB cert=JKS4que9Waw8PyJ0YRmx3QrSxv/YauS7HfxzmR51rCJ/M9jCKscJu7SOuz//dmzGJiMXdw iat-mode=2"
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

def duckduckgo_search(query):
    import html
    time.sleep(random.uniform(2, 5))

    headers = {
        'User-Agent': 'Mozilla/5.0',
    }

    try:
        session = requests.Session()
        session.proxies = {
            'http': get_tor_proxy(),
            'https': get_tor_proxy(),
        }
        url = DUCKDUCKGO_LITE + f"?q={quote_plus(query)}"
        response = session.get(url, headers=headers, timeout=20)

        soup = BeautifulSoup(response.text, 'html.parser')
        results = []

        # DuckDuckGo Lite format: <a rel="nofollow" class="result-link" href="...">Title</a>
        for a in soup.find_all("a", href=True):
            if "result" in a.get("class", []) or "nofollow" in a.get("rel", []):
                href = html.unescape(a["href"])
                text = a.get_text(strip=True)
                if href.startswith(("http://", "https://")) and text:
                    results.append((text, href))

        if not results:
            debug_path = f"/tmp/ddg_debug_{query.replace(' ', '_')}.html"
            with open(debug_path, "w", encoding="utf-8") as f:
                f.write(response.text)
            console.print(f"[Darkelf] Parsing failed for '{query}'. Saved raw HTML to {debug_path}")

        return results

    except Exception as e:
        console.print(f"[Darkelf] DuckDuckGo search error for '{query}': {e}")
        return []

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
    import base64, os

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

class DarkelfMessenger:
    def __init__(self, kem_algo="Kyber768"):
        self.kem_algo = kem_algo

    def generate_keys(self, pubkey_path="my_pubkey.bin", privkey_path="my_privkey.bin"):
        kem = oqs.KeyEncapsulation(self.kem_algo)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        with open(pubkey_path, "wb") as f:
            f.write(public_key)
        with open(privkey_path, "wb") as f:
            f.write(private_key)

        logging.info("🔐 Keys saved: %s, %s", pubkey_path, privkey_path)

    def send_message(self, recipient_pubkey_path, message_text, output_path="msg.dat"):
        if not os.path.exists(recipient_pubkey_path):
            logging.error("Missing recipient pubkey: %s", recipient_pubkey_path)
            return 1
        if not message_text.strip():
            logging.error("Message cannot be empty.")
            return 1

        kem = oqs.KeyEncapsulation(self.kem_algo)
        with open(recipient_pubkey_path, "rb") as f:
            pubkey = f.read()

        ciphertext, shared_secret = kem.encap_secret(pubkey)
        key = base64.urlsafe_b64encode(shared_secret[:32])
        token = Fernet(key).encrypt(message_text.encode())

        # Base64 encode the ciphertext and token to avoid delimiter collision
        ct_b64 = base64.b64encode(ciphertext)
        token_b64 = base64.b64encode(token)

        with open(output_path, "wb") as f:
            f.write(b"v1||" + ct_b64 + b"||" + token_b64)

        logging.info("📤 Message saved to: %s", output_path)
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

        if not content.startswith(b"v1||"):
            logging.error("Message format invalid or corrupted.")
            return 1

        try:
            _, ct_b64, token_b64 = content.split(b"||", 2)
            ciphertext = base64.b64decode(ct_b64)
            token = base64.b64decode(token_b64)

            with open(privkey_path, "rb") as f:
                privkey = f.read()

            # Pass secret_key=privkey to the constructor
            kem = oqs.KeyEncapsulation(self.kem_algo, secret_key=privkey)
            shared_secret = kem.decap_secret(ciphertext)

            key = base64.urlsafe_b64encode(shared_secret[:32])
            message = Fernet(key).decrypt(token)
            console.print("📥 Message decrypted:", message.decode())
            return 0
        except Exception as e:
            logging.error("Decryption failed: %s", e)
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
    console.print("[bold cyan]Darkelf CLI Browser — Command Reference[/bold cyan]\n")
    console.print("Select by and type full command:\n")

    categories = [
        ("General OSINT and Searching", [
            ("search <keywords>",     "Search DuckDuckGo (onion)"),
            ("debug <keywords>",      "Search and show full debug info"),
            ("osintscan <term|url>",  "Fetch a URL & extract emails, phones, etc."),
            ("findonions <keywords>", "Discover .onion services by keywords")
        ]),

        ("Security and Privacy Tools", [
            ("stealth",               "Toggle extra stealth options"),
            ("genkeys",               "Generate post-quantum keys"),
            ("sendmsg",               "Encrypt & send a message"),
            ("recvmsg",               "Decrypt & show received message"),
            ("tornew",                "Request new Tor circuit (if supported)"),
            ("checkip",               "Verify you're routed through Tor"),
            ("iplookup <ip>",         "Lookup IP address info"),
            ("tlsstatus",             "Show recent TLS Monitor activity"),
            ("beacon <.onion>",       "Check if a .onion site is reachable via Tor"),
            ("dnsleak",               "Run a dnsleak test"),
            ("analyze! <url>",        "Analyze a URL for threat signals"),
            ("open <url>",            "Open and fetch a full URL (tracker-safe)"),
            ("emailintel",            "Lookup Email Information")
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

console = Console()

class Page:
    def __init__(self, url):
        self.url = url
        self.lines = []
        self.links = []
        self.error = None
        self.fetch()

    def fetch(self):
        try:
            html, _ = fetch_with_requests(self.url, debug=False)
            soup = BeautifulSoup(html, 'html.parser')

            # Remove scripts/styles/noscript
            for s in soup(['script', 'style', 'noscript']):
                s.decompose()

            main_content = None
            # Special case: Wikipedia homepage (central-featured) or article (mw-parser-output)
            if "wikipedia.org" in self.url:
                main = soup.find("div", class_="central-featured")
                if main:
                    main_content = main.get_text(separator='\n')
                else:
                    main = soup.find("div", class_="mw-parser-output")
                    if main:
                        main_content = main.get_text(separator='\n')
            # Fallback: all <p> tags
            if not main_content:
                ps = soup.find_all("p")
                if ps:
                    main_content = "\n".join(p.get_text(strip=True) for p in ps if p.get_text(strip=True))
            # Fallback: all visible text
            if not main_content or not main_content.strip():
                main_content = soup.get_text(separator='\n')

            # Clean up lines: remove empties/whitespace only
            self.lines = [l.strip() for l in main_content.splitlines() if l.strip()]
            if not self.lines:
                self.lines = ["[dim]No content available.[/dim]"]

            # Extract links as before
            self.links = [
                (i + 1, a.get_text(strip=True), a.get('href'))
                for i, a in enumerate(soup.find_all('a'))
            ]

            # Annotate first occurrence of link text in the output
            for i, (num, label, _) in enumerate(self.links):
                if label:
                    annotated = f"[{num}] {label}"
                    for idx, line in enumerate(self.lines):
                        if label in line:
                            self.lines[idx] = line.replace(label, annotated, 1)
                            break

        except Exception as e:
            self.error = str(e)

class DarkelfCLIBrowser:
    def __init__(self):
        self.history = []
        self.forward_stack = []
        self.current_page = None
        self.scroll = 0

        term_height = shutil.get_terminal_size((80, 24)).lines
        # Leave 8 lines for header/footer
        self.height = max(12, term_height - 2)

    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def render(self):
        self.clear()

        if not self.current_page:
            console.print(Panel("[blue]No page loaded.[/blue]", title="Darkelf CLI Browser", border_style="blue"))
            return

        # Header
        url_display = self.current_page.url
        if len(url_display) > 100:
            url_display = url_display[:96] + "..."

        header = Panel(
            f"[bold cyan]Darkelf CLI Browser[/bold cyan]\n[blue underline]{url_display}[/blue underline]",
            border_style="cyan",
            padding=(1, 2),
            expand=True
        )
        console.print(header)

        # Error panel
        if self.current_page.error:
            console.print(Panel(f"[red]Error: {self.current_page.error}[/blue]", title="Page Error", border_style="blue"))
            return

        # Page content
        visible_lines = self.current_page.lines[self.scroll:self.scroll + self.height]
        if visible_lines:
            page_text = "\n".join(visible_lines)
            content = Text(page_text, style="white")
        else:
            content = Text("[dim]No content available.[/dim]", style="dim")

        console.print(Panel(content, title="📰 Page Content", border_style="white", expand=True))

        # End-of-article marker
        end_index = min(self.scroll + self.height, len(self.current_page.lines))
        if end_index >= len(self.current_page.lines):
            console.print("[dim]-- End of article --[/dim]")

        # Footer
        footer = Text()
        footer.append("↑/↓", style="bold blue")
        footer.append(": Scroll  |  ")
        footer.append("o", style="bold blue")
        footer.append(": Open Link  |  ")
        footer.append("u", style="bold blue")
        footer.append(": URL  |  ")
        footer.append("b", style="bold blue")
        footer.append(": Back  |  ")
        footer.append("q", style="bold blue")
        footer.append(": Quit")

        console.print(Rule(style="grey37"))
        console.print(Align.center(footer))
    

    def visit(self, url):
        if self.current_page:
            self.history.append(self.current_page.url)

        self.scroll = 0
        self.forward_stack.clear()
        self.current_page = Page(url)
        self.render()

    def open_link(self, number):
        try:
            link = dict((num, href) for num, _, href in self.current_page.links)[number]
            if link:
                if not link.startswith("http"):
                    from urllib.parse import urljoin
                    link = urljoin(self.current_page.url, link)
                self.visit(link)
        except:
            pass
            
    def run(self):
        self.visit("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite")
        while True:
            key = get_key()
            if key in ('q', 'Q'):
                break
            elif key in ('\x1b[A', 'w'):
                if self.scroll > 0:
                    self.scroll -= 1
                    self.render()
            elif key in ('\x1b[B', 's'):
                if self.scroll + self.height < len(self.current_page.lines):
                    self.scroll += 1
                    self.render()
            elif key == 'u':
                console.print("\nEnter URL: ", end="")
                console.print("[bold green]>>[/bold green] ", end="")
                url = input().strip()
                if not url:
                    continue
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url
                self.visit(url)
            elif key == 'b':
                if self.history:
                    url = self.history.pop()
                    self.forward_stack.append(self.current_page.url)
                    self.visit(url)
            elif key == 'o':
                try:
                    console.print("[bold green]>>[/bold green] ", end="")
                    user_input = input()
                    num = int(user_input)
                    self.open_link(num)
                except:
                    pass

def interactive_prompt():

    buffer = []
    history = deque([], maxlen=100)
    cursor = 0

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        console.print("[bold green]>>[/bold green] ", end="", soft_wrap=True)
        sys.stdout.flush()

        while True:
            key = sys.stdin.read(1)
            if key == '\x1b':
                key += sys.stdin.read(2)

            if key == '\r':  # Enter
                print()
                cmd = ''.join(buffer)
                history.append(cmd)
                return cmd

            elif key == '\x7f':  # Backspace
                if buffer:
                    buffer.pop()
                    cursor -= 1
                    print('\b \b', end='', flush=True)

            elif key == '\x1b[A':  # Up (history stub)
                pass
            elif key == '\x1b[B':  # Down
                pass
            elif key == '\x1b[C':  # Right
                pass
            elif key == '\x1b[D':  # Left
                pass
            else:
                buffer.append(key)
                print(key, end='', flush=True)
                cursor += 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        
class DarkelfUtils:
    def __init__(self):
        self.socks_proxy = "socks5h://127.0.0.1:9052"

    def beacon_onion_service(self, onion_url):
        if not onion_url.startswith("http"):
            onion_url = "http://" + onion_url
        try:
            r = requests.get(
                onion_url,
                headers={"User-Agent": "Mozilla/5.0"},
                proxies={"http": self.socks_proxy, "https": self.socks_proxy},
                timeout=15
            )
            if r.status_code < 400:
                console.print(f"[🛰] Onion service is live: {onion_url} (Status {r.status_code})")
            else:
                console.print(f"[⚠] Onion responded with status {r.status_code}")
        except Exception as e:
            console.print(f"[🚫] Failed to reach onion service: {e}")

# Assume console, USER_AGENTS, DUCKDUCKGO_LITE, get_tor_proxy, fetch_with_requests are defined globally

def run_phoneinfoga_scan(number: str):
    console.print(f"[cyan]📾 Running PhoneInfoga on:[/cyan] [bold]{number}[/bold]")
    try:
        result = subprocess.run(
            ["phoneinfoga", "scan", "-n", number],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            console.print(f"[green]✔ PhoneInfoga result:[/green]\n{result.stdout}")
        else:
            console.print(f"[red]✖ PhoneInfoga failed:[/red] {result.stderr}")
    except Exception as e:
        console.print(f"[red]⚠ Error running PhoneInfoga:[/red] {e}")

def run_theharvester_scan(target: str):
    console.print(f"[cyan]📧 Running theHarvester on:[/cyan] [bold]{target}[/bold]")
    try:
        result = subprocess.run(
            ["theHarvester", "-d", target, "-b", "all"],
            capture_output=True, text=True, timeout=90
        )
        if result.returncode == 0:
            console.print(f"[green]✔ theHarvester result:[/green]\n{result.stdout}")
        else:
            console.print(f"[red]✖ theHarvester failed:[/red] {result.stderr}")
    except Exception as e:
        console.print(f"[red]⚠ Error running theHarvester:[/red] {e}")

def run_sherlock_scan(username: str):
    console.print(f"[cyan]🕵️ Running Sherlock on:[/cyan] [bold]{username}[/bold]")
    try:
        result = subprocess.run(
            ["sherlock", username],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            console.print(f"[green]✔ Sherlock result:[/green]\n{result.stdout}")
        else:
            console.print(f"[red]✖ Sherlock failed:[/red] {result.stderr}")
    except Exception as e:
        console.print(f"[red]⚠ Error running Sherlock:[/red] {e}")

def osintscan(query):
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    proxies = {'http': get_tor_proxy(), 'https': get_tor_proxy()}
    url = DUCKDUCKGO_LITE + f"?q={quote_plus(query)}"

    is_email = bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", query))
    is_phone = bool(re.match(r"^\+?\d[\d\s\-().]{6,}$", query))
    is_username = bool(re.match(r"^@?[a-zA-Z0-9_.-]{3,32}$", query)) and not is_email and not is_phone

    username = query.lstrip('@') if is_username else None
    phone = re.sub(r"[^\d]", "", query) if is_phone else None
    email = query if is_email else None

    direct_links = []

    if is_username:
        run_sherlock_scan(username)
        platforms = {
            "Twitter": f"https://twitter.com/{username}",
            "GitHub": f"https://github.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "Facebook": f"https://facebook.com/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "LinkedIn Search": f"https://www.linkedin.com/search/results/all/?keywords={username}",
            "Pinterest": f"https://www.pinterest.com/{username}/",
        }
        direct_links = [(site, link) for site, link in platforms.items()]

    elif is_email:
        domain_match = re.search(r"@(.+)", email)
        if domain_match:
            run_theharvester_scan(domain_match.group(1))
        platforms = {
            "Google Search": f"https://www.google.com/search?q={quote_plus(email)}",
            "Hunter.io": f"https://hunter.io/search/{quote_plus(email)}",
            "LinkedIn Search": f"https://www.linkedin.com/search/results/all/?keywords={quote_plus(email)}",
            "Twitter Search": f"https://twitter.com/search?q={quote_plus(email)}",
            "Facebook Search": f"https://www.facebook.com/search/top/?q={quote_plus(email)}",
            "Skype Search": f"https://www.skype.com/en/search/?q={quote_plus(email)}",
            "DuckDuckGo": f"https://duckduckgo.com/?q={quote_plus(email)}"
        }
        direct_links = [(site, link) for site, link in platforms.items()]

    elif is_phone:
        run_phoneinfoga_scan(query)
        platforms = {
            "Google Search": f"https://www.google.com/search?q={quote_plus(query)}",
            "Sync.me": f"https://sync.me/search/?number={phone}",
            "TrueCaller": f"https://www.truecaller.com/search/{phone[:2]}/{phone}",
            "Facebook Search": f"https://www.facebook.com/search/top/?q={quote_plus(query)}",
            "Twitter Search": f"https://twitter.com/search?q={quote_plus(query)}",
            "DuckDuckGo": f"https://duckduckgo.com/?q={quote_plus(query)}"
        }
        direct_links = [(site, link) for site, link in platforms.items()]

    if direct_links:
        console.print(f"\n[cyan]🔗 Direct OSINT links for query:[/cyan] [bold]{query}[/bold]")
        for site, link in direct_links:
            console.print(f"   [magenta]{site}:[/magenta] [green]{link}[/green]")

    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=20)
        soup = BeautifulSoup(response.text, 'html.parser')
        results = []
        for a in soup.find_all("a", href=True):
            href = html.unescape(a["href"])
            text = a.get_text(strip=True)
            if href.startswith("http"):
                results.append((text, href))

        if not results:
            url_matches = set(re.findall(r'https?://[^\s"\'<>]+', response.text))
            if url_matches:
                console.print(f"[yellow]🔗 URLs found by regex fallback:[/yellow]")
                for link in url_matches:
                    console.print(f"   [green]{link}[/green]")
                results = [("", link) for link in url_matches]
            else:
                console.print("[red]No URLs found in DuckDuckGo results.[/red]")
        else:
            console.print(f"[yellow]🔗 URLs found in DuckDuckGo results:[/yellow]")
            for txt, link in results:
                console.print(f"   [green]{link}[/green] ({txt})")

        scan_urls = [u for _, u in results]
        if direct_links:
            scan_urls += [link for site, link in direct_links if not any(s in site.lower() for s in ["search", "google", "duckduckgo"])]

        all_data = {
            "emails": set(),
            "phone_numbers": set(),
            "social_handles": set(),
            "crypto_wallets": set(),
            "urls": set(),
        }

        for u in scan_urls:
            all_data["urls"].add(u)

        for u in scan_urls[:5]:
            console.print(f"[blue]→ Scanning:[/blue] {u}")
            try:
                html_content, _ = fetch_with_requests(u)
                osint_data = extract_osint_data(html_content, source_url=u)
                for key in all_data:
                    all_data[key].update(osint_data.get(key, []))
            except Exception as e:
                console.print(f"[red]  Failed to fetch or parse {u}: {e}[/red]")

        console.print("\n[yellow bold]📊 OSINT Summary:[/yellow bold]")
        for key, values in all_data.items():
            if values:
                console.print(f"[cyan]{key}[/cyan]:")
                for v in sorted(values):
                    console.print(f"   [green]- {v}[/green]")
            else:
                console.print(f"[dim]{key}: (none found)[/dim]")

    except Exception as e:
        console.print(f"[red]OSINT scan failed: {e}[/red]")

def extract_osint_data(html_content: str, source_url: str = "(unknown)") -> dict:
    data = {
        "emails": list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html_content))),
        "phone_numbers": list(set(re.findall(r"\b\+?\d{1,4}?[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", html_content))),
        "social_handles": list(set(re.findall(r"(?:@\w{2,}|(?:twitter|facebook|instagram)\.com/\w+)", html_content))),
        "crypto_wallets": list(set(re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", html_content))),
        "urls": list(set(re.findall(r"https?://[^\s\"'>]+", html_content))),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_url": source_url
    }
    return data

def save_osint_data_to_json(data: dict, output_path: str = "osint_scrape_output.json"):
    try:
        with open(output_path, "r") as infile:
            existing = json.load(infile)
    except (FileNotFoundError, json.JSONDecodeError):
        existing = []

    existing.append(data)

    with open(output_path, "w") as outfile:
        json.dump(existing, outfile, indent=4)

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

            # inside the REPL command checks
            elif cmd.startswith("beacon "):
                onion = cmd.split(" ", 1)[1]
                utils.beacon_onion_service(onion)
                print()

            elif cmd.startswith("iplookup"):
                parts = cmd.split()
                ip = parts[1] if len(parts) > 1 else ""
                IPLookup(use_tor=True).lookup(ip)
                print()

            elif cmd == "dnsleak":
                check_dns_leak()
                print()
                
            elif cmd.startswith("analyze! "):  # exclamation = force
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
                EmailIntelPro(target, session=get_tor_session()).analyze()

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
                DarkelfCLIBrowser().run()
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
