# Darkelf CLI Browser v3.0 – ML-KEM Encrypted, Privacy-Focused Terminal Browser  
# Copyright (C) 2025 Dr. Kevin Moore  
#
# SPDX-License-Identifier: LGPL-3.0-or-later  
#
# This software is a command-line based secure browser focused on privacy and anonymity,  
# incorporating post-quantum ML-KEM encryption (via liboqs) and Tor integration for encrypted  
# traffic routing.  
#
# LICENSE:  
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU Lesser General Public License as published by  
# the Free Software Foundation, either version 3 of the License, or  
# (at your option) any later version.  
#
# This software is distributed in the hope that it will be useful,  
# but WITHOUT ANY WARRANTY; without even the implied warranty of  
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  
# GNU Lesser General Public License for more details.  
#
# You should have received a copy of the GNU Lesser General Public License  
# along with this program. If not, see <https://www.gnu.org/licenses/>.  
#
# EXPORT COMPLIANCE NOTICE:  
# This software contains cryptographic source code, specifically implementing  
# post-quantum ML-KEM key encapsulation mechanisms. It is made publicly available  
# under License Exception TSU pursuant to 15 CFR §740.13(e) of the  
# U.S. Export Administration Regulations (EAR).  
#
# A notification has been submitted to the U.S. Bureau of Industry and Security (BIS)  
# and the National Security Agency (NSA) as required.  
#
# This software is intended strictly for lawful academic, research, educational,  
# and privacy-preserving use in non-restricted jurisdictions.  
#
# PROHIBITED DESTINATIONS:  
# This software may not be exported, re-exported, or transferred to:  
# - Countries or territories subject to U.S. embargoes or comprehensive sanctions,  
#   including those listed in Country Group E:1 or E:2.  
# - Individuals or entities on the Denied Persons List, Entity List,  
#   Specially Designated Nationals (SDN) List, or other restricted parties lists.  
#
# END-USE RESTRICTIONS:  
# This software may not be used for the development, production, or deployment of  
# weapons of mass destruction (WMD), including nuclear, biological, or chemical weapons,  
# or missile delivery systems, as defined in Part 744 of the EAR.  
#
# By downloading, using, or distributing this software, you agree to comply with  
# all applicable U.S. export control laws and regulations.  
#
# This CLI-only browser does not include a GUI and does not ship any compiled binaries.  
# It is published under the LGPL v3.0 license and was authored by Dr. Kevin Moore in 2025.  

# PLEASE READ!
# These packages are required for install through terminal use Pip and Python3.11
# This Edition is full of Tor, Stealth, Anti Forensics use in Terminal - No Gui
#requests
#beautifulsoup4
#oqs-python
#cryptography
#stem
#pycryptodome

import os
import time
import random
import base64
import hashlib
import threading
import shutil
import socket
from urllib.parse import quote_plus, unquote, parse_qs, urlparse
from bs4 import BeautifulSoup
from oqs import KeyEncapsulation
from cryptography.fernet import Fernet
import requests

# --- Tor integration via Stem ---
import stem.process
from stem.control import Controller
from stem import process as stem_process

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
                print(f"[Darkelf] Tor is running on SOCKS:{self.socks_port}, CONTROL:{self.control_port}, DNS:{self.dns_port}")

    def start_tor(self):
        try:
            if self.tor_process:
                print("Tor is already running.")
                return

            tor_path = shutil.which("tor")
            obfs4_path = shutil.which("obfs4proxy")

            if not tor_path or not os.path.exists(tor_path):
                print("Tor not found. Please install it using:\n\n  brew install tor\nor\n  sudo apt install tor")
                return

            if not obfs4_path or not os.path.exists(obfs4_path):
                print("obfs4proxy not found. Please install it using:\n\n  brew install obfs4proxy\nor\n  sudo apt install obfs4proxy")
                return

            bridges = [
                "obfs4 185.177.207.158:8443 B9E39FA01A5C72F0774A840F91BC72C2860954E5 cert=WA1P+AQj7sAZV9terWaYV6ZmhBUcj89Ev8ropu/IED4OAtqFm7AdPHB168BPoW3RrN0NfA iat-mode=0",
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
                    init_msg_handler=lambda line: print("[tor]", line)
                )
            except Exception as bridge_error:
                print("[Darkelf] Bridge connection failed:", bridge_error)

                if not getattr(self, "allow_direct_fallback", True):
                    print("Bridge connection failed and direct fallback is disabled.")
                    return  # Stop here if fallback not allowed

                print("[Darkelf] Bridge connection failed. Trying direct Tor connection...")
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
            self.controller = Controller.from_port(port=self.control_port)
            cookie_path = os.path.join(tor_config['DataDirectory'], 'control_auth_cookie')
            with open(cookie_path, 'rb') as f:
                cookie = f.read()
            self.controller.authenticate(password=None, cookie=cookie)
            print("[Darkelf] Tor authenticated via cookie.")

        except OSError as e:
            print(f"Failed to start Tor: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def is_tor_running(self):
        try:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                return True
        except Exception as e:
            print(f"Tor is not running: {e}")
            return False

    def stop_tor(self):
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process = None
            print("Tor stopped.")

    def close(self):
        self.stop_tor()


def get_tor_proxy():
    # Use the Tor SOCKS port started by TorManagerCLI (default 9052)
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

def get_fernet_key():
    if not os.path.exists("logkey.bin"):
        key = Fernet.generate_key()
        with open("logkey.bin", "wb") as f:
            f.write(key)
        return key
    with open("logkey.bin", "rb") as f:
        return f.read()

class DarkelfMessenger:
    def __init__(self):
        self.kem_algo = "ML-KEM-768"

    def generate_keys(self):
        kem = KeyEncapsulation(self.kem_algo)
        pub = kem.generate_keypair()
        with open("my_pubkey.bin", "wb") as f:
            f.write(pub)
        with open("my_privkey.bin", "wb") as f:
            f.write(kem.export_secret_key())
        print("🔐 Keys created")

    def send_message(self, recipient_pubkey_path, message_text, output_path="msg.dat"):
        kem = KeyEncapsulation(self.kem_algo)
        with open(recipient_pubkey_path, "rb") as f:
            pubkey = f.read()
        ciphertext, shared_secret = kem.encap_secret(pubkey)
        key = base64.urlsafe_b64encode(shared_secret[:32])
        token = Fernet(key).encrypt(message_text.encode())
        with open(output_path, "wb") as f:
            f.write(ciphertext + b'||' + token)
        print("📤 Message encrypted")

    def receive_message(self, privkey_path="my_privkey.bin", msg_path="msg.dat"):
        kem = KeyEncapsulation(self.kem_algo)
        with open(privkey_path, "rb") as f:
            kem.import_secret_key(f.read())
        with open(msg_path, "rb") as f:
            ciphertext, token = f.read().split(b'||')
        shared_secret = kem.decap_secret(ciphertext)
        key = base64.urlsafe_b64encode(shared_secret[:32])
        message = Fernet(key).decrypt(token)
        print("📥 Message decrypted:", message.decode())

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
            print("\n[DEBUG] Request URL:", url)
            print("[DEBUG] Request Headers:", headers)
            print("[DEBUG] Response Status:", resp.status_code)
            print("[DEBUG] Response Headers:", dict(resp.headers))
            print("[DEBUG] Raw HTML preview:\n", resp.text[:2000], "\n[END DEBUG]\n")
        return resp.text, headers
    except Exception as e:
        if debug:
            print(f"[DEBUG] Exception during fetch: {e}")
        trigger_self_destruct(f"Fetch failed: {e}")

def parse_ddg_lite_results(soup):
    results = []
    # Main results
    for td in soup.find_all("td"):
        a = td.find("a", href=True)
        if a and a['href'].startswith("/l/?"):
            query = urlparse(a['href']).query
            qdict = parse_qs(query)
            uddg = unquote(qdict.get('uddg', [''])[0])
            label = a.get_text(strip=True)
            if label and uddg:
                results.append((label, uddg))
    # Fallback: any <a href="/l/?"...> in the document
    if not results:
        for a in soup.find_all("a", href=True):
            if a['href'].startswith("/l/?"):
                query = urlparse(a['href']).query
                qdict = parse_qs(query)
                uddg = unquote(qdict.get('uddg', [''])[0])
                label = a.get_text(strip=True)
                if label and uddg:
                    results.append((label, uddg))
    # Try to detect "No results found"
    if not results:
        nores = soup.find(string=lambda text: text and "No results found" in text)
        if nores:
            return "no_results"
    return results

def fetch_and_display(url, session=None, extra_stealth_options=None, debug=False):
    html, headers = fetch_with_requests(
        url,
        session=session,
        extra_stealth_options=extra_stealth_options,
        debug=debug
    )
    soup = BeautifulSoup(html, "html.parser")
    print("\n📄 Title:", soup.title.string.strip() if soup.title else "No title")
    is_ddg_search = "duckduckgo" in url and ("q=" in url or "search" in url)
    results = []
    if is_ddg_search:
        results = parse_ddg_lite_results(soup)
        # If no results, try POST fallback
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
            print("  ▪ DuckDuckGo Lite reports no results for this query.")
        elif results:
            for txt, link in results:
                print(f"  ▪ {txt} — {link if link else '[no url]'}")
        else:
            print("  ▪ No results found or parsing failed.")
            if debug:
                print(html)
    else:
        found = False
        for p in soup.find_all("p"):
            text = p.get_text(strip=True)
            if text:
                print("  ▪", text)
                found = True
        if not found:
            print("  ▪ No results found or parsing failed.")
    # Encrypted logging
    key = get_fernet_key()
    logmsg = f"{hash_url(url)} | {headers.get('User-Agent','?')}\n"
    enc_log = encrypt_log(logmsg, key)
    with open("log.enc", "ab") as log:
        log.write(enc_log + b'\n')

def trigger_self_destruct(reason="Unknown"):
    print(f"💀 INTRUSION DETECTED: {reason} → WIPING...")
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
        print("🔄 Tor circuit renewed.")
    except Exception as e:
        print("Failed to renew Tor circuit:", e)

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

def onion_discovery(keywords, extra_stealth_options=None):
    ahmia = "https://msydqstlz2kzerdg.onion/search/?q=" + quote_plus(keywords)
    print(f"🌐 Discovering .onion services for: {keywords}")
    try:
        html, _ = fetch_with_requests(ahmia, extra_stealth_options=extra_stealth_options)
        soup = BeautifulSoup(html, "html.parser")
        seen = set()
        for a in soup.find_all("a", href=True):
            href = a['href']
            if ".onion" in href and href not in seen:
                print("  ▪", href)
                seen.add(href)
        if not seen:
            print("  ▪ No .onion services found for this query.")
    except Exception as e:
        print("  ▪ Error during onion discovery:", e)

def print_help():
    print(
        "Commands:\n"
        "  search <keywords>      — Search DuckDuckGo (onion)\n"
        "  duck                   — Open DuckDuckGo homepage (onion)\n"
        "  debug <keywords>       — Search and show full debug info\n"
        "  stealth                — Toggle extra stealth options\n"
        "  genkeys                — Generate post-quantum keys\n"
        "  sendmsg                — Encrypt & send a message\n"
        "  recvmsg                — Decrypt & show received message\n"
        "  tornew                 — Request new Tor circuit (if supported)\n"
        "  findonions <keywords>  — Discover .onion services by keywords (no bookmarks/history)\n"
        "  wipe                   — Self-destruct and wipe sensitive files\n"
        "  help                   — Show this help\n"
        "  exit                   — Exit browser\n"
    )

def main():
    intrusion_check()
    tor_manager = TorManagerCLI()
    tor_manager.init_tor()
    messenger = DarkelfMessenger()
    print("🛡️  Darkelf CLI Browser - Stealth Mode - Auto Tor rotation, decoy traffic, onion discovery")
    print_help()
    extra_stealth_options = {
        "random_order": True,
        "add_noise_headers": True,
        "minimal_headers": False,
        "spoof_platform": True,
        "session_isolation": False,
        "delay_range": (0.1, 1.2)
    }
    stealth_on = True

    threading.Thread(target=tor_auto_renew_thread, daemon=True).start()
    threading.Thread(target=decoy_traffic_thread, args=(extra_stealth_options,), daemon=True).start()

    while True:
        try:
            cmd = input("darkelf> ").strip()
            if not cmd:
                continue
            elif cmd == "help":
                print_help()
            elif cmd == "stealth":
                stealth_on = not stealth_on
                print("🫥 Extra stealth options are now", "ENABLED" if stealth_on else "DISABLED")
            elif cmd.startswith("search "):
                q = cmd.split(" ", 1)[1]
                fetch_and_display(
                    f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}",
                    extra_stealth_options=extra_stealth_options if stealth_on else {},
                    debug=False
                )
            elif cmd.startswith("debug "):
                q = cmd.split(" ", 1)[1]
                fetch_and_display(
                    f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}",
                    extra_stealth_options=extra_stealth_options if stealth_on else {},
                    debug=True
                )
            elif cmd == "duck":
                fetch_and_display(
                    DUCKDUCKGO_LITE,
                    extra_stealth_options=extra_stealth_options if stealth_on else {},
                    debug=False
                )
            elif cmd == "genkeys":
                messenger.generate_keys()
            elif cmd == "sendmsg":
                to = input("Recipient pubkey path: ")
                msg = input("Message: ")
                messenger.send_message(to, msg)
            elif cmd == "recvmsg":
                messenger.receive_message()
            elif cmd == "tornew":
                renew_tor_circuit()
            elif cmd.startswith("findonions "):
                keywords = cmd.split(" ", 1)[1]
                onion_discovery(keywords, extra_stealth_options=extra_stealth_options if stealth_on else {})
            elif cmd == "wipe":
                trigger_self_destruct("Manual wipe")
            elif cmd == "exit":
                print("🧩 Exiting securely.")
                break
            else:
                print("❓ Unknown command")
        except KeyboardInterrupt:
            print("\n⛔ Ctrl+C - exit requested.")
            break

if __name__ == "__main__":
    main()
