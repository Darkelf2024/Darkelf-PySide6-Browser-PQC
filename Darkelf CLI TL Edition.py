import os
import sys
import time
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
import platform
import shlex
import subprocess
import re
from datetime import datetime
import psutil
from urllib.parse import quote_plus, unquote, parse_qs, urlparse
from bs4 import BeautifulSoup
from oqs import KeyEncapsulation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
                print(f"🔻 LOW MEMORY: < {self.threshold // (1024 * 1024)} MB available. Exiting to prevent swap.")
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

        # === ML-KEM-768: Post-Quantum Key Exchange ===
        self.kem = KeyEncapsulation("ML-KEM-768")
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
                print(f"[PhishingDetector] ✅ Flushed encrypted phishing log to {self.flush_path}")
            except Exception as e:
                print(f"[PhishingDetector] ⚠️ Log flush failed: {e}")

# --- NetworkProtector: PQ-encrypted, padded, jittered socket comms ---
class NetworkProtector:
    def __init__(self, sock, peer_kyber_pub_b64: str):
        self.sock = sock
        self.secure_random = random.SystemRandom()
        self.peer_pub = base64.b64decode(peer_kyber_pub_b64)

    def add_jitter(self, min_delay=0.05, max_delay=0.3):
        jitter = self.secure_random.uniform(min_delay, max_delay)
        time.sleep(jitter)
        print(f"[Darkelf] Jitter applied: {jitter:.3f}s")

    def send_with_padding(self, data: bytes, min_padding=128, max_padding=256):
        target_size = max(len(data), self.secure_random.randint(min_padding, max_padding))
        pad_len = target_size - len(data)
        padded_data = data + os.urandom(pad_len)
        self.sock.sendall(padded_data)
        print(f"[Darkelf] Sent padded data (original: {len(data)}, padded: {len(padded_data)}, pad: {pad_len})")

    def send_protected(self, data: bytes):
        self.add_jitter()
        encrypted = self.encrypt_data_kyber768(data)
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
            info=b"darkelf-transport"
        ).derive(shared_secret)

        aesgcm = AESGCM(aes_key)
        encrypted_payload = aesgcm.encrypt(nonce, data, None)

        packet = {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "payload": base64.b64encode(encrypted_payload).decode(),
            "salt": base64.b64encode(salt).decode(),
            "version": 1
        }

        return base64.b64encode(json.dumps(packet).encode())

# --- Existing CLI code below (unchanged, but now can use above tools) ---

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
    for td in soup.find_all("td"):
        a = td.find("a", href=True)
        if a and a['href'].startswith("/l/?"):
            query = urlparse(a['href']).query
            qdict = parse_qs(query)
            uddg = unquote(qdict.get('uddg', [''])[0])
            label = a.get_text(strip=True)
            if label and uddg:
                results.append((label, uddg))
    if not results:
        for a in soup.find_all("a", href=True):
            if a['href'].startswith("/l/?"):
                query = urlparse(a['href']).query
                qdict = parse_qs(query)
                uddg = unquote(qdict.get('uddg', [''])[0])
                label = a.get_text(strip=True)
                if label and uddg:
                    results.append((label, uddg))
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

def open_tool(tool):
    """
    Install and open a terminal tool by name via platform-specific method.
    """
    allowed_tools = [
        "sherlock", "shodan", "recon-ng", "theharvester", "nmap", "yt-dlp", "maltego", "masscan",
        "amass", "subfinder", "exiftool", "mat2", "neomutt", "thunderbird"
    ]
    tool = tool.lower()
    if tool not in allowed_tools:
        print(f"Tool '{tool}' is not in the allowed list.")
        return

    sanitized_tool = shlex.quote(tool)
    system = platform.system()
    try:
        if system == "Darwin":  # macOS
            subprocess.run([
                "osascript", "-e",
                f'''tell application "Terminal"
do script "brew install {sanitized_tool} && exec $SHELL"
activate
end tell'''
            ], check=True)
        elif system == "Linux":
            subprocess.run([
                "gnome-terminal", "--", "sh", "-c",
                f"brew install {sanitized_tool} && exec bash"
            ], check=True)
        elif system == "Windows":
            subprocess.run([
                "cmd.exe", "/c", "start", "cmd.exe", "/k",
                f"brew install {sanitized_tool}"
            ], check=True)
        else:
            print(f"Unsupported platform: {system}")
    except Exception as e:
        print(f"Failed to open/install tool '{tool}': {e}")

def print_tools_help():
    print(
        "Tools CLI usage:\n"
        "  tool <name>      — Install and launch terminal tool\n"
        "Available tools:\n"
        "  sherlock, shodan, recon-ng, theharvester, nmap, yt-dlp, maltego, masscan,\n"
        "  amass, subfinder, exiftool, mat2, neomutt, thunderbird\n"
    )

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
        "  tool <name>            — Install and launch terminal tool\n"
        "  tools                  — List available terminal tools\n"
        "  wipe                   — Self-destruct and wipe sensitive files\n"
        "  help                   — Show this help\n"
        "  exit                   — Exit browser\n"
    )

def main():
    intrusion_check()
    mem_monitor = MemoryMonitor()
    mem_monitor.start()
    pq_logger = StealthCovertOpsPQ(stealth_mode=True)
    phishing_detector = PhishingDetectorZeroTrace(pq_logger=pq_logger)
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
            elif cmd == "tools":
                print_tools_help()
            elif cmd.startswith("tool "):
                tool_name = cmd.split(" ", 1)[1]
                open_tool(tool_name)
            elif cmd == "stealth":
                stealth_on = not stealth_on
                print("🫥 Extra stealth options are now", "ENABLED" if stealth_on else "DISABLED")
            elif cmd.startswith("search "):
                q = cmd.split(" ", 1)[1]
                url = f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}"
                suspicious, reason = phishing_detector.is_suspicious_url(url)
                if suspicious:
                    print(f"⚠️ [PHISHING WARNING] {reason}")
                fetch_and_display(url, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=False)
            elif cmd.startswith("debug "):
                q = cmd.split(" ", 1)[1]
                url = f"{DUCKDUCKGO_LITE}?q={quote_plus(q)}"
                suspicious, reason = phishing_detector.is_suspicious_url(url)
                if suspicious:
                    print(f"⚠️ [PHISHING WARNING] {reason}")
                fetch_and_display(url, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=True)
            elif cmd == "duck":
                fetch_and_display(DUCKDUCKGO_LITE, extra_stealth_options=extra_stealth_options if stealth_on else {}, debug=False)
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
                pq_logger.panic()
                trigger_self_destruct("Manual wipe")
            elif cmd == "exit":
                print("🧩 Exiting securely.")
                phishing_detector.flush_logs_on_exit()
                break
            else:
                print("❓ Unknown command. Type `help` for options.")
        except KeyboardInterrupt:
            print("\n⛔ Ctrl+C - exit requested.")
            phishing_detector.flush_logs_on_exit()
            break

    threading.Thread(target=tor_auto_renew_thread, daemon=True).start()
    threading.Thread(target=decoy_traffic_thread, args=(extra_stealth_options,), daemon=True).start()

if __name__ == "__main__":
    main()
