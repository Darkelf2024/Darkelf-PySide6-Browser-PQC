#!/usr/bin/env python3
"""
Demonstration of Darkelf CLI TL Edition Security and Scalability Improvements
"""

import os
import sys
import time
import json
import threading
import secrets
from datetime import datetime

print("🔒 Darkelf CLI TL Edition - Security & Scalability Demo")
print("=" * 60)

# 1. Enhanced Entropy Check Demo
print("\n1. 📊 Enhanced Entropy Check")
print("-" * 30)

def calculate_shannon_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0
    
    import math
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    
    entropy = 0
    length = len(data)
    for count in counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    
    return entropy

# Test with different entropy sources
print("Testing entropy from multiple sources:")
entropy_sources = [
    ("secrets.token_bytes(256)", secrets.token_bytes(256)),
    ("os.urandom(256)", os.urandom(256)),
    ("/dev/urandom", open("/dev/urandom", "rb").read(256) if os.path.exists("/dev/urandom") else b"N/A")
]

for name, data in entropy_sources:
    if data != b"N/A":
        entropy = calculate_shannon_entropy(data)
        status = "✅ Good" if entropy > 7.5 else "⚠️ Low"
        print(f"  {name}: {entropy:.3f} bits {status}")

# 2. URL Sanitization Demo
print("\n2. 🛡️  URL Sanitization & Input Validation")
print("-" * 40)

def sanitize_url(url):
    """Sanitize URL (simplified version for demo)."""
    import re
    from urllib.parse import urlparse
    
    if not url or not isinstance(url, str):
        return None
    
    dangerous_patterns = [
        r'javascript:', r'data:', r'vbscript:', r'file:',
        r'[<>"\'\\\x00]'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return None
    
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ['http', 'https']:
            return None
        return url
    except:
        return None

test_urls = [
    "https://example.com",
    "javascript:alert('xss')",
    "https://site.com/<script>",
    "data:text/html,malicious",
    "http://legitimate.org/page"
]

print("Testing URL sanitization:")
for url in test_urls:
    result = sanitize_url(url)
    if result:
        print(f"  ✅ ALLOWED: {url}")
    else:
        print(f"  🚫 BLOCKED: {url}")

# 3. Parallel Processing Demo
print("\n3. ⚡ Parallel Processing Performance")
print("-" * 35)

import concurrent.futures

def mock_url_scan(url):
    """Mock URL scanning function."""
    time.sleep(0.1)  # Simulate network delay
    return {
        "url": url,
        "status": "processed",
        "timestamp": datetime.now().isoformat()
    }

urls = [f"https://example{i}.com" for i in range(6)]

# Sequential processing
print("Sequential processing:")
start_time = time.time()
seq_results = []
for url in urls:
    seq_results.append(mock_url_scan(url))
seq_time = time.time() - start_time

# Parallel processing
print("Parallel processing:")
start_time = time.time()
par_results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    futures = {executor.submit(mock_url_scan, url): url for url in urls}
    for future in concurrent.futures.as_completed(futures):
        par_results.append(future.result())
par_time = time.time() - start_time

print(f"  Sequential: {seq_time:.3f}s")
print(f"  Parallel:   {par_time:.3f}s")
print(f"  Speedup:    {seq_time/par_time:.2f}x")

# 4. Enhanced Logging Demo
print("\n4. 📝 Enhanced Logging with Category Separation")
print("-" * 45)

from cryptography.fernet import Fernet

class DemoLogManager:
    def __init__(self):
        key = Fernet.generate_key()
        self.fernet = Fernet(key)
        self.logs = {"phishing": [], "security": [], "network": [], "tools": [], "onion": []}
        self.lock = threading.Lock()
    
    def log(self, category, message):
        with self.lock:
            timestamp = datetime.now().isoformat()
            log_entry = f"[{timestamp}] {message}"
            encrypted = self.fernet.encrypt(log_entry.encode())
            self.logs[category].append(encrypted)
    
    def get_stats(self):
        return {cat: len(entries) for cat, entries in self.logs.items()}

logger = DemoLogManager()

# Simulate different types of logs
logger.log("security", "SSL certificate validation passed")
logger.log("phishing", "Suspicious URL detected and blocked")
logger.log("network", "Connection established via Tor")
logger.log("tools", "OSINT scan completed")
logger.log("security", "Memory wipe initiated")

print("Log entries by category:")
for category, count in logger.get_stats().items():
    print(f"  {category}: {count} entries")

# 5. Memory Security Demo
print("\n5. 🔐 Secure Memory Management")
print("-" * 30)

class SecureBuffer:
    def __init__(self, size=1024):
        self.data = bytearray(size)
        self.size = size
    
    def write(self, data):
        for i, byte in enumerate(data[:self.size]):
            self.data[i] = byte
    
    def secure_wipe(self):
        # Multiple overwrites with random data
        for _ in range(3):
            for i in range(self.size):
                self.data[i] = secrets.randbits(8)
        # Final zero wipe
        for i in range(self.size):
            self.data[i] = 0

# Demo secure buffer
buffer = SecureBuffer(100)
sensitive_data = b"TOP SECRET INFORMATION" * 3
print("Writing sensitive data to secure buffer...")
buffer.write(sensitive_data)

# Verify data is present
if sensitive_data[:20] in bytes(buffer.data[:len(sensitive_data)]):
    print("  ✅ Data written successfully")

print("Performing secure wipe...")
buffer.secure_wipe()

# Verify data is wiped
if sensitive_data[:20] not in bytes(buffer.data):
    print("  ✅ Data securely wiped from memory")

# 6. Resource Monitoring Demo
print("\n6. 📊 System Resource Monitoring")
print("-" * 32)

try:
    import psutil
    
    # Get system stats
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    print(f"Memory usage: {memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)")
    print(f"Disk usage:   {disk.percent:.1f}% ({disk.used // (1024**3):.1f}GB / {disk.total // (1024**3):.1f}GB)")
    
    # Simulate resource threshold checking
    if memory.percent > 90:
        print("  ⚠️ High memory usage - cleanup recommended")
    else:
        print("  ✅ Memory usage within normal limits")
        
    if disk.percent > 95:
        print("  ⚠️ Low disk space - cleanup recommended")
    else:
        print("  ✅ Disk usage within normal limits")
        
except ImportError:
    print("  ⚠️ psutil not available - install for full monitoring")

print("\n" + "=" * 60)
print("✅ Security and Scalability Improvements Demonstration Complete!")
print("\nKey Improvements Implemented:")
print("  🔐 Enhanced entropy validation with multiple sources")
print("  🛡️ Comprehensive URL sanitization and input validation")
print("  ⚡ Parallel processing for OSINT and URL scanning")
print("  📝 Enhanced logging with category separation and encryption")
print("  🔒 Secure memory management with proper wiping")
print("  📊 System resource monitoring for graceful degradation")
print("  🚨 Robust error handling for network and crypto operations")
print("  🧹 Comprehensive cleanup mechanisms for sensitive data")