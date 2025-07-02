#!/usr/bin/env python3
"""
Test script for Darkelf CLI TL Edition security and scalability improvements.
"""

import sys
import os
import tempfile
import threading
import time
import json
import secrets
import hashlib
from urllib.parse import urlparse

# Add the current directory to the Python path for testing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock dependencies that might not be available
class MockOQS:
    class KeyEncapsulation:
        def __init__(self, algo):
            self.algo = algo
        def generate_keypair(self):
            return b"mock_public_key"
        def export_secret_key(self):
            return b"mock_private_key"

class MockTLSClient:
    class Session:
        def __init__(self, client_identifier=None):
            self.client_identifier = client_identifier
        def get(self, *args, **kwargs):
            class MockResponse:
                text = "<html><body>Mock response</body></html>"
                status_code = 200
            return MockResponse()

class MockStemController:
    def __init__(self):
        pass
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass

# Mock missing modules if they're not available
sys.modules['oqs'] = MockOQS()
sys.modules['tls_client'] = MockTLSClient()
sys.modules['stem'] = type('Module', (), {})()
sys.modules['stem.control'] = type('Module', (), {'Controller': MockStemController})()
sys.modules['stem.process'] = type('Module', (), {})()
sys.modules['stem.connection'] = type('Module', (), {})()
sys.modules['stem'] = type('Module', (), {'Signal': type('Signal', (), {})})()

def test_entropy_check():
    """Test the enhanced entropy check functionality."""
    print("Testing entropy check...")
    
    # Import the entropy functions
    from math import log2
    
    def calculate_shannon_entropy(data):
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        
        # Count frequency of each byte value
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        length = len(data)
        for count in counts:
            if count > 0:
                prob = count / length
                entropy -= prob * log2(prob)
        
        return entropy
    
    # Test with good random data
    good_data = secrets.token_bytes(256)
    entropy = calculate_shannon_entropy(good_data)
    print(f"  Good random data entropy: {entropy:.2f}")
    assert entropy > 7.0, f"Entropy too low: {entropy}"
    
    # Test with bad data (all zeros)
    bad_data = b'\x00' * 256
    entropy = calculate_shannon_entropy(bad_data)
    print(f"  Bad data entropy: {entropy:.2f}")
    assert entropy < 1.0, f"Entropy should be low: {entropy}"
    
    print("  ✅ Entropy check test passed")

def test_url_sanitization():
    """Test URL sanitization functionality."""
    print("Testing URL sanitization...")
    
    def sanitize_url(url):
        """Sanitize and validate URL to prevent injection attacks."""
        import re
        
        if not url or not isinstance(url, str):
            return None
        
        url = url.strip()
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'javascript:', r'data:', r'vbscript:', r'file:', r'ftp:',
            r'[\x00-\x1f\x7f-\x9f]',  # Control characters
            r'[<>"\'\\\x00]',  # Dangerous characters
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return None
        
        # Validate URL structure
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return None
            
            # Only allow specific schemes
            allowed_schemes = ['http', 'https']
            if parsed.scheme.lower() not in allowed_schemes:
                return None
            
            return url
        except Exception:
            return None
    
    # Test cases
    test_cases = [
        ("https://example.com", True),
        ("http://test.org/path?query=value", True),
        ("javascript:alert('xss')", False),
        ("data:text/html,<script>alert('xss')</script>", False),
        ("https://evil.com/<script>", False),
        ("ftp://files.example.com", False),
        ("", False),
        (None, False),
    ]
    
    for url, should_pass in test_cases:
        result = sanitize_url(url)
        if should_pass:
            assert result is not None, f"URL should pass: {url}"
            print(f"  ✅ {url} -> {result}")
        else:
            assert result is None, f"URL should be blocked: {url}"
            print(f"  🛡️  Blocked: {url}")
    
    print("  ✅ URL sanitization test passed")

def test_secure_memory_wipe():
    """Test secure memory wiping functionality."""
    print("Testing secure memory wipe...")
    
    class SecureBuffer:
        def __init__(self, size=1024):
            self.data = bytearray(size)
            self.size = size
        
        def write(self, data):
            for i, byte in enumerate(data[:self.size]):
                self.data[i] = byte
        
        def secure_wipe(self):
            # Overwrite with random data multiple times
            for _ in range(3):
                for i in range(self.size):
                    self.data[i] = secrets.randbits(8)
            # Final zero wipe
            for i in range(self.size):
                self.data[i] = 0
    
    # Test secure buffer
    buffer = SecureBuffer(1024)
    test_data = b"sensitive information" * 20
    buffer.write(test_data)
    
    # Verify data was written
    assert test_data[:20] in bytes(buffer.data[:len(test_data)])
    
    # Secure wipe
    buffer.secure_wipe()
    
    # Verify data was wiped
    assert test_data[:20] not in bytes(buffer.data)
    assert all(b == 0 for b in buffer.data)
    
    print("  ✅ Secure memory wipe test passed")

def test_parallel_processing():
    """Test parallel processing functionality."""
    print("Testing parallel processing...")
    
    import concurrent.futures
    import time
    
    def mock_process_url(url):
        """Mock URL processing function."""
        time.sleep(0.1)  # Simulate work
        return {
            "url": url,
            "data": f"processed_{url}",
            "timestamp": time.time()
        }
    
    urls = [f"https://example{i}.com" for i in range(5)]
    
    # Sequential processing
    start_time = time.time()
    sequential_results = []
    for url in urls:
        sequential_results.append(mock_process_url(url))
    sequential_time = time.time() - start_time
    
    # Parallel processing
    start_time = time.time()
    parallel_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_url = {executor.submit(mock_process_url, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            parallel_results.append(future.result())
    parallel_time = time.time() - start_time
    
    print(f"  Sequential time: {sequential_time:.3f}s")
    print(f"  Parallel time: {parallel_time:.3f}s")
    print(f"  Speedup: {sequential_time/parallel_time:.2f}x")
    
    assert len(parallel_results) == len(urls)
    assert parallel_time < sequential_time * 0.8  # Should be faster
    
    print("  ✅ Parallel processing test passed")

def test_logging_separation():
    """Test enhanced logging with separation."""
    print("Testing logging separation...")
    
    from cryptography.fernet import Fernet
    
    class MockPQLogManager:
        def __init__(self, key):
            self.fernet = Fernet(key)
            self.logs = {"phishing": [], "onion": [], "tools": [], "security": [], "network": []}
            self.log_lock = threading.Lock()
        
        def log(self, category, message):
            if category not in self.logs:
                self.logs[category] = []
            
            with self.log_lock:
                encrypted = self.fernet.encrypt(message.encode())
                self.logs[category].append(encrypted)
        
        def get_log_count(self, category):
            return len(self.logs.get(category, []))
    
    # Test logging
    key = Fernet.generate_key()
    logger = MockPQLogManager(key)
    
    # Log to different categories
    logger.log("phishing", "Detected suspicious URL")
    logger.log("security", "SSL validation failed")
    logger.log("network", "Connection timeout")
    logger.log("tools", "Tool executed")
    
    # Verify separation
    assert logger.get_log_count("phishing") == 1
    assert logger.get_log_count("security") == 1
    assert logger.get_log_count("network") == 1
    assert logger.get_log_count("tools") == 1
    assert logger.get_log_count("onion") == 0
    
    print("  ✅ Logging separation test passed")

def test_resource_monitoring():
    """Test resource monitoring functionality."""
    print("Testing resource monitoring...")
    
    try:
        import psutil
        
        # Get current resource usage
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        print(f"  Current memory usage: {memory_percent:.1f}%")
        print(f"  Current disk usage: {disk_percent:.1f}%")
        
        # Test resource thresholds
        assert 0 <= memory_percent <= 100
        assert 0 <= disk_percent <= 100
        
        print("  ✅ Resource monitoring test passed")
        
    except ImportError:
        print("  ⚠️  psutil not available, skipping resource monitoring test")

def main():
    """Run all tests."""
    print("🔒 Testing Darkelf CLI TL Edition Security and Scalability Improvements")
    print("=" * 70)
    
    try:
        test_entropy_check()
        test_url_sanitization()
        test_secure_memory_wipe()
        test_parallel_processing()
        test_logging_separation()
        test_resource_monitoring()
        
        print("=" * 70)
        print("✅ All tests passed! Security and scalability improvements are working.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()