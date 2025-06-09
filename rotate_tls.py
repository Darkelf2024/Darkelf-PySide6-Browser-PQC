# rotate_tls.py - JA3 fingerprint rotation hook for mitmproxy
# Copyright (C) 2025 Dr. Kevin Moore
#
# This file is part of Darkelf Browser or associated tooling.
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


from mitmproxy import http
import random

# Custom JA3 fingerprints inspired by popular browser fingerprints (altered for originality)
JA3_LIBRARY = [
    # Firefox-inspired (extension order adjusted)
    "771,4866-4867-4865-49195-49196-49199-49188-49192-49162-49172,0-10-11-35-13-5-18-23-65281,29-23-24,0",

    # Chrome-inspired (cipher order slightly altered)
    "771,4866-4867-4865-49195-49196-49199-49188-49192,0-11-10-35-13-5-23-18-51-45-43,23-24,0",

    # Safari-style (missing one less-common extension)
    "771,49196-49199-49195-49188-49192,0-10-35-16-5-23-65281,13-15,0",

    # Brave-like (elliptic curve order randomized)
    "771,49195-49199-49196-49188-49192,0-11-10-35-5-13-23-65281,25-23-24,0",

    # Tor-mimic (extension sequence shuffled)
    "771,4865-4866-4867-49195-49196-49199-49188-49192,0-11-10-13-5-18-35-23-51-45-43,29-23-24,0"
]

def request(flow: http.HTTPFlow):
    """
    Assigns a randomized JA3 fingerprint to every new client connection.
    This helps simulate different browser TLS handshakes for evasion or analysis.
    """
    if hasattr(flow.client_conn, "ja3"):
        flow.client_conn.ja3 = random.choice(JA3_LIBRARY)
