#!/usr/bin/env python3
"""
Test to verify if header nonce matches derived nonce
"""

import sys
sys.path.insert(0, 'src')

from src.core import key_derivation
from src.common import constants
import struct

def test_nonce_comparison():
    """Compare header nonce with what we would derive"""
    
    password = "Hallo&Welt!1"
    
    # Read original file components
    with open("abcd-txt.lisq", 'rb') as f:
        f.seek(6 + 16 + 4)  # Skip to salt
        salt = f.read(64)
        f.seek(6 + 16 + 4 + 64 + 4)  # Skip to nonce
        header_nonce = f.read(12)
    
    # Derive master key
    master_key = key_derivation.derive_key_from_password(password, salt)
    
    # Try different nonce derivation patterns
    patterns = [
        b"AES-GCM-V3-nonce-0",
        b"AES-GCM-V3-nonce",
        b"AESGCM-V3-nonce-0", 
        b"AES-GCM-nonce-0",
        b"nonce-0",
        b"nonce",
    ]
    
    print(f"Header nonce: {header_nonce.hex()}")
    print(f"Salt: {salt.hex()}")
    print(f"Master key: {master_key.hex()}")
    print()
    
    for pattern in patterns:
        try:
            derived = key_derivation.expand_key(master_key, pattern, 12)
            matches = derived == header_nonce
            print(f"Pattern '{pattern.decode()}': {derived.hex()} {'✓ MATCH!' if matches else '✗'}")
        except Exception as e:
            print(f"Pattern '{pattern.decode()}': ERROR - {e}")
    
    # Also test if maybe the nonce is derived differently
    print(f"\nTesting other approaches...")
    
    # Maybe it's just the first 12 bytes of a longer derivation?
    long_derived = key_derivation.expand_key(master_key, b"AES-GCM-V3-nonce-0", 32)
    print(f"First 12 bytes of 32-byte derivation: {long_derived[:12].hex()} {'✓ MATCH!' if long_derived[:12] == header_nonce else '✗'}")
    
    # Maybe it's from a different master key?
    print(f"\nLet's also check if we're deriving the master key correctly...")
    print(f"Our scrypt parameters: N={constants.SCRYPT_N}, r={constants.SCRYPT_R}, p={constants.SCRYPT_P}")

if __name__ == "__main__":
    test_nonce_comparison()
