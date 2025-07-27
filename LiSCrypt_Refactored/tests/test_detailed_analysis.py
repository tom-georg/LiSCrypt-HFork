#!/usr/bin/env python3
"""
Detailed byte-level analysis to find authentication differences
"""

import sys
import os
import struct
sys.path.insert(0, 'src')

from src.core import key_derivation
from src.common import constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def analyze_original_file():
    """Analyze the original file structure byte by byte"""
    
    file_path = "abcd-txt.lisq"
    password = "Hallo&Welt!1"
    
    print("=== DETAILED ORIGINAL FILE ANALYSIS ===")
    
    with open(file_path, 'rb') as f:
        # Read header components step by step
        magic = f.read(4)
        method_id = struct.unpack('>H', f.read(2))[0]
        scrypt_n = struct.unpack('>Q', f.read(8))[0]
        scrypt_r = struct.unpack('>I', f.read(4))[0]
        scrypt_p = struct.unpack('>I', f.read(4))[0]
        salt_len = struct.unpack('>I', f.read(4))[0]
        salt = f.read(salt_len)
        nonce_len = struct.unpack('>I', f.read(4))[0]
        nonce = f.read(nonce_len)
        mod_time = struct.unpack('>Q', f.read(8))[0]
        acc_time = struct.unpack('>Q', f.read(8))[0]
        file_size = struct.unpack('>Q', f.read(8))[0]
        filename_len = struct.unpack('>Q', f.read(8))[0]
        version_len = struct.unpack('>H', f.read(2))[0]
        
        print(f"Magic: {magic}")
        print(f"Method ID: {method_id}")
        print(f"Scrypt N: {scrypt_n}")
        print(f"Scrypt r: {scrypt_r}")
        print(f"Scrypt p: {scrypt_p}")
        print(f"Salt length: {salt_len}")
        print(f"Salt: {salt.hex()}")
        print(f"Nonce length: {nonce_len}")
        print(f"Nonce: {nonce.hex()}")
        print(f"File size: {file_size}")
        print(f"Filename length: {filename_len}")
        print(f"Version length: {version_len}")
        
        # Calculate expected encrypted data length
        expected_encrypted_len = 5 + filename_len + version_len + file_size
        print(f"Expected encrypted data length: {expected_encrypted_len}")
        
        # Read encrypted data
        encrypted_data = f.read(expected_encrypted_len)
        print(f"Actual encrypted data length: {len(encrypted_data)}")
        print(f"Encrypted data: {encrypted_data.hex()}")
        
        # Read tag info
        tag_len = struct.unpack('>I', f.read(4))[0]
        tag = f.read(tag_len)
        print(f"Tag length: {tag_len}")
        print(f"Tag: {tag.hex()}")
        
        # Check for extra data
        extra = f.read()
        print(f"Extra data at end: {len(extra)} bytes")
        if extra:
            print(f"Extra data: {extra.hex()}")
    
    # Now test key derivation step by step
    print("\n=== KEY DERIVATION ANALYSIS ===")
    
    # Step 1: Password to master key
    master_key = key_derivation.derive_key_from_password(password, salt)
    print(f"Master key: {master_key.hex()}")
    
    # Step 2: Master key to encryption key
    encryption_key = key_derivation.expand_key(master_key, b"AES-GCM-V3-key", constants.AES_GCM_KEY_LENGTH)
    print(f"Encryption key: {encryption_key.hex()}")
    
    # Step 3: Test decryption components
    print(f"Header nonce: {nonce.hex()}")
    
    # CRITICAL: Derive the actual nonce used for encryption (not from header!)
    derived_nonce = key_derivation.expand_key(master_key, b"AES-GCM-V3-nonce-0", constants.AES_GCM_NONCE_LENGTH)
    print(f"Derived nonce: {derived_nonce.hex()}")
    print(f"Using tag: {tag.hex()}")
    
    # Create header for authentication
    header_end_pos = 6 + 16 + 4 + salt_len + 4 + nonce_len + 34
    with open(file_path, 'rb') as f:
        header_data = f.read(header_end_pos)
    
    print(f"Header length: {len(header_data)}")
    print(f"Header data: {header_data.hex()}")
    
    # Test decryption step by step
    print("\n=== DECRYPTION TEST ===")
    
    try:
        decryptor = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(derived_nonce, tag),  # Use derived nonce!
            backend=default_backend()
        ).decryptor()
        
        print("✓ Decryptor created successfully")
        
        decryptor.authenticate_additional_data(header_data)
        print("✓ Header authenticated successfully")
        
        decrypted_data = decryptor.update(encrypted_data)
        print(f"✓ Data decrypted: {decrypted_data.hex()}")
        print(f"✓ Decrypted text portion: {decrypted_data[5:].decode('utf-8', errors='ignore')}")
        
        decryptor.finalize()
        print("✓ Tag verification successful!")
        
        # Parse decrypted data
        null_bytes = decrypted_data[:5]
        filename = decrypted_data[5:5+filename_len].decode()
        version = decrypted_data[5+filename_len:5+filename_len+version_len].decode()
        content = decrypted_data[5+filename_len+version_len:]
        
        print(f"Null bytes: {null_bytes.hex()}")
        print(f"Filename: '{filename}'")
        print(f"Version: '{version}'")
        print(f"Content: '{content.decode()}'")
        
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        import traceback
        traceback.print_exc()

def compare_with_working_encryption():
    """Compare with our working encryption to find differences"""
    
    print("\n=== COMPARING WITH WORKING ENCRYPTION ===")
    
    # Create our encrypted file for comparison
    password = "Hallo&Welt!1"
    test_file = "abcd.txt"
    our_encrypted = "our_test.lisq"
    
    # First get the original salt to ensure same master key
    with open("abcd-txt.lisq", 'rb') as f:
        f.seek(6 + 16 + 4)  # Skip to salt
        original_salt = f.read(64)
    
    master_key = key_derivation.derive_key_from_password(password, original_salt)
    
    print(f"Using original salt: {original_salt.hex()}")
    print(f"Master key: {master_key.hex()}")
    
    # Now manually encrypt using exact same process
    from src.core.crypto_manager import CryptoManager
    crypto_manager = CryptoManager()
    
    try:
        crypto_manager.encrypt_file(test_file, our_encrypted, master_key, constants.METHOD_AES_GCM_V3)
        print("✓ Our encryption successful")
        
        # Compare file structures
        orig_size = os.path.getsize("abcd-txt.lisq")
        our_size = os.path.getsize(our_encrypted)
        print(f"Original file size: {orig_size}, Our file size: {our_size}")
        
        # Test decryption of our file
        our_decrypted = "our_decrypted.txt"
        crypto_manager.decrypt_file(our_encrypted, our_decrypted, master_key)
        
        with open(our_decrypted, 'r') as f:
            content = f.read()
        print(f"✓ Our file decrypts to: '{content}'")
        
        # Clean up
        os.remove(our_encrypted)
        os.remove(our_decrypted)
        
    except Exception as e:
        print(f"✗ Our encryption/decryption failed: {e}")

if __name__ == "__main__":
    analyze_original_file()
    compare_with_working_encryption()
