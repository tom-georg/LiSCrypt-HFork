#!/usr/bin/env python3
"""
Test script to encrypt a file and compare with original structure
"""

import sys
import os
sys.path.insert(0, 'src')

from src.core.crypto_manager import CryptoManager
from src.core import key_derivation
from src.common import constants

def test_encrypt_and_compare():
    """Encrypt test file and compare structure with original"""
    
    password = "Hallo&Welt!1"
    original_file = "abcd.txt"  # Same name as original
    encrypted_file = "abcd.txt.lisq"
    
    print("Testing encryption with same content as original file...")
    
    # Generate master key (use same salt as we would for encryption)
    salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
    master_key = key_derivation.derive_key_from_password(password, salt)
    
    # Encrypt using our refactored code
    crypto_manager = CryptoManager()
    method_id = constants.METHOD_AES_GCM_V3
    
    try:
        crypto_manager.encrypt_file(original_file, encrypted_file, master_key, method_id)
        print("✓ Encryption successful!")
        
        # Compare file structures
        print("\n--- File Structure Comparison ---")
        
        # Our encrypted file
        if os.path.exists(encrypted_file):
            our_size = os.path.getsize(encrypted_file)
            print(f"Our encrypted file size: {our_size} bytes")
            
            with open(encrypted_file, 'rb') as f:
                our_header = f.read(50)  # First 50 bytes for comparison
            print(f"Our header (first 50 bytes): {our_header.hex()}")
        
        # Original encrypted file
        original_encrypted = "abcd-txt.lisq"
        if os.path.exists(original_encrypted):
            orig_size = os.path.getsize(original_encrypted)
            print(f"Original encrypted file size: {orig_size} bytes")
            
            with open(original_encrypted, 'rb') as f:
                orig_header = f.read(50)  # First 50 bytes for comparison
            print(f"Original header (first 50 bytes): {orig_header.hex()}")
        
        # Test decryption of our own file
        print("\n--- Testing Decryption of Our File ---")
        decrypted_file = "test_abcd_decrypted.txt"
        crypto_manager.decrypt_file(encrypted_file, decrypted_file, master_key)
        
        if os.path.exists(decrypted_file):
            with open(decrypted_file, 'r') as f:
                content = f.read()
            print(f"✓ Our file decrypted successfully: '{content}'")
            os.remove(decrypted_file)
        
        # Clean up
        os.remove(encrypted_file)
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_encrypt_and_compare()
