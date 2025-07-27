#!/usr/bin/env python3
"""
Test script to decrypt original file using same approach as our working encryption
"""

import sys
import os
sys.path.insert(0, 'src')

from src.core.crypto_manager import CryptoManager
from src.core import key_derivation
from src.common import constants
from src.controller.main_controller import MainController

def test_decrypt_with_original_salt():
    """Try to decrypt original file using same approach that works for our files"""
    
    password = "Hallo&Welt!1"
    original_encrypted = "abcd-txt.lisq"
    decrypted_file = "abcd_decrypted_with_original_salt.txt"
    
    print("Testing decryption of original file with exact salt...")
    
    try:
        # Read salt from original file exactly as our working code does
        controller = MainController()
        salt = controller._read_salt_from_file(original_encrypted)
        print(f"Salt from original file: {salt.hex()}")
        
        # Derive master key using same process as our working encryption
        master_key = key_derivation.derive_key_from_password(password, salt)
        print(f"Master key: {master_key.hex()}")
        
        # Try decryption
        crypto_manager = CryptoManager()
        crypto_manager.decrypt_file(original_encrypted, decrypted_file, master_key)
        
        if os.path.exists(decrypted_file):
            with open(decrypted_file, 'r') as f:
                content = f.read()
            print(f"✓ Original file decrypted successfully: '{content}'")
            os.remove(decrypted_file)
        else:
            print("✗ Decryption failed - no output file created")
            
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

def test_encrypt_with_original_salt():
    """Encrypt our file using the exact same salt as the original"""
    
    password = "Hallo&Welt!1"
    our_file = "abcd.txt"
    encrypted_file = "abcd_with_original_salt.txt.lisq"
    original_encrypted = "abcd-txt.lisq"
    
    print("\nTesting encryption with original salt...")
    
    try:
        # Read salt from original file
        controller = MainController()
        original_salt = controller._read_salt_from_file(original_encrypted)
        print(f"Using original salt: {original_salt.hex()}")
        
        # Use our working master key derivation but with original salt
        master_key = key_derivation.derive_key_from_password(password, original_salt)
        
        # Create crypto manager and encrypt
        crypto_manager = CryptoManager()
        method_id = constants.METHOD_AES_GCM_V3
        
        # Need to modify the encrypt method to use a provided salt instead of generating random
        # For now, let's just print the keys we would use
        encryption_key = key_derivation.expand_key(master_key, b"AES-GCM-V3-key", constants.AES_GCM_KEY_LENGTH)
        print(f"Master key with original salt: {master_key.hex()}")
        print(f"Encryption key with original salt: {encryption_key.hex()}")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_decrypt_with_original_salt()
    test_encrypt_with_original_salt()
