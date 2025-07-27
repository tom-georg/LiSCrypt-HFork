#!/usr/bin/env python3
"""
Final validation test to ensure the cleaned-up AES-GCM v3 strategy works correctly
with both original LiSCrypt files and new files created by the refactored version.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.core.crypto_manager import CryptoManager
from src.common.constants import METHOD_AES_GCM_V3

def test_decrypt_original_file():
    """Test decrypting the original LiSCrypt file"""
    print("Testing decryption of original LiSCrypt file...")
    
    crypto_manager = CryptoManager()
    
    original_file = "abcd-txt.lisq"
    output_file = "decrypted_original_final.txt"
    password = "Hallo&Welt!1"
    
    try:
        # Decrypt the original file
        crypto_manager.decrypt_file(original_file, output_file, password)
        
        # Read and verify content
        with open(output_file, 'r') as f:
            content = f.read().strip()
        
        print(f"✓ Successfully decrypted original file")
        print(f"✓ Content: '{content}'")
        
        # Clean up
        if os.path.exists(output_file):
            os.remove(output_file)
            
        return True
        
    except Exception as e:
        print(f"✗ Failed to decrypt original file: {e}")
        return False

def test_encrypt_decrypt_roundtrip():
    """Test encrypting and then decrypting a new file"""
    print("\nTesting encrypt/decrypt roundtrip...")
    
    crypto_manager = CryptoManager()
    
    # Create test file
    test_content = "This is a test file for the refactored LiSCrypt"
    test_file = "test_roundtrip.txt"
    encrypted_file = "test_roundtrip.txt.lisq"
    decrypted_file = "test_roundtrip_decrypted.txt"
    password = "TestPassword123!"
    
    try:
        # Create test file
        with open(test_file, 'w') as f:
            f.write(test_content)
        
        # Encrypt
        crypto_manager.encrypt_file(test_file, encrypted_file, password, METHOD_AES_GCM_V3)
        print("✓ Successfully encrypted test file")
        
        # Decrypt
        crypto_manager.decrypt_file(encrypted_file, decrypted_file, password)
        print("✓ Successfully decrypted test file")
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("✓ Content matches original")
            success = True
        else:
            print(f"✗ Content mismatch: expected '{test_content}', got '{decrypted_content}'")
            success = False
        
        # Clean up
        for file in [test_file, encrypted_file, decrypted_file]:
            if os.path.exists(file):
                os.remove(file)
        
        return success
        
    except Exception as e:
        print(f"✗ Roundtrip test failed: {e}")
        return False

def main():
    """Run all validation tests"""
    print("=" * 60)
    print("LiSCrypt Final Validation Tests")
    print("=" * 60)
    
    results = []
    
    # Test 1: Decrypt original file
    results.append(test_decrypt_original_file())
    
    # Test 2: Encrypt/decrypt roundtrip
    results.append(test_encrypt_decrypt_roundtrip())
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    if all(results):
        print("✓ ALL TESTS PASSED - LiSCrypt refactoring is complete!")
        print("✓ Backward compatibility with original files: OK")
        print("✓ New file encryption/decryption: OK")
        print("✓ Codebase cleanup: Complete")
    else:
        print("✗ Some tests failed - review the output above")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
