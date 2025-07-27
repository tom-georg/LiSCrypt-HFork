#!/usr/bin/env python3
"""
Comprehensive test for the refactored LiSCrypt application.
This test will decrypt an existing .lisq file and test encryption/decryption round-trip.
"""

import sys
import os
import tempfile
import traceback

# Add the src directory to the path so we can import our modules
current_dir = os.path.dirname(__file__)
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

# Check if required dependencies are available
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: cryptography module not available. Install with: pip install cryptography")

try:
    from PyQt5 import QtCore, QtWidgets
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    print("WARNING: PyQt5 module not available. Install with: pip install PyQt5")

if CRYPTO_AVAILABLE:
    from src.core.crypto_manager import CryptoManager
    from src.core import key_derivation
    from src.common import constants
    from src.controller.main_controller import MainController


def test_decrypt_existing_file():
    """Test decrypting the existing abcd-txt.lisq file created by original LiSCrypt."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping decryption test - cryptography module not available")
        return False
    
    print("Testing decryption of existing .lisq file...")
    
    encrypted_file = "abcd-txt.lisq"
    decrypted_file = "abcd_decrypted.txt"
    password = "Hallo&Welt!1"
    
    if not os.path.exists(encrypted_file):
        print(f"✗ Encrypted file {encrypted_file} not found")
        return False
    
    try:
        # Use the controller to decrypt
        controller = MainController()
        controller.set_password(password)
        controller.set_function(constants.PROGRAM_FUNCTION_DECRYPT)
        controller.set_selected_files([encrypted_file])
        
        # For this test, we'll directly use the crypto manager
        crypto_manager = CryptoManager()
        
        # Read salt from file to derive key
        salt = controller._read_salt_from_file(encrypted_file)
        master_key = key_derivation.derive_key_from_password(password, salt)
        
        # Decrypt the file
        crypto_manager.decrypt_file(encrypted_file, decrypted_file, master_key)
        
        # Check if decryption was successful
        if os.path.exists(decrypted_file):
            with open(decrypted_file, 'r') as f:
                content = f.read()
            print(f"✓ Decryption successful!")
            print(f"✓ Decrypted content: '{content.strip()}'")
            
            # Clean up
            os.remove(decrypted_file)
            return True
        else:
            print("✗ Decryption failed - output file not created")
            return False
            
    except Exception as e:
        print(f"✗ Decryption failed with error: {e}")
        traceback.print_exc()
        return False


def test_encryption_round_trip():
    """Test encrypting a new file and then decrypting it."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping round-trip test - cryptography module not available")
        return False
    
    print("\nTesting encryption/decryption round-trip...")
    
    password = "Hallo&Welt!1"
    test_content = "Hello, this is a test message for LiSCrypt encryption!"
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        temp_file.write(test_content)
        original_file = temp_file.name
    
    encrypted_file = original_file + constants.FILE_EXTENSION
    decrypted_file = original_file + "_decrypted.txt"
    
    try:
        # Test encryption
        controller = MainController()
        controller.set_password(password)
        controller.set_function(constants.PROGRAM_FUNCTION_ENCRYPT)
        controller.set_selected_files([original_file])
        
        crypto_manager = CryptoManager()
        
        # Generate master key for encryption
        salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
        master_key = key_derivation.derive_key_from_password(password, salt)
        
        # Choose encryption method (AES-GCM for small files)
        method_id = constants.METHOD_AES_GCM_V3
        
        # Encrypt
        crypto_manager.encrypt_file(original_file, encrypted_file, master_key, method_id)
        
        if not os.path.exists(encrypted_file):
            print("✗ Encryption failed - encrypted file not created")
            return False
        
        print(f"✓ Encryption successful! Created {os.path.basename(encrypted_file)}")
        
        # Test decryption
        salt_from_file = controller._read_salt_from_file(encrypted_file)
        master_key_decrypt = key_derivation.derive_key_from_password(password, salt_from_file)
        
        crypto_manager.decrypt_file(encrypted_file, decrypted_file, master_key_decrypt)
        
        if not os.path.exists(decrypted_file):
            print("✗ Decryption failed - decrypted file not created")
            return False
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("✓ Decryption successful! Content matches original.")
            print(f"✓ Round-trip test passed!")
            return True
        else:
            print(f"✗ Content mismatch!")
            print(f"  Original: '{test_content}'")
            print(f"  Decrypted: '{decrypted_content}'")
            return False
            
    except Exception as e:
        print(f"✗ Round-trip test failed with error: {e}")
        traceback.print_exc()
        return False
    finally:
        # Clean up temporary files
        for file_path in [original_file, encrypted_file, decrypted_file]:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass


def test_file_header_reading():
    """Test reading file headers from the existing .lisq file."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping header test - cryptography module not available")
        return False
    
    print("\nTesting file header reading...")
    
    encrypted_file = "abcd-txt.lisq"
    
    if not os.path.exists(encrypted_file):
        print(f"✗ File {encrypted_file} not found")
        return False
    
    try:
        crypto_manager = CryptoManager()
        method_id = crypto_manager._get_method_id_from_file(encrypted_file)
        
        print(f"✓ File header read successfully")
        print(f"✓ Encryption method ID: {method_id}")
        
        # Identify the method
        method_name = "Unknown"
        if method_id == constants.METHOD_AES_GCM_V3:
            method_name = "AES-GCM v3"
        elif method_id == constants.METHOD_CHACHA20_V3_1:
            method_name = "ChaCha20+HMAC v3.1"
        elif method_id == constants.METHOD_AES_GCM_V2:
            method_name = "AES-GCM v2 (Legacy)"
        elif method_id == constants.METHOD_CHACHA20_V3:
            method_name = "ChaCha20+HMAC v3 (Legacy)"
        
        print(f"✓ Encryption method: {method_name}")
        
        # Try to read detailed header information
        controller = MainController()
        salt = controller._read_salt_from_file(encrypted_file)
        print(f"✓ Salt read successfully, length: {len(salt)} bytes")
        
        return True
        
    except Exception as e:
        print(f"✗ Header reading failed: {e}")
        traceback.print_exc()
        return False


def test_password_validation():
    """Test password validation and key derivation."""
    if not CRYPTO_AVAILABLE:
        print("⚠️  Skipping password test - cryptography module not available")
        return False
    
    print("\nTesting password validation and key derivation...")
    
    try:
        controller = MainController()
        
        # Test valid password
        password = "Hallo&Welt!1"
        controller.set_password(password)
        print(f"✓ Password '{password}' accepted")
        
        # Test key derivation
        salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
        key = key_derivation.derive_key_from_password(password, salt)
        print(f"✓ Key derivation successful, key length: {len(key)} bytes")
        
        # Test key expansion
        expanded_key = key_derivation.expand_key(key, b"test-info", 32)
        print(f"✓ Key expansion successful, expanded key length: {len(expanded_key)} bytes")
        
        return True
        
    except Exception as e:
        print(f"✗ Password/key test failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all tests."""
    print("=" * 70)
    print("LiSCrypt Refactored - Comprehensive Encryption/Decryption Tests")
    print("Testing with file created by ORIGINAL LiSCrypt application")
    print("=" * 70)
    
    if not CRYPTO_AVAILABLE:
        print("\n🚨 CRITICAL: cryptography module not available!")
        print("   Install with: pip install cryptography")
        print("   Some tests will be skipped.\n")
    
    success_count = 0
    total_tests = 4
    
    # Run tests
    tests = [
        ("Password Validation", test_password_validation),
        ("File Header Reading", test_file_header_reading),
        ("Decrypt Original LiSCrypt File", test_decrypt_existing_file),
        ("Encryption Round-trip", test_encryption_round_trip),
    ]
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            if test_func():
                success_count += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("🎉 ALL TESTS PASSED!")
        print("🎉 The refactored LiSCrypt is working correctly!")
        print("🎉 Successfully decrypted file created by original LiSCrypt!")
    elif success_count > 0:
        print(f"⚠️  {total_tests - success_count} tests failed or skipped")
        if not CRYPTO_AVAILABLE:
            print("   (Some failures may be due to missing dependencies)")
    else:
        print("🚨 ALL TESTS FAILED!")
    
    print("=" * 70)
    
    return success_count == total_tests


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
