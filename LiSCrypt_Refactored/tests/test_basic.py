#!/usr/bin/env python3
"""
Simple test script for the refactored LiSCrypt application.
"""

import sys
import os
import tempfile

# Add the src directory to the path so we can import our modules
current_dir = os.path.dirname(__file__)
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

from src.core.crypto_manager import CryptoManager
from src.core import key_derivation
from src.common import constants
from src.controller.main_controller import MainController


def test_key_derivation():
    """Test key derivation functionality."""
    print("Testing key derivation...")
    
    password = "test_password_123"
    salt = b"test_salt_64_bytes_" + b"0" * 46  # 64 bytes total
    
    # Test password-based key derivation
    key = key_derivation.derive_key_from_password(password, salt)
    print(f"✓ Password-based key derivation successful, key length: {len(key)}")
    
    # Test key expansion
    expanded_key = key_derivation.expand_key(key, b"test-info", 32)
    print(f"✓ Key expansion successful, expanded key length: {len(expanded_key)}")


def test_crypto_manager():
    """Test crypto manager initialization."""
    print("Testing crypto manager...")
    
    crypto_manager = CryptoManager()
    print(f"✓ Crypto manager initialized with {len(crypto_manager._strategies)} strategies")


def test_controller():
    """Test main controller."""
    print("Testing main controller...")
    
    controller = MainController()
    
    # Test setting password
    controller.set_password("test_password_123")
    print("✓ Password set successfully")
    
    # Test setting function
    controller.set_function(constants.PROGRAM_FUNCTION_ENCRYPT)
    print(f"✓ Function set to: {controller.get_current_function()}")
    
    # Test destroy originals setting
    controller.set_destroy_originals(True)
    print(f"✓ Destroy originals set to: {controller.get_destroy_originals()}")


def test_file_operations():
    """Test file operations with a small test file."""
    print("Testing file operations...")
    
    controller = MainController()
    controller.set_password("test_password_123")
    controller.set_function(constants.PROGRAM_FUNCTION_ENCRYPT)
    
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write("This is a test file for LiSCrypt encryption.")
        temp_file_path = temp_file.name
    
    try:
        controller.set_selected_files([temp_file_path])
        print(f"✓ Selected test file: {os.path.basename(temp_file_path)}")
        
        # Test encryption
        encrypted_file_path = temp_file_path + constants.FILE_EXTENSION
        
        # For this test, we'll just verify the controller accepts the file
        # without actually running the encryption (which would require a full setup)
        files = controller.get_selected_files()
        assert len(files) == 1
        assert files[0] == temp_file_path
        print("✓ File selection and controller setup successful")
        
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


def main():
    """Run all tests."""
    print("=" * 50)
    print("LiSCrypt Refactored - Basic Tests")
    print("=" * 50)
    
    try:
        test_key_derivation()
        print()
        
        test_crypto_manager()
        print()
        
        test_controller()
        print()
        
        test_file_operations()
        print()
        
        print("=" * 50)
        print("✓ All tests passed successfully!")
        print("=" * 50)
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
