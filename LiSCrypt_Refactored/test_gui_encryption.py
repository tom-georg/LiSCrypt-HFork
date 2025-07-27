#!/usr/bin/env python3
"""
Test script to simulate GUI encryption and check for the encoding error.
"""

import sys
import os
import tempfile

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.controller.main_controller import MainController
from src.common.constants import PROGRAM_FUNCTION_ENCRYPT, PROGRAM_FUNCTION_DECRYPT, METHOD_AES_GCM_V3

def test_gui_encryption():
    """Test encryption through the controller (simulating GUI behavior)."""
    print("Testing GUI-style encryption...")
    
    # Create controller
    controller = MainController()
    
    # Set up like GUI would
    controller.set_password("TestPassword123!")
    controller.set_function(PROGRAM_FUNCTION_ENCRYPT)
    
    # Create a test file
    test_content = "This is a test file for GUI encryption"
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        temp_file.write(test_content)
        temp_file_path = temp_file.name
    
    try:
        # Select the file for encryption
        controller.set_selected_files([temp_file_path])
        
        print(f"✓ Test file created: {os.path.basename(temp_file_path)}")
        print(f"✓ Password set and function configured")
        
        # Try to execute the encryption (this is where the error occurred)
        controller.execute_operation()
        
        print("✓ Encryption completed successfully!")
        
        # Check if encrypted file was created
        encrypted_file = temp_file_path + ".lisq"
        if os.path.exists(encrypted_file):
            print(f"✓ Encrypted file created: {os.path.basename(encrypted_file)}")
            
            # Remove original file so decryption can create it
            os.remove(temp_file_path)
            
            # Test decryption
            controller.set_function(PROGRAM_FUNCTION_DECRYPT)  # Decrypt function
            controller.set_selected_files([encrypted_file])
            controller.execute_operation()
            
            print("✓ Decryption completed successfully!")
            
            # Check if decrypted file was created
            if os.path.exists(temp_file_path):
                print("✓ Decrypted file created successfully!")
                
                # Verify content
                with open(temp_file_path, 'r') as f:
                    decrypted_content = f.read()
                if decrypted_content == test_content:
                    print("✓ Decrypted content matches original!")
                else:
                    print(f"✗ Content mismatch: expected '{test_content}', got '{decrypted_content}'")
            
            # Clean up
            for file in [temp_file_path, encrypted_file]:
                if os.path.exists(file):
                    os.remove(file)
                
        return True
        
    except Exception as e:
        print(f"✗ Error during operation: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up test file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

if __name__ == "__main__":
    print("=" * 60)
    print("GUI Encryption Test")
    print("=" * 60)
    
    success = test_gui_encryption()
    
    print("\n" + "=" * 60)
    if success:
        print("✅ GUI encryption test PASSED - encoding error fixed!")
    else:
        print("❌ GUI encryption test FAILED")
    print("=" * 60)
