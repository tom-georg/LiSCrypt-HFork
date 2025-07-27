#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.strategies.aes_gcm_v3 import AESGCMV3Strategy
from src.common.constants import METHOD_AES_GCM_V3

def test_decrypt_original():
    """Test decrypting the original file with our fixed strategy."""
    
    strategy = AESGCMV3Strategy()
    
    # Test decryption of original file
    try:
        strategy.decrypt(
            input_file_path='abcd-txt.lisq',
            output_file_path='decrypted_abcd.txt',
            password='Hallo&Welt!1'
        )
        
        # Read and verify content
        with open('decrypted_abcd.txt', 'r') as f:
            content = f.read()
        
        print(f"✓ SUCCESS! Decrypted content: '{content}'")
        
        if content == 'Hallo&Welt!1':
            print("✓ Content matches expected value!")
        else:
            print(f"✗ Content mismatch. Expected 'Hallo&Welt!1', got '{content}'")
            
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        import traceback
        traceback.print_exc()

def test_encrypt_decrypt_round_trip():
    """Test encryption and decryption with our strategy."""
    
    strategy = AESGCMV3Strategy()
    
    # Create test file
    test_content = "This is a test file for the new strategy."
    with open('test_input.txt', 'w') as f:
        f.write(test_content)
    
    try:
        # Encrypt
        strategy.encrypt(
            input_file_path='test_input.txt',
            output_file_path='test_encrypted.lisq',
            password='TestPassword123',
            method_id=METHOD_AES_GCM_V3
        )
        print("✓ Encryption successful")
        
        # Decrypt
        strategy.decrypt(
            input_file_path='test_encrypted.lisq',
            output_file_path='test_decrypted.txt',
            password='TestPassword123'
        )
        print("✓ Decryption successful")
        
        # Verify content
        with open('test_decrypted.txt', 'r') as f:
            decrypted_content = f.read()
        
        if decrypted_content == test_content:
            print("✓ Round-trip test successful!")
        else:
            print(f"✗ Content mismatch. Expected '{test_content}', got '{decrypted_content}'")
            
    except Exception as e:
        print(f"✗ Round-trip test failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Cleanup
        for file in ['test_input.txt', 'test_encrypted.lisq', 'test_decrypted.txt']:
            if os.path.exists(file):
                os.remove(file)

if __name__ == '__main__':
    print("Testing AES-GCM v3 strategy with backward compatibility...")
    print()
    
    print("1. Testing decryption of original file:")
    test_decrypt_original()
    print()
    
    print("2. Testing round-trip encryption/decryption:")
    test_encrypt_decrypt_round_trip()
    print()
    
    print("Test complete!")
