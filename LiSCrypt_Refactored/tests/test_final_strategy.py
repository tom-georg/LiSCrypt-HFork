#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.strategies.aes_gcm_v3_fixed import AESGCMV3Strategy

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

if __name__ == '__main__':
    print("Testing AES-GCM v3 strategy with backward compatibility...")
    test_decrypt_original()
