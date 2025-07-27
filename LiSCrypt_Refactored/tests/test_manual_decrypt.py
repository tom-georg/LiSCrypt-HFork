#!/usr/bin/env python3
"""
Try to decrypt by manually following exact original process step by step
"""

import sys
import struct
sys.path.insert(0, 'src')

from src.core import key_derivation
from src.common import constants
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def manual_decrypt_test():
    """Manually decrypt step by step to isolate the issue"""
    
    password = "Hallo&Welt!1"
    file_path = "abcd-txt.lisq"
    
    with open(file_path, 'rb') as f:
        # Read file step by step exactly as original would
        magic = f.read(4)
        method_id = struct.unpack('>H', f.read(2))[0]
        scrypt_n = struct.unpack('>Q', f.read(8))[0]
        scrypt_r = struct.unpack('>I', f.read(4))[0]
        scrypt_p = struct.unpack('>I', f.read(4))[0]
        salt_len = struct.unpack('>I', f.read(4))[0]
        salt = f.read(salt_len)
        nonce_len = struct.unpack('>I', f.read(4))[0]
        nonce = f.read(nonce_len)
        
        # Rest of header
        mod_time = struct.unpack('>Q', f.read(8))[0]
        acc_time = struct.unpack('>Q', f.read(8))[0]
        file_size = struct.unpack('>Q', f.read(8))[0]
        filename_len = struct.unpack('>Q', f.read(8))[0]
        version_len = struct.unpack('>H', f.read(2))[0]
        
        # Now read encrypted data and tag
        expected_data_len = 5 + filename_len + version_len + file_size
        encrypted_data = f.read(expected_data_len)
        tag_len = struct.unpack('>I', f.read(4))[0]
        tag = f.read(tag_len)
    
    print(f"Read {len(encrypted_data)} bytes of encrypted data")
    print(f"Encrypted data: {encrypted_data.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Tag: {tag.hex()}")
    
    # Derive keys
    master_key = key_derivation.derive_key_from_password(password, salt)
    encryption_key = key_derivation.expand_key(master_key, b"AES-GCM-V3-key", 32)
    
    print(f"Master key: {master_key.hex()}")
    print(f"Encryption key: {encryption_key.hex()}")
    
    # Create header for authentication - test different header lengths
    header_lens_to_test = [140, 138, 142, 136, 144]
    
    for header_len in header_lens_to_test:
        print(f"\n--- Testing header length: {header_len} ---")
        
        with open(file_path, 'rb') as f:
            header_data = f.read(header_len)
        
        try:
            # Create decryptor
            decryptor = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            
            # Authenticate header
            decryptor.authenticate_additional_data(header_data)
            print(f"✓ Header {header_len} authenticated successfully")
            
            # Decrypt data
            decrypted = decryptor.update(encrypted_data)
            print(f"✓ Data decrypted: {decrypted.hex()}")
            
            # Finalize (this is where the tag verification happens)
            decryptor.finalize()
            print(f"✓ SUCCESS! Header length {header_len} works!")
            
            # Parse the decrypted data
            null_bytes = decrypted[:5]
            filename = decrypted[5:5+filename_len].decode()
            version = decrypted[5+filename_len:5+filename_len+version_len].decode()
            content = decrypted[5+filename_len+version_len:]
            
            print(f"✓ Null bytes: {null_bytes.hex()}")
            print(f"✓ Filename: '{filename}'")
            print(f"✓ Version: '{version}'")
            print(f"✓ Content: '{content.decode()}'")
            return
            
        except Exception as e:
            print(f"✗ Header length {header_len} failed: {e}")

if __name__ == "__main__":
    manual_decrypt_test()
