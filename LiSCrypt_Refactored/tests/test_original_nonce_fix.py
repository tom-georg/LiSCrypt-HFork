#!/usr/bin/env python3

import struct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def test_original_nonce_derivation():
    """Test nonce derivation using the original app's method"""
    
    # Test password and salt from the original file header
    password = "Hallo&Welt!1"
    
    # Read the original file
    with open('abcd-txt.lisq', 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes")
    
    # Parse header to extract scrypt salt
    # Assuming header structure: magic + version + various fields + scrypt salt (32 bytes)
    # Let's extract the scrypt salt from position that worked before
    scrypt_salt_offset = 16  # Based on our previous analysis
    scrypt_salt = data[scrypt_salt_offset:scrypt_salt_offset + 32]
    print(f"Scrypt salt: {scrypt_salt.hex()}")
    
    # Derive master key using scrypt (original parameters)
    scrypt_params = {
        'n': 262144,  # C_SCRYPT_AUFWANDSFAKTOR_WERT
        'r': 8,       # C_SCRYPT_BLOCK_GROESSE  
        'p': 1        # C_SCRYPT_PARALLELISIERUNG_WERT
    }
    
    kdf = Scrypt(
        length=64,  # 512 bits for master key
        salt=scrypt_salt,
        n=scrypt_params['n'],
        r=scrypt_params['r'],
        p=scrypt_params['p'],
        backend=default_backend()
    )
    
    master_key = kdf.derive(password.encode('utf-8'))
    print(f"Master key: {master_key.hex()}")
    
    # Derive encryption key using HKDF (this part should be correct)
    info_key = b'AES-GCM-V3-key'
    hkdf_key = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=32,  # 256 bits for AES key
        info=info_key,
        backend=default_backend()
    )
    encryption_key = hkdf_key.derive(master_key)
    print(f"Encryption key: {encryption_key.hex()}")
    
    # Derive nonce using HKDF with counter 0 (original method)
    counter = 0  # First file encrypted with this key
    info_nonce = b'AES-GCM-V3-nonce-' + str(counter).encode()
    print(f"HKDF info for nonce: {info_nonce}")
    
    hkdf_nonce = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=12,  # 96 bits for GCM nonce
        info=info_nonce,
        backend=default_backend()
    )
    derived_nonce = hkdf_nonce.derive(master_key)
    print(f"Derived nonce (counter 0): {derived_nonce.hex()}")
    
    # Extract nonce from header (at offset 48, 12 bytes)
    header_nonce = data[48:60]
    print(f"Header nonce: {header_nonce.hex()}")
    
    # Compare
    if derived_nonce == header_nonce:
        print("✓ Nonce derivation MATCHES!")
    else:
        print("✗ Nonce derivation MISMATCH")
        
    # Now try to decrypt with the correct nonce
    try:
        # Get encrypted content (after header)
        header_length = 140  # From our previous tests
        encrypted_with_tag = data[header_length:]
        
        # Split encrypted data and tag
        tag_length = 16
        encrypted_data = encrypted_with_tag[:-tag_length]
        tag = encrypted_with_tag[-tag_length:]
        
        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Tag: {tag.hex()}")
        
        # Decrypt using the derived nonce
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(derived_nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Add header as additional authenticated data
        header = data[:header_length]
        decryptor.authenticate_additional_data(header)
        
        # Decrypt
        decrypted = decryptor.update(encrypted_data)
        decryptor.finalize()
        
        print(f"Decrypted data: {decrypted}")
        print(f"Decrypted as text: {decrypted}")
        
        # The decrypted data should start with null bytes, then filename, then version, then actual content
        print("✓ DECRYPTION SUCCESSFUL!")
        
    except Exception as e:
        print(f"✗ Decryption failed: {e}")

if __name__ == '__main__':
    test_original_nonce_derivation()
