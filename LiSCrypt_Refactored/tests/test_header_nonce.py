#!/usr/bin/env python3

import struct
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def parse_header_v3(data):
    """Parse the AES-GCM V3 header according to the original structure"""
    offset = 0
    
    # Read magic bytes "LiSX"
    magic = data[offset:offset+4]
    offset += 4
    
    # Read version (2 bytes, big endian)
    version = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # Read Scrypt parameters
    scrypt_n = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    scrypt_r = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    scrypt_p = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Read Scrypt salt length
    scrypt_salt_length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Read Scrypt salt
    scrypt_salt = data[offset:offset+scrypt_salt_length]
    offset += scrypt_salt_length
    
    # Read AES nonce length
    nonce_length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    
    # Read AES nonce
    nonce = data[offset:offset+nonce_length]
    offset += nonce_length
    
    # Read timestamps and file info
    mtime = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    atime = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    file_size = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    filename_length = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    
    version_string_length = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    return {
        'magic': magic,
        'version': version,
        'scrypt_n': scrypt_n,
        'scrypt_r': scrypt_r,
        'scrypt_p': scrypt_p,
        'scrypt_salt': scrypt_salt,
        'nonce': nonce,
        'header_length': offset,
        'file_size': file_size,
        'filename_length': filename_length,
        'version_string_length': version_string_length
    }

def test_decrypt_with_header_nonce():
    """Test decryption using the nonce from the header directly"""
    
    password = "Hallo&Welt!1"
    
    # Read the original file
    with open('abcd-txt.lisq', 'rb') as f:
        data = f.read()
    
    print(f"Total file size: {len(data)} bytes")
    
    # Parse header
    header_info = parse_header_v3(data)
    header_length = header_info['header_length']
    scrypt_salt = header_info['scrypt_salt']
    nonce = header_info['nonce']  # Use nonce directly from header
    
    print(f"Header length: {header_length}")
    print(f"Using nonce from header: {nonce.hex()}")
    print(f"File size from header: {header_info['file_size']}")
    print(f"Filename length: {header_info['filename_length']}")
    print(f"Version string length: {header_info['version_string_length']}")
    
    # Derive master key using scrypt
    kdf = Scrypt(
        length=64,  # 512 bits for master key
        salt=scrypt_salt,
        n=header_info['scrypt_n'],
        r=header_info['scrypt_r'],
        p=header_info['scrypt_p'],
        backend=default_backend()
    )
    
    master_key = kdf.derive(password.encode('utf-8'))
    print(f"Master key: {master_key.hex()}")
    
    # Derive encryption key using HKDF
    hkdf_key = HKDFExpand(
        algorithm=hashes.SHA512(),
        length=32,  # 256 bits for AES key
        info=b'AES-GCM-V3-key',
        backend=default_backend()
    )
    encryption_key = hkdf_key.derive(master_key)
    print(f"Encryption key: {encryption_key.hex()}")
    
    # Try to decrypt using header nonce
    try:
        # Get encrypted content
        encrypted_with_tag = data[header_length:]
        
        # Extract tag (last 16 bytes)
        tag = encrypted_with_tag[-16:]
        encrypted_data = encrypted_with_tag[:-16]
        
        print(f"Encrypted data length: {len(encrypted_data)}")
        print(f"Tag: {tag.hex()}")
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Add header as additional authenticated data
        header = data[:header_length]
        decryptor.authenticate_additional_data(header)
        
        # Decrypt
        decrypted = decryptor.update(encrypted_data)
        decryptor.finalize()
        
        print(f"✓ DECRYPTION SUCCESSFUL!")
        print(f"Decrypted raw data: {decrypted}")
        print(f"Decrypted hex: {decrypted.hex()}")
        
        # Parse decrypted content
        offset = 0
        
        # First 5 bytes should be nulls
        nulls = decrypted[offset:offset+5]
        offset += 5
        print(f"Null bytes: {nulls.hex()} (should be 0000000000)")
        
        # Next should be filename
        filename_len = header_info['filename_length']
        filename = decrypted[offset:offset+filename_len]
        offset += filename_len
        print(f"Filename: '{filename.decode('utf-8')}'")
        
        # Then version string
        version_len = header_info['version_string_length']
        version_str = decrypted[offset:offset+version_len]
        offset += version_len
        print(f"Version string: '{version_str.decode('utf-8')}'")
        
        # The rest should be the actual file content
        content = decrypted[offset:]
        print(f"File content: '{content.decode('utf-8')}'")
        
        print(f"✓ COMPLETE SUCCESS! Original file content: '{content.decode('utf-8')}'")
        
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_decrypt_with_header_nonce()
