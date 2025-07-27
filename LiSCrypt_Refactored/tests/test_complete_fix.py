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
    print(f"Magic: {magic}")
    
    # Read version (2 bytes, big endian)
    version = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    print(f"Version: {version}")
    
    # Read Scrypt parameters
    scrypt_n = struct.unpack('>Q', data[offset:offset+8])[0]
    offset += 8
    print(f"Scrypt N: {scrypt_n}")
    
    scrypt_r = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    print(f"Scrypt r: {scrypt_r}")
    
    scrypt_p = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    print(f"Scrypt p: {scrypt_p}")
    
    # Read Scrypt salt length
    scrypt_salt_length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    print(f"Scrypt salt length: {scrypt_salt_length}")
    
    # Read Scrypt salt
    scrypt_salt = data[offset:offset+scrypt_salt_length]
    offset += scrypt_salt_length
    print(f"Scrypt salt: {scrypt_salt.hex()}")
    
    # Read AES nonce length
    nonce_length = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    print(f"Nonce length: {nonce_length}")
    
    # Read AES nonce
    nonce = data[offset:offset+nonce_length]
    offset += nonce_length
    print(f"Header nonce: {nonce.hex()}")
    
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
    
    print(f"Header length: {offset}")
    print(f"File size: {file_size}")
    print(f"Filename length: {filename_length}")
    
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
        'filename_length': filename_length
    }

def test_complete_decryption():
    """Test complete decryption with proper header parsing"""
    
    password = "Hallo&Welt!1"
    
    # Read the original file
    with open('abcd-txt.lisq', 'rb') as f:
        data = f.read()
    
    print(f"Total file size: {len(data)} bytes")
    print()
    
    # Parse header
    header_info = parse_header_v3(data)
    header_length = header_info['header_length']
    scrypt_salt = header_info['scrypt_salt']
    header_nonce = header_info['nonce']
    
    print()
    
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
    
    # Test nonce derivation with different counters
    for counter in range(5):
        info_nonce = b'AES-GCM-V3-nonce-' + str(counter).encode()
        hkdf_nonce = HKDFExpand(
            algorithm=hashes.SHA512(),
            length=12,  # 96 bits for GCM nonce
            info=info_nonce,
            backend=default_backend()
        )
        derived_nonce = hkdf_nonce.derive(master_key)
        
        print(f"Counter {counter} - Info: {info_nonce}")
        print(f"Counter {counter} - Derived nonce: {derived_nonce.hex()}")
        
        if derived_nonce == header_nonce:
            print(f"✓ NONCE MATCH with counter {counter}!")
            
            # Now try to decrypt
            try:
                # Get encrypted content
                encrypted_with_tag = data[header_length:]
                
                # The encrypted data includes: 5 null bytes + filename + version string + actual content + MAC tag
                # Let's try to decrypt everything first
                
                # Extract tag (last 16 bytes)
                tag = encrypted_with_tag[-16:]
                encrypted_data = encrypted_with_tag[:-16]
                
                print(f"Encrypted data length: {len(encrypted_data)}")
                print(f"Tag: {tag.hex()}")
                
                # Decrypt
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
                
                print(f"Decrypted raw data: {decrypted}")
                print(f"Decrypted hex: {decrypted.hex()}")
                
                # Parse decrypted content
                # First 5 bytes should be nulls
                nulls = decrypted[:5]
                print(f"Null bytes: {nulls.hex()}")
                
                # Next should be filename
                filename_len = header_info['filename_length']
                filename = decrypted[5:5+filename_len]
                print(f"Filename: {filename}")
                
                # Then version string (we need to figure out its length)
                # Let's assume it's something like "1.0.10" = 6 bytes
                remaining_start = 5 + filename_len
                version_part = decrypted[remaining_start:remaining_start+10]  # Try first 10 bytes
                print(f"Version area: {version_part}")
                
                # The rest should be the actual file content
                # Let's try different offsets for the content
                for content_start in range(remaining_start, min(remaining_start + 20, len(decrypted))):
                    content = decrypted[content_start:]
                    try:
                        content_str = content.decode('utf-8')
                        print(f"Content at offset {content_start}: '{content_str}'")
                        if content_str.strip():  # If non-empty content
                            print(f"✓ DECRYPTION SUCCESSFUL! Content: '{content_str}'")
                            return
                    except:
                        pass
                
                print("✓ DECRYPTION SUCCESSFUL but couldn't parse content clearly")
                return
                
            except Exception as e:
                print(f"✗ Decryption failed with counter {counter}: {e}")
        else:
            print(f"✗ Nonce mismatch for counter {counter}")
    
    print("✗ No matching nonce found")

if __name__ == '__main__':
    test_complete_decryption()
