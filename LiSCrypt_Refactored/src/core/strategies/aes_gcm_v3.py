"""
AES-GCM v3 encryption strategy for LiSCrypt.
This strategy matches the exact file format used by the original LiSCrypt application,
ensuring full backward compatibility with files encrypted by the original LiSCrypt.
"""

import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions as cryptography_exceptions

from src.common import constants, exceptions


class AESGCMV3Strategy:
    """
    AES-GCM v3 encryption strategy that follows the original LiSCrypt format exactly.
    
    This implementation ensures full backward compatibility with files encrypted by
    the original LiSCrypt application by following the exact same:
    - Password hashing (SHA512)
    - Key derivation (Scrypt + HKDF)
    - File format (header structure, data layout)
    - Authentication tag handling
    """

    def encrypt(self, input_file_path: str, output_file_path: str, password: str, method_id: int):
        """
        Encrypts a file using AES-GCM v3, following the exact original format.
        
        Args:
            input_file_path: Path to the file to encrypt
            output_file_path: Path where the encrypted file will be saved
            password: Password to use for encryption
            method_id: Method identifier (should be constants.METHOD_AES_GCM_V3)
        """
        # Get file stats and read content
        stat = os.stat(input_file_path)
        original_filename = os.path.basename(input_file_path)
        
        with open(input_file_path, 'rb') as infile:
            file_content = infile.read()
        
        # Generate random salt for Scrypt
        salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
        
        # Calculate SHA512 of password (as original does)
        password_hash = hashlib.sha512(password.encode('utf-8')).digest()
        
        # Derive master key using Scrypt with SHA512 hash
        kdf = Scrypt(
            salt=salt,
            length=64,  # 512 bits for master key
            n=constants.SCRYPT_N,
            r=constants.SCRYPT_R,
            p=constants.SCRYPT_P,
            backend=default_backend()
        )
        master_key = kdf.derive(password_hash)
        
        # Derive encryption key using HKDF from master key
        hkdf_key = HKDFExpand(
            algorithm=hashes.SHA512(),
            length=32,  # 256 bits for AES key
            info=b'AES-GCM-V3-key',
            backend=default_backend()
        )
        encryption_key = hkdf_key.derive(master_key)
        
        # Derive nonce using HKDF with counter (as original does)
        counter = 0  # First file with this key
        info_nonce = b'AES-GCM-V3-nonce-' + str(counter).encode()
        hkdf_nonce = HKDFExpand(
            algorithm=hashes.SHA512(),
            length=12,  # 96 bits for GCM nonce
            info=info_nonce,
            backend=default_backend()
        )
        nonce = hkdf_nonce.derive(master_key)
        
        # Create header (following original format exactly)
        header = b''
        header += b'LiSX'  # Magic bytes
        header += struct.pack('>H', method_id)  # Method ID
        header += struct.pack('>Q', constants.SCRYPT_N)  # Scrypt N
        header += struct.pack('>I', constants.SCRYPT_R)  # Scrypt r
        header += struct.pack('>I', constants.SCRYPT_P)  # Scrypt p
        header += struct.pack('>I', constants.SCRYPT_SALT_LENGTH)  # Salt length
        header += salt  # Salt
        header += struct.pack('>I', constants.AES_GCM_NONCE_LENGTH)  # Nonce length
        header += nonce  # Nonce
        header += struct.pack('>Q', int(round(stat.st_mtime_ns)))  # Modification time
        header += struct.pack('>Q', int(round(stat.st_atime_ns)))  # Access time
        header += struct.pack('>Q', stat.st_size)  # File size
        header += struct.pack('>Q', len(original_filename.encode()))  # Filename length
        header += struct.pack('>H', len(constants.REQUIRED_LISCRYPT_VERSION))  # Version length
        
        # Create encryptor
        encryptor = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        
        # Write encrypted file
        with open(output_file_path, 'wb') as outfile:
            # Write header
            outfile.write(header)
            
            # Authenticate header
            encryptor.authenticate_additional_data(header)
            
            # Encrypt and write data in original order
            outfile.write(encryptor.update(b'\x00\x00\x00\x00\x00'))  # 5 null bytes
            outfile.write(encryptor.update(original_filename.encode()))  # Filename
            outfile.write(encryptor.update(constants.REQUIRED_LISCRYPT_VERSION.encode()))  # Version
            outfile.write(encryptor.update(file_content))  # File content
            
            # Finalize encryption
            encryptor.finalize()
            
            # Write MAC tag with length prefix (as original does)
            tag = encryptor.tag
            outfile.write(struct.pack('>I', len(tag)))  # Tag length
            outfile.write(tag)  # Tag

    def decrypt(self, input_file_path: str, output_file_path: str, password: str):
        """
        Decrypts a file using AES-GCM v3, following the exact original format.
        
        This method can decrypt files created by both the original LiSCrypt
        application and this refactored version.
        
        Args:
            input_file_path: Path to the encrypted file
            output_file_path: Path where the decrypted file will be saved
            password: Password to use for decryption
        """
        with open(input_file_path, 'rb') as infile:
            # Read and parse header
            header_data = self._parse_header(infile)
            
            # Calculate SHA512 of password (as original does)
            password_hash = hashlib.sha512(password.encode('utf-8')).digest()
            
            # Derive master key using Scrypt with stored salt
            kdf = Scrypt(
                salt=header_data['salt'],
                length=64,  # 512 bits for master key
                n=header_data['scrypt_n'],
                r=header_data['scrypt_r'],
                p=header_data['scrypt_p'],
                backend=default_backend()
            )
            master_key = kdf.derive(password_hash)
            
            # Derive encryption key using HKDF from master key
            hkdf_key = HKDFExpand(
                algorithm=hashes.SHA512(),
                length=32,  # 256 bits for AES key
                info=b'AES-GCM-V3-key',
                backend=default_backend()
            )
            encryption_key = hkdf_key.derive(master_key)
            
            # Use nonce from header (critical for backward compatibility)
            nonce = header_data['nonce']
            
            # Read encrypted data and tag
            remaining_data = infile.read()
            
            # Parse tag (last 4 bytes are tag length, then tag)
            tag_length_bytes = remaining_data[-20:-16]  # 4 bytes before last 16
            tag_length = struct.unpack('>I', tag_length_bytes)[0]
            tag = remaining_data[-tag_length:]
            encrypted_data = remaining_data[:-4-tag_length]
            
            # Create decryptor
            decryptor = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            
            # Authenticate header
            decryptor.authenticate_additional_data(header_data['header_bytes'])
            
            # Decrypt data
            try:
                decrypted_data = decryptor.update(encrypted_data)
                decryptor.finalize()
            except cryptography_exceptions.InvalidTag:
                raise exceptions.AuthenticationError("Invalid password or corrupted file")
            
            # Parse decrypted content
            offset = 0
            
            # Skip null bytes (5 bytes)
            offset += 5
            
            # Skip filename
            filename_length = header_data['filename_length']
            offset += filename_length
            
            # Skip version string
            version_length = header_data['version_length']
            offset += version_length
            
            # Extract file content
            file_content = decrypted_data[offset:]
            
            # Write decrypted file
            with open(output_file_path, 'wb') as outfile:
                outfile.write(file_content)

    def _parse_header(self, file_obj):
        """
        Parses the header of an encrypted file and returns header data.
        
        Args:
            file_obj: Open file object positioned at the start of the file
            
        Returns:
            dict: Header data including all parsed fields and raw header bytes
        """
        start_pos = file_obj.tell()
        
        # Read magic bytes
        magic = file_obj.read(4)
        if magic != b'LiSX':
            raise exceptions.InvalidFileFormatError("Invalid magic bytes")
        
        # Read method ID
        method_id = struct.unpack('>H', file_obj.read(2))[0]
        
        # Read Scrypt parameters
        scrypt_n = struct.unpack('>Q', file_obj.read(8))[0]
        scrypt_r = struct.unpack('>I', file_obj.read(4))[0]
        scrypt_p = struct.unpack('>I', file_obj.read(4))[0]
        
        # Read salt
        salt_length = struct.unpack('>I', file_obj.read(4))[0]
        salt = file_obj.read(salt_length)
        
        # Read nonce
        nonce_length = struct.unpack('>I', file_obj.read(4))[0]
        nonce = file_obj.read(nonce_length)
        
        # Read file metadata
        mtime = struct.unpack('>Q', file_obj.read(8))[0]
        atime = struct.unpack('>Q', file_obj.read(8))[0]
        file_size = struct.unpack('>Q', file_obj.read(8))[0]
        filename_length = struct.unpack('>Q', file_obj.read(8))[0]
        version_length = struct.unpack('>H', file_obj.read(2))[0]
        
        # Calculate header length
        header_end_pos = file_obj.tell()
        header_length = header_end_pos - start_pos
        
        # Read full header for authentication
        file_obj.seek(start_pos)
        header_bytes = file_obj.read(header_length)
        
        return {
            'magic': magic,
            'method_id': method_id,
            'scrypt_n': scrypt_n,
            'scrypt_r': scrypt_r,
            'scrypt_p': scrypt_p,
            'salt': salt,
            'nonce': nonce,
            'mtime': mtime,
            'atime': atime,
            'file_size': file_size,
            'filename_length': filename_length,
            'version_length': version_length,
            'header_length': header_length,
            'header_bytes': header_bytes
        }