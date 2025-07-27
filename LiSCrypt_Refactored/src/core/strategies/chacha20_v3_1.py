# LiSCrypt - File encryption program using AES-GCM-256 or ChaCha20+HMAC
# Copyright(C) 2018-2022 QUA-LiS NRW
#
# This file is part of LiSCrypt.
#
# LiSCrypt is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# LiSCrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LiSCrypt.  If not, see <https://www.gnu.org/licenses/>.

"""This module implements the ChaCha20+HMAC v3.1 encryption/decryption strategy."""

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions as cryptography_exceptions

from .base_strategy import BaseStrategy
from ..crypto_constants import METHOD_CHACHA20_V3_1, MAGIC_BYTES
from ...common import constants, exceptions
from .. import key_derivation

class ChaCha20V3_1Strategy(BaseStrategy):
    """Implements the ChaCha20+HMAC v3.1 strategy."""

    def encrypt(self, input_file_path: str, output_file_path: str, master_key: bytes):
        """Encrypts a file using ChaCha20+HMAC v3.1."""
        salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
        nonce = os.urandom(constants.CHACHA20_NONCE_LENGTH)

        encryption_key = key_derivation.expand_key(master_key, b"chacha20-v3.1-key", constants.CHACHA20_KEY_LENGTH)
        hmac_key = key_derivation.expand_key(master_key, b"chacha20-v3.1-hmac-key", constants.HMAC_SHA512_KEY_LENGTH)

        encryptor = Cipher(
            algorithms.ChaCha20(encryption_key, nonce),
            mode=None,
            backend=default_backend()
        ).encryptor()

        hmac_builder = hmac.HMAC(hmac_key, hashes.SHA512(), backend=default_backend())

        with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            header = self._create_header(input_file_path, salt, nonce)
            outfile.write(header)
            hmac_builder.update(header)

            # Null byte sequence
            null_bytes = b'\x00\x00\x00\x00\x00'
            encrypted_null_bytes = encryptor.update(null_bytes)
            outfile.write(encrypted_null_bytes)
            hmac_builder.update(encrypted_null_bytes)

            # Original filename
            original_filename = os.path.basename(input_file_path).encode()
            encrypted_filename = encryptor.update(original_filename)
            outfile.write(encrypted_filename)
            hmac_builder.update(encrypted_filename)

            # Required LiSCrypt version
            required_version = constants.REQUIRED_LISCRYPT_VERSION.encode()
            encrypted_version = encryptor.update(required_version)
            outfile.write(encrypted_version)
            hmac_builder.update(encrypted_version)

            # File content
            while chunk := infile.read(constants.FILE_CHUNK_SIZE):
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)
                hmac_builder.update(encrypted_chunk)

            # HMAC tag
            tag = hmac_builder.finalize()
            outfile.write(struct.pack('>I', len(tag)))
            outfile.write(tag)

    def decrypt(self, input_file_path: str, output_file_path: str, master_key: bytes):
        """Decrypts a file using ChaCha20+HMAC v3.1."""
        with open(input_file_path, 'rb') as infile:
            header_data = self._read_header(infile)

            encryption_key = key_derivation.expand_key(master_key, b"chacha20-v3.1-key", constants.CHACHA20_KEY_LENGTH)
            hmac_key = key_derivation.expand_key(master_key, b"chacha20-v3.1-hmac-key", constants.HMAC_SHA512_KEY_LENGTH)

            decryptor = Cipher(
                algorithms.ChaCha20(encryption_key, header_data['nonce']),
                mode=None,
                backend=default_backend()
            ).decryptor()

            hmac_builder = hmac.HMAC(hmac_key, hashes.SHA512(), backend=default_backend())

            # Authenticate header
            infile.seek(0)
            header_bytes = infile.read(header_data['header_length'])
            hmac_builder.update(header_bytes)

            # Authenticate and decrypt null byte sequence
            null_bytes_encrypted = infile.read(5)
            hmac_builder.update(null_bytes_encrypted)
            null_bytes_decrypted = decryptor.update(null_bytes_encrypted)
            if null_bytes_decrypted != b'\x00\x00\x00\x00\x00':
                raise exceptions.LiSCryptError("Null byte sequence not recognized.")

            # Authenticate and decrypt original filename
            original_filename_len = header_data['original_filename_length']
            original_filename_encrypted = infile.read(original_filename_len)
            hmac_builder.update(original_filename_encrypted)
            original_filename_decrypted = decryptor.update(original_filename_encrypted)

            # Authenticate and decrypt required LiSCrypt version
            required_version_len = header_data['required_liscrypt_version_length']
            required_version_encrypted = infile.read(required_version_len)
            hmac_builder.update(required_version_encrypted)
            required_version_decrypted = decryptor.update(required_version_encrypted).decode()

            # Verify LiSCrypt version
            # This part needs a helper function to compare versions, similar to LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen
            # For now, a simple check:
            if required_version_decrypted != constants.REQUIRED_LISCRYPT_VERSION:
                 raise exceptions.LiSCryptTooOldError(f"LiSCrypt update required. File encrypted with {required_version_decrypted}, current is {constants.REQUIRED_LISCRYPT_VERSION}", "")

            # Authenticate and decrypt file content in chunks
            current_pos = infile.tell()
            infile.seek(0, os.SEEK_END)
            file_end_pos = infile.tell()
            infile.seek(current_pos)

            remaining_bytes_to_read = header_data['original_file_size'] # Total encrypted data size
            
            # Read and authenticate encrypted data chunks
            encrypted_chunks = b''
            while remaining_bytes_to_read > 0:
                chunk_size = min(constants.FILE_CHUNK_SIZE, remaining_bytes_to_read)
                chunk = infile.read(chunk_size)
                if not chunk:
                    raise exceptions.LiSCryptError("Unexpected end of file during decryption.")
                hmac_builder.update(chunk)
                encrypted_chunks += chunk
                remaining_bytes_to_read -= len(chunk)

            # Read and verify HMAC tag
            tag_len = struct.unpack('>I', infile.read(struct.calcsize('I')))[0]
            tag = infile.read(tag_len)
            
            try:
                hmac_builder.verify(tag)
            except cryptography_exceptions.InvalidSignature:
                raise exceptions.LiSCryptError("Invalid HMAC signature. File may be corrupted or tampered with.")

            # Decrypt and write to output file
            with open(output_file_path, 'wb') as outfile:
                # Decrypt the main encrypted data (null bytes, filename, version, file content)
                # This is a simplified approach. In a real scenario, you'd decrypt as you read.
                # For now, we'll decrypt the whole chunk that was authenticated.
                decrypted_full_content = decryptor.update(encrypted_chunks) + decryptor.finalize()
                
                # Skip the null bytes, filename, and version from the decrypted content
                # This assumes the order of encryption was: null_bytes, filename, version, file_content
                offset = 5 + original_filename_len + required_version_len
                outfile.write(decrypted_full_content[offset:])

        # Restore original file metadata (modification and access times)
        if header_data.get('original_modification_time') and header_data.get('original_access_time'):
            os.utime(output_file_path, (header_data['original_access_time'], header_data['original_modification_time']))

            # Authenticate and decrypt original filename
            original_filename_len = header_data['original_filename_length']
            original_filename_encrypted = infile.read(original_filename_len)
            hmac_builder.update(original_filename_encrypted)
            original_filename_decrypted = decryptor.update(original_filename_encrypted)

            # Authenticate and decrypt required LiSCrypt version
            required_version_len = header_data['required_liscrypt_version_length']
            required_version_encrypted = infile.read(required_version_len)
            hmac_builder.update(required_version_encrypted)
            required_version_decrypted = decryptor.update(required_version_encrypted).decode()

            # Verify LiSCrypt version
            # This part needs a helper function to compare versions, similar to LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen
            # For now, a simple check:
            if required_version_decrypted != constants.REQUIRED_LISCRYPT_VERSION:
                 raise exceptions.LiSCryptTooOldError(f"LiSCrypt update required. File encrypted with {required_version_decrypted}, current is {constants.REQUIRED_LISCRYPT_VERSION}", "")

            # Authenticate and decrypt file content in chunks
            current_pos = infile.tell()
            infile.seek(0, os.SEEK_END)
            file_end_pos = infile.tell()
            infile.seek(current_pos)

            remaining_bytes_to_read = header_data['original_file_size'] # Total encrypted data size
            
            # Read and authenticate encrypted data chunks
            encrypted_chunks = b''
            while remaining_bytes_to_read > 0:
                chunk_size = min(constants.FILE_CHUNK_SIZE, remaining_bytes_to_read)
                chunk = infile.read(chunk_size)
                if not chunk:
                    raise exceptions.LiSCryptError("Unexpected end of file during decryption.")
                hmac_builder.update(chunk)
                encrypted_chunks += chunk
                remaining_bytes_to_read -= len(chunk)

            # Read and verify HMAC tag
            tag_len = struct.unpack('>I', infile.read(struct.calcsize('I')))[0]
            tag = infile.read(tag_len)
            
            try:
                hmac_builder.verify(tag)
            except cryptography_exceptions.InvalidSignature:
                raise exceptions.LiSCryptError("Invalid HMAC signature. File may be corrupted or tampered with.")

            # Decrypt and write to output file
            with open(output_file_path, 'wb') as outfile:
                # Decrypt the main encrypted data (null bytes, filename, version, file content)
                # This is a simplified approach. In a real scenario, you'd decrypt as you read.
                # For now, we'll decrypt the whole chunk that was authenticated.
                decrypted_full_content = decryptor.update(encrypted_chunks) + decryptor.finalize()
                
                # Skip the null bytes, filename, and version from the decrypted content
                # This assumes the order of encryption was: null_bytes, filename, version, file_content
                offset = 5 + original_filename_len + required_version_len
                outfile.write(decrypted_full_content[offset:])

        # Restore original file metadata (modification and access times)
        if header_data.get('original_modification_time') and header_data.get('original_access_time'):
            os.utime(output_file_path, (header_data['original_access_time'], header_data['original_modification_time']))

    def _create_header(self, file_path: str, salt: bytes, nonce: bytes) -> bytes:
        """Creates the header for a ChaCha20+HMAC v3.1 encrypted file."""
        stat = os.stat(file_path)
        original_filename = os.path.basename(file_path).encode()

        header = b''
        header += b'LiSX'
        header += struct.pack('>H', METHOD_CHACHA20_V3_1)
        header += struct.pack('>Q', constants.SCRYPT_N)
        header += struct.pack('>I', constants.SCRYPT_R)
        header += struct.pack('>I', constants.SCRYPT_P)
        header += struct.pack('>I', len(salt))
        header += salt
        header += struct.pack('>I', len(nonce))
        header += nonce
        header += struct.pack('>Q', int(round(stat.st_mtime_ns)))
        header += struct.pack('>Q', int(round(stat.st_atime_ns)))
        header += struct.pack('>Q', stat.st_size)
        header += struct.pack('>Q', len(original_filename))
        header += struct.pack('>H', len(constants.REQUIRED_LISCRYPT_VERSION.encode()))
        return header

    def _read_header(self, file_handle) -> dict:
        """Reads and parses the header from a ChaCha20+HMAC v3.1 encrypted file."""
        header_data = {}
        
        # Read file signature
        signature = file_handle.read(4)
        if signature != b'LiSX':
            raise exceptions.LiSCryptError("Invalid file signature")
        
        # Read method ID
        method_id = struct.unpack('>H', file_handle.read(2))[0]
        if method_id != METHOD_CHACHA20_V3_1:
            raise exceptions.LiSCryptError(f"Unexpected method ID: {method_id}")
        
        # Read Scrypt parameters
        header_data['scrypt_n'] = struct.unpack('>Q', file_handle.read(8))[0]
        header_data['scrypt_r'] = struct.unpack('>I', file_handle.read(4))[0]
        header_data['scrypt_p'] = struct.unpack('>I', file_handle.read(4))[0]
        
        # Read salt
        salt_len = struct.unpack('>I', file_handle.read(4))[0]
        header_data['salt'] = file_handle.read(salt_len)
        
        # Read nonce
        nonce_len = struct.unpack('>I', file_handle.read(4))[0]
        header_data['nonce'] = file_handle.read(nonce_len)
        
        # Read original file times
        header_data['original_modification_time'] = struct.unpack('>Q', file_handle.read(8))[0] / 1e9
        header_data['original_access_time'] = struct.unpack('>Q', file_handle.read(8))[0] / 1e9
        
        # Read original file size
        header_data['original_file_size'] = struct.unpack('>Q', file_handle.read(8))[0]
        
        # Read original filename length
        header_data['original_filename_length'] = struct.unpack('>Q', file_handle.read(8))[0]
        
        # Read required LiSCrypt version length  
        header_data['required_liscrypt_version_length'] = struct.unpack('>H', file_handle.read(2))[0]
        
        # Calculate header length
        header_data['header_length'] = file_handle.tell()
        
        return header_data
