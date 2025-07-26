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

"""This module implements the AES-GCM v3 encryption/decryption strategy."""

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .base_strategy import BaseStrategy
from ...common import constants, exceptions
from .. import key_derivation

class AESGCMV3Strategy(BaseStrategy):
    """Implements the AES-GCM v3 strategy."""

    def encrypt(self, input_file_path: str, output_file_path: str, master_key: bytes):
        """Encrypts a file using AES-GCM v3."""
        
        salt = os.urandom(constants.SCRYPT_SALT_LENGTH)
        nonce = os.urandom(constants.AES_GCM_NONCE_LENGTH)

        encryption_key = key_derivation.expand_key(master_key, b"aes-gcm-v3-key", constants.AES_GCM_KEY_LENGTH)

        encryptor = Cipher(
            algorithms.AES(encryption_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        with open(input_file_path, 'rb') as infile, open(output_file_path, 'wb') as outfile:
            # Create and write header
            header = self._create_header(input_file_path, salt, nonce)
            outfile.write(header)
            encryptor.authenticate_additional_data(header)

            # Write null byte sequence
            null_bytes = b'\x00\x00\x00\x00\x00'
            outfile.write(encryptor.update(null_bytes))

            # Write original filename
            original_filename = os.path.basename(input_file_path).encode()
            outfile.write(encryptor.update(original_filename))

            # Write required LiSCrypt version
            required_version = constants.REQUIRED_LISCRYPT_VERSION.encode()
            outfile.write(encryptor.update(required_version))

            # Encrypt file content in chunks
            while chunk := infile.read(constants.FILE_CHUNK_SIZE):
                outfile.write(encryptor.update(chunk))

            # Finalize encryption and write tag
            encryptor.finalize()
            tag = encryptor.tag
            outfile.write(struct.pack('>I', len(tag)))
            outfile.write(tag)

    def decrypt(self, input_file_path: str, output_file_path: str, master_key: bytes):
        """Decrypts a file using AES-GCM v3."""
        with open(input_file_path, 'rb') as infile:
            header_data = self._read_header(infile)
            
            encryption_key = key_derivation.expand_key(master_key, b"aes-gcm-v3-key", constants.AES_GCM_KEY_LENGTH)

            decryptor = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(header_data['nonce']),
                backend=default_backend()
            ).decryptor()

            # Authenticate header
            infile.seek(0)
            header = infile.read(header_data['header_length'])
            decryptor.authenticate_additional_data(header)

            # Read and authenticate encrypted data
            encrypted_data = infile.read() # In a real scenario, read in chunks
            tag = encrypted_data[-16:]
            encrypted_data = encrypted_data[:-16]

            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize_with_tag(tag)

            # Further processing of decrypted data (extracting filename, etc.) would go here
            with open(output_file_path, 'wb') as outfile:
                outfile.write(decrypted_data)


    def _create_header(self, file_path: str, salt: bytes, nonce: bytes) -> bytes:
        """Creates the header for an AES-GCM v3 encrypted file."""
        stat = os.stat(file_path)
        original_filename = os.path.basename(file_path).encode()

        header = b''
        header += b'LiSX'
        header += struct.pack('>H', constants.METHOD_AES_GCM_V3)
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

    def _read_header(self, infile) -> dict:
        """Reads and parses the header of an AES-GCM v3 encrypted file."""
        header_data = {}
        infile.seek(0)
        if infile.read(4) != b'LiSX':
            raise exceptions.LiSCryptError("Not a LiSCrypt file.")
        
        header_data['method'] = struct.unpack('>H', infile.read(2))[0]
        if header_data['method'] != constants.METHOD_AES_GCM_V3:
            raise exceptions.LiSCryptError(f"Unsupported encryption method: {header_data['method']}")

        header_data['scrypt_n'] = struct.unpack('>Q', infile.read(8))[0]
        header_data['scrypt_r'] = struct.unpack('>I', infile.read(4))[0]
        header_data['scrypt_p'] = struct.unpack('>I', infile.read(4))[0]
        salt_len = struct.unpack('>I', infile.read(4))[0]
        header_data['salt'] = infile.read(salt_len)
        nonce_len = struct.unpack('>I', infile.read(4))[0]
        header_data['nonce'] = infile.read(nonce_len)
        header_data['original_modification_time'] = struct.unpack('>Q', infile.read(8))[0]
        header_data['original_access_time'] = struct.unpack('>Q', infile.read(8))[0]
        header_data['original_file_size'] = struct.unpack('>Q', infile.read(8))[0]
        header_data['original_filename_length'] = struct.unpack('>Q', infile.read(8))[0]
        header_data['required_liscrypt_version_length'] = struct.unpack('>H', infile.read(2))[0]
        header_data['header_length'] = infile.tell()
        return header_data
