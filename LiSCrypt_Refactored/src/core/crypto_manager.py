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

"""This module manages the selection and execution of encryption/decryption strategies."""

import struct

from .strategies.aes_gcm_v3 import AESGCMV3Strategy
from .strategies.chacha20_v3_1 import ChaCha20V3_1Strategy
from .crypto_constants import METHOD_AES_GCM_V3, METHOD_CHACHA20_V3_1, MAGIC_BYTES
# TODO: Move exceptions to core to eliminate this dependency
from ..common.exceptions import LiSCryptError

class CryptoManager:
    """Manages encryption and decryption operations by selecting the appropriate strategy."""

    def __init__(self):
        self._strategies = {
            METHOD_AES_GCM_V3: AESGCMV3Strategy(),
            METHOD_CHACHA20_V3_1: ChaCha20V3_1Strategy(),
            # Add other strategies here as they are implemented
        }

    def encrypt_file(self, input_file_path: str, output_file_path: str, password: str, method_id: int, keyfile_path: str = None):
        """Encrypts a file using the specified method."""
        strategy = self._strategies.get(method_id)
        if not strategy:
            raise LiSCryptError(f"Unsupported encryption method ID: {method_id}")
        
        # For now, we only support password authentication in AES-GCM
        # Keyfile support can be added later if needed
        if keyfile_path:
            raise LiSCryptError("Keyfile authentication not yet supported")
            
        strategy.encrypt(input_file_path, output_file_path, password, method_id)

    def decrypt_file(self, input_file_path: str, output_file_path: str, password: str, keyfile_path: str = None):
        """Decrypts a file by reading its header and selecting the appropriate strategy."""
        method_id = self._get_method_id_from_file(input_file_path)
        strategy = self._strategies.get(method_id)
        if not strategy:
            raise LiSCryptError(f"Unsupported decryption method ID: {method_id}")
            
        # For now, we only support password authentication in AES-GCM
        # Keyfile support can be added later if needed
        if keyfile_path:
            raise LiSCryptError("Keyfile authentication not yet supported")
            
        strategy.decrypt(input_file_path, output_file_path, password)

    def _get_method_id_from_file(self, file_path: str) -> int:
        """Reads the encryption method ID from the file header."""
        with open(file_path, 'rb') as f:
            magic_bytes = f.read(4)
            if magic_bytes != MAGIC_BYTES:
                raise LiSCryptError("Not a LiSCrypt file.")
            method_id = struct.unpack('>H', f.read(2))[0]
        return method_id
