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

"""This module handles all key derivation logic."""

import hashlib
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from ..common import constants

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password using SHA-512 and Scrypt."""
    password_hash = hashlib.sha512(password.encode()).digest()
    return _derive_key(password_hash, salt)

def derive_key_from_keyfile(keyfile_path: str, salt: bytes) -> bytes:
    """Derives an encryption key from a keyfile using SHA-512 and Scrypt."""
    with open(keyfile_path, 'rb') as f:
        keyfile_content = f.read()
    keyfile_hash = hashlib.sha512(keyfile_content).digest()
    return _derive_key(keyfile_hash, salt)

def _derive_key(initial_hash: bytes, salt: bytes) -> bytes:
    """Derives a key using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=constants.SCRYPT_OUTPUT_LENGTH_V3,
        n=constants.SCRYPT_N,
        r=constants.SCRYPT_R,
        p=constants.SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(initial_hash)

def expand_key(master_key: bytes, info: bytes, length: int) -> bytes:
    """Expands a master key to a specific length using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)
