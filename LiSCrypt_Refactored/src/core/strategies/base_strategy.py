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

"""This module defines the base class for all encryption/decryption strategies."""

from abc import ABC, abstractmethod

class BaseStrategy(ABC):
    """Abstract base class for encryption/decryption strategies."""

    @abstractmethod
    def encrypt(self, input_file_path: str, output_file_path: str, key: bytes):
        """Encrypts a file."""
        pass

    @abstractmethod
    def decrypt(self, input_file_path: str, output_file_path: str, key: bytes):
        """Decrypts a file."""
        pass
