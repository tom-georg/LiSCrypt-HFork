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

"""This module contains the main controller that bridges UI and core logic."""

import os
from typing import List, Optional

from ..core.crypto_manager import CryptoManager
from ..core.crypto_constants import METHOD_AES_GCM_V3, METHOD_CHACHA20_V3_1
from ..common import constants, exceptions


class MainController:
    """Main controller that handles interactions between UI and core logic."""

    def __init__(self):
        self.crypto_manager = CryptoManager()
        self._selected_files: List[str] = []
        self._password: Optional[str] = None
        self._keyfile_path: Optional[str] = None
        self._current_function: str = constants.PROGRAM_FUNCTION_ENCRYPT
        self._destroy_originals: bool = False

    def set_selected_files(self, file_paths: List[str]):
        """Sets the list of files to process."""
        self._selected_files = file_paths

    def set_password(self, password: str):
        """Sets the password for encryption/decryption."""
        if len(password) < constants.PASSWORD_KEYFILE_MIN_LENGTH:
            raise exceptions.NoPasswordError("Password too short")
        self._password = password

    def set_keyfile(self, keyfile_path: str):
        """Sets the keyfile path for encryption/decryption."""
        if not os.path.exists(keyfile_path):
            raise exceptions.DialogDisplayError("Keyfile does not exist")
        
        file_size = os.path.getsize(keyfile_path)
        if file_size < constants.PASSWORD_KEYFILE_MIN_LENGTH:
            raise exceptions.KeyFileTooSmallError("Keyfile too small")
        
        self._keyfile_path = keyfile_path

    def set_function(self, function: str):
        """Sets the program function (encrypt, decrypt, wipe)."""
        if function in [constants.PROGRAM_FUNCTION_ENCRYPT, 
                       constants.PROGRAM_FUNCTION_DECRYPT, 
                       constants.PROGRAM_FUNCTION_WIPE]:
            self._current_function = function
        else:
            raise ValueError(f"Invalid function: {function}")

    def set_destroy_originals(self, destroy: bool):
        """Sets whether to destroy original files after processing."""
        self._destroy_originals = destroy

    def execute_operation(self, progress_callback=None):
        """Executes the current operation on selected files."""
        if not self._selected_files:
            raise exceptions.DialogDisplayError("No files selected")

        if self._current_function == constants.PROGRAM_FUNCTION_ENCRYPT:
            self._encrypt_files(progress_callback)
        elif self._current_function == constants.PROGRAM_FUNCTION_DECRYPT:
            self._decrypt_files(progress_callback)
        elif self._current_function == constants.PROGRAM_FUNCTION_WIPE:
            self._wipe_files(progress_callback)

    def _encrypt_files(self, progress_callback=None):
        """Encrypts the selected files."""
        for i, file_path in enumerate(self._selected_files):
            if progress_callback:
                progress_callback(i, len(self._selected_files), f"Encrypting {os.path.basename(file_path)}")

            # Check authentication method
            if not self._password and not self._keyfile_path:
                raise exceptions.NoPasswordError("No password or keyfile provided")

            # Determine output path
            output_path = file_path + constants.FILE_EXTENSION

            # Check if output file already exists
            if os.path.exists(output_path):
                # In a real implementation, this would show a dialog to the user
                raise exceptions.FileSkippedByUserError(f"File {output_path} already exists", "")

            # Choose encryption method based on file size
            file_size = os.path.getsize(file_path)
            if file_size > constants.AES_GCM_MAX_FILE_SIZE:
                method_id = METHOD_CHACHA20_V3_1
            else:
                method_id = METHOD_AES_GCM_V3

            # Encrypt the file
            self.crypto_manager.encrypt_file(file_path, output_path, self._password, method_id, self._keyfile_path)

            # Destroy original if requested
            if self._destroy_originals:
                self._secure_delete(file_path)

    def _decrypt_files(self, progress_callback=None):
        """Decrypts the selected files."""
        for i, file_path in enumerate(self._selected_files):
            if progress_callback:
                progress_callback(i, len(self._selected_files), f"Decrypting {os.path.basename(file_path)}")

            # Check authentication method
            if not self._password and not self._keyfile_path:
                raise exceptions.NoPasswordError("No password or keyfile provided")

            # Determine output path
            if file_path.endswith(constants.FILE_EXTENSION):
                output_path = file_path[:-len(constants.FILE_EXTENSION)]
            else:
                output_path = file_path + ".decrypted"

            # Check if output file already exists
            if os.path.exists(output_path):
                # In a real implementation, this would show a dialog to the user
                raise exceptions.FileSkippedByUserError(f"File {output_path} already exists", "")

            # Decrypt the file
            self.crypto_manager.decrypt_file(file_path, output_path, self._password, self._keyfile_path)

            # Destroy original if requested
            if self._destroy_originals:
                self._secure_delete(file_path)

    def _wipe_files(self, progress_callback=None):
        """Securely wipes the selected files."""
        for i, file_path in enumerate(self._selected_files):
            if progress_callback:
                progress_callback(i, len(self._selected_files), f"Wiping {os.path.basename(file_path)}")
            self._secure_delete(file_path)

    def _secure_delete(self, file_path: str):
        """Securely deletes a file by overwriting it multiple times."""
        # This is a simplified secure delete implementation
        # A more robust implementation would use multiple passes with different patterns
        if not os.path.exists(file_path):
            return

        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as f:
            # Overwrite with random data
            for _ in range(3):  # 3 passes
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    chunk_size = min(constants.FILE_CHUNK_SIZE, remaining)
                    random_data = os.urandom(chunk_size)
                    f.write(random_data)
                    remaining -= chunk_size
                f.flush()
                os.fsync(f.fileno())

        # Finally, delete the file
        os.remove(file_path)

    def get_selected_files(self) -> List[str]:
        """Returns the list of selected files."""
        return self._selected_files.copy()

    def get_current_function(self) -> str:
        """Returns the current program function."""
        return self._current_function

    def get_destroy_originals(self) -> bool:
        """Returns whether original files will be destroyed."""
        return self._destroy_originals
