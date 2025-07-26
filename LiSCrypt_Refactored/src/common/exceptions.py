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

"""This module contains the classes of the LiSCrypt-specific exception hierarchy."""

class LiSCryptError(Exception):
    """Base class for all LiSCrypt exceptions."""
    pass

class AbstractClassError(LiSCryptError):
    """Indicates an attempt to instantiate an abstract class."""    
    pass

class ObjectZeroizationError(LiSCryptError):
    """Indicates a failed attempt to overwrite an object in memory."""
    pass

class FileListDisplayError(LiSCryptError):
    """Indicates a file-related exception that should be displayed in the report area."""
    def __init__(self, message, tooltip):
        super().__init__(message)
        self.tooltip = tooltip

class LiSCryptTooOldError(FileListDisplayError):
    """Indicates that the LiSCrypt version is too old to decrypt a file."""
    pass

class FileSkippedByUserError(FileListDisplayError):
    """Indicates that file processing was skipped due to an existing file of the same name."""
    pass

class DialogDisplayError(LiSCryptError):
    """Indicates a serious general exception that should be displayed in a modal dialog."""
    pass

class KeyFileTooSmallError(DialogDisplayError):
    """Indicates that a selected key file is too small."""
    pass

class NoPasswordError(LiSCryptError):
    """Indicates that an empty password was provided."""
    pass

class ProcessStoppedByUserError(LiSCryptError):
    """Indicates that the user cancelled the process."""
    pass
