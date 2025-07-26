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

"""
This module contains global program constants.
"""

import os
import sys
import tempfile

# General Constants:
__author__ = 'Qualitäts- und UnterstützungsAgentur - Landesinstitut für Schule Nordrhein-Westfalen (QUA-LiS NRW)'
__license__ = 'GNU General Public License Version 3 (GNU GPL v3)'
__version__ = '1.0.12'
__year__ = '2024'
__maintainer__ = 'Thomas Georg'
__email__ = ''
__status__ = 'production'
__docformat__ = 'reStructuredText'

# Program Functions
PROGRAM_FUNCTION_ENCRYPT = 'Verschlüsseln'
PROGRAM_FUNCTION_DECRYPT = 'Entschlüsseln'
PROGRAM_FUNCTION_WIPE = 'Vernichten'

# Key Types
KEY_TYPE_PASSWORD = 'Passwort'
KEY_TYPE_KEYFILE = 'Schlüsseldatei'

# IQB Variant
IS_IQB_VERSION = True

# Program Name
PROGRAM_NAME = 'LiSCrypt' + (' IQB' if IS_IQB_VERSION else '')

# Encrypted File Extension
FILE_EXTENSION = '.lisx' if not IS_IQB_VERSION else '.lisq'

# Required LiSCrypt Version for decryption
REQUIRED_LISCRYPT_VERSION = '1.0.9'

# Platform and OS
PLATFORM = str.lower(os.name)
OS = str.lower(sys.platform)

# Paths
if OS.startswith('linux') or OS == 'darwin':
    CONFIG_LOG_PATH = os.path.join(os.path.expandvars(r'$HOME'), '.liscrypt' + ('IQB' if IS_IQB_VERSION else ''))
    HOME_PATH = os.path.expandvars(r'$HOME')
elif OS == 'win32':
    CONFIG_LOG_PATH = os.path.join(os.path.expandvars(r'%APPDATA%'), 'liscrypt' + ('IQB' if IS_IQB_VERSION else ''))
    HOME_PATH = os.path.expandvars(r'%HOMEPATH%')
else:
    if getattr(sys, 'frozen', False):  # PyInstaller executable
        CONFIG_LOG_PATH = os.path.dirname(os.path.abspath(sys.executable))
    else:  # Script
        CONFIG_LOG_PATH = os.path.dirname(os.path.abspath(__file__))
    HOME_PATH = CONFIG_LOG_PATH

# Temp Directory
TEMP_DIR_PATH = tempfile.gettempdir()

# Config File
CONFIG_FILE_NAME = os.path.join(CONFIG_LOG_PATH, 'LiSCrypt.cfg')

# Log File
LOG_FILE_NAME = os.path.join(CONFIG_LOG_PATH, 'LiSCrypt.log')
LOGGING_LEVEL = 'ERROR'

# Regex for null byte check
REGEX_NULLBYTES = b'\x00+'

# AES-GCM Encryption Constants
METHOD_AES_GCM_V1 = 1  # DEPRECATED
METHOD_AES_GCM_V2 = 10
METHOD_AES_GCM_V3 = 12

AES_GCM_NONCE_LENGTH = 12  # 96 bits
AES_GCM_MAX_NONCE_VALUE = 256 ** AES_GCM_NONCE_LENGTH - 1
AES_GCM_KEY_LENGTH = 32  # 256 bits
AES_GCM_MAX_FILE_SIZE = (2 ** 39 - 256) / 8 - 1  # NIST SP 800-38D
AES_GCM_MAX_FILES_PER_KEY = 2 ** 32

# ChaCha20 Encryption Constants
METHOD_CHACHA20_V1 = 2  # DEPRECATED
METHOD_CHACHA20_V2 = 50
METHOD_CHACHA20_V3 = 52
METHOD_CHACHA20_V3_1 = 53

CHACHA20_NONCE_LENGTH = 16
CHACHA20_MAX_NONCE_VALUE = 256 ** CHACHA20_NONCE_LENGTH - 1
CHACHA20_KEY_LENGTH = 32
CHACHA20_MAX_FILES_PER_KEY = 2 ** 42

# HMAC Authentication Constants
HMAC_KEY_LENGTH = 32
HMAC_SHA512_KEY_LENGTH = 64

# File Operations
FILE_CHUNK_SIZE = 64 * 1024

# Scrypt Constants
SCRYPT_SALT_LENGTH = 64
SCRYPT_N = 2 ** 19
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_OUTPUT_LENGTH_V1_V2 = 32
SCRYPT_OUTPUT_LENGTH_V3 = 64

# HKDF Constants
HKDF_SALT_AES_GCM_V2_LENGTH = 64
HKDF_SALT_CHACHA20_V2_LENGTH = 64
HKDF_SALT_HMAC_LENGTH = 64

# Keyfile Constants
GENERATED_KEYFILE_MIN_LENGTH = 128
GENERATED_KEYFILE_MAX_LENGTH = 512

# Password/Keyfile Minimum Length
PASSWORD_KEYFILE_MIN_LENGTH = 8
