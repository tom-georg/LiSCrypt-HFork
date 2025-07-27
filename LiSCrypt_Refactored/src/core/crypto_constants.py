# LiSCrypt Core Cryptographic Constants
# 
# This module contains cryptographic constants used by the core encryption/decryption
# strategies. These constants are separate from application-level constants to maintain
# clean separation of concerns and reduce dependencies.

"""
Core cryptographic constants for LiSCrypt encryption strategies.

This module contains only the constants needed by the core encryption logic,
keeping the core components independent from application-level configuration.
"""

# File Format Constants
MAGIC_BYTES = b'LiSX'

# Encryption Method IDs
METHOD_AES_GCM_V3 = 12
METHOD_CHACHA20_V3_1 = 53

# AES-GCM Parameters  
AES_GCM_NONCE_LENGTH = 12  # 96 bits
AES_GCM_KEY_LENGTH = 32    # 256 bits

# Scrypt Parameters (from working implementation - these decrypt our test file correctly)
SCRYPT_SALT_LENGTH = 64     # 512 bits (matches working test file)
SCRYPT_N = 524288          # 2^19 (matches current working constants)
SCRYPT_R = 8               # Block size  
SCRYPT_P = 1               # Parallelization

# HKDF Info Strings (critical for backward compatibility)
HKDF_INFO_AES_KEY = b'AES-GCM-V3-key'
HKDF_INFO_AES_NONCE_PREFIX = b'AES-GCM-V3-nonce-'

# LiSCrypt Version for File Compatibility  
REQUIRED_LISCRYPT_VERSION = '1.0.9'  # Current version that works

# Header Field Sizes (for parsing)
MAGIC_BYTES_LENGTH = 4
METHOD_ID_LENGTH = 2
SCRYPT_N_LENGTH = 8
SCRYPT_R_LENGTH = 4  
SCRYPT_P_LENGTH = 4
SALT_LENGTH_FIELD_LENGTH = 4
NONCE_LENGTH_FIELD_LENGTH = 4
TIMESTAMP_LENGTH = 8
FILE_SIZE_LENGTH = 8
FILENAME_LENGTH_FIELD_LENGTH = 8
VERSION_LENGTH_FIELD_LENGTH = 2
TAG_LENGTH_FIELD_LENGTH = 4
AES_GCM_TAG_LENGTH = 16
