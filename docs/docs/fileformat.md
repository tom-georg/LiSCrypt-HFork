# Encrypted File Format

This document describes the file format for files encrypted with LiSCrypt.

## Overview

An encrypted file consists of a header followed by the encrypted data. The file begins with the magic bytes `LiSX` to identify it as a LiSCrypt file.

## Header

The header contains metadata about the encrypted file and the encryption parameters used. The structure of the header varies depending on the encryption method and version.

### Common Header Fields

All header versions start with the following fields:

| Field | Type | Size (bytes) | Description |
|---|---|---|---|
| Magic Bytes | `bytes` | 4 | The string `LiSX` to identify the file type. |
| Encryption Method | `unsigned short` | 2 | An identifier for the encryption method and version used. |

### Version-Specific Header Fields

The rest of the header fields depend on the encryption method version. Here are the details for the most recent versions:

#### AES-GCM v3 (Method ID: 12)

| Field | Type | Size (bytes) | Description |
|---|---|---|---|
| Scrypt Work Factor | `unsigned long long` | 8 | The `n` parameter for scrypt. |
| Scrypt Block Size | `unsigned int` | 4 | The `r` parameter for scrypt. |
| Scrypt Parallelization | `unsigned int` | 4 | The `p` parameter for scrypt. |
| Scrypt Salt Length | `unsigned int` | 4 | The length of the scrypt salt. |
| Scrypt Salt | `bytes` | variable | The salt used for scrypt. |
| AES-GCM Nonce Length | `unsigned int` | 4 | The length of the AES-GCM nonce. |
| AES-GCM Nonce | `bytes` | variable | The nonce used for AES-GCM. |
| Original Modification Time | `unsigned long long` | 8 | The modification timestamp of the original file. |
| Original Access Time | `unsigned long long` | 8 | The access timestamp of the original file. |
| Original File Size | `unsigned long long` | 8 | The size of the original file in bytes. |
| Original Filename Length | `unsigned long long` | 8 | The length of the original filename in bytes. |
| Required LiSCrypt Version Length | `unsigned short` | 2 | The length of the required LiSCrypt version string. |

#### ChaCha20+HMAC v3.1 (Method ID: 53)

| Field | Type | Size (bytes) | Description |
|---|---|---|---|
| Scrypt Work Factor | `unsigned long long` | 8 | The `n` parameter for scrypt. |
| Scrypt Block Size | `unsigned int` | 4 | The `r` parameter for scrypt. |
| Scrypt Parallelization | `unsigned int` | 4 | The `p` parameter for scrypt. |
| Scrypt Salt Length | `unsigned int` | 4 | The length of the scrypt salt. |
| Scrypt Salt | `bytes` | variable | The salt used for scrypt. |
| ChaCha20 Nonce Length | `unsigned int` | 4 | The length of the ChaCha20 nonce. |
| ChaCha20 Nonce | `bytes` | variable | The nonce used for ChaCha20. |
| Original Modification Time | `unsigned long long` | 8 | The modification timestamp of the original file. |
| Original Access Time | `unsigned long long` | 8 | The access timestamp of the original file. |
| Original File Size | `unsigned long long` | 8 | The size of the original file in bytes. |
| Original Filename Length | `unsigned long long` | 8 | The length of the original filename in bytes. |
| Required LiSCrypt Version Length | `unsigned short` | 2 | The length of the required LiSCrypt version string. |

## Encrypted Data

The encrypted data follows the header and contains the following parts:

1.  **Null Byte Sequence:** A sequence of five null bytes (`\x00\x00\x00\x00\x00`) is encrypted and written to the file. This is used as a quick check during decryption to verify the key.
2.  **Original Filename:** The original filename is encrypted and stored.
3.  **Required LiSCrypt Version:** The required version of LiSCrypt to decrypt the file is encrypted and stored.
4.  **File Content:** The actual content of the original file is encrypted in chunks.

## Authentication Tag

The encrypted file ends with an authentication tag to ensure data integrity and authenticity. This tag is a short piece of data that is generated during the encryption process and is used to verify that the data has not been tampered with.

### How it Works

The authentication tag is created using a cryptographic function that takes the secret key and the encrypted data as input. This process generates a unique tag that is specific to the data and the key. When the file is decrypted, the same function is used to regenerate the tag from the received data and the secret key.

If the regenerated tag matches the tag that was appended to the file, it provides strong assurance that:

*   **Data Integrity:** The data has not been altered or corrupted since it was encrypted.
*   **Authenticity:** The data was encrypted by someone who possesses the secret key.

This mechanism protects against various attacks, such as bit-flipping attacks, where an attacker modifies the ciphertext in an attempt to alter the decrypted plaintext.

### Implementation Details

*   **AES-GCM:** The Galois/Counter Mode (GCM) is an authenticated encryption mode. It generates a Message Authentication Code (MAC) tag as part of the encryption process. This tag is 16 bytes (128 bits) long and is appended to the end of the encrypted file.

*   **ChaCha20+HMAC:** This combination uses the ChaCha20 stream cipher for encryption and a Hash-based Message Authentication Code (HMAC) for authentication. The HMAC is calculated over the ciphertext using a separate authentication key derived from the master key. The resulting HMAC tag is appended to the end of the encrypted file.

## Example

Here is an example of how to read the header of an encrypted file using Python:

```python
import struct

with open('encrypted_file.lisx', 'rb') as f:
    magic = f.read(4)
    if magic != b'LiSX':
        raise ValueError('Not a LiSCrypt file')

    method_id = struct.unpack('>H', f.read(2))[0]

    if method_id == 12: # AES-GCM v3
        scrypt_n = struct.unpack('>Q', f.read(8))[0]
        scrypt_r = struct.unpack('>I', f.read(4))[0]
        scrypt_p = struct.unpack('>I', f.read(4))[0]
        salt_len = struct.unpack('>I', f.read(4))[0]
        salt = f.read(salt_len)
        nonce_len = struct.unpack('>I', f.read(4))[0]
        nonce = f.read(nonce_len)
        # ... and so on
    elif method_id == 53: # ChaCha20+HMAC v3.1
        scrypt_n = struct.unpack('>Q', f.read(8))[0]
        scrypt_r = struct.unpack('>I', f.read(4))[0]
        scrypt_p = struct.unpack('>I', f.read(4))[0]
        salt_len = struct.unpack('>I', f.read(4))[0]
        salt = f.read(salt_len)
        nonce_len = struct.unpack('>I', f.read(4))[0]
        nonce = f.read(nonce_len)
        # ... and so on
```
