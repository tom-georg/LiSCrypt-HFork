# Encryption Process

This document provides a detailed overview of the encryption and key derivation processes used in LiSCrypt.

## Key Derivation

The encryption keys used in LiSCrypt are not directly based on user-provided passwords or key files. Instead, a robust multi-stage key derivation process is used to generate strong, specific cryptographic keys from the user's input.

1.  **Initial Hashing:** The user's password or the content of the key file is first hashed using **SHA-512**. This produces a 512-bit digest.

2.  **Scrypt Key Strengthening:** This 512-bit digest is then used as the input password for the **scrypt** algorithm. Scrypt is a password-based key derivation function that is intentionally slow and memory-intensive to protect against brute-force attacks. It takes the initial hash and a random **salt** (which is stored in the file header) to produce a master key. The primary purpose of this step is to make password guessing computationally expensive.

3.  **HKDF for Final Key Generation:** The master key from scrypt is *not* used directly for encryption. Instead, it becomes the input keying material for **HKDF (HMAC-based Key Derivation Function)**. HKDF is excellent for taking a master secret and creating multiple, cryptographically separate keys from it. HKDF is used to derive:
    *   The final **256-bit (32-byte) encryption key** for AES-GCM.
    *   The final **256-bit (32-byte) encryption key** for ChaCha20.
    *   A separate **authentication key** for the HMAC when ChaCha20 is used.
    *   The unique **nonce** required for each encryption operation.

This layered approach ensures that we derive exactly the key sizes needed (e.g., 256-bit) and that the keys used for encryption and authentication are independent, which is a critical security practice.

## Encryption Algorithms

LiSCrypt employs two different authenticated encryption algorithms depending on the size of the file being encrypted.

### 1. AES-256-GCM

For files up to a certain size threshold, LiSCrypt uses **AES (Advanced Encryption Standard)** with a 256-bit key in **GCM (Galois/Counter Mode)**.

*   **Encryption:** AES is a symmetric block cipher that is widely regarded as the standard for secure encryption.
*   **GCM Mode:** GCM is a mode of operation that provides both confidentiality (encryption) and authenticity (protection against tampering). It does this by generating an **authentication tag** (a MAC) during the encryption process.
*   **Nonce:** A unique **nonce** (number used once) is required for each encryption with the same key. LiSCrypt generates a new nonce for each file using a **HKDF (HMAC-based Key Derivation Function)** to ensure that the nonces are unique and unpredictable. The nonce is stored in the file header.

### 2. ChaCha20-Poly1305

For larger files, LiSCrypt switches to **ChaCha20** for encryption, combined with a **HMAC-SHA512** for authentication.

*   **Encryption:** ChaCha20 is a modern, high-performance stream cipher that is also considered highly secure.
*   **Authentication:** A **Hash-based Message Authentication Code (HMAC)** using the **SHA-512** hash function is calculated over the encrypted data (ciphertext). This provides the same authenticity and integrity guarantees as the GCM tag. A separate authentication key is derived from the master key for this purpose.
*   **Nonce:** Similar to AES-GCM, ChaCha20 also requires a unique nonce for each encryption, which is generated via HKDF and stored in the header.

## Summary of the Process

1.  A master key is derived from the user's input using **SHA-512** and **scrypt**.
2.  Depending on the file size, either **AES-GCM** or **ChaCha20+HMAC** is chosen.
3.  A unique **nonce** is generated using **HKDF**.
4.  The file content is encrypted.
5.  An **authentication tag** (either GCM tag or HMAC) is generated from the encrypted data.
6.  A header is created containing metadata like the algorithm used, scrypt parameters, salt, and nonce.
7.  The final encrypted file is constructed by combining the header, the encrypted data, and the authentication tag.
