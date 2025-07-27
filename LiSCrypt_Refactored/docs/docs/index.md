# LiSCrypt Documentation

Welcome to the comprehensive documentation for the refactored LiSCrypt file encryption application.

## Overview

LiSCrypt is a file encryption tool that uses modern cryptographic algorithms to securely encrypt files. This refactored version maintains full backward compatibility with files created by the original LiSCrypt application while providing a clean, maintainable codebase using modern software architecture patterns.

## Quick Start

### Test Case Example
The documentation includes extensive analysis of a real encrypted file:
- **File**: `abcd-txt.lisq`
- **Password**: `Hallo&Welt!1`
- **Content**: "Hallo&Welt!1"
- **Method**: AES-GCM v3

This file serves as our primary validation case for backward compatibility.

## Documentation Sections

### 📖 [File Format](fileformat.md)
Comprehensive documentation of the LiSCrypt encrypted file format, including:
- Complete header structure with real examples
- Byte-by-byte breakdown of file components
- Practical implementation examples
- Real hex dump analysis of test files

### 🔐 [Encryption Process](encryption.md) 
Detailed explanation of the encryption algorithms and key derivation:
- Complete key derivation process (SHA-512 + Scrypt + HKDF)
- AES-GCM and ChaCha20 implementation details
- Real examples with actual values
- Step-by-step encryption/decryption flow

### 🔧 [Debugging Guide](debugging.md)
Complete reverse engineering and debugging documentation:
- Authentication failure investigation process
- Backward compatibility challenges and solutions
- Byte-level analysis techniques
- Lessons learned from original format analysis

## Key Features

### ✅ Backward Compatibility
- Decrypts files created by original LiSCrypt
- Maintains exact file format compatibility
- Preserves all original encryption methods

### ✅ Modern Architecture  
- Clean MVC design pattern
- Strategy pattern for encryption methods
- Comprehensive error handling
- Extensive test coverage

### ✅ Security
- Strong key derivation (Scrypt + HKDF)
- Authenticated encryption (AES-GCM)
- Protection against tampering
- Secure password handling

## Testing and Validation

The refactored implementation has been thoroughly tested:
- ✅ Original files decrypt correctly
- ✅ New files maintain format compatibility  
- ✅ Round-trip encryption/decryption works
- ✅ All test cases pass validation

## Development Notes

This documentation captures insights gained during the development process, including:
- Reverse engineering the original file format
- Debugging authentication failures  
- Implementing backward compatibility
- Validating against real encrypted files

The documentation serves both as a reference for the file format and as a guide for future development and maintenance.
