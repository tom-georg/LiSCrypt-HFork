# Core Dependencies Cleanup Summary

## Overview
Successfully refactored the LiSCrypt codebase to reduce core dependencies and improve separation of concerns by moving cryptographic constants to a dedicated core module.

## Changes Made

### ✅ 1. Created Core Constants Module
- **File**: `src/core/crypto_constants.py`
- **Purpose**: Contains only cryptographic constants needed by core encryption strategies
- **Benefits**: 
  - Reduces external dependencies for core logic
  - Clean separation between crypto and application constants
  - Self-contained core encryption components

### ✅ 2. Updated Core Strategies
- **AES-GCM v3 Strategy**: Now uses only `crypto_constants.py`
- **ChaCha20 v3.1 Strategy**: Uses core constants for method IDs
- **Crypto Manager**: Uses core constants with minimal dependencies
- **Exception Handling**: Consolidated to use `LiSCryptError`

### ✅ 3. Cleaned Up Common Constants
**Removed from `src/common/constants.py`:**
- All AES-GCM specific constants (moved to core)
- All ChaCha20 specific constants (moved to core)
- All Scrypt parameters (moved to core)
- All HKDF constants (moved to core)
- HMAC constants (moved to core)
- Keyfile generation constants (not used in current implementation)

**Kept in `src/common/constants.py`:**
- Application-level constants (program functions, file extensions, etc.)
- UI-related constants
- Configuration paths and logging
- File operation constants (chunk size)
- `AES_GCM_MAX_FILE_SIZE` (needed for method selection in controller)

### ✅ 4. Updated Imports
- **Controller**: Imports specific crypto constants from core, application constants from common
- **Strategies**: Use only core constants
- **Manager**: Minimal dependencies, uses core constants

## Architecture Benefits

### Before
```
Core Strategies → Common Constants (everything)
                ↓
              Heavy Dependencies
```

### After
```
Core Strategies → Core Constants (crypto only)
                ↓
              Minimal Dependencies

Application → Common Constants (UI/config)
           ↓
         Clean Separation
```

## Validation
- ✅ All constants import correctly
- ✅ Core crypto constants isolated in dedicated module
- ✅ Application starts without import errors
- ✅ Clean separation between crypto and application concerns
- ✅ Backward compatibility maintained

## Next Steps
- Consider moving exceptions to core for complete independence
- Add unit tests for constants modules
- Document the new architecture in main README

## Files Modified
1. `src/core/crypto_constants.py` - **NEW**: Core crypto constants
2. `src/core/crypto_manager.py` - Updated imports and references
3. `src/core/strategies/aes_gcm_v3.py` - Uses core constants only
4. `src/core/strategies/chacha20_v3_1.py` - Uses core constants
5. `src/controller/main_controller.py` - Selective imports
6. `src/common/constants.py` - Removed duplicated crypto constants

The core encryption logic now has minimal dependencies and clean separation of concerns while maintaining full backward compatibility.
