# LiSCrypt Refactored

This is a refactored version of LiSCrypt that follows modern software engineering principles and design patterns.

## Architecture Overview

The refactored LiSCrypt follows a clean, decoupled architecture:

```
src/
├── LiSCryptStart.py         # Main application entry point
├── core/                    # Core cryptographic logic (no UI dependencies)
│   ├── key_derivation.py    # Handles Scrypt and HKDF key derivation
│   ├── crypto_manager.py    # Main orchestrator for encryption/decryption
│   └── strategies/          # Strategy pattern for different encryption versions
│       ├── base_strategy.py # Abstract base class for all strategies
│       ├── aes_gcm_v3.py    # AES-GCM v3 implementation
│       └── chacha20_v3_1.py # ChaCha20+HMAC v3.1 implementation
├── ui/                      # PyQt5 UI components
│   ├── application.py       # Main application class
│   ├── main_window.py       # Main window UI
│   └── components/          # Reusable UI components
│       └── dialogs.py       # Dialog components
├── controller/              # Bridge between UI and Core
│   └── main_controller.py   # Main controller handling UI events
└── common/                  # Shared utilities
    ├── constants.py         # Application constants
    ├── exceptions.py        # Custom exception hierarchy
    └── config.py           # Configuration management
```

## Key Improvements

### 1. Separation of Concerns
- **Core**: Pure business logic with no UI dependencies
- **UI**: Only handles presentation and user interaction
- **Controller**: Mediates between UI and core logic

### 2. Strategy Pattern
- Each encryption version is implemented as a separate strategy
- Easy to add new encryption methods without modifying existing code
- Follows Open/Closed Principle

### 3. Single Responsibility Principle
- Each class has a single, well-defined responsibility
- `key_derivation.py` only handles key derivation
- Each strategy only handles one encryption method
- `crypto_manager.py` only orchestrates strategy selection

### 4. Improved Testability
- Core logic can be tested independently of UI
- Strategies can be unit tested in isolation
- Dependency injection makes mocking easier

### 5. Better Error Handling
- Custom exception hierarchy for different error types
- Clear separation between display errors and logic errors
- Proper error propagation through layers

## Running the Application

### GUI Mode
```bash
python LiSCryptStart.py
```

### Basic Test
```bash
python test_basic.py
```

## Dependencies

The refactored version uses the same dependencies as the original:
- PyQt5 (for GUI)
- cryptography (for encryption/decryption)

## File Structure Comparison

### Original Structure Issues:
- **Tight Coupling**: Model classes directly imported PyQt5
- **God Objects**: Single classes handling multiple responsibilities
- **Long Methods**: Complex conditional blocks for different versions
- **Hard to Test**: Business logic tightly coupled with UI

### Refactored Structure Benefits:
- **Loose Coupling**: Core logic independent of UI framework
- **Single Responsibility**: Each class has one clear purpose
- **Strategy Pattern**: Clean separation of encryption methods
- **Testable**: Core logic can be tested without GUI

## Migration Notes

To migrate from the original LiSCrypt:
1. The core encryption/decryption algorithms remain unchanged
2. File formats are fully compatible
3. All existing encrypted files can be decrypted
4. Configuration and user preferences are preserved

## Future Enhancements

The new architecture makes it easy to:
- Add new encryption algorithms
- Create a command-line interface
- Add different UI frameworks
- Implement batch processing
- Add logging and monitoring
- Create automated tests

## Development

### Adding a New Encryption Strategy

1. Create a new file in `src/core/strategies/`
2. Inherit from `BaseStrategy`
3. Implement `encrypt()` and `decrypt()` methods
4. Register the strategy in `CryptoManager`

### Adding UI Components

1. Create new components in `src/ui/components/`
2. Use signals/slots for communication
3. Let the controller handle business logic

This refactored version maintains full compatibility with the original LiSCrypt while providing a much cleaner, more maintainable codebase.
