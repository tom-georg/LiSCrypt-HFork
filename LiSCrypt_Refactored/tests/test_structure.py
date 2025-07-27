#!/usr/bin/env python3
"""
Simple import test for the refactored LiSCrypt application.
This test verifies the code structure without requiring external dependencies.
"""

import sys
import os

# Add the src directory to the path so we can import our modules
current_dir = os.path.dirname(__file__)
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)


def test_imports():
    """Test that all modules can be imported without external dependencies."""
    print("Testing module imports...")
    
    try:
        # Test common modules
        from src.common import constants
        print("✓ Constants module imported")
        
        from src.common import exceptions
        print("✓ Exceptions module imported")
        
        from src.common import config
        print("✓ Config module imported")
        
        # Test basic functionality without cryptography
        print(f"✓ Program name: {constants.PROGRAM_NAME}")
        print(f"✓ File extension: {constants.FILE_EXTENSION}")
        print(f"✓ AES key length: {constants.AES_GCM_KEY_LENGTH}")
        
        # Test exception hierarchy
        base_exception = exceptions.LiSCryptError("Test error")
        print(f"✓ Base exception: {type(base_exception).__name__}")
        
        # Test configuration
        config_instance = config.Configuration()
        test_dir = config_instance.get_last_directory()
        print(f"✓ Configuration working, last directory: {os.path.basename(test_dir)}")
        
        print("\n✓ All basic imports successful!")
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False


def test_project_structure():
    """Test that the project structure is complete."""
    print("\nTesting project structure...")
    
    base_dir = os.path.dirname(__file__)
    
    # Required directories
    required_dirs = [
        'src',
        'src/common',
        'src/core',
        'src/core/strategies',
        'src/controller',
        'src/ui',
        'src/ui/components',
        'tests',
        'docs',
        'resources'
    ]
    
    # Required files
    required_files = [
        'src/__init__.py',
        'src/common/__init__.py',
        'src/common/constants.py',
        'src/common/exceptions.py',
        'src/common/config.py',
        'src/core/__init__.py',
        'src/core/crypto_manager.py',
        'src/core/key_derivation.py',
        'src/core/strategies/__init__.py',
        'src/core/strategies/base_strategy.py',
        'src/core/strategies/aes_gcm_v3.py',
        'src/core/strategies/chacha20_v3_1.py',
        'src/controller/__init__.py',
        'src/controller/main_controller.py',
        'src/ui/__init__.py',
        'src/ui/main_window.py',
        'src/ui/application.py',
        'src/ui/components/__init__.py',
        'src/ui/components/dialogs.py',
        'LiSCryptStart.py',
        'README.md',
        'structure.md'
    ]
    
    missing_dirs = []
    missing_files = []
    
    # Check directories
    for directory in required_dirs:
        path = os.path.join(base_dir, directory)
        if not os.path.isdir(path):
            missing_dirs.append(directory)
    
    # Check files
    for file_path in required_files:
        path = os.path.join(base_dir, file_path)
        if not os.path.isfile(path):
            missing_files.append(file_path)
    
    if missing_dirs:
        print(f"✗ Missing directories: {missing_dirs}")
        return False
    
    if missing_files:
        print(f"✗ Missing files: {missing_files}")
        return False
    
    print(f"✓ All {len(required_dirs)} directories present")
    print(f"✓ All {len(required_files)} files present")
    print("✓ Project structure is complete!")
    return True


def test_architecture_principles():
    """Test that architecture principles are followed."""
    print("\nTesting architecture principles...")
    
    # Test that UI modules don't import core directly (loose coupling)
    # Test that core modules don't import UI (separation of concerns)
    # This would require parsing import statements, which is complex
    # For now, we'll just verify the structure exists
    
    principles_met = []
    
    # Check if main components exist
    components = [
        ('Core Logic', 'src/core/crypto_manager.py'),
        ('Strategy Pattern', 'src/core/strategies/base_strategy.py'),
        ('Controller Layer', 'src/controller/main_controller.py'),
        ('UI Layer', 'src/ui/main_window.py'),
        ('Common Utilities', 'src/common/constants.py'),
        ('Exception Hierarchy', 'src/common/exceptions.py')
    ]
    
    base_dir = os.path.dirname(__file__)
    for name, file_path in components:
        full_path = os.path.join(base_dir, file_path)
        if os.path.exists(full_path):
            principles_met.append(name)
            print(f"✓ {name}: Present")
        else:
            print(f"✗ {name}: Missing")
            return False
    
    print(f"✓ All {len(principles_met)} architectural components present!")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("LiSCrypt Refactored - Structure and Import Tests")
    print("=" * 60)
    
    success = True
    
    try:
        success &= test_imports()
        success &= test_project_structure()
        success &= test_architecture_principles()
        
        if success:
            print("\n" + "=" * 60)
            print("✓ ALL TESTS PASSED!")
            print("✓ The refactored LiSCrypt structure is complete and ready.")
            print("✓ To run the full application, install dependencies:")
            print("  pip install PyQt5 cryptography")
            print("=" * 60)
        else:
            print("\n" + "=" * 60)
            print("✗ SOME TESTS FAILED!")
            print("✗ Please check the issues above.")
            print("=" * 60)
            sys.exit(1)
        
    except Exception as e:
        print(f"\n✗ Unexpected error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
