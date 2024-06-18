from setuptools import setup, find_packages
import os

# Finde alle Pakete im src-Verzeichnis
packages = find_packages(where="src")

APP = ['src/LiSCryptStart.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': True,
    'packages': packages,  # Automatisch gefundene Pakete hinzufügen
    'includes': ['_cffi_backend', 'cryptography', 'cryptography.hazmat.bindings._rust'],  # Sicherstellen, dass diese Module einbezogen werden
    'excludes': ['tkinter', 'PyQt5.QtNetwork',
                 'PyQt5.QtMultimedia',
                 'PyQt5.QtWebEngineWidgets',
                 'PyQt5.QtWebEngineCore',
                 'PyQt5.Translations',
                 ],
                     # Schließe unnötige Pakete aus, um Probleme zu vermeiden
    'plist': {
        'CFBundleName': 'LiSCryptStart',
        'CFBundleShortVersionString': '0.1.0',
        'CFBundleVersion': '0.1.0',
        'CFBundleIdentifier': 'com.yourname.LiSCryptStart',
    },
    'resources': [],  # Kann leer gelassen werden, wenn keine zusätzlichen Dateien manuell hinzugefügt werden müssen
    'optimize': 2,
    'strip': True,
    'compressed': True,
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)
