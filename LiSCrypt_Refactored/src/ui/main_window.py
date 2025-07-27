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

"""This module contains the main window UI component."""

import os
from typing import List, Optional
from PyQt5 import QtCore, QtGui, QtWidgets

from ..common import constants, exceptions


class MainWindow(QtWidgets.QMainWindow):
    """Main window of the LiSCrypt application."""
    
    # Signals
    files_selected = QtCore.pyqtSignal(list)
    password_changed = QtCore.pyqtSignal(str)
    keyfile_changed = QtCore.pyqtSignal(str)
    function_changed = QtCore.pyqtSignal(str)
    destroy_originals_changed = QtCore.pyqtSignal(bool)
    operation_requested = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setupUi()
        self._selected_files: List[str] = []

    def setupUi(self):
        """Sets up the user interface."""
        self.setWindowTitle(constants.PROGRAM_NAME)
        self.setGeometry(100, 100, 800, 600)
        
        # Central widget
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QtWidgets.QVBoxLayout(central_widget)
        
        # Function selection
        function_group = QtWidgets.QGroupBox("Function")
        function_layout = QtWidgets.QHBoxLayout(function_group)
        
        self.encrypt_radio = QtWidgets.QRadioButton("Encrypt")
        self.decrypt_radio = QtWidgets.QRadioButton("Decrypt")
        self.wipe_radio = QtWidgets.QRadioButton("Wipe")
        self.encrypt_radio.setChecked(True)
        
        function_layout.addWidget(self.encrypt_radio)
        function_layout.addWidget(self.decrypt_radio)
        function_layout.addWidget(self.wipe_radio)
        layout.addWidget(function_group)
        
        # File selection
        file_group = QtWidgets.QGroupBox("Files")
        file_layout = QtWidgets.QVBoxLayout(file_group)
        
        file_button_layout = QtWidgets.QHBoxLayout()
        self.select_files_btn = QtWidgets.QPushButton("Select Files")
        self.select_folder_btn = QtWidgets.QPushButton("Select Folder")
        file_button_layout.addWidget(self.select_files_btn)
        file_button_layout.addWidget(self.select_folder_btn)
        file_layout.addLayout(file_button_layout)
        
        self.file_list = QtWidgets.QListWidget()
        file_layout.addWidget(self.file_list)
        layout.addWidget(file_group)
        
        # Key selection
        key_group = QtWidgets.QGroupBox("Key")
        key_layout = QtWidgets.QVBoxLayout(key_group)
        
        # Key type selection
        key_type_layout = QtWidgets.QHBoxLayout()
        self.password_radio = QtWidgets.QRadioButton("Password")
        self.keyfile_radio = QtWidgets.QRadioButton("Key File")
        self.password_radio.setChecked(True)
        key_type_layout.addWidget(self.password_radio)
        key_type_layout.addWidget(self.keyfile_radio)
        key_layout.addLayout(key_type_layout)
        
        # Password input
        self.password_widget = QtWidgets.QWidget()
        password_layout = QtWidgets.QVBoxLayout(self.password_widget)
        password_layout.setContentsMargins(0, 0, 0, 0)
        
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_confirm = QtWidgets.QLineEdit()
        self.password_confirm.setEchoMode(QtWidgets.QLineEdit.Password)
        
        password_layout.addWidget(QtWidgets.QLabel("Password:"))
        password_layout.addWidget(self.password_input)
        password_layout.addWidget(QtWidgets.QLabel("Confirm Password:"))
        password_layout.addWidget(self.password_confirm)
        
        # Keyfile input
        self.keyfile_widget = QtWidgets.QWidget()
        keyfile_layout = QtWidgets.QHBoxLayout(self.keyfile_widget)
        keyfile_layout.setContentsMargins(0, 0, 0, 0)
        
        self.keyfile_path = QtWidgets.QLineEdit()
        self.keyfile_browse = QtWidgets.QPushButton("Browse")
        keyfile_layout.addWidget(QtWidgets.QLabel("Key File:"))
        keyfile_layout.addWidget(self.keyfile_path)
        keyfile_layout.addWidget(self.keyfile_browse)
        
        key_layout.addWidget(self.password_widget)
        key_layout.addWidget(self.keyfile_widget)
        self.keyfile_widget.hide()
        
        layout.addWidget(key_group)
        
        # Options
        options_group = QtWidgets.QGroupBox("Options")
        options_layout = QtWidgets.QVBoxLayout(options_group)
        
        self.destroy_originals_checkbox = QtWidgets.QCheckBox("Destroy original files")
        options_layout.addWidget(self.destroy_originals_checkbox)
        layout.addWidget(options_group)
        
        # Progress
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        
        button_layout.addStretch()
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        # Connect signals
        self._connect_signals()

    def _connect_signals(self):
        """Connects UI signals to slots."""
        # Function selection
        self.encrypt_radio.toggled.connect(self._on_function_changed)
        self.decrypt_radio.toggled.connect(self._on_function_changed)
        self.wipe_radio.toggled.connect(self._on_function_changed)
        
        # File selection
        self.select_files_btn.clicked.connect(self._select_files)
        self.select_folder_btn.clicked.connect(self._select_folder)
        
        # Key selection
        self.password_radio.toggled.connect(self._on_key_type_changed)
        self.keyfile_radio.toggled.connect(self._on_key_type_changed)
        self.password_input.textChanged.connect(self._on_password_changed)
        self.password_confirm.textChanged.connect(self._on_password_changed)
        self.keyfile_browse.clicked.connect(self._browse_keyfile)
        self.keyfile_path.textChanged.connect(self._on_keyfile_changed)
        
        # Options
        self.destroy_originals_checkbox.toggled.connect(self.destroy_originals_changed.emit)
        
        # Buttons
        self.start_btn.clicked.connect(self._start_operation)

    def _on_function_changed(self):
        """Handles function selection changes."""
        if self.encrypt_radio.isChecked():
            self.function_changed.emit(constants.PROGRAM_FUNCTION_ENCRYPT)
        elif self.decrypt_radio.isChecked():
            self.function_changed.emit(constants.PROGRAM_FUNCTION_DECRYPT)
        elif self.wipe_radio.isChecked():
            self.function_changed.emit(constants.PROGRAM_FUNCTION_WIPE)

    def _on_key_type_changed(self):
        """Handles key type selection changes."""
        if self.password_radio.isChecked():
            self.password_widget.show()
            self.keyfile_widget.hide()
        else:
            self.password_widget.hide()
            self.keyfile_widget.show()

    def _select_files(self):
        """Opens file selection dialog."""
        files, _ = QtWidgets.QFileDialog.getOpenFileNames(
            self, "Select Files", "", "All Files (*)")
        if files:
            self._selected_files = files
            self._update_file_list()
            self.files_selected.emit(files)

    def _select_folder(self):
        """Opens folder selection dialog and adds all files recursively."""
        folder = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select Folder")
        if folder:
            files = []
            for root, dirs, filenames in os.walk(folder):
                for filename in filenames:
                    files.append(os.path.join(root, filename))
            self._selected_files = files
            self._update_file_list()
            self.files_selected.emit(files)

    def _update_file_list(self):
        """Updates the file list display."""
        self.file_list.clear()
        for file_path in self._selected_files:
            self.file_list.addItem(os.path.basename(file_path))

    def _on_password_changed(self):
        """Handles password input changes."""
        password = self.password_input.text()
        confirm = self.password_confirm.text()
        
        if password and password == confirm:
            self.password_changed.emit(password)

    def _on_keyfile_changed(self):
        """Handles keyfile path changes."""
        keyfile_path = self.keyfile_path.text()
        if keyfile_path and os.path.exists(keyfile_path):
            self.keyfile_changed.emit(keyfile_path)

    def _browse_keyfile(self):
        """Opens keyfile browser dialog."""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Select Key File", "", "All Files (*)")
        if file_path:
            self.keyfile_path.setText(file_path)

    def _start_operation(self):
        """Initiates the operation."""
        # Validate inputs
        if not self._selected_files:
            QtWidgets.QMessageBox.warning(self, "Warning", "No files selected")
            return

        if self.password_radio.isChecked():
            password = self.password_input.text()
            confirm = self.password_confirm.text()
            if not password:
                QtWidgets.QMessageBox.warning(self, "Warning", "Please enter a password")
                return
            if password != confirm:
                QtWidgets.QMessageBox.warning(self, "Warning", "Passwords do not match")
                return
        else:
            keyfile_path = self.keyfile_path.text()
            if not keyfile_path or not os.path.exists(keyfile_path):
                QtWidgets.QMessageBox.warning(self, "Warning", "Please select a valid key file")
                return

        self.operation_requested.emit()

    def set_progress(self, current: int, total: int, message: str = ""):
        """Updates the progress bar."""
        if total > 0:
            self.progress_bar.setVisible(True)
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)
            if message:
                self.progress_bar.setFormat(f"{message} (%p%)")
        else:
            self.progress_bar.setVisible(False)

    def show_error(self, title: str, message: str):
        """Shows an error dialog."""
        QtWidgets.QMessageBox.critical(self, title, message)

    def show_info(self, title: str, message: str):
        """Shows an information dialog."""
        QtWidgets.QMessageBox.information(self, title, message)
