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

"""This module contains dialog components for the UI."""

from PyQt5 import QtWidgets, QtCore


class PasswordDialog(QtWidgets.QDialog):
    """Dialog for password input."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        """Sets up the dialog UI."""
        self.setWindowTitle("Enter Password")
        self.setModal(True)
        self.resize(300, 150)

        layout = QtWidgets.QVBoxLayout(self)

        # Password input
        layout.addWidget(QtWidgets.QLabel("Password:"))
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addWidget(self.password_input)

        # Confirm password
        layout.addWidget(QtWidgets.QLabel("Confirm Password:"))
        self.confirm_input = QtWidgets.QLineEdit()
        self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addWidget(self.confirm_input)

        # Buttons
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        # Connect validation
        self.password_input.textChanged.connect(self._validate)
        self.confirm_input.textChanged.connect(self._validate)
        
        self.ok_button = buttons.button(QtWidgets.QDialogButtonBox.Ok)
        self.ok_button.setEnabled(False)

    def _validate(self):
        """Validates password input."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        valid = len(password) >= 8 and password == confirm
        self.ok_button.setEnabled(valid)

    def get_password(self) -> str:
        """Returns the entered password."""
        return self.password_input.text()


class ProgressDialog(QtWidgets.QDialog):
    """Dialog showing operation progress."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi()

    def setupUi(self):
        """Sets up the dialog UI."""
        self.setWindowTitle("Processing...")
        self.setModal(True)
        self.resize(400, 100)

        layout = QtWidgets.QVBoxLayout(self)

        self.label = QtWidgets.QLabel("Processing files...")
        layout.addWidget(self.label)

        self.progress_bar = QtWidgets.QProgressBar()
        layout.addWidget(self.progress_bar)

        self.cancel_button = QtWidgets.QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

    def set_progress(self, current: int, total: int, message: str = ""):
        """Updates the progress display."""
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        if message:
            self.label.setText(message)


class ErrorDialog(QtWidgets.QMessageBox):
    """Enhanced error dialog."""

    def __init__(self, title: str, message: str, details: str = "", parent=None):
        super().__init__(parent)
        self.setIcon(QtWidgets.QMessageBox.Critical)
        self.setWindowTitle(title)
        self.setText(message)
        
        if details:
            self.setDetailedText(details)
        
        self.setStandardButtons(QtWidgets.QMessageBox.Ok)
