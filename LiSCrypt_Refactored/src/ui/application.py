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

"""This module contains the main application class."""

import sys
from PyQt5 import QtWidgets, QtCore

from .main_window import MainWindow
from ..controller.main_controller import MainController
from ..common import constants, exceptions


class LiSCryptApplication:
    """Main application class that coordinates UI and controller."""

    def __init__(self):
        self.app = QtWidgets.QApplication(sys.argv)
        self.main_window = MainWindow()
        self.controller = MainController()
        self._connect_signals()

    def _connect_signals(self):
        """Connects signals between UI and controller."""
        # UI to Controller
        self.main_window.files_selected.connect(self.controller.set_selected_files)
        self.main_window.password_changed.connect(self._on_password_changed)
        self.main_window.keyfile_changed.connect(self._on_keyfile_changed)
        self.main_window.function_changed.connect(self.controller.set_function)
        self.main_window.destroy_originals_changed.connect(self.controller.set_destroy_originals)
        self.main_window.operation_requested.connect(self._execute_operation)

    def _on_password_changed(self, password: str):
        """Handles password changes with error handling."""
        try:
            self.controller.set_password(password)
        except exceptions.NoPasswordError as e:
            # Don't show error for too short passwords during typing
            pass

    def _on_keyfile_changed(self, keyfile_path: str):
        """Handles keyfile changes with error handling."""
        try:
            self.controller.set_keyfile(keyfile_path)
        except (exceptions.DialogDisplayError, exceptions.KeyFileTooSmallError) as e:
            self.main_window.show_error("Error", str(e))

    def _execute_operation(self):
        """Executes the operation with progress updates and error handling."""
        try:
            # Create a progress dialog or use the progress bar in main window
            def progress_callback(current, total, message):
                self.main_window.set_progress(current, total, message)
                QtCore.QCoreApplication.processEvents()

            self.controller.execute_operation(progress_callback)
            self.main_window.set_progress(0, 0)  # Hide progress bar
            self.main_window.show_info("Success", "Operation completed successfully")

        except exceptions.FileSkippedByUserError as e:
            self.main_window.show_error("File Skipped", str(e))
        except exceptions.DialogDisplayError as e:
            self.main_window.show_error("Error", str(e))
        except exceptions.LiSCryptTooOldError as e:
            self.main_window.show_error("Version Error", str(e))
        except exceptions.LiSCryptError as e:
            self.main_window.show_error("LiSCrypt Error", str(e))
        except Exception as e:
            self.main_window.show_error("Unexpected Error", f"An unexpected error occurred: {e}")
        finally:
            self.main_window.set_progress(0, 0)  # Hide progress bar

    def run(self):
        """Runs the application."""
        self.main_window.show()
        return self.app.exec_()


def main():
    """Main entry point for the refactored application."""
    app = LiSCryptApplication()
    sys.exit(app.run())


if __name__ == "__main__":
    main()
