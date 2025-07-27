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

"""This module handles configuration and settings."""

import os
import json
import logging
from typing import Dict, Any

from . import constants


class Configuration:
    """Handles application configuration and settings."""

    def __init__(self):
        self._config: Dict[str, Any] = {
            'last_directory': constants.HOME_PATH,
            'destroy_originals': False,
            'window_geometry': None,
            'logging_level': 'ERROR',
        }
        self.load_configuration()

    def load_configuration(self):
        """Loads configuration from file."""
        try:
            os.makedirs(constants.CONFIG_LOG_PATH, exist_ok=True)
            
            if os.path.exists(constants.CONFIG_FILE_NAME):
                with open(constants.CONFIG_FILE_NAME, 'r') as f:
                    loaded_config = json.load(f)
                    self._config.update(loaded_config)
        except (OSError, json.JSONDecodeError) as e:
            # If config can't be loaded, use defaults
            logging.warning(f"Could not load configuration: {e}")

    def save_configuration(self):
        """Saves configuration to file."""
        try:
            os.makedirs(constants.CONFIG_LOG_PATH, exist_ok=True)
            
            with open(constants.CONFIG_FILE_NAME, 'w') as f:
                json.dump(self._config, f, indent=2)
        except OSError as e:
            logging.error(f"Could not save configuration: {e}")

    def get(self, key: str, default=None):
        """Gets a configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value):
        """Sets a configuration value."""
        self._config[key] = value

    def get_last_directory(self) -> str:
        """Gets the last used directory."""
        return self.get('last_directory', constants.HOME_PATH)

    def set_last_directory(self, directory: str):
        """Sets the last used directory."""
        self.set('last_directory', directory)

    def get_destroy_originals(self) -> bool:
        """Gets the destroy originals setting."""
        return self.get('destroy_originals', False)

    def set_destroy_originals(self, destroy: bool):
        """Sets the destroy originals setting."""
        self.set('destroy_originals', destroy)

    def get_window_geometry(self):
        """Gets the saved window geometry."""
        return self.get('window_geometry')

    def set_window_geometry(self, geometry):
        """Sets the window geometry."""
        # Convert QByteArray to list for JSON serialization
        if hasattr(geometry, 'data'):
            geometry = list(geometry.data())
        self.set('window_geometry', geometry)

    def get_logging_level(self) -> str:
        """Gets the logging level."""
        return self.get('logging_level', 'ERROR')

    def set_logging_level(self, level: str):
        """Sets the logging level."""
        self.set('logging_level', level)


# Global configuration instance
config = Configuration()
