# LiSCrypt - File encryption program using AES-GCM-256 or ChaCha20+HMAC (the latter for particularly large files)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LiSCrypt.  If not, see <https://www.gnu.org/licenses/>.

"""Dieses Modul enthält die Klasse zur Realisierung eines System-Tray-Icons (Version 1.0.0: Nicht realisiert)."""

from Modell import LiSKonstanten

from PyQt5 import QtWidgets, QtGui, QtCore

class Ui_SystemTrayIcon(QtWidgets.QSystemTrayIcon):
    """
    Modelliert das System-Tray-icon von LiSCrypt
    """
    def __init__(self, parent):
        lLiSCryptIcon16x16QPixmap = QtGui.QPixmap()
        lLiSCryptIcon16x16QPixmap.loadFromData(LiSKonstanten.C_LISCRYPT_ICON16X16, 'PNG')
        lLiSCryptIcon16x16QIcon = QtGui.QIcon(lLiSCryptIcon16x16QPixmap)
        super(Ui_SystemTrayIcon, self).__init__(lLiSCryptIcon16x16QIcon, parent)
        self.menu = QtWidgets.QMenu(parent)
        self.menu.addAction("LiSCrypt beenden", QtCore.QCoreApplication.quit)
        self.setContextMenu(self.menu)
        self.show()

