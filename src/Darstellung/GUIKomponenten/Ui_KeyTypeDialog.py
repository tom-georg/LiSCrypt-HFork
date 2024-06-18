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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with LiSCrypt.  If not, see <https://www.gnu.org/licenses/>.

"""Dieses Modul enthält die Klassen zur Realisierung eines Auswahldialogs für eine Schlüsseldatei."""

from Modell import LiSKonfiguration, LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtWidgets

class SchluesselartMessageBox(QtWidgets.QMessageBox):
	"""Eine eigene MessageBox zur Auswahl einer Schlüsselart (mit Abbruchmöglichkeit).

	Die Klasse SchluesselartMessageBox ist eine Unterklasse von QtWidgets.QMessageBox.
	"""
	def __init__(self, pParent):
		"""Initialisiert ein Objekt der Klasse SchluesselartMessageBox (zur Auswahl einer Schlüsselart bei Ausführung
		per parametrisiertem Aufruf ohne Angabe der Schlüsselart).

		 :param pParent: Elter gemäß PyQt-Spezifikation
		 :type pParent: PyQt5.QtCore.QObject
		 """
		super(SchluesselartMessageBox, self).__init__(parent=pParent)

		self.setWindowTitle('Schlüsselart wählen')
		self.setIcon(QtWidgets.QMessageBox.Question)

		self.setText('Bitten wählen Sie die Schlüsselart.')

		lDefaultButtonQPushButton = QtWidgets.QPushButton('Passwort', parent=self)
		self.addButton(lDefaultButtonQPushButton, LiSKonstanten.C_SCHLUESSELARTMESSAGEBOX_SCHLUESSELARTEN['Passwort'])
		self.addButton('Schlüsseldatei', LiSKonstanten.C_SCHLUESSELARTMESSAGEBOX_SCHLUESSELARTEN['Schlüsseldatei'])
		self.addButton('Abbrechen', LiSKonstanten.C_SCHLUESSELARTMESSAGEBOX_SCHLUESSELARTEN['Abbrechen'])

		self.setDefaultButton(lDefaultButtonQPushButton)
