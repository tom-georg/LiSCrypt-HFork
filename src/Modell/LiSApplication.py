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

from Modell import LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtWidgets

import threading

class QFileOpenEventApplication(QtWidgets.QApplication):
	"""
	Modelliert eine  Variante von QtWidgets.QApplication, die auf ein FileOpenEvent reagiert
	"""

	def __init__(self, pControllerQController, *args, **kwargs):
		super(QFileOpenEventApplication, self).__init__(*args, **kwargs)
		self.sControllerQController = pControllerQController
		self.sErweitertePfadeZuDateienList = []
		self.sProzessbearbeitungGestartetBoolean = False

	def event(self, pEventEvent):
		if LiSKonstanten.C_BETRIEBSSYSTEM == 'darwin':
			if pEventEvent.type() == QtCore.QEvent.FileOpen:
				lPfadzuDateiString = pEventEvent.url().path()
				lErweiterterPfadZuDateiString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lPfadzuDateiString)
				if self.sProzessbearbeitungGestartetBoolean is False:
					self.sErweitertePfadeZuDateienList.append(lErweiterterPfadZuDateiString)
					QtCore.QTimer.singleShot(500, self.starteProzessbearbeitung)
				else:
					if LiSKonstanten.C_IQB_VERSION is False:
						self.sControllerQController.starteFunktionAusParameterliste(['screen','decrypt','choose', lErweiterterPfadZuDateiString])
					else:
						self.sControllerQController.starteFunktionAusParameterliste(['screen', 'decrypt', 'password', lErweiterterPfadZuDateiString])
		return super(QFileOpenEventApplication, self).event(pEventEvent)

	def starteProzessbearbeitung(self):
		if self.sProzessbearbeitungGestartetBoolean is False:
			self.sProzessbearbeitungGestartetBoolean = True
			lErweitertePfadeZuDateienList = self.sErweitertePfadeZuDateienList[:]
			self.sErweitertePfadeZuDateienList.clear()
			lParameterlisteList = ['screen', 'decrypt', 'wipeoriginals']
			if LiSKonstanten.C_IQB_VERSION is False:
				lParameterlisteList.append('choose')
			else:
				lParameterlisteList.append('password')
			lParameterlisteList.extend(lErweitertePfadeZuDateienList)
			self.sControllerQController.starteFunktionAusParameterliste(lParameterlisteList)
			self.sProzessbearbeitungGestartetBoolean = False