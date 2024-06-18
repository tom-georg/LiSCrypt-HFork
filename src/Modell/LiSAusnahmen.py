# LiSCrypt - File encryption program using AES-GCM-256 or ChaCha20+HMAC (the latter for particularly large files)
# Copyright(C) 2018-2022 QUA-LiS NRW

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

"""Dieses Modul ethält die Klassen der LiSCrypt-eigenen Exception-Hierarchie."""

class QError(Exception):
	"""
	Indiziert einen generischen LiSCrypt-Ausnahmefehler.
	"""
	pass

class QAbstractClassError(QError):
	"""
	Indiziert einen Versuch der Instanziierung einer abstrakten Klasse.
	"""
	pass

class QObjectZeroizationError(QError):
	"""
	Indiziert einen fehlgeschlagenen Versuch, ein Objekt im Speicher zu überschreiben
	"""
	pass

class QFileListDisplayError(QError):
	"""
	Indiziert einen dateibezogenen Ausnahmefehler (wird im Berichtsbereich (Verlaufsprotokoll) angezeigt).
	"""
	def __init__(self, pInformationZeileString, pToolTipString):
		super(QFileListDisplayError, self).__init__(pInformationZeileString)
		self.sToolTipString = pToolTipString

	def gibToolTipString(self):
		return self.sToolTipString

class QLiSCryptTooOldError(QFileListDisplayError):
	"""
	Indiziert einen sepeziellen dateibezogenen Ausnahmefehler, der darauf hinweist, dass die Version LiSCrypt zu alt ist, um eine
	Datei zu entschlüsseln.
	"""
	pass

class QFileSkippedByUserError(QFileListDisplayError):
	"""
	Indiziert einen sepeziellen dateibezogenen Ausnahmefehler, der darauf hinweist, die Ver- oder Entschlüsselung
	einer Datei übersprungen wurde, da bereits eine Datei gleichen Namens existiert-
	"""
	pass

class QDialogDisplayError(QError):
	"""
	Indiziert einen schweren allgemeinen Ausnahmefehler (wird in einem modalen Dialog angezeigt).
	"""
	def __init__(self, pFehlermeldungString):
		super(QDialogDisplayError, self).__init__(pFehlermeldungString)

class QKeyFileToSmallError(QDialogDisplayError):
	"""
	Indiziert, dass eine gewählte Schlüsseldatei zu klein ist.
	"""
	def __init__(self, pFehlermeldungString):
		super(QKeyFileToSmallError, self).__init__(pFehlermeldungString)

class QNoPasswordError(QError):
	"""
	Indiziert die Setzung eines leeren Passworts (None, Leerstring, 0-Byte-String) für die Ausführung einer
	Programmfunktion in einer Instanz von QControllerWorkerThread
	"""
	def __init__(self, pFehlermeldungString=None):
		if pFehlermeldungString is None:
			super(QNoPasswordError, self).__init__()
		else:
			super(QNoPasswordError, self).__init__(pFehlermeldungString)

class QProcessStoppedByUserError(QError):
	"""
	Indiziert den Abbruch der Ausführung einer Programmfunktion durch den Nutzer.
	"""
	def __init__(self, pInformationZeileString=None):
		if pInformationZeileString is None:
			super(QProcessStoppedByUserError, self).__init__()
		else:
			super(QProcessStoppedByUserError, self).__init__(pInformationZeileString)



