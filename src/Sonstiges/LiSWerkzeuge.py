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

"""
Dieses Modul enthält Klassen mit statischen Hilfsmethoden.
"""

from Modell import LiSAusnahmen, LiSKonstanten

import ctypes
import logging
import os
import psutil
import random
import stat
import string
import sys
import typing

if str.lower(os.name) == 'posix':
	import resource

class Dateiwerkzeuge:
	def __init__(self):
		if type(self) is Dateiwerkzeuge:
			raise LiSAusnahmen.QAbstractClassError('Datei kann nicht instanziiert werden.')

	@staticmethod
	def istFIFO(pErweiterterPfadZuDateinameString):
		lErgebnisMode = os.lstat(pErweiterterPfadZuDateinameString)[stat.ST_MODE]
		lIstFIFOBoolean = stat.S_ISFIFO(lErgebnisMode)
		return lIstFIFOBoolean

	@staticmethod
	def istRegulaereDatei(pErweiterterPfadZuDateinameString):
		lErgebnisMode = os.lstat(pErweiterterPfadZuDateinameString)[stat.ST_MODE]
		lIstRegulaereDateiBoolean = stat.S_ISREG(lErgebnisMode)
		return lIstRegulaereDateiBoolean

	@staticmethod
	def istBeschreibbar(pErweiterterPfadZuDateinameString):
		lIstBeschreibbarBoolean = True
		try:
			with open(pErweiterterPfadZuDateinameString,'r+'):
				pass
		except OSError:
			lIstBeschreibbarBoolean = False
		return lIstBeschreibbarBoolean

class Dateisystemwerkzeuge:
	def __init__(self):
		if type(self) is Dateisystemwerkzeuge:
			raise LiSAusnahmen.QAbstractClassError('Dateisystemwerzeuge kann nicht instanziiert werden.')

	@staticmethod
	def ermittleDateisystemBlockgroesse(pErweiterterPfadString):
		if str.lower(os.name) == 'nt':
			# https://stackoverflow.com/questions/2493172/determine-cluster-size-of-file-system-in-python
			lBytesPerSector = ctypes.c_ulonglong(0)
			lNurVerzeichnisMitFinalemBackslashString = os.path.dirname(pErweiterterPfadString) + '\\'
			lPathname = ctypes.c_wchar_p(lNurVerzeichnisMitFinalemBackslashString)
			ctypes.windll.kernel32.GetDiskFreeSpaceW(lPathname,
													 None,
													 ctypes.pointer(lBytesPerSector),
													 None,
													 None,
													 )
			lDateisystemBlockgroesseInteger = lBytesPerSector.value
		elif str.lower(os.name) == 'posix':
			lDateisystemBlockgroesseInteger = os.statvfs(pErweiterterPfadString).f_bsize
			# stat.st_blksize gibt nur die "bevorzugte" Blockgröße für effizientes I/O an:
			# https://linux.die.net/man/2/stat
		else: # unbekannt, dann besser nicht zuviel schreiben
			lDateisystemBlockgroesseInteger = 1
		return lDateisystemBlockgroesseInteger

	@staticmethod
	def ermittleDateisystemVonPfad(pErweiterterPfadString):
		lBestePassungString = ''
		lTypberzeichnungString = None
		for lPartition in psutil.disk_partitions():
			lErweiterterMountpointString = Pfadwerkzeuge.ermittleErweitertenPfad(lPartition.mountpoint)
			if pErweiterterPfadString.startswith(lErweiterterMountpointString) and len(lBestePassungString) < len(lErweiterterMountpointString):
				lTypberzeichnungString = lPartition.fstype
				lBestePassungString = lErweiterterMountpointString
		if lTypberzeichnungString is None:
			return None
		else:
			return str.lower(lTypberzeichnungString)


class Loggingwerkzeuge:
	"""
	Stellt statische Methoden zum Logging zur Verfügung, die die vorhandenen Funktionen des Moduls logging ergänzen
	"""
	def __init__(self):
		if type(self) is Loggingwerkzeuge:
			raise LiSAusnahmen.QAbstractClassError('Loggingwerkzeuge kann nicht instanziiert werden.')

	@staticmethod
	def loggeMitLoglevelDebugWennNichtPaketiert(lNachrichtBytes, *args, **kwargs):
		"""Gibt die Logging-Nachricht lNachrichtBytes mittelslogging.debug(...), falls LiSCrypt nicht in pakettierter
		Form (PyInstaller) läuft

		:param lNachrichtBytes: Logging-Nachricht
		:type lNachrichtBytes: Bytesequenz
		:param args: Siehe logging.debug
		:param kwargs: Siehe logging.debug
		"""
		if not getattr(sys, 'frozen', False):
			logging.debug(lNachrichtBytes, *args, **kwargs)


class Pfadwerkzeuge:
	"""
	Stellt statische Methoden zur Pfadverarbeitung zur Verfügung.
	"""
	def __init__(self):
		if type(self) is Pfadwerkzeuge:
			raise LiSAusnahmen.QAbstractClassError('Pfadwerkezeuge kann nicht instanziiert werden.')

	@staticmethod
	def ermittleErweitertenPfad(pPfadString):
		"""
		Returniert die erweiterte (extended) Darstellung des absoluten Pfades zu pPfadString (erlaubt 32,767-Zeichen lange Pfadnamen).

		:param pPfadString: Pfadangabe
		:type pPfadString: String
		:return: Erweiterte Darstellung von des absoluten Pfades zu pPfadString
		:rtype: String
		"""
		lAbsoluterPfadString = os.path.abspath(pPfadString)
		if os.name == 'nt' and not lAbsoluterPfadString.startswith('\\\\?\\'):
			if lAbsoluterPfadString.startswith('\\\\'):
				lPfadMitNativeSeparatorsString = '\\\\?\\unc\\' + lAbsoluterPfadString[2:]
			else:
				lPfadMitNativeSeparatorsString = '\\\\?\\' + lAbsoluterPfadString
		else:
			lPfadMitNativeSeparatorsString = lAbsoluterPfadString
		return lPfadMitNativeSeparatorsString

	@staticmethod
	def ermittleReduziertenPfad(pErweiterterPfadString):
		"""
		Returniert die reduzierte Darstellung von des absoluten Pfades zu pPfadString (i.d.R. zu Darstellungzweckne).

		:param pPfadString: Pfadangabe
		:type pPfadString: String
		:return: Reduzierte Darstellung von des absoluten Pfades zu pPfadString
		:rtype: String
		"""
		lAbsoluterPfadString = os.path.abspath(pErweiterterPfadString)
		if os.name == 'nt':
			if lAbsoluterPfadString.startswith('\\\\?\\unc\\'):
				return '\\' + lAbsoluterPfadString[7:]
			elif lAbsoluterPfadString.startswith('\\\\?\\'):
				return lAbsoluterPfadString[4:]
		return lAbsoluterPfadString

	@staticmethod
	def sortiereInVerzeichnissUndDateien(pPfadeList):
		"""
		Returniert Pfadangaben aus pPfadeList getrennt in Verzeichnisnamen und Dateinamen, jeweils alphabetisch soritert

		:param pPfadeList: Pfadangaben
		:type pPfadeList: Liste von Strings
		:return: Pfadangaben aus pPfadeList; getrennt in alphabetisch sortierte Verzeichnisnamen und alphabetisch sortierte Dateinamen
		:rtype: Liste von Strings
		"""
		lSortiertList = pPfadeList[:]
		lSortiertList.sort(key=str.lower)
		lDragAndDropsVerzeichnisseSortiertList = []
		lDragAndDropsDateienSortiertList = []
		for lEintragString in lSortiertList:
			if os.path.isdir(lEintragString):
				lDragAndDropsVerzeichnisseSortiertList.append(lEintragString)
			else:
				lDragAndDropsDateienSortiertList.append(lEintragString)
		return lDragAndDropsVerzeichnisseSortiertList + lDragAndDropsDateienSortiertList

	@staticmethod
	def pruefePfadAufVerschluesselteDateien(pErweiterterPfadString):
		lEnthaeltVerschluesselteDateiBoolean = False
		for lWurzel, lVerzeichnisse, lDateien in os.walk(pErweiterterPfadString):
			for lDateiname in lDateien:
				if str.lower(lDateiname).endswith(LiSKonstanten.C_DATEIENDUNG) and not os.path.islink(lDateiname):
					lEnthaeltVerschluesselteDateiBoolean = True
					break
			if lEnthaeltVerschluesselteDateiBoolean is True:
				break
		return lEnthaeltVerschluesselteDateiBoolean

	@staticmethod
	def pruefePfadAufUnverschluesselteDateien(pErweiterterPfadString):
		lEnthaeltUnverschluesselteDateiBoolean = False
		for lWurzel, lVerzeichnisse, lDateien in os.walk(pErweiterterPfadString):
			for lDateiname in lDateien:
				if not str.lower(lDateiname).endswith(LiSKonstanten.C_DATEIENDUNG) and not os.path.islink(lDateiname):
					lEnthaeltUnverschluesselteDateiBoolean = True
					break
			if lEnthaeltUnverschluesselteDateiBoolean is True:
				break
		return lEnthaeltUnverschluesselteDateiBoolean

class Prozessspeicherwerkzeuge:
	"""
	Stellt statische Methoden zur Prozessspeicherverwaltung zur Verfügung
	"""
	T_BYTES_STRING_NONETYPE = typing.TypeVar('T_BYTES_STRING_NONE', bytes, str, type(None))

	@staticmethod
	def verhindereCoreDumpPOSIX():
		"""
		Verhindert einen core dump unter unixoiden Betriebssystemen.
		"""
		if LiSKonstanten.C_PLATTFORM == 'posix':
			resource.setrlimit(resource.RLIMIT_CORE, [0, 0]) # Verhinderung von core dumps unter unixoiden Betriebssystemen

	@staticmethod
	def ueberschreibeBytesequenzOderString(pZielobjektObjekt: T_BYTES_STRING_NONETYPE, pStringBestaetigungBoolean=False):
		"""
		Überschreibt pZielobjektObjekt im Arbeitsspeicher, wenn es sich dabei um eine Bytesequenz oder einen String mit
		Länge > 1 handelt. Das Überschreiben eines Strings muss darüber hinaus über pStringBestaetigungBoolean=True
		explizit gestattet werden (Vorsichtsmaßnahme wg. String-Interning)

		:param pZielobjektObjekt: Zu überschreibenedes Objekt
		:type pZielobjektObjekt: Bytesequenz oder String
		:param pStringBestaetigungBoolean: Bestätigung des Überschreibens von String (True: ja, False: nein)
		:type pStringBestaetigungBoolean: boolean
		"""
		if pZielobjektObjekt is not None:
			if isinstance(pZielobjektObjekt, bytes) or (isinstance(pZielobjektObjekt, str) and pStringBestaetigungBoolean is True):
				if len(pZielobjektObjekt) > 1: # Byteobjekte mit Länge <= 1 sind 'interned' in CPYTHON
					try:
						lObjektgroesseInteger = len(pZielobjektObjekt)
						lPuffergroesseInteger = lObjektgroesseInteger + 1
						lOffsetInteger = sys.getsizeof(pZielobjektObjekt) - lPuffergroesseInteger
						lSchreibadresseInteger = id(pZielobjektObjekt) + lOffsetInteger
						ctypes.memset(lSchreibadresseInteger, 0, lObjektgroesseInteger)
					except Exception:
						pass
			elif isinstance(pZielobjektObjekt, str) and pStringBestaetigungBoolean is False:
				raise ValueError('Strings können nur mit Bestätigung überschrieben werden.')
			else:
				raise TypeError('Es können nur String- oder Byteobjekte überschrieben werden.')

class Stringwerkzeuge:
	"""
	Stellt statische Methoden zur Stringverarbeitung zur Verfügung
	"""
	@staticmethod
	def rreplace(pOriginalStringString, pAlterTeilstringString, pNeuerTeilstringString, pNInteger):
		"""
		Ersetzt das n-te Vorkommen von rechts des Teilstrings old im String s durch den Teilstring new

		:param pOriginalStringString: Ursprünglicher String
		:type pOriginalStringString: String
		:param pAlterTeilstringString: zu ersetztender Teilstring in s
		:type pAlterTeilstringString: String
		:param pNeuerTeilstringString: neuer Teilstring für old
		:type pNeuerTeilstringString: String
		:param pNInteger: Vorkommen des Teilstrings von rechts
		:type pNInteger: int
		:return: Neuer String mit vorgenommendes Ersetzung
		:rtype: String
		"""
		li = pOriginalStringString.rsplit(pAlterTeilstringString, pNInteger)
		return pNeuerTeilstringString.join(li)

	@staticmethod
	def erzeugeZufaelligenBuchstabenUndZiffernStringMitMaximalerLaenge(pMaxLaengeInteger):
		"""
		Returniert eine zufällige Kombination aus Buchstaben in Groß- und Kleinschreibung, Ziffern und Unterstrichen mit
		minimaler Länge 1 und maximaler Länge pMaxLaengeInteger

		:param pMaxLaengeInteger: Maximale Länge der zufälligen Zeichenkombination
		:type pMaxLaengeInteger: int
		:return: Zufällig Zeichenkombination aus Buchstaben in Groß- und Kleinschreibung, Ziffern und Unterstrichen
		:rtype: String
		"""
		lLaengeInteger = SichereZufallswerkzeuge.erzeugeGanzeZufallszahlZwischen(1,pMaxLaengeInteger)
		return ''.join(random.SystemRandom().choice(string.ascii_letters + '0123456789_')
					   for i in range(lLaengeInteger))

	@staticmethod
	def erzeugeZufaelligenStringFuerSchluesseldatei(pLaengeInteger):
		"""
		Returniert eine zufällige Kombination aus Buchstaben in Groß- und Kleinschreibung, Ziffern, Interpunktionszeichen und Leerzeichen

		:param pLaengeInteger: Avisierte Länge der zufälligen Zeichenkombination
		:type pLaengeInteger: int
		:return: Zufällig Zeichenkombination aus Buchstaben in Groß- und Kleinschreibung, Ziffern, Interpunktionszeichen und Leerzeichen
		:rtype: String
		"""
		return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + string.punctuation + ' ')
					   for i in range(pLaengeInteger))

	@staticmethod
	def erzeugeZufaelligenStringFuerVernichtung(pLaengeInteger):
		"""
		Returniert eine zufällige Kombination aus Buchstaben in Groß- und Kleinschreibung und Ziffern.

		:param pLaengeInteger: Avisierte Länge der zufälligen Zeichenkombination
		:type pLaengeInteger: int
		"""
		return ''.join(random.SystemRandom().choice(string.ascii_letters + '0123456789_.-')
					   for i in range(pLaengeInteger))

	@staticmethod
	def vergleicheVersionen(pVersion1String, pVersion2String):
		"""
		Vergleicht die durch pVerson1String und pVersion2String (Format: X.X.X mit X = beliebige natürliche Zahl inkl.
		0) beschriebenen Versionen. Returniert -1, falls die durch pVersion1String beschriebene Version kleiner ist
		als die durch pVersion2String beschriebene Version, 0 falls die Versionen identisch sind, ansonsten 1.

		:param pVersion1String: Version 1
		:type pVersion1String: String
		:param pVersion1String: Version 2
		:type pVersion1String: String
		:return: Ergebnis des Vergleichs (-1: Version 1 < Version 2; 0: Version 1 == Version 2; 1 Version 1 > Version 2)
		:rtype: Integer
		"""
		lVersion1List = pVersion1String.split('.')
		lVersion2List = pVersion2String.split('.')
		lVergleichsergebnisInteger = 0
		if len(lVersion1List) == len(lVersion2List):
			for lIndexInteger in range(len(lVersion1List)):
				lVersion1ElementInteger = int(lVersion1List[lIndexInteger])
				lVersion2ElementInteger = int(lVersion2List[lIndexInteger])
				if lVersion1ElementInteger < lVersion2ElementInteger:
					lVergleichsergebnisInteger = -1
					break
				elif lVersion1ElementInteger > lVersion2ElementInteger:
					lVergleichsergebnisInteger = 1
					break
		else:
			raise ValueError('Versionsstrings haben unterschiedliche Formate.')
		return lVergleichsergebnisInteger

class SichereZufallswerkzeuge:
	"""
	Stellt kryptografisch sichere Zufallsmethoden zur Verfügung.
	"""
	@staticmethod
	def erzeugeZufaelligeBytefolge(pLaengeInteger):
		"""
		Returniert eine kryptografisch sichere zufällige Bytesequenz der Länge pLaengeInteger.

		:param pLaengeInteger: Länge der zu generierenden Bytesequenz in Bytes
		:type pLaengeInteger: int
		:return: Kryptografische sichere zufällige Bytesequenz
		:rtype: Bytesequenz
		"""
		return os.urandom(pLaengeInteger)

	@staticmethod
	def erzeugeGanzeZufallszahlZwischen(pUntergrenzeInteger, pObergrenzeInteger):
		"""
		Returniert eine kryptografisch sichere zufällige ganzzahlige Zufallszahl zwischen pUntergrenze und pObergrenze.

		:param pUntergrenzeInteger: Untergrenze für die zugenerierende Zufallszahl
		:type pUntergrenzeInteger: int
		:param pObergrenzeInteger: Obergrenze für die zugenerierende Zufallszahl
		:type pObergrenzeInteger: int
		:return: Kryptografische sichere Zufallszahl
		:rtype: int
		"""
		return random.SystemRandom().randrange(start=pUntergrenzeInteger, stop=pObergrenzeInteger+1)

class Verzeichniswerkzeuge:
	"""
	Stellt statische Methoden zum Umgang mit Verzeichnissen zur Verfügung.
	"""
	@staticmethod
	def istVerzeichnis(pErweiterterPfadZuVerzeichnisnameString):
		lErgebnisMode = os.lstat(pErweiterterPfadZuVerzeichnisnameString)[stat.ST_MODE]
		lIstVerzeichnisBoolean = stat.S_ISDIR(lErgebnisMode)
		return lIstVerzeichnisBoolean