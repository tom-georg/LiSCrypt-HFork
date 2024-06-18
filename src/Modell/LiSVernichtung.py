## LiSCrypt - File encryption program using AES-GCM-256 or ChaCha20+HMAC (the latter for particularly large files)
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
#
# *****
# Diese Datei basiert auf einem Teil der Software BleachBit (https://www.bleachbit.org), genauer der Datei
# https://github.com/bleachbit/bleachbit/blob/master/bleachbit/FileUtilities.py, entnommen am 27.02.2018
# Wesentliche Änderungen durch QUA-LiS u.a.:
# 1. Anpassung an Python 3.9
# 2. Eingliederung in LiSCrypt, u.a. in objektorientiertes Paradigma und Verwendung LiSCrypt-eigener Exceptions
# 3. Deutsche Übersetzung
# 4. Modifikation des Überschreibens von Dateien im NTFS-Dateisystem (Berücksichtigung kleiner Dateien im MFT)
# 5. Orientierung der Blockgröße beim "normalen" Überschreiben von Dateien an os.statvfs(...).f_bsize
# 6. Spezifika der Einbindung des Windows-spezifischen Vernichtens mit Administrationsrechten
# 7. Exception-Generierung stark an Exception-Handling in LiSCrypt angepasst
#
# Für die Originalversion gilt:
#
# BleachBit
# Copyright (C) 2008-2021 Andrew Ziem
# https://www.bleachbit.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# *****

"""Diese Modul enthält die Klasse für die Vernichtung von Verzeichniseintträgen"""

from Modell import LiSAusnahmen, LiSKonstanten
from Sonstiges import LiSWerkzeuge

import errno
import os
import stat
import sys
import time

# Für Windows-Admin-spezifische Überschreibroutine:
if LiSKonstanten.C_PLATTFORM == 'nt':
	from Sonstiges import LiSWindowsWipe
	import win32file

class QVerzeichniseintrag:
	"""
	QVerzeichniseintrag modelliert Verzeichniseinträge (Dateien, Links, Pipes oder Verzeichnisse), die zur
	Vernichtung vorgesehen sind. Diese Klasse ist - mit Anpassungen an Python 3.9 - an den Quellcode von
	BleachBit angelehnt.
	"""

	def __init__(self, pControllerQController, pErweiterterPfadZuVerzeichniseintrag):
		"""
		Initialisiert eine zu pErweiterterPfadZuDateiOderVerzeichnisString gehörige Instanz von QVerzeichniseintrag

		:param pControllerQController: Zentrale Coller-Komponente
		:type pControllerQController: QController
		:param pErweiterterPfadZuVerzeichniseintrag: Erweiterter Pfad zu Datei oder Verzeichnis
		:type pErweiterterPfadZuVerzeichniseintrag: String
		"""
		if os.path.exists(pErweiterterPfadZuVerzeichniseintrag):
			self.sControllerQController = pControllerQController
			self.sErweiterterPfadZuDateiOderVerzeichnisString = pErweiterterPfadZuVerzeichniseintrag
			self.sReduzierterPfadZuDateiOderVerzeichnisString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(
				self.sErweiterterPfadZuDateiOderVerzeichnisString)
			self.sErweiterterPfadVorEndnameString = os.path.dirname(self.sErweiterterPfadZuDateiOderVerzeichnisString)
			self.sNurEndnameString = os.path.basename(self.sErweiterterPfadZuDateiOderVerzeichnisString)
			self.sWindowsWipeBoolean = False
		else:
			lEintragnameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuVerzeichniseintrag)
			lNurEndnameString = os.path.basename(lEintragnameReduziertString)
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Vernichtung: Nicht gefunden]', lEintragnameReduziertString)

	def vernichten(self, pIgnoriereFunktionsprozessAktivBoolean):
		"""
		Veranlasst die Vernichtung des Verzeichniseintrags (Datei, Verzeichnis, Verweis oder FIFO).
		"""
		if self.sControllerQController.istFunktionsprozessAktiv() is True or pIgnoriereFunktionsprozessAktivBoolean is True:
			# Aus Sicherheitsgründen wird kann eine Vernichtung ausschließlich _zwischen_ verschiedenen
			# Dateien abgebrochen werden. Hat das Überschreiben einer Datei einmal begonnen, wird es
			# wird es in jedem Fall zuende geführt.
			try:
				self._vernichten()
			except LiSAusnahmen.QFileListDisplayError:
				raise
			except Exception as lException:
				raise LiSAusnahmen.QFileListDisplayError(
					self.sNurEndnameString + ': [Vernichtung fehlgeschlagen]', self.sReduzierterPfadZuDateiOderVerzeichnisString) from lException
			else:
				return(self.sWindowsWipeBoolean)
		else:
			raise LiSAusnahmen.QProcessStoppedByUserError()

	## --- Interne Methode zu Koordination des Vernichtungsvorgangs

	def _vernichten(self):
		"""
		Interne Methode. Vernichtet den Verzeichniseintrag (Datei, Verzeichnis, Verweis oder FIFO).
		"""
		lErgebnisMode = os.lstat(self.sErweiterterPfadZuDateiOderVerzeichnisString)[stat.ST_MODE]
		if LiSKonstanten.C_PLATTFORM == 'posix' and (stat.S_ISFIFO(lErgebnisMode) or stat.S_ISLNK(lErgebnisMode)): # Verzeichnuseintrag ist FIFO oder Verweis unter Linux
			os.remove(self._uberschreibeDateinameOderVerknuepfungsnameOderFIFOnameOderVerzeichnisname())

		elif stat.S_ISDIR(lErgebnisMode): # Verzeichniseintrag ist Verzeichnis
			if self._istVerzeichnisLeer():
				# Beschränkung auf einmalige Überprüfung, ob Verzeichnis leer ist
				lNeuerErweiterterPfadZuVerzeichnisString = self._uberschreibeDateinameOderVerknuepfungsnameOderFIFOnameOderVerzeichnisname()
				try:
					os.rmdir(lNeuerErweiterterPfadZuVerzeichnisString)
				except OSError as e: # Exception-Handling notwendig wg. Unterscheidungen
					# Keine weitere Differenzierung der Fehlercodes notwendig
					raise LiSAusnahmen.QFileListDisplayError(self.sNurEndnameString + ': [Vernichtung: Verzeichnis nicht löschbar]',
						self.sReduzierterPfadZuDateiOderVerzeichnisString) from e
			raise LiSAusnahmen.QFileListDisplayError(
				self.sNurEndnameString + ': [Vernichtung: Verzeichnis nicht leer]',	self.sReduzierterPfadZuDateiOderVerzeichnisString)

		elif stat.S_ISREG(lErgebnisMode): # Verezichniseintrag ist reguläre Datei
			# Exceptions bei den folgenden Aufrufen werden nach oben weitergereicht
			self._ueberschreibeDateiinhalt()
			os.remove(self._uberschreibeDateinameOderVerknuepfungsnameOderFIFOnameOderVerzeichnisname())

		else: # Verzeichniseintrag ist unbekannten Typs
			raise LiSAusnahmen.QFileListDisplayError(self.sNurEndnameString + ': [Vernichtung: Typ nicht löschbar]', self.sReduzierterPfadZuDateiOderVerzeichnisString)

	## --- Private Methoden zum Überschreiben des Dateiinhalts, des Datei- oder Verzeichnisnamens und zur Kappung einer Datei

	def _ueberschreibeDateiinhalt(self):
		"""
		Interne Meta-Methode zum Überschreiben des Dateiinhalts. Das genaue Verfahren wird basierend auf
		Betriebssystem, Nutzerrechten und Dateisystem ausgewählt.
		"""
		if not os.path.isfile(self.sErweiterterPfadZuDateiOderVerzeichnisString) or os.path.islink(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Verknüpfung oder keine Datei. Überschreiben nicht möglich.')
		if LiSKonstanten.C_PLATTFORM == 'nt':
			try:
				self._ueberschreibeDateiinhaltMitWindowsSpezialverfahren()
			except OSError as lException: # Exception-Handling notwendig wg. differenzierter Reaktion
				if lException.winerror in (32, 33): # Existiert, falls unter Windows (s. https://docs.python.org/3/library/exceptions.html#bltin-exceptions)
					# 32=The process cannot access the file because it is being used by another process.
					# 33=The process cannot access the file because another process has locked a portion of the file.
					raise
			except Exception:
				self._ueberschreibeDateiinhaltNormal()
		else:
			self._ueberschreibeDateiinhaltNormal()

	def _ueberschreibeDateiinhaltMitWindowsSpezialverfahren(self):
		"""
		Versucht, das Überschreiben des Dateiinhalts mit Nullwerten mittels einem aufwändigeren, Windows-spezifischen Verfahren
		zu veranlassen.
		"""
		if not LiSWerkzeuge.Dateiwerkzeuge.istRegulaereDatei(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Keine reguläre Datei.')
		LiSWindowsWipe.file_wipe(self.sErweiterterPfadZuDateiOderVerzeichnisString)

		f = open(self.sErweiterterPfadZuDateiOderVerzeichnisString, 'r+b')
		self._setzeDateigroesseAufNull(f)
		f.close()
		self.sWindowsWipeBoolean = True

	def _ueberschreibeDateiinhaltNormal(self):
		"""
		Überschreibt den Dateiinhalt mit normalen Methoden des Dateisstems mit Nullwerten und veranlasst die Kappung
		des Dateiinhalts (Setzen der Dateigröße auf 0 Bytes).
		"""
		if not LiSWerkzeuge.Dateiwerkzeuge.istRegulaereDatei(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Keine reguläre Datei.')
		size = self._ermittleDateigroesseAufDatentraeger()

		f = open(self.sErweiterterPfadZuDateiOderVerzeichnisString, 'r+b')

		lBlockgroesseInteger = LiSWerkzeuge.Dateisystemwerkzeuge.ermittleDateisystemBlockgroesse(self.sErweiterterPfadZuDateiOderVerzeichnisString)
		if LiSWerkzeuge.Dateisystemwerkzeuge.ermittleDateisystemVonPfad(self.sErweiterterPfadZuDateiOderVerzeichnisString) != 'ntfs' or size > 1024: # Ist der Dateiinhalt sicher außerhalb des NTFS-MFT?
			# Wichtig: 1024 mod 512 = 0 (wg. physikalischer Größenberechnung für Dateien in Sonstiges.LiSWerkzeuge)
			blanks = (chr(0) * lBlockgroesseInteger).encode()
			while size > 0:
				f.write(blanks)
				size -= lBlockgroesseInteger
			f.flush()  # flush to OS buffer
			os.fsync(f.fileno())  # force write to disk
		else:
			while size > 0:
				for i in range(lBlockgroesseInteger):
					f.write(b'\x00')
					f.flush() # flush each byte to OS buffer separately
					os.fsync(f.fileno())  # force write to disk for each byte
				size -= lBlockgroesseInteger

		self._setzeDateigroesseAufNull(f)

		f.close()

	def _uberschreibeDateinameOderVerknuepfungsnameOderFIFOnameOderVerzeichnisname(self):
		"""
		Benennt den Verzeichniseintrag pErweiterterPfadZuDateuOderverzeichnisString zweimal in zufällige Namen um und
		returniert das Ergebnis der letzten Umbenennung. Falls die Umbenennungen fehlschlagen, ist der returnierte
		Name identisch mit dem urpsrünglichen Namen.

		:return: Neuer Name des Verzeichniseintrags als erweiterter Pfad
		:rtype: String
		"""
		if not LiSWerkzeuge.Dateiwerkzeuge.istRegulaereDatei(self.sErweiterterPfadZuDateiOderVerzeichnisString)\
				and not LiSWerkzeuge.Dateiwerkzeuge.istFIFO(self.sErweiterterPfadZuDateiOderVerzeichnisString)\
				and not os.path.isdir(self.sErweiterterPfadZuDateiOderVerzeichnisString)\
				and not os.path.islink(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Keine reguläre Datei, keine Verknüpfung, keine FIFO und kein Verzeichnis.')
		lMaximaleLaengeFuerNeuenEndnameInteger = 226 # Siehe auch: http://en.wikipedia.org/wiki/Comparison_of_file_systems#Limits

		# Zunächst: Umbenennung in langen zufälligen Namen
		lAnzahlErfolgloseUmbennenungsversucheInteger = 0
		lIstUmbenanntBoolean = False
		while lIstUmbenanntBoolean is False and lAnzahlErfolgloseUmbennenungsversucheInteger <= 100:
			try:
				lErweiterterPfad2String = os.path.join(self.sErweiterterPfadVorEndnameString, LiSWerkzeuge.Stringwerkzeuge.erzeugeZufaelligenStringFuerVernichtung(lMaximaleLaengeFuerNeuenEndnameInteger))
				if os.path.exists(lErweiterterPfad2String):
					raise OSError('Eintrag mit langem Zufallsnamen existiert bereits!') # Stellt sicher, dass man unter POSIX nicht überschreibt
				os.rename(self.sErweiterterPfadZuDateiOderVerzeichnisString, lErweiterterPfad2String)
				while not os.path.lexists(lErweiterterPfad2String): # Auf Umbenennung warten (ggf. Wartezeit auf Netzlaufwerk)
					time.sleep(.1)
				lIstUmbenanntBoolean = True
			except OSError: # Exception-Handling notwendig, weil keine Weiterreichung nach oben
				if lMaximaleLaengeFuerNeuenEndnameInteger > 10:
					lMaximaleLaengeFuerNeuenEndnameInteger -= 10
				lAnzahlErfolgloseUmbennenungsversucheInteger += 1
		if lAnzahlErfolgloseUmbennenungsversucheInteger > 100:
			lErweiterterPfad2String = self.sErweiterterPfadZuDateiOderVerzeichnisString

		# Abschließend: Umbenennung in kurzen zufälligen Namen
		lAnzahlErfolgloseUmbennenungsversucheInteger = 0
		lIstUmbenanntBoolean = False
		while  lIstUmbenanntBoolean is False and lAnzahlErfolgloseUmbennenungsversucheInteger <= 100:
			try:
				lErweiterterPfad3String = os.path.join(self.sErweiterterPfadVorEndnameString, LiSWerkzeuge.Stringwerkzeuge.erzeugeZufaelligenStringFuerVernichtung(lAnzahlErfolgloseUmbennenungsversucheInteger + 1))
				if os.path.exists(lErweiterterPfad3String):
					raise OSError('Eintrag mit kurzem Zufallsnamen existiert bereits!') # Stellt sicher, dass man unter POSIX nicht überschreibt
				os.rename(lErweiterterPfad2String, lErweiterterPfad3String)
				while not os.path.lexists(lErweiterterPfad3String):
					time.sleep(.1) # Auf Umbenennung warten (ggf. Wartezeit auf Netzlaufwerk)
				lIstUmbenanntBoolean = True
			except OSError: # Exception-Handling notwendig, weil keine Weiterreichung nach oben
				lAnzahlErfolgloseUmbennenungsversucheInteger += 1
			if lAnzahlErfolgloseUmbennenungsversucheInteger > 100:
				lErweiterterPfad3String = lErweiterterPfad2String

		return lErweiterterPfad3String

	def _ermittleDateigroesseAufDatentraeger(self):
		"""
		Interne Methode. Returniert eine möglichst akkurate Abschätzung der Größe einer Datei auf dem Datenträger
		(funktioniert auch auch für Verknüpfungen und sparse files)
		"""
		if not LiSWerkzeuge.Dateiwerkzeuge.istRegulaereDatei(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Keine reguläre Datei.')
		# Sicherstellen, dass es sich wirklich um eine reguläre Datei handelt (und dass sie noch immer existiert)
		if LiSKonstanten.C_PLATTFORM == 'posix': # Das folgende Verfahren funktioniert (anders als os.path.getsize) auch bei sparse files
			lErgebnisStat = os.lstat(self.sErweiterterPfadZuDateiOderVerzeichnisString)
			# lstat-Aufruf wirft OSError im Fehlerfall
			lDateigroesseInteger = lErgebnisStat.st_blocks * 512
			# 512: https://stackoverflow.com/questions/12950511/actual-size-of-a-file
			# Annahme 512 gemäß https://linux.die.net/man/2/stat unter linux
			# und https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/stat.2.html
			# unter macOS (in reiner POSIX-Spezifikation nicht festgelegt: http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_stat.h.html)
		elif LiSKonstanten.C_PLATTFORM == 'nt': # Da stat unter Windows nicht die benötigten Felder liefert, Nutzung nicht möglich
			# In seltenen Fällen liefert os.path.getsize() offenbar "access denied", daher zunächst
			# ein Versuch mit FindFilesW.
			finddata = win32file.FindFilesW(self.sErweiterterPfadZuDateiOderVerzeichnisString)
			lDateigroesseInteger = (finddata[0][4] * (0xffffffff + 1)) + finddata[0][5] # http://timgolden.me.uk/pywin32-docs/WIN32_FIND_DATA.html
			if finddata == []:
				# Manuelles Werfen eines OSError sinnvoll, um stat-Verhalten (s.o.) zu kopieren
				raise FileNotFoundError('Datei ' + self.sReduzierterPfadZuDateiOderVerzeichnisString + ' nicht gefunden.') # FileNotFoundError ist Unterklasse von OSError
		else: # Fallback für andere Betriebssysteme
			lDateigroesseInteger = os.path.getsize(self.sErweiterterPfadZuDateiOderVerzeichnisString)
		return lDateigroesseInteger

	def _setzeDateigroesseAufNull(self, pOffeneDateiFileobjekt):
		"""
		Interne Methode. Kappt die per pOffeneDateiFileobjekt übergebene Datei (setzt die Dateigröße auf 0 Bytes).

		:param pOffeneDateiFileobjekt: Zum Schreiben geöffnetes Dateiobjekt.
		:type pOffeneDateiFileobjekt: Fileobjekt
		"""
		if not LiSWerkzeuge.Dateiwerkzeuge.istRegulaereDatei(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Keine reguläre Datei.')
		pOffeneDateiFileobjekt.truncate(0)
		pOffeneDateiFileobjekt.flush()
		os.fsync(pOffeneDateiFileobjekt.fileno())

	def _istVerzeichnisLeer(self):
		"""
		Interne Methode. Returniert True wenn das durch self.sErweiterterPfadZuDateiOderVerzeichnisString referenzierte
		Verzeichnis	leer ist.

		:return: Angabe, ob durch pErweiterterPfadZuVerzeichnisString referenzierte Verzeichnis leer ist (True: ja, False: nein)
		:rtype: Boolean
		"""
		if not LiSWerkzeuge.Verzeichniswerkzeuge.istVerzeichnis(self.sErweiterterPfadZuDateiOderVerzeichnisString):
			raise AssertionError('Kein Verzeichnis.')
		lVerzeichnisLeerBoolean = False
		lVerzeichniseintraegeIterator = os.scandir(self.sErweiterterPfadZuDateiOderVerzeichnisString)
		try:
			lVerzeichniseintraegeIterator.__next__()
		except StopIteration:
			lVerzeichnisLeerBoolean = True
		return lVerzeichnisLeerBoolean
