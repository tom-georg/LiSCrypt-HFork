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

from Modell import LiSAusnahmen, LiSKonstanten
from Sonstiges import LiSWerkzeuge

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions as cryptography_exceptions

from PyQt5 import QtWidgets

import datetime 
import logging
import os
import re
import struct


class QDatei:
	"""
	Modelliert eine Datei inkl. darauf definierter Operationen aus der Perspektive von LiSCrypt.
	"""
	def __init__(self, pQControllerWorkerThread, pErweiterterPfadZuDateiString):
		"""
		Initialisiert ein zur Datei pErweiterterPfadZuDateiString gehöriges Objekt der Klasse QDatei.

		:param pQControllerWorkerThread: QControllerWorkerThread, der das Objekt erzeugt hat.
		:type pQControllerWorkerThread: QControllerWorkerThread
		:param pErweiterterPfadZuDateiString: Erweiterte Pfadangabe zur Datei
		:type pErweiterterPfadZuDateiString: String
		"""
		if os.path.isfile(pErweiterterPfadZuDateiString) and not os.path.islink(pErweiterterPfadZuDateiString):
			self.sQControllerWorkerThread = pQControllerWorkerThread
			self.sErweiterterPfadZuQuelldateiString = pErweiterterPfadZuDateiString
		else:
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiString)
			lNurEndnameString = os.path.basename(lDateinameReduziertString)
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Ver-/Entschlüsselung: Nicht gefunden]', lDateinameReduziertString)

	def verschluesseln(self, pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString):
		"""
		Veranlasst die Verschlüsselung der zu self.sErweiterterPfadZuDateiString gehörigen Datei als pErweiterterPfadZuZieldateiString
		unter Verwendung eines mittels Scrypt aus pSHA512HashwertBytes generierten Schlüssels

		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		:param pErweiterterPfadZuZieldateiString: Erweiterte Pfadangabe zu Zieldatei
		:type pErweiterterPfadZuZieldateiString: String
		"""
		if self.sQControllerWorkerThread.istFunktionsprozessAktiv() is True:
			self._verschluesseln(pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString)
		else:
			raise LiSAusnahmen.QProcessStoppedByUserError()

	def _verschluesseln(self, pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString):
		"""
		Verschlüsselt die zu self.sErweiterterPfadZuDateiString gehörigen Datei als pErweiterterPfadZuZieldateiString
		unter Verwendung eines mittels Scrypt aus pSHA512HashwertBytes generierten Schlüssels

		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		:param pErweiterterPfadZuZieldateiString: Erweiterte Pfadangabe zu Zieldatei
		:type pErweiterterPfadZuZieldateiString: String
		"""
		lQuelldateiEndnameString = os.path.basename(self.sErweiterterPfadZuQuelldateiString)

		try:
			lQuelldateiStat = os.stat(self.sErweiterterPfadZuQuelldateiString, follow_symlinks=False)
			lQuelldateigroesseInteger = lQuelldateiStat.st_size

			if lQuelldateigroesseInteger <= LiSKonstanten.C_AES_GCM_MAXIMALE_DATEIGROESSE: # Verwende Verschlüsselungsverfahren LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert('Verschlüsselung mit AES-GCM 256')
				lAESGCMV3SchluesselDictionary = self.sQControllerWorkerThread.ermittleAESGCM_V3Schluessel(pSHA512HashwertBytes=pSHA512HashwertBytes)
				lAESGCMV3SchluesselBytes = lAESGCMV3SchluesselDictionary['AESGCMV3Schluessel']
				lInitialesScryptSaltBytes = lAESGCMV3SchluesselDictionary['InitialesScryptSalt']
				lAESGCMV3NonceBytes = self.sQControllerWorkerThread.gibNeueAESGCMNoncePerHKDF()

				# Testausgabe zur Funktionsüberprüfung
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln AES-GCM-V3-Schluessel:' + lAESGCMV3SchluesselBytes)
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln Scrypt Salt:' + lInitialesScryptSaltBytes)
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln AES-GCM-V3-Nonce:' + lAESGCMV3NonceBytes)

				lEncryptor = Cipher(algorithms.AES(key=lAESGCMV3SchluesselBytes),
									modes.GCM(initialization_vector=lAESGCMV3NonceBytes),
									backend=default_backend()).encryptor()

				# Anzeige in Statusleiste anpassen:
				self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Verschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

				with open(self.sErweiterterPfadZuQuelldateiString, 'rb') as lQuelldatei:
					with open(pErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:

						# Headerdaten zusammenstellen:
						lHeaderBytes = self._erstelleHeaderFuerAESGCM_V3(pQuelldateiStat=lQuelldateiStat,
																		 pScryptSaltBytes=lInitialesScryptSaltBytes,
																		 pAESNonceBytes=lAESGCMV3NonceBytes)

						# Headerdaten schreiben und in MAC mit einbeziehen
						lZieldatei.write(lHeaderBytes)
						lEncryptor.authenticate_additional_data(lHeaderBytes)

						# Zehn \x00-Werte schreiben (vorangestellte 0-Folge zur frühzeitigen Kontrolle der Entschlüsselung)
						lNullbytefolgeBytes = b'\x00\x00\x00\x00\x00'
						lZieldatei.write(lEncryptor.update(lNullbytefolgeBytes))

						# Dateinamen der Quelldatei verschlüsseln und schreiben
						lQuelldateiEndnameBytes = lQuelldateiEndnameString.encode()
						lZieldatei.write(lEncryptor.update(lQuelldateiEndnameBytes))

						# Erforderliche LiSCrypt-Version (zur Entschlüsselung) verschlüsseln und schreiben
						lErforderlicheLiSCryptVersionBytes = LiSKonstanten.C_ERFORDERLICHE_LISCRYPT_VERSION.encode()
						lZieldatei.write(lEncryptor.update(lErforderlicheLiSCryptVersionBytes))

						# Quelldatei chunkweise verschlüsseln:
						lBlock = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
						while lBlock:
							if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
								lZieldatei.write(lEncryptor.update(lBlock))  # Quelldatei blockweiseverschlüsseln
								lBlock = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
							else:
								raise LiSAusnahmen.QProcessStoppedByUserError()


						# MAC-Tag aus Header + Daten ermitteln und schreiben
						lEncryptor.finalize()
						lMACTagBytes = lEncryptor.tag #MAC-Tag ermitteln
						lZieldatei.write(struct.pack('>I', len(lMACTagBytes))) # Länge des MAC-Tags schreiben (default: 16 Bytes)
						lZieldatei.write(lMACTagBytes) # MAC-Tag schreiben (default: 16 Bytes)

			else: # Verwende Verschlüsselungsverfahren LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3_1, weil Datei Größer als LiSKonstanten.C_AES_GCM_MAXIMALE_DATEIGROESSE
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert('Verschlüsselung mit ChaCha20+HMAC')
				lChaCha20V3SchluesselDictionary = self.sQControllerWorkerThread.ermittleChaCha20_V3Schluessel(
					pSHA512HashwertBytes=pSHA512HashwertBytes)
				lChaCha20V3SchluesselBytes = lChaCha20V3SchluesselDictionary['ChaCha20V3Schluessel']
				lInitialesScryptSaltBytes = lChaCha20V3SchluesselDictionary['InitialesScryptSalt']
				lChaCha20V3NonceBytes = self.sQControllerWorkerThread.gibNeueChaCha20NoncePerHKDF()

				# Testausgabe zur Funktionsüberprüfung
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln ChaCha20-V3_1-Krypto-Schluessel:' + lChaCha20V3SchluesselBytes)
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln Scrypt Salt:' + lInitialesScryptSaltBytes)
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln ChaCha20-V3_1-Nonce:' + lChaCha20V3NonceBytes)

				lEncryptor = Cipher(algorithms.ChaCha20(key=lChaCha20V3SchluesselBytes, nonce=lChaCha20V3NonceBytes),
									mode=None,
									backend=default_backend()).encryptor()

				lHMACSchluesselDictionary = self.sQControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V3_1()
				lHMACSchluesselBytes = lHMACSchluesselDictionary['HMACSchluessel']

				# Testausgabe zur Funktionsüberprüfung
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln ChaCha20-V3_1-HMAC-Schluessel:' + lHMACSchluesselBytes)

				lHMACBuilder = hmac.HMAC(key=lHMACSchluesselBytes,
										 algorithm=hashes.SHA512(),
										 backend=default_backend())

				# Anzeige in Statusleiste anpassen:
				self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Verschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

				with open(self.sErweiterterPfadZuQuelldateiString, 'rb') as lQuelldatei:
					with open(pErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:

						# Headerdaten zusammenstellen:
						lHeaderBytes = self._erstelleHeaderFuerChaCha20_V3_1(pQuelldateiStat=lQuelldateiStat,
																			 pScryptSaltBytes=lInitialesScryptSaltBytes,
																			 pChaCha20NonceBytes=lChaCha20V3NonceBytes)

						# Headerdaten schreiben und in HMAC mit einbeziehen
						lZieldatei.write(lHeaderBytes)
						lHMACBuilder.update(lHeaderBytes)

						# Fünf \x00-Werte schreiben (vorangestellte 0-Folge zur frühzeitigen Kontrolle der Entschlüsselung)
						lNullbytefolgeBytes = b'\x00\x00\x00\x00\x00'
						lNullbytefolgeVerschluesselBytes = lEncryptor.update(lNullbytefolgeBytes)
						lZieldatei.write(lNullbytefolgeVerschluesselBytes)
						lHMACBuilder.update(lNullbytefolgeVerschluesselBytes)

						# Dateinamen der Quelldatei verschlüsseln, schreiben und das Chiffrat in HMAC mit einbeziehen
						lQuelldateiEndnameBytes = lQuelldateiEndnameString.encode()
						lQuelldateiEndnameVerschluesseltBytes = lEncryptor.update(lQuelldateiEndnameBytes)
						lZieldatei.write(lQuelldateiEndnameVerschluesseltBytes)
						lHMACBuilder.update(lQuelldateiEndnameVerschluesseltBytes)

						# Erforderliche LiSCrypt-Version (zur Entschlüsselung) verschlüsseln, schreiben und das Chiffrat in HMAC mit einbeziehen
						lErforderlicheLiSCryptVersionBytes = LiSKonstanten.C_ERFORDERLICHE_LISCRYPT_VERSION.encode()
						lErforderlicheLiSCryptVersionVerschluesseltBytes = lEncryptor.update(lErforderlicheLiSCryptVersionBytes)
						lZieldatei.write(lErforderlicheLiSCryptVersionVerschluesseltBytes)
						lHMACBuilder.update(lErforderlicheLiSCryptVersionVerschluesseltBytes)

						# Quelldatei chunkweise verschlüsseln:
						lBlock = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
						while lBlock:
							if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
								lEncryptedblockBytes = lEncryptor.update(lBlock)  # Quelldatei blockweise verschlüsseln
								lZieldatei.write(lEncryptedblockBytes)  # Verschlüsselte Datei blockweise schreiben
								lHMACBuilder.update(lEncryptedblockBytes)  # Chiffretext blockweise authentifizieren
								lBlock = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
							else:
								raise LiSAusnahmen.QProcessStoppedByUserError()

						# HMAC-Tag aus Header + Daten ermitteln und schreiben
						lHMACTagBytes = lHMACBuilder.finalize() #HMAC-Tag ermitteln
						lZieldatei.write(struct.pack('>I', len(lHMACTagBytes))) # Länge des HMAC-Tags schreiben (64 Bytes bei HMAC-SHA512)
						lZieldatei.write(lHMACTagBytes) #HMAC-Tag schreiben
		except LiSAusnahmen.QProcessStoppedByUserError:
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
			self.sQControllerWorkerThread.ergaenzeBerichtAusgabe(pZeileString=lQuelldateiEndnameString + ': [Verschlüsselung abgebrochen]',	pToolTipString=lDateinameReduziertString)
			if os.path.isfile(pErweiterterPfadZuZieldateiString) and not os.path.islink(pErweiterterPfadZuZieldateiString):
				try:
					self.sQControllerWorkerThread.vernichte(pErweiterterPfadZuZieldateiString, pAusgabeEintragsnameBoolean=True, pIgnoriereFunktionsprozessAktivBoolean=True)
				except:
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung nach Abbruch von Verschlüsselung')
			raise
		except Exception as lException:
			if os.path.isfile(pErweiterterPfadZuZieldateiString) and not os.path.islink(pErweiterterPfadZuZieldateiString):
				try:
					self.sQControllerWorkerThread.vernichte(pErweiterterPfadZuZieldateiString, pAusgabeEintragsnameBoolean=True, pIgnoriereFunktionsprozessAktivBoolean=True)
				except:
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung nach Exception bei Verschlüsselung')
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
			raise LiSAusnahmen.QFileListDisplayError(lQuelldateiEndnameString + ': [Verschlüsselung fehlgeschlagen]', lDateinameReduziertString) from lException
		finally:
			# Test auf 0-Byte-Folgen mit Ausgabe im Log-Level Debug (Werte können real 0-Byte-Folgen sein!).
			# Die Schlüssel dürfen hier nicht überschrieben werden, da sie im Falle weiterer Verschlüsselungen nicht erneut berechnet werden, sofern
			# die maximale Anzahl an Verschlüsselungen pro Schlüssel nicht überschritten wird. Das Überschreiben geschieht dann in
			# der jeweiligen Methode zur Übermittlung eines neuen Schlüsseln bzw. übergeordnet nach Ende des kompletten Funktionsdurchlaufs.
			if 'lAESGCMV3SchluesselBytes' in locals():
				if re.match(LiSKonstanten.C_REGEX_NULLBYTES, lAESGCMV3SchluesselBytes) is not None:
					LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln: lAESGCMV3SchluesselBytes ist Nullbytefolge!')
			elif 'lChaCha20V3SchluesselBytes' in locals():
				if re.match(LiSKonstanten.C_REGEX_NULLBYTES, lChaCha20V3SchluesselBytes) is not None:
					LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSKrypto.QDatei._verschluesseln: lChaCha20V3SchluesselBytes ist Nullbytefolge!')


	def entschluesseln(self, pSHA256HashwertBytes, pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString):
		"""
		Veranlasst die Entschlüsselung der zu self.sErweiterterPfadZuDateiString gehörigen Datei als pErweiterterPfadZuZieldateiString
		unter Verwendung eines mittels Scrypt aus pSHA256HashwertBytes oder pSHA512HashwertBytes generierten Schlüssels

		:param pSHA256HashwertBytes: SHA256-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA256HashwertBytes: Bytesequenz
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		:param pErweiterterPfadZuZieldateiString: Erweiterte Pfadangabe zu Zieldatei
		:type pErweiterterPfadZuZieldateiString: String
		"""
		if self.sQControllerWorkerThread.istFunktionsprozessAktiv() is True:
			lErweiterterPfadZuZieldateiString = self._entschluesseln(pSHA256HashwertBytes=pSHA256HashwertBytes, pSHA512HashwertBytes=pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString=pErweiterterPfadZuZieldateiString)
			return lErweiterterPfadZuZieldateiString
		else:
			raise LiSAusnahmen.QProcessStoppedByUserError()

	def _entschluesseln(self, pSHA256HashwertBytes, pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString):
		"""
		Entschlüsselt die zu self.sErweiterterPfadZuDateiString gehörigen Datei als pErweiterterPfadZuZieldateiString
		unter Verwendung eines mittels Scrypt aus pSHA256HashwertBytes oder pSHA512HashwertBytes generierten Schlüssels

		:param pSHA256HashwertBytes: SHA256-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA256HashwertBytes: Bytesequenz
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		:param pErweiterterPfadZuZieldateiString: Erweiterte Pfadangabe zu Zieldatei
		:type pErweiterterPfadZuZieldateiString: String
		:return Erweiterter Pfad zu Zieldatei (im Erfolgsfall, sonst Abbruch durch weitergereichte Exception)
		:rtype String
		"""

		lZuVernichtendeBytesequenzenListe_LOESCHEN = [] # Sammlung von Bytesequenzen, die am Schluss überschrieben werden müssen

		lErweiterterPfadZuZieldateiString = pErweiterterPfadZuZieldateiString
		lQuelldateiEndnameString = os.path.basename(self.sErweiterterPfadZuQuelldateiString)
		
		try:
			with open(self.sErweiterterPfadZuQuelldateiString, 'rb') as lQuelldatei:
				if(lQuelldatei.read(4).decode() != 'LiSX'):
					lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
					lNurEndnameString = os.path.basename(lDateinameReduziertString)
					raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Keine LiSCrypt-Datei]', lDateinameReduziertString)
				else:

					# Header einlesen:
					lHeaderDictionary = self._liesHeaderAusDatei(lQuelldatei)

					if lHeaderDictionary is not None:
						if lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V1:
							lAESSchluesselDictionary = self.sQControllerWorkerThread.ermittleAESGCM_V1Schluessel(
								pSHA256HashwertBytes=pSHA256HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'])

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lAESSchluesselDictionary['AESGCMV1Schluessel'])

							lAESDecryptor_Authentifizierung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV1Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV1NonceBytes']),
								backend=default_backend()).decryptor()
							lAESDecryptor_Entschluesselung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV1Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV1NonceBytes']),
								backend=default_backend()).decryptor()

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lAESDecryptor_Authentifizierung.authenticate_additional_data(lHeaderBytes)

							# Verschlüsselten Dateinamen authentifizieren
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							# Zwecks Authentifizierung entschlüsselten Dateinamen überschreiben und Referenz entfernen
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
									lBlockEntschluesseltBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lBlockBytes)
									# Zwecks Authentifizierung entschlüsselten Block sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag lesen und Header + Daten authentifizieren:
							lMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lMACTagBytes = lQuelldatei.read(lMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString)
							try:
								lAESDecryptor_Authentifizierung.finalize_with_tag(lMACTagBytes)
							except cryptography_exceptions.InvalidSignature:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							#Headerdaten müssen in Entschlüsselung einbezogen werden:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								lAESDecryptor_Entschluesselung.authenticate_additional_data(lHeaderBytes)

								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lAESDecryptor_Entschluesselung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lAESDecryptor_Entschluesselung.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
										lNurEndnameString = os.path.basename(lDateinameReduziertString)
										raise LiSAusnahmen.QProcessStoppedByUserError()

						elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V2:
							lAESSchluesselDictionary = self.sQControllerWorkerThread.ermittleAESGCM_V2Schluessel(
								pSHA256HashwertBytes=pSHA256HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pInitialesScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'],
								pHKDFSaltBytes=lHeaderDictionary['HKDFSaltFuerAESGCMV2Bytes'])

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lAESSchluesselDictionary['AESGCMV2Schluessel'])

							lAESDecryptor_Authentifizierung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV2Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV2NonceBytes']),
								backend=default_backend()).decryptor()
							lAESDecryptor_Entschluesselung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV2Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV2NonceBytes']),
								backend=default_backend()).decryptor()

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lAESDecryptor_Authentifizierung.authenticate_additional_data(lHeaderBytes)

							# Verschlüsselten Dateinamen authentifizieren
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							# Zwecks Authentifizierung entschlüsselten Dateinamen überschreiben und Referenz entfernen
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Erforderliche LiSCrypt-Version authentifizieren
							lErforderlicheLiSCryptVersionVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
							lAESDecryptor_Authentifizierung.update(lErforderlicheLiSCryptVersionVerschluesseltBytes)

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
									lBlockEntschluesseltBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lBlockBytes)
									# Zwecks Authentifizierung entschlüsselten Block sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
									lNurEndnameString = os.path.basename(lDateinameReduziertString)
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag lesen und Header + Daten authentifizieren:
							lMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lMACTagBytes = lQuelldatei.read(lMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString)
							try:
								lAESDecryptor_Authentifizierung.finalize_with_tag(lMACTagBytes)
							except cryptography_exceptions.InvalidTag:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							#Headerdaten müssen in Entschlüsselung einbezogen werden:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								lAESDecryptor_Entschluesselung.authenticate_additional_data(lHeaderBytes)

								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lAESDecryptor_Entschluesselung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Erforderliche LiSCrypt-Version entschlüsseln:
								lErforderlicheLiSCryptVersionString = lAESDecryptor_Entschluesselung.update(lErforderlicheLiSCryptVersionVerschluesseltBytes).decode()
								if LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen(LiSKonstanten.__version__, lErforderlicheLiSCryptVersionString) < 0:
									lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
									lNurEndnameString = os.path.basename(lDateinameReduziertString)
									raise LiSAusnahmen.QLiSCryptTooOldError(lNurEndnameString + ': [LiSCrypt-Update erforderlich]', lDateinameReduziertString)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] + lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lAESDecryptor_Entschluesselung.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										raise LiSAusnahmen.QProcessStoppedByUserError()

						elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3:
							lAESSchluesselDictionary = self.sQControllerWorkerThread.ermittleAESGCM_V3Schluessel(
								pSHA512HashwertBytes=pSHA512HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pInitialesScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'],)

							# lAESSchluesselDictionary['AESGCMV3Schluessel'] darf nach Verwendung NICHT direkt überschrieben werden (Wiederverwendung mit neuer Nonce, global in LiSCrypt.py!)

							lAESDecryptor_Authentifizierung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV3Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV3NonceBytes']),
								backend=default_backend()).decryptor()
							lAESDecryptor_Entschluesselung = Cipher(
								algorithms.AES(key=lAESSchluesselDictionary['AESGCMV3Schluessel']),
								modes.GCM(initialization_vector=lHeaderDictionary['AESGCMV3NonceBytes']),
								backend=default_backend()).decryptor()

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lAESDecryptor_Authentifizierung.authenticate_additional_data(lHeaderBytes)

							# Verschlüsselte Nullbytefolge authentifizieren:
							lNullbytefolgeVerschluesseltBytes = lQuelldatei.read(5)
							lNullbytefolgeEntschluesseltBytes = lAESDecryptor_Authentifizierung.update(lNullbytefolgeVerschluesseltBytes)
							if lNullbytefolgeEntschluesseltBytes != b'\x00\x00\x00\x00\x00':
								raise ValueError('Nullbytefolge nicht erkannt.')

							# Verschlüsselten Dateinamen authentifizieren
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							# Zwecks Authentifizierung entschlüsselten Dateinamen überschreiben und Referenz entfernen
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Erforderliche LiSCrypt-Version authentifizieren
							lErforderlicheLiSCryptVersionVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
							lAESDecryptor_Authentifizierung.update(lErforderlicheLiSCryptVersionVerschluesseltBytes)

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
									lBlockEntschluesseltBytes_LOESCHEN = lAESDecryptor_Authentifizierung.update(lBlockBytes)
									# lBlockEntschluesseltBytes_LOESCHEN sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag lesen und Header + Daten authentifizieren:
							lMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lMACTagBytes = lQuelldatei.read(lMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString)
							try:
								lAESDecryptor_Authentifizierung.finalize_with_tag(lMACTagBytes)
							except cryptography_exceptions.InvalidTag:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							#Headerdaten müssen in Entschlüsselung einbezogen werden:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								lAESDecryptor_Entschluesselung.authenticate_additional_data(lHeaderBytes)

								# Nullbytefolge durch Decryptor schicken, da dieser stateful ist:
								lAESDecryptor_Entschluesselung.update(lNullbytefolgeVerschluesseltBytes)

								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lAESDecryptor_Entschluesselung.update(lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Erforderliche LiSCrypt-Version entschlüsseln:
								lErforderlicheLiSCryptVersionString = lAESDecryptor_Entschluesselung.update(lErforderlicheLiSCryptVersionVerschluesseltBytes).decode()
								if LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen(LiSKonstanten.__version__, lErforderlicheLiSCryptVersionString) < 0:
									lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
									lNurEndnameString = os.path.basename(lDateinameReduziertString)
									raise LiSAusnahmen.QLiSCryptTooOldError(lNurEndnameString + ': [LiSCrypt-Update erforderlich]', lDateinameReduziertString)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + len(lNullbytefolgeVerschluesseltBytes) + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] + lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv:
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lAESDecryptor_Entschluesselung.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										raise LiSAusnahmen.QProcessStoppedByUserError()


						elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V1:
							lChaCha20SchluesselDictionary = self.sQControllerWorkerThread.ermittleChaCha20_V1Schluessel(
								pSHA256HashwertBytes=pSHA256HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'])

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lChaCha20SchluesselDictionary['ChaCha20V1Schluessel'])

							lChaCha20Decryptor = Cipher(algorithms.ChaCha20(key=lChaCha20SchluesselDictionary['ChaCha20V1Schluessel'], nonce=lHeaderDictionary['ChaCha20V1NonceBytes']),
												mode=None,
												backend=default_backend()).decryptor()

							lHMACSchluesselDictionary = self.sQControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V1(
								pSHA256HashwertBytes=pSHA256HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pScryptSaltBytes=lHeaderDictionary['ScryptSaltHMACFuerChaCha20V1Bytes'])

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lHMACSchluesselDictionary['HMACSchluessel'])

							lHMACSchluesselBytes = lHMACSchluesselDictionary['HMACSchluessel']
							lHMACBuilder = hmac.HMAC(key=lHMACSchluesselBytes,
													 algorithm=hashes.SHA256(),
													 backend=default_backend())

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lHMACBuilder.update(lHeaderBytes)

							# Ursprünglichen Dateinamen authentifizieren:
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lHMACBuilder.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockEntschluesseltBytes_LOESCHEN = lQuelldatei.read(lVerbleibendeBytesInteger)
									lHMACBuilder.update(lBlockBytes)
									# lBlockEntschluesseltBytes_LOESCHEN sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag (HMAC) lesen und Header + Daten authentifizieren:
							lHMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lHMACTagBytes = lQuelldatei.read(lHMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString)
							try:
								lHMACBuilder.verify(lHMACTagBytes)
							except cryptography_exceptions.InvalidSignature:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							# Ursprünglichen Dateinamen entschlüsseln:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lChaCha20Decryptor.update(lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv:
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lChaCha20Decryptor.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										raise LiSAusnahmen.QProcessStoppedByUserError()

						elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V2:
							lChaCha20SchluesselDictionary = self.sQControllerWorkerThread.ermittleChaCha20_V2Schluessel(
								pSHA256HashwertBytes=pSHA256HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary['ScryptParallelisierungInteger'],
								pInitialesScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'],
								pBase91Boolean=True,
								pHKDFSaltBytes=lHeaderDictionary['HKDFSaltFuerChaCha20V2Bytes'])

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lChaCha20SchluesselDictionary['ChaCha20V2Schluessel'])

							lChaCha20Decryptor = Cipher(
								algorithms.ChaCha20(key=lChaCha20SchluesselDictionary['ChaCha20V2Schluessel'],
								nonce=lHeaderDictionary['ChaCha20V2NonceBytes']),
								mode=None,
								backend=default_backend()).decryptor()


							lHMACSchluesselDictionary = self.sQControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V2(
								pHKDFSaltBytes=lHeaderDictionary['HKDFSaltFuerChaCha20V2Bytes']) # HMAC-Schlüssel unterscheidet sich von ChaCha20V2-Schlüssel nur durch anderen Kontext (info)

							lZuVernichtendeBytesequenzenListe_LOESCHEN.append(lHMACSchluesselDictionary['HMACSchluessel'])

							lHMACSchluesselBytes = lHMACSchluesselDictionary['HMACSchluessel']
							lHMACBuilder = hmac.HMAC(key=lHMACSchluesselBytes,
													 algorithm=hashes.SHA256(),
													 backend=default_backend())

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lHMACBuilder.update(lHeaderBytes)

							# Ursprünglichen Dateinamen authentifizieren:
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lHMACBuilder.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Erforderliche LiSCrypt-Version authentifizieren
							lErforderlicheLiSCryptVersionVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
							lHMACBuilder.update(lErforderlicheLiSCryptVersionVerschluesseltBytes)

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
									lBlockEntschluesseltBytes_LOESCHEN = lHMACBuilder.update(lBlockBytes)
									# lBlockEntschluesseltBytes_LOESCHEN sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag (HMAC) lesen und Header + Daten authentifizieren:
							lHMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lHMACTagBytes = lQuelldatei.read(lHMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString)
							try:
								lHMACBuilder.verify(lHMACTagBytes)
							except cryptography_exceptions.InvalidSignature:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							# Ursprünglichen Dateinamen entschlüsseln:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lChaCha20Decryptor.update(lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Erforderliche LiSCrypt-Version entschlüsseln:
								lErforderlicheLiSCryptVersionString = lChaCha20Decryptor.update(lErforderlicheLiSCryptVersionVerschluesseltBytes).decode()
								if LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen(LiSKonstanten.__version__, lErforderlicheLiSCryptVersionString) < 0:
									lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
									lNurEndnameString = os.path.basename(lDateinameReduziertString)
									raise LiSAusnahmen.QLiSCryptTooOldError(lNurEndnameString + ': [LiSCrypt-Update erforderlich]',	lDateinameReduziertString)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] + lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lChaCha20Decryptor.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										raise LiSAusnahmen.QProcessStoppedByUserError()

						elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3 \
								or lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3_1:
							lChaCha20SchluesselDictionary = self.sQControllerWorkerThread.ermittleChaCha20_V3Schluessel(
								pSHA512HashwertBytes=pSHA512HashwertBytes,
								pScryptAufwandsfaktorInteger=lHeaderDictionary['ScryptAufwandsfaktorInteger'],
								pScryptBlockgroesseInteger=lHeaderDictionary['ScryptBlockgroesseInteger'],
								pScryptParallelisierungInteger=lHeaderDictionary[
									'ScryptParallelisierungInteger'],
								pInitialesScryptSaltBytes=lHeaderDictionary['ScryptSaltBytes'])

							# lChaCha20SchluesselDictionary['ChaCha20V3Schluessel'] darf nach Verwendung nicht direkt überschrieben werden (Wiederverwendung mit neuer Nonce!)

							lChaCha20Decryptor = Cipher(
								algorithms.ChaCha20(key=lChaCha20SchluesselDictionary['ChaCha20V3Schluessel'],
													nonce=lHeaderDictionary['ChaCha20V3NonceBytes']),
													mode=None,
													backend=default_backend()).decryptor()

							if lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3:
								lHMACSchluesselDictionary = self.sQControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V3()
							else:
								lHMACSchluesselDictionary = self.sQControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V3_1()

							# lHMACSchluesselDictionary['HMACSchluessel'] darf bei LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3
							# und LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3_1 NICHT direkt überschrieben werden (Wiederverwendung mit neuer Nonce, global in LiSCrypt.py)

							lHMACSchluesselBytes = lHMACSchluesselDictionary['HMACSchluessel']
							lHMACBuilder = hmac.HMAC(key=lHMACSchluesselBytes,
													 algorithm=hashes.SHA512(),
													 backend=default_backend())

							# Anzeige in Statusleiste anpassen:
							self.sQControllerWorkerThread.setzeStatusleisteUndGUIZustand(pTextString='Entschlüsselung: ' + lQuelldateiEndnameString, pAbbrechenButtonAktivBoolean=True)

							# Header authentifizieren:
							lPositionNachHeaderInQuelldateiInteger = lQuelldatei.tell()
							lQuelldatei.seek(0)
							lHeaderBytes = lQuelldatei.read(lPositionNachHeaderInQuelldateiInteger)
							lHMACBuilder.update(lHeaderBytes)

							# Verschlüsselte Nullbytefolge authentifizieren:
							lNullbytefolgeVerschluesseltBytes = lQuelldatei.read(5)
							lHMACBuilder.update(lNullbytefolgeVerschluesseltBytes)

							# Ursprünglichen Dateinamen authentifizieren:
							lDateiOriginaldateiEndnameVerschluesseltBytes = lQuelldatei.read(
								lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'])
							lDateiOriginaldateiEndnameBytes_LOESCHEN = lHMACBuilder.update(lDateiOriginaldateiEndnameVerschluesseltBytes)
							LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
							del lDateiOriginaldateiEndnameBytes_LOESCHEN

							# Erforderliche LiSCrypt-Version authentifizieren
							lErforderlicheLiSCryptVersionVerschluesseltBytes = lQuelldatei.read(lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
							lHMACBuilder.update(lErforderlicheLiSCryptVersionVerschluesseltBytes)

							# Quelldatei chunkweise authentifizieren:
							lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
							while lVerbleibendeBytesInteger > 0:
								if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
									if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
										lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
									else:
										lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
									lBlockEntschluesseltBytes_LOESCHEN = lHMACBuilder.update(lBlockBytes)
									# lBlockEntschluesseltBytes_LOESCHEN sofort überschreiben und Referenz entfernen:
									LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockEntschluesseltBytes_LOESCHEN)
									del lBlockEntschluesseltBytes_LOESCHEN
									lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
								else:
									raise LiSAusnahmen.QProcessStoppedByUserError()

							# AUTH-Tag (HMAC) lesen und Header + Daten authentifizieren:
							lHMACTagLaengeInteger = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
							lHMACTagBytes = lQuelldatei.read(lHMACTagLaengeInteger)
							if (lQuelldatei.read() != b''):
								lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
								lNurEndnameString = os.path.basename(lDateinameReduziertString)
								raise LiSAusnahmen.QFileListDisplayError(
									lNurEndnameString + ': [Entschlüsselung fehlgeschlagen]',
									lDateinameReduziertString)
							try:
								lHMACBuilder.verify(lHMACTagBytes)
							except cryptography_exceptions.InvalidSignature:
								raise

							# OK, verschlüsselte Datei ist authentifiziert - weiter mit der Entschlüsselung:
							# Ursprünglichen Dateinamen entschlüsseln:
							with open(lErweiterterPfadZuZieldateiString, 'wb') as lZieldatei:
								# Nullbytefolge entschlüsseln:
								lNullbytefolgeBytes = lChaCha20Decryptor.update(
									lNullbytefolgeVerschluesseltBytes)
								if lNullbytefolgeBytes != b'\x00\x00\x00\x00\x00':
									raise ValueError('Nullbytefolge nicht erkannt.')

								# Ursprünglichen Dateinamen entschlüsseln:
								lDateiOriginaldateiEndnameBytes = lChaCha20Decryptor.update(
									lDateiOriginaldateiEndnameVerschluesseltBytes)

								# Erforderliche LiSCrypt-Version entschlüsseln:
								lErforderlicheLiSCryptVersionString = lChaCha20Decryptor.update(
									lErforderlicheLiSCryptVersionVerschluesseltBytes).decode()
								if LiSWerkzeuge.Stringwerkzeuge.vergleicheVersionen(LiSKonstanten.__version__, lErforderlicheLiSCryptVersionString) < 0:
									lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
									lNurEndnameString = os.path.basename(lDateinameReduziertString)
									raise LiSAusnahmen.QLiSCryptTooOldError(lNurEndnameString + ': [LiSCrypt-Update erforderlich]', lDateinameReduziertString)

								# Quelldatei chunkweise entschlüsseln:
								lQuelldatei.seek(lPositionNachHeaderInQuelldateiInteger + len(lNullbytefolgeVerschluesseltBytes) + lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] + lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'])
								lVerbleibendeBytesInteger = lHeaderDictionary['DateiOriginalgroesse']
								while lVerbleibendeBytesInteger > 0:
									if self.sQControllerWorkerThread.istFunktionsprozessAktiv():
										if lVerbleibendeBytesInteger >= LiSKonstanten.C_DATEI_BLOCKGROESSE:
											lBlockBytes = lQuelldatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
										else:
											lBlockBytes = lQuelldatei.read(lVerbleibendeBytesInteger)
										lZieldatei.write(lChaCha20Decryptor.update(lBlockBytes))
										lVerbleibendeBytesInteger -= LiSKonstanten.C_DATEI_BLOCKGROESSE
									else:
										lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
										raise LiSAusnahmen.QProcessStoppedByUserError('Abbruch durch Nutzer: ' + lDateinameReduziertString)

						else:
							# Wenn das Verfahren nicht erkannt wurde (Fehlermeldung: Entschlüsselung fehlgeschlagen):
							raise ValueError
					else:
						# Wenn lHeaderDictionary None ist, d.h. kein Header gelesen werden konnte
						raise ValueError

			lQuelldatei.close()
			lZieldatei.close()

			lZieldateinameVorEndnameString = os.path.split(lErweiterterPfadZuZieldateiString)[0]
			lOriginaldateinameString = os.path.join(lZieldateinameVorEndnameString,lDateiOriginaldateiEndnameBytes.decode())

			if not os.path.lexists(lOriginaldateinameString):
				try:
					os.rename(lErweiterterPfadZuZieldateiString, lOriginaldateinameString)
					lErweiterterPfadZuZieldateiString = lOriginaldateinameString
				except OSError:
					raise
				try:
					os.utime(lOriginaldateinameString, ns=(lHeaderDictionary['DateiOriginalZugriffsdatumInteger'], lHeaderDictionary['DateiOriginalAenderungsdatumInteger']))
				except OSError:
					pass
			else:
				lUeberschreibenInteger = self.sQControllerWorkerThread._zeigeUeberschreibenDialog(lOriginaldateinameString)
				if lUeberschreibenInteger == QtWidgets.QMessageBox.Yes:
					try:
						self.sQControllerWorkerThread.vernichte(lOriginaldateinameString, pAusgabeEintragsnameBoolean=True)
					except (LiSAusnahmen.QFileListDisplayError, LiSAusnahmen.QProcessStoppedByUserError):
						raise
					try:
						os.rename(lErweiterterPfadZuZieldateiString, lOriginaldateinameString)
						lErweiterterPfadZuZieldateiString = lOriginaldateinameString
					except OSError as lException:
						raise
					try:
						os.utime(lOriginaldateinameString, ns=(lHeaderDictionary['DateiOriginalZugriffsdatumInteger'], lHeaderDictionary['DateiOriginalAenderungsdatumInteger']))
					except OSError:
						pass
				elif lUeberschreibenInteger == QtWidgets.QMessageBox.No:
					lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
					lNurEndnameString = os.path.basename(lDateinameReduziertString)
					raise LiSAusnahmen.QFileSkippedByUserError(lNurEndnameString + ': [Übersprungen: Nutzer-Auswahl]', lDateinameReduziertString)
				else: #d.h. lUeberschreibenBoolean=None
					self.sQControllerWorkerThread.stoppeFunktionsprozess()
					raise LiSAusnahmen.QProcessStoppedByUserError()

		except LiSAusnahmen.QProcessStoppedByUserError:
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
			self.sQControllerWorkerThread.ergaenzeBerichtAusgabe(pZeileString=lQuelldateiEndnameString + ': [Entschlüsselung abgebrochen]',	pToolTipString=lDateinameReduziertString)
			if os.path.isfile(lErweiterterPfadZuZieldateiString) and not os.path.islink(lErweiterterPfadZuZieldateiString):
				try:
					self.sQControllerWorkerThread.vernichte(lErweiterterPfadZuZieldateiString, pAusgabeEintragsnameBoolean=False, pIgnoriereFunktionsprozessAktivBoolean=True)
				except:
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung nach Abbruch von Entschlüsselung')
			raise
		except LiSAusnahmen.QFileSkippedByUserError:
			# Exception-Nachricht wurde schon erstellt
			if os.path.isfile(lErweiterterPfadZuZieldateiString) and not os.path.islink(lErweiterterPfadZuZieldateiString):
				try:
					self.sQControllerWorkerThread.vernichte(lErweiterterPfadZuZieldateiString, pAusgabeEintragsnameBoolean=False, pIgnoriereFunktionsprozessAktivBoolean=True)
				except:
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung nach Auswahl \'Nein\' bei Namenskonflikt')
			raise
		except Exception as lException:
			if os.path.isfile(lErweiterterPfadZuZieldateiString) and not os.path.islink(lErweiterterPfadZuZieldateiString):
				try:
					self.sQControllerWorkerThread.vernichte(lErweiterterPfadZuZieldateiString, pAusgabeEintragsnameBoolean=True, pIgnoriereFunktionsprozessAktivBoolean=True)
				except:
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung nach Exception bei Verschlüsselung')
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(self.sErweiterterPfadZuQuelldateiString)
			raise LiSAusnahmen.QFileListDisplayError(lQuelldateiEndnameString + ': [Entschlüsselung fehlgeschlagen]', lDateinameReduziertString) from lException
		else:
			return lErweiterterPfadZuZieldateiString # Im Erfolgsfall (Entschlüsselt und umbenannt in ursprünglichen Dateinamen)
		finally:
			if 'lDateiOriginaldateiEndnameBytes_LOESCHEN' in locals():
				try:
					LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
					del lDateiOriginaldateiEndnameBytes_LOESCHEN
				except:
					# Falls Überschreiben eines Objekts im Speicher fehlschlägt, nichts machen
					pass
			if 'lBlockEntschluesseltBytes_LOESCHEN' in locals():
				try:
					LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lDateiOriginaldateiEndnameBytes_LOESCHEN)
					del lDateiOriginaldateiEndnameBytes_LOESCHEN
				except:
					# Falls Überschreiben eines Objekts im Speicher fehlschlägt, nichts machen
					pass
			for lEintragBytes_LOESCHEN in lZuVernichtendeBytesequenzenListe_LOESCHEN:
				try:
					LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lEintragBytes_LOESCHEN)
					lZuVernichtendeBytesequenzenListe_LOESCHEN.remove(lEintragBytes_LOESCHEN)
				except:
					# Falls Überschreiben eines Objekts im Speicher fehlschlägt, nichts machen
					pass

	# Interne Methoden zur Erstellung bzw. zum Auslesen des Headers verschlüsselter Dateien

	def _erstelleHeaderFuerAESGCM_V3(self, *, pQuelldateiStat, pScryptSaltBytes, pAESNonceBytes):
		"""
		Interne Methode. Erstellt einen Header für Verschlüsselung mit dem durch LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3
		beschriebenen Verfahren und returniert diesen.
		:param pQuelldateiStat: Stat-Objekt zur Quelldatei
		:type pQuelldateiStat: Stat-Object
		:param pScryptSaltBytes: Salt für Scrypt
		:type pScryptSaltBytes: Bytesequenz
		:param pAESNonceBytes: Nonce für AESGCM_V3
		:type pAESNonceBytes: Bytesequenz
		:return: Header
		:rtype: Bytesequenz
		"""
		lQuelldateiAenderungsdatumInteger = int(round(pQuelldateiStat.st_mtime_ns))
		lQuelldateiZugriffsdatumInteger = int(round(pQuelldateiStat.st_atime_ns))
		lQuelldateigroesseInteger = pQuelldateiStat.st_size
		lQuelldateiEndnameString = os.path.basename(self.sErweiterterPfadZuQuelldateiString)
		lQuelldateiEndnameLaengeInteger = len(lQuelldateiEndnameString.encode())

		lHeaderBytes = b''
		lHeaderBytes = lHeaderBytes.join(
			['LiSX'.encode(),
			 struct.pack('>H', LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3),
			 struct.pack('>Q', LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_BLOCK_GROESSE),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_SALT_LAENGE),
			 pScryptSaltBytes,
			 struct.pack('>I', LiSKonstanten.C_AES_GCM_NONCE_LAENGE),
			 pAESNonceBytes,
			 struct.pack('>Q', lQuelldateiAenderungsdatumInteger),
			 struct.pack('>Q', lQuelldateiZugriffsdatumInteger),
			 struct.pack('>Q', lQuelldateigroesseInteger),
			 struct.pack('>Q', lQuelldateiEndnameLaengeInteger),
			 struct.pack('>H', len(LiSKonstanten.C_ERFORDERLICHE_LISCRYPT_VERSION))])
		return lHeaderBytes

	def _erstelleHeaderFuerChaCha20_V3_1(self, *, pQuelldateiStat, pScryptSaltBytes, pChaCha20NonceBytes):
		"""
		Interne Methode. Erstellt einen Header für Verschlüsselung mit dem durch LiSKonstanten.C_VERFAHREN_CHACHA20_V3_1
		beschriebenen Verfahren und returniert diesen.
		:param pQuelldateiStat: Stat-Objekt zur Quelldatei
		:type pQuelldateiStat: Stat-Object
		:param pScryptSaltBytes: Salt für Scrypt
		:type pScryptSaltBytes: Bytesequenz
		:param pChaCha20NonceBytes: Nonce für CHACHA20_V3
		:type pChaCha20NonceBytes: Bytesequenz
		:return: Header
		:rtype: Bytesequenz
		"""
		lQuelldateiAenderungsdatumInteger = int(round(pQuelldateiStat.st_mtime_ns))
		lQuelldateiZugriffsdatumInteger = int(round(pQuelldateiStat.st_atime_ns))
		lQuelldateigroesseInteger = pQuelldateiStat.st_size
		lQuelldateiEndnameString = os.path.basename(self.sErweiterterPfadZuQuelldateiString)
		lQuelldateiEndnameLaengeInteger = len(lQuelldateiEndnameString.encode())

		lHeaderBytes = b''
		lHeaderBytes = lHeaderBytes.join(
			['LiSX'.encode(),
			 struct.pack('>H', LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3_1),
			 struct.pack('>Q', LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_BLOCK_GROESSE),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT),
			 struct.pack('>I', LiSKonstanten.C_SCRYPT_SALT_LAENGE),
			 pScryptSaltBytes,
			 struct.pack('>I', LiSKonstanten.C_CHACHA20_NONCE_LAENGE),
			 pChaCha20NonceBytes,
			 struct.pack('>Q', lQuelldateiAenderungsdatumInteger),
			 struct.pack('>Q', lQuelldateiZugriffsdatumInteger),
			 struct.pack('>Q', lQuelldateigroesseInteger),
			 struct.pack('>Q', lQuelldateiEndnameLaengeInteger),
			 struct.pack('>H', len(LiSKonstanten.C_ERFORDERLICHE_LISCRYPT_VERSION))])
		return lHeaderBytes

	def _liesHeaderAusDatei(self, pQuelldateiFile):
		"""
		Liest die Headerdaten aus einer verschlüsselten Datei aus und returniert diese.

		:param pQuelldateiFile: Zum Lesen geöffnete verschlüsselte Datei
		:type pQuelldateiFile: File-Objekt
		:return: Headerdaten als Bytesequenzen
		:rtype: Dictionary
		"""
		lQuelldatei = pQuelldateiFile
		lHeaderDictionary = dict()

		lHeaderDictionary['VerfahrenKennungInteger'] = struct.unpack('>H', lQuelldatei.read(struct.calcsize('H')))[0]  # Kompatibilität mit < 0.3.15rc1-8.

		if lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V1:
			lHeaderDictionary['DateiBlockgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['AESGCMV1NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['AESGCMV1NonceBytes'] = lQuelldatei.read(lHeaderDictionary['AESGCMV1NoncelaengeInteger'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]

		elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V2:
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['HKDFSaltlaengeFuerAESGCMV2Integer'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['HKDFSaltFuerAESGCMV2Bytes'] = lQuelldatei.read(lHeaderDictionary['HKDFSaltlaengeFuerAESGCMV2Integer'])
			lHeaderDictionary['AESGCMV2NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['AESGCMV2NonceBytes'] = lQuelldatei.read(lHeaderDictionary['AESGCMV2NoncelaengeInteger'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'] = struct.unpack('>H', lQuelldatei.read(struct.calcsize('H')))[0]

		elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_AES_GCM_KENNUNG_V3:
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['AESGCMV3NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['AESGCMV3NonceBytes'] = lQuelldatei.read(lHeaderDictionary['AESGCMV3NoncelaengeInteger'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'] = struct.unpack('>H', lQuelldatei.read(struct.calcsize('H')))[0]

		elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V1: # Kompatibilität zu < 0.3.15rc1-8.
			lHeaderDictionary['DateiBlockgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['ChaCha20V1NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ChaCha20V1NonceBytes'] = lQuelldatei.read(lHeaderDictionary['ChaCha20V1NoncelaengeInteger'])
			lHeaderDictionary['ScryptSaltlaengeFuerHMACFuerChaCha20V1Integer'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltHMACFuerChaCha20V1Bytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeFuerHMACFuerChaCha20V1Integer'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]

		elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V2:
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['ChaCha20V2NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ChaCha20V2NonceBytes'] = lQuelldatei.read(lHeaderDictionary['ChaCha20V2NoncelaengeInteger'])
			lHeaderDictionary['ScryptSaltlaengeFuerHMACFuerChaCha20V2Integer'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltHMACFuerChaCha20V2Bytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeFuerHMACFuerChaCha20V2Integer'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'] = struct.unpack('>H', lQuelldatei.read(struct.calcsize('H')))[0]

		elif lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3\
				or lHeaderDictionary['VerfahrenKennungInteger'] == LiSKonstanten.C_VERFAHREN_CHACHA20_KENNUNG_V3_1:
			lHeaderDictionary['ScryptAufwandsfaktorInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ScryptBlockgroesseInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptParallelisierungInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltlaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ScryptSaltBytes'] = lQuelldatei.read(lHeaderDictionary['ScryptSaltlaengeInteger'])
			lHeaderDictionary['ChaCha20V3NoncelaengeInteger'] = struct.unpack('>I', lQuelldatei.read(struct.calcsize('I')))[0]
			lHeaderDictionary['ChaCha20V3NonceBytes'] = lQuelldatei.read(lHeaderDictionary['ChaCha20V3NoncelaengeInteger'])
			lHeaderDictionary['DateiOriginalAenderungsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalZugriffsdatumInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginalgroesse'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['DateiOriginaldateiEndnameLaengeInteger'] = struct.unpack('>Q', lQuelldatei.read(struct.calcsize('Q')))[0]
			lHeaderDictionary['ErforderlicheLiSCryptVersionLaengeInteger'] = struct.unpack('>H', lQuelldatei.read(struct.calcsize('H')))[0]

		if len(lHeaderDictionary) < 2: # Wenn nichts oder nur die Verfahrenskennung im Header-Dictionary enthalten ist
			lHeaderDictionary = None

		return lHeaderDictionary