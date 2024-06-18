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

"""Dieses Modul enthält Klassen und statische Methoden zur Verhinderung eines Merhfachstarts von LiSCrypt."""

from Modell import LiSKonfiguration, LiSKonstanten

from PyQt5 import QtCore

import psutil
import socket
import struct
import yaml

class LiSCryptProzesse:
	"""
	Stellt eine statische Methode zur Identifikation aktiver LiSCrypt-Prozesse zur Verfügung
	"""
	@staticmethod
	def ermittleAnzahlLaufenderLiSCryptProzesse():
		"""
		Ermittelt die Anzahl aktiver Prozesse mit Namensbestandteil 'liscrypt' und ggf. 'iqb' (Vergleiche sind case
		insensitive) in Abhängigkeit von LiSKonstanten.C_IQB_VERSION

		:return: Anzahl aktiver Prozesse mit Namensbestandteil 'liscrypt' und ggf. 'iqb' (Vergleiche sind case
		insensitive) in Abhängigkeit von LiSKonstanten.C_IQB_VERSION
		:rtype: Integer
		"""
		lAnzahlLiSCryptProzesseInteger = 0
		for lProzess in psutil.process_iter(['name']):
			if LiSKonstanten.C_IQB_VERSION is False:
				if 'liscrypt' in str.lower(lProzess.info['name']) and 'iqb' not in str.lower(lProzess.info['name']):
					lAnzahlLiSCryptProzesseInteger += 1
			else:
				if 'liscrypt' in str.lower(lProzess.info['name']) and 'iqb'  in str.lower(lProzess.info['name']):
					lAnzahlLiSCryptProzesseInteger += 1
		return lAnzahlLiSCryptProzesseInteger

class QServer(QtCore.QThread):
	"""
	Ein lokaler Server, der Befehle zur Steuerung von LiSCrypt entgegennehmen kann.
	"""
	C_LISTENEMPFANG_SIGNAL = QtCore.pyqtSignal(list)

	class QVerbindungMitClient(QtCore.QThread):
		"""
		Eine nebenläufige Verbindung zu einem Client, die Befehle zur Steuerung von LiSCrypt von einem bestimmten Client
		entgegennehmen kann.
		"""
		# PyQt-Signale zur Interaktion mit QController
		C_LISTENEMPFANG_SIGNAL = QtCore.pyqtSignal(list)

		def __init__(self, pClientSocket, pClientVerbindungenVonServerList):
			"""
			Initialisiert ein Objekt der Klasse QVerbindungMitClient.

			:param pClientSocket: Der Verbindung zum Client zugeordnete Socket
			:type pClientSocket: Socket
			:param pClientVerbindungenVonServerList: Liste aller Clientverbindungen des Servers
			:type pClientVerbindungenVonServerList: Liste von Strings
			"""
			super(QServer.QVerbindungMitClient, self).__init__()
			self.sAktivBoolean = False
			self.sClientSocket = pClientSocket
			self.sClientVerbindungenVonServerList = pClientVerbindungenVonServerList
			self.sClientVerbindungenVonServerList.append(self)
			self.sStatusString = 'verbunden'

		def run(self):
			"""
			Überschriebene Methode der Oberklasse QtCore.QThread. Wird durch QThread.start automatisch aufgerufen.
			"""
			self.sAktivBoolean = True
			self.sendeNachricht(b'+LISCRYPT_SERVER')
			lIdentifikationVonClientBytes = self.empfangeNachricht()

			if lIdentifikationVonClientBytes == b'+LISCRYPT_CLIENT':
				self.sStatusString = 'legitimiert'
				self.sendeNachricht(b'+LIST')
				lAufrufParameterlisteBytes = self.empfangeNachricht()
				lAufrufParameterlisteList = yaml.load(lAufrufParameterlisteBytes.decode(),Loader=yaml.SafeLoader)
				# Whitelisting der ersten drei Aufrufparameter
				if lAufrufParameterlisteList[0] in LiSKonstanten.C_AUFRUFPARAMETER_WHITELISTS['logging'] \
					and lAufrufParameterlisteList[1] in LiSKonstanten.C_AUFRUFPARAMETER_WHITELISTS['action'] \
					and lAufrufParameterlisteList[2] in LiSKonstanten.C_AUFRUFPARAMETER_WHITELISTS['originals'] \
					and	lAufrufParameterlisteList[3] in LiSKonstanten.C_AUFRUFPARAMETER_WHITELISTS['keytype']:
					self.C_LISTENEMPFANG_SIGNAL.emit(lAufrufParameterlisteList)
			self.sStatusString = 'geschlossen'
			self.sendeNachricht(b'+BYE')
			self.sClientSocket.close()
			self.stop()

		def istAktiv(self):
			"""
			Returniert den Wert des Attributs sAktivBoolean, welches angibt, ob die nebenläufige Verbindung zu einem
			Client noch aktiv ist.

			:return: Wert des Attributs sAktivBoolean
			:rtype: Boolean
			"""
			return self.sAktivBoolean

		def stop(self):
			"""
			Veranlasst den Stopp der nebenläufigen Verbindung zu einem Client durch Setzen des Werts des Attributs
			sAktivBoolean auf False und entfernt die Instanz aus der Liste der Client-Verbindungen des Servers.
			"""
			self.sAktivBoolean = False
			if self in self.sClientVerbindungenVonServerList:
				self.sClientVerbindungenVonServerList.remove(self)

		def sendeNachricht(self, pNachrichtBytes):
			"""
			Sende pNachrichtBytes zum Client, der über diese Instanz von QClientVerbindung mit dem Server verbunden ist.

			:param pNachrichtBytes: Zu sendende Nachricht
			:type pNachrichtBytes: Bytesequenz
			"""
			lLaengeDerNachrichtInteger = len(pNachrichtBytes)
			self.sClientSocket.sendall(struct.pack('>Q', lLaengeDerNachrichtInteger) + pNachrichtBytes)

		def empfangeNachricht(self):
			"""
			Blockierende Methode, die eine Nachricht des Servers empfängt, diese in Längenangabe und Inhaltsteil zerlegt
			und den Inhaltsteil returniert. Wurde die Instanz von QVerbindungMitVlient zwischenzeitlich gestoppt,
			liefert die Methode None zurück.

			:return: Inhaltsteil der empfangenenen Nachricht
			:rtype: Bytesequenz
			"""
			lLaengeDerNachrichtBytes = b''
			while len(lLaengeDerNachrichtBytes) < 8 and self.sAktivBoolean is True:
				lLaengeDerNachrichtBytes += self.sClientSocket.recv(1)
			lLaengeDerNachrichtInteger = struct.unpack('>Q',lLaengeDerNachrichtBytes)[0]
			lNachrichtBytes = b''
			while len(lNachrichtBytes) < lLaengeDerNachrichtInteger and self.sAktivBoolean is True:
				lNachrichtBytes += self.sClientSocket.recv(1)
			if self.sAktivBoolean is True:
				return lNachrichtBytes
			else:
				return None

	def __init__(self):
		"""
		Initialisiert ein Objekt der Klasse QServer.
		"""
		super(QServer, self).__init__()
		self.sAktivBoolean = False
		self.sServerSocket = socket.socket()
		self.sServerSocket.bind(('127.0.0.1', 0))
		self.sPortInteger = self.sServerSocket.getsockname()[1]
		self.sServerSocket.listen()
		self.sClientVerbindungen = []

	def run(self):
		"""
		Überschriebene Methode der Oberklasse QtCore.QThread. Wird durch QThread.start automatisch aufgerufen.
		"""
		self.sAktivBoolean = True
		while self.sAktivBoolean is True:
			lClientSocket, lIPAdresse = self.sServerSocket.accept()  # Verbindung mit Client herstellen.
			lVerbindungMitClient = QServer.QVerbindungMitClient(lClientSocket, self.sClientVerbindungen)
			lVerbindungMitClient.start()
			lVerbindungMitClient.C_LISTENEMPFANG_SIGNAL.connect(self._emittiereListenEmpfangssignal)

		for lVerbindung in self.sClientVerbindungen:
			lVerbindung.stop()

	def gibPort(self):
		"""
		Returniert den Port des Servers.

		:return: Port des Servers
		:rtype: Integer
		"""
		return(self.sPortInteger)

	def stop(self):
		"""
		Veranlasst den Stopp des Serverthreads durch setzen des Wertes des Attributs sAktivBoolean auf False.
		"""
		self.sAktivBoolean = False

	def _emittiereListenEmpfangssignal(self, pAufrufparameterList):
		"""
		Emittiert das Signal C_LISTENEMPFANG_SIGNAL mit der übergebenen Instanz einer Liste von Aufrufparametern einer
		verbundenen Clientinstanz.

		:param pAufrufparameterList: Aufrufparameter einer verbundenen Clientinstanz.
		:return: Liste von Strings
		"""
		self.C_LISTENEMPFANG_SIGNAL.emit(pAufrufparameterList)



class QClient():
	"""
	Ein Client, der Befehle zur Steuerung von LiSCrypt an einen lokalen Server senden kann.
	"""
	def __init__(self):
		"""
		Initialisiert ein Objekt der Klasse QClient.
		"""
		self.sClientSocket = socket.socket()
		try:
			self.sClientSocket.connect(('127.0.0.1',LiSKonfiguration.Konfiguration.G_SERVER_PORT))
			self.sAktivBoolean = True
			self._initialisiereVerbindung()
		except Exception as lException:
			raise RuntimeError from lException

	def _initialisiereVerbindung(self):
		"""
		Interne Methode. Initialisiert die Verbindung zum verbundenen Server durch Empfang und anschließenden Versand
		einer einer Identifikationskennung.
		"""
		lIdentifikationVonServerBytes = self._empfangeNachricht()
		if lIdentifikationVonServerBytes != b'+LISCRYPT_SERVER':
			raise RuntimeError
		self._sendeNachricht(b'+LISCRYPT_CLIENT')
		lListenanforderungBytes = self._empfangeNachricht()
		if lListenanforderungBytes != b'+LIST':
			raise RuntimeError

	def sendeAufrufparameterUndTrenneVerbindung(self):
		"""
		Sendet die Aufrufparameter der Clientinstanz an den verbundenen Server, wartet auf eine Antwort des Servers und
		trennt die Verbindung, falls der Server den Empfang mit einer Abschlussnachricht beantwortet. Sendet der Server
		eien davon abweichende Antwort, wirft die Methode eine Exception.
		:return:
		"""
		lAufrufparameterList = LiSKonfiguration.Konfiguration.gibAurufparameterAlsGeordneteListe()
		lDatenZumSendenBytes = yaml.dump(lAufrufparameterList).encode()
		self._sendeNachricht(lDatenZumSendenBytes)
		lByeBytes = self._empfangeNachricht()
		if lByeBytes == b'+BYE':
			self.stop()
			self.sClientSocket.close()
		else:
			raise RuntimeError

	def _sendeNachricht(self, pNachrichtBytes):
		"""
		Interne Methode. Sendet die Nachticht pNachrichtBytes an den verbundenen Server (unter Voranstellung der Länge
		der Nachricht).
		:param pNachrichtBytes:
		"""
		lLaengeDerNachrichtInteger = len(pNachrichtBytes)
		self.sClientSocket.sendall(struct.pack('>Q', lLaengeDerNachrichtInteger) + pNachrichtBytes)

	def _empfangeNachricht(self):
		"""
		Blockierende Methode Nachricht vom verbundenen Server empfängt, diese in Längenangabe und Inhaltsteil zerlegt
		und den Inhaltsteil returniert. Wurde die Instanz von Client zwischenzeitlich gestoppt, liefert die Methode
		None zurück.

		:return: Inhaltsteil der empfangenen Nachricht oder None
		:rtype: Bytesequenz
		"""
		lLaengeDerNachrichtBytes = b''
		while len(lLaengeDerNachrichtBytes) < 8 and self.sAktivBoolean is True:
			lLaengeDerNachrichtBytes += self.sClientSocket.recv(1)

		lLaengeDerNachrichtInteger = struct.unpack('>Q',lLaengeDerNachrichtBytes)[0]
		lNachrichtBytes = b''
		while len(lNachrichtBytes) < lLaengeDerNachrichtInteger and self.sAktivBoolean is True:
			lNachrichtBytes += self.sClientSocket.recv(1)

		if self.sAktivBoolean is True:
			return lNachrichtBytes
		else:
			return None

	def stop(self):
		"""
		Veranlasst den Stopp der Verbindung zum Server durch Setzen des Werts des Attributs sAktivBoolean auf False.
		"""
		self.sAktivBoolean = False

