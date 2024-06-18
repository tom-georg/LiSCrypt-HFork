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

"""
Dieses Modul modelliert den Controller-Anteil der Software LiSCrypt.

Bei LiSCrypt handelt es sich um eine Software zur symmetrischen
Verschlüsselung von Einzeldateien unter Verwendung von AES-GCM-256
bzw. einer Kombination von ChaCha20 und HMAC für sehr große Dateien.

LiSCrypt wurde ursprünglich von der Qualitäts- und UnterstützungsAgentur -
Landesintitut für Schule in Nordrhein-Westfalen entwickelt.
"""

from Darstellung import LiSAnzeige
from Modell import LiSAusnahmen, LiSKonfiguration, LiSKonstanten, LiSKrypto, LiSSingleton, LiSVernichtung
from Sonstiges import LiSWerkzeuge

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import scrypt, hkdf
from cryptography.hazmat.backends import default_backend

from PyQt5 import QtCore, QtGui, QtWidgets

import base91
import datetime
import gc
import logging
import os
import re
import tempfile
import sys

class QController:
	"""
	Zentrale zur Übermittlung von Nachrichten zwischen Benutzeroberfläche (z.B. Nutzereingaben) und
	dem Modell (Dateien/Verzeichnissen etc.).
	"""

	def __init__(self):
		"""
		Initialisiert ein Objekt der Klasse QController (u.a. Instantiierung der zentralen View-Komponente)
		"""
		# 1. Client oder Server starten:
		self.sClientQClient = None
		self.sServerQServer = None
		try:
			self.sClientQClient = LiSSingleton.QClient()
		except:
			try:
				if LiSKonstanten.C_PLATTFORM != 'nt'\
						or LiSSingleton.LiSCryptProzesse.ermittleAnzahlLaufenderLiSCryptProzesse() < 2: # Funktioniert nur sicher unter Windows
					self.sServerQServer = LiSSingleton.QServer()
					self.sServerQServer.start()
					LiSKonfiguration.Konfiguration.G_SERVER_PORT = self.sServerQServer.gibPort()
					LiSKonfiguration.Konfiguration.speichereKonfiguration()
			except:
				raise

		if self.sServerQServer is not None:
			self.sViewQView = LiSAnzeige.QView(self)

			# 2. Logger starten:
			if LiSKonfiguration.Konfiguration.G_AUFRUF_PARAMETER.logging == 'file':
				try:
					logging.basicConfig(filename=LiSKonstanten.C_LOG_DATEINAME, filemode='w', level=LiSKonstanten.C_LOGGING_LEVEL)
				except OSError:
					# Wenn sich das Log nicht im Temporärverzeichnis schreiben lässt, Standardausgabe
					self.sViewQView.zeigeFehlerDialog(
						'Fehler beim Schreiben in Logdatei. Kein persistentes Logging.')
					logging.basicConfig(level=LiSKonstanten.C_LOGGING_LEVEL)
			else:
				logging.basicConfig(level=LiSKonstanten.C_LOGGING_LEVEL)

			# 3. Slot für Slave-Funktionsausführung verbinden:
			self._verbindeServerSlots()

			# 4. Attribute für spätere Instanzen von QControllerWorkerThread zuweisen:
			self.sFunktionsStarterThread = None
			self.sFunktionsausfuehrerThread = None

			# 5. LiSCrypt-Blockiert-Zustand auf "nicht blockiert" setzen:
			self.sLiSCryptBlockiertBoolean = False

			# 6. Liste der Pfadangaben zu den aktuell ausgewählten Dateisystemeinträgen zunächst mit None initialisieren:
			self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList = None

			# 7. Liste der Pfadangaben zu den zuletzt ausgewählten Dateisystemeinträgen zunächst mit None initialisieren:
			self.sErweitertePfadeAllerZuletztAusgewaehltenEintraegeList = None

			# 7. Liste der Pfadangaben zu den zuletzt ggf. erzeugten Dateien zunächst mit None initialisieren:
			self.sErweitertePfadeAllerZuletztErzeugtenDateienList = None

	def starteFunktionAusParameterliste(self, pAufrufparameterList):
		"""
		Veranlasst den Start eines Funktionsstarterthreads anhand der Inhalte von pAufrufparameterList, sofern aktuell
		keine Programmfunktion ausgeführt wird.

		:param pAufrufparameterList: Aufrufparameter
		:type pAufrufparameterList: Liste von Strings
		"""
		lItemsAusgewaehltBoolean = True if len(pAufrufparameterList) > 4 else False
		if lItemsAusgewaehltBoolean is True:
			self.sViewQView.zeigeHauptfensterInNormalgroesseFallsMinimiert()

			if self._istLiSCryptBeschaeftigt() is True or self.istLiSCryptBlockiert() is True:
				if self.istLiSCryptBlockiert() is False:
					self.sViewQView.zeigeFehlerDialog('LiSCrypt ist gerade beschäftigt. Bitte wiederholen Sie Ihren Befehl später.')
			else:
				lItemsAusgewaehltBoolean = True if len(pAufrufparameterList) > 4 else False
				if lItemsAusgewaehltBoolean is True:
					lPfadeZuEintraegenList = pAufrufparameterList[3:]
					self.sFunktionsStarterThread = QFunktionsstarterThread(lPfadeZuEintraegenList)

					lFunktionBrauchtSchluesselBoolean = False
					lStarteFunktionsstarterThreadBoolean = False

					# pAufrufparameterList[0] spezifiziert das Logging und wird an anderer Stelle ausgewertet
					if pAufrufparameterList[1] == 'encrypt':
						self.sViewQView.aktiviereVerschluesseln()
						lFunktionBrauchtSchluesselBoolean = True
					elif pAufrufparameterList[1] == 'decrypt':
						self.sViewQView.aktiviereEntschluesseln()
						lFunktionBrauchtSchluesselBoolean = True
					else:
						self.sViewQView.aktiviereVernichten()
						lStarteFunktionsstarterThreadBoolean = True

					if lFunktionBrauchtSchluesselBoolean is True: # Wurde LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL oder LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL gewählt?
						if pAufrufparameterList[2] == 'wipeoriginals':
							self.sViewQView.setzeOriginaleVernichten(True)
						elif pAufrufparameterList[2] == 'keeporiginals':
							self.sViewQView.setzeOriginaleVernichten(False)

						if pAufrufparameterList[3] == 'choose':
							lSchluesselartString = self.sViewQView.zeigeSchluesselartwahlDialog()
						else:
							lSchluesselartString = pAufrufparameterList[3]
						if lSchluesselartString == 'password':
							self.sViewQView.waehleVerschluesselungMitPasswort_Kommandozeile()
							lStarteFunktionsstarterThreadBoolean = True
						elif lSchluesselartString == 'keyfile':
							# Funktion nur ausführen, wenn tatsächlich eine Schlüsseldatei ausgewählt wurde
							lStarteFunktionsstarterThreadBoolean = \
								self.sViewQView.waehleVerschluesselungMitSchluesseldatei_Kommandozeile()

					if lStarteFunktionsstarterThreadBoolean is True:
						self._verbindeFunktionsStarterSlots()
						self.sFunktionsStarterThread.start()
					else:
						self.sFunktionsStarterThread = None # Verweis FunktionsStarterThread löschen, falls dieser nicht gebraucht wird

	def stoppeServerThread(self):
		"""
		Veranlasst das Schließen des lokalen Servers zur Befehlsentgegenname.
		"""
		if self.sServerQServer is not None:
			self.sServerQServer.stop()

	def warteAufViewEreignisse(self):
		"""
		Veranlasst die zentrale View-Komponente (self.sViewQView) den Qt-Event-Loop zu starten. Nach Abschluss oder bei Unterbrechung des
		Qt-Event-Loops wird die Entfernung eines eventuell gemerkten Passworts aus dem Prozessspeicher veranlasst. Wird von der __main__-Umgebung aufgerufen.
		"""
		try: # Auf die Nutzung des atexit-Moduls wird verzichtet, da die Funktionalität über try...finally vollständig abgedeckt wird.
			self.sViewQView.warteAufEreignisse()
		finally:
			self.sViewQView.entferneGemerktesPasswortAusProzessspeicherFallsEinzigeReferenz() # falls noch gemerktes Passwort im Arbeitsspeicher

	def istMaster(self):
		"""
		Returniert, ob es sich bei der aktuellen LiSCrypt-Instanz um einen Master handelt (true: ja, false: nein)
		:return: Ergebnis
		:rtype: Boolean
		"""
		return self.sServerQServer is not None

	def sendeAufrufparameterAnMaster(self):
		"""
		Sendet die Aufrufparameter der Instanz per Client-Server-Verbindung an die Master-Instanz
		"""
		if self.sClientQClient is None:
			raise AssertionError('Keine Client-Instanz zum Versenden der Aufrufparameter über Socket vorhanden.')
		self.sClientQClient.sendeAufrufparameterUndTrenneVerbindung()

	def fuehreFunktionAus(self, pErweitertePfadeZuAusgewaehltenEintraegenList, pSonderfunktionString=None):
		"""
		Führt die in der Benutzerobefläche Programmfunktion ('Verschlüsselung'/'Entschlüsselung'/'Vernichtung) auf den
		vom Nutzer ausgewählten Dateien/Verzeichnissen mit den in der UI festgelegten Optionen aus, falls noch kein
		Fuktionsprozess läuft. Wird von der View aufgerufen bzw. von einem QFunktionsStarterThread
		durch Signal-Emittierung aufgerufen.

		:param pErweitertePfadeZuAusgewaehltenEintraegenList: Pfadangaben der vom Nutzer ausgewählten Dateien/Verzeichnisse, None wenn keine Auswahl durch Nutzer (d.h. Sonderfunktion)
		:type pErweitertePfadeZuAusgewaehltenEintraegenList: Liste von Strings
		:param pSonderfunktionString: Angabe, ob eine Sonderfnuktionsbutton (Funktion wiederholen ('Wiederhoung"), Funktion umkehren ('Umkehrung')) betätigt wurde
		:type pSonderfunktionString: String
		"""
		lFunktionString = self.sViewQView.gibFunktion()
		lOriginaleVernichtenStatusBoolean = self.sViewQView.gibOriginaleVernichtenStatus()
		lSchluesselart = self.sViewQView.gibSchluesselart()
		lErweiterterPfadZuSchluesseldatei = self.sViewQView.gibErweitertenPfadZuSchluesseldatei()

		self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList = \
			pErweitertePfadeZuAusgewaehltenEintraegenList if pSonderfunktionString is None else \
				self.sErweitertePfadeAllerZuletztAusgewaehltenEintraegeList if pSonderfunktionString == 'Wiederholung' else \
					self.sErweitertePfadeAllerZuletztErzeugtenDateienList if pSonderfunktionString == 'Umkehrung' \
						else None

		if self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList is None: # Dürfte nie passieren, da Aufruf mit None nur geschehen sollte, wenn Liste aus vorheriger Funktionsausführung vorliegt.
			raise AssertionError('QController.fuehreFunktionAus: Keine Pfade zu Einträgen vorhanden.')

		try:
			# Zur Sicherheit jede mögliche Exception fangen und loggen
			if lErweiterterPfadZuSchluesseldatei != '':
				try:
					lGroesseSchluesseldateiInBytesInteger = os.path.getsize(lErweiterterPfadZuSchluesseldatei)
					if lSchluesselart == LiSKonstanten.C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL \
							and lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL \
							and lGroesseSchluesseldateiInBytesInteger < LiSKonstanten.C_PASSWORT_SCHLUESSELDATEI_MINLAENGE:
						raise LiSAusnahmen.QKeyFileToSmallError('Die Schlüsseldatei ist zu klein ('
																+ str(lGroesseSchluesseldateiInBytesInteger)
																+ ' Byte(s)).'
																+ ' Schlüsseldateien müssen eine Mindestgröße von '
																+ str(LiSKonstanten.C_PASSWORT_SCHLUESSELDATEI_MINLAENGE)
																+ ' Bytes haben.')
				except OSError as lOSError:
					raise OSError('Schlüsseldatei nicht gefunden oder nicht lesbar! Prozess abgebrochen.') from lOSError
			# Dateiliste für Bestätigungsdialog bestimmen:
			lpassendeEintraegeFuerProgrammfunktionGefundenBoolean = False
			if lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
				lBereinigteDragAndDropsList = self._ermittleZulaessigeDateienUndVerzeichnisse(self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList, pVerbotenesEndeString=LiSKonstanten.C_DATEIENDUNG)
				for lEintrag in lBereinigteDragAndDropsList:
					if os.path.isdir(lEintrag) and not os.path.islink(lEintrag):
						if LiSWerkzeuge.Pfadwerkzeuge.pruefePfadAufUnverschluesselteDateien(lEintrag):
							lpassendeEintraegeFuerProgrammfunktionGefundenBoolean = True
					elif os.path.isfile(lEintrag):
						lpassendeEintraegeFuerProgrammfunktionGefundenBoolean = True
			elif lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
				lBereinigteDragAndDropsList = self._ermittleZulaessigeDateienUndVerzeichnisse(self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList, pEndeString=LiSKonstanten.C_DATEIENDUNG)
				for lEintrag in lBereinigteDragAndDropsList:
					if os.path.isdir(lEintrag) and not os.path.islink(lEintrag):
						if LiSWerkzeuge.Pfadwerkzeuge.pruefePfadAufVerschluesselteDateien(lEintrag):
							lpassendeEintraegeFuerProgrammfunktionGefundenBoolean = True
					elif os.path.isfile(lEintrag):
						lpassendeEintraegeFuerProgrammfunktionGefundenBoolean = True
			else:
				lBereinigteDragAndDropsList = self._ermittleZulaessigeDateienUndVerzeichnisse(self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList)

			if lBereinigteDragAndDropsList and \
					(lpassendeEintraegeFuerProgrammfunktionGefundenBoolean or lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL): # Nur Funktionssthread starten, wenn Dateien/Verzeichnisse für Funktion infrage kommen:
				lSortierteBereinigteDragAndDropsList = LiSWerkzeuge.Pfadwerkzeuge.sortiereInVerzeichnissUndDateien(lBereinigteDragAndDropsList)
				if self.sViewQView.erbitteFunktionsbestaetigung(lFunktionString, lSortierteBereinigteDragAndDropsList, lOriginaleVernichtenStatusBoolean):
					# Anzeige des Listendialogs hat die Statusleiste in 'Sicherheitsabfrage...'
					self._setzeStatusleisteUndGUIZustand('Vorbereiten...')
					self.sFunktionsausfuehrerThread = QControllerWorkerThread(lSortierteBereinigteDragAndDropsList, lFunktionString, lOriginaleVernichtenStatusBoolean, lSchluesselart, lErweiterterPfadZuSchluesseldatei)
					self._verbindeFunktionsAusfuehrerSlots()
					self.sFunktionsausfuehrerThread.start()
				else: # Wenn der Funktionssthread nicht gestartet wird, setzt er auch nicht die Statusleiste zurück
					self._setzeStatusleisteUndGUIZustand()

			elif lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
				self._zeigeFehlerDialog('Keine unverschlüsselten Dateien gefunden.')
			elif lFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
				self._zeigeFehlerDialog('Keine verschlüsselten Dateien gefunden.')
		except LiSAusnahmen.QKeyFileToSmallError as lException:
			self._zeigeFehlerDialog(str(lException))
			logging.exception(
				datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Schlüsseldatei für Verschlüsselung zu klein Fehler')
		except Exception as lException:
			self._zeigeFehlerDialog(str(lException))
			logging.exception(
				datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Unbekannter Fehler')

	def stoppeFunktionsprozess(self):
		"""
		Stoppt die Ausführung einer Programmfunktion durch Stopp des entsprechenden Threads.
		"""
		self.sFunktionsausfuehrerThread.stoppeFunktionsprozess()

	def kopiereVerlaufsprotokollInZwischenablage(self):
		"""
		Kopiert das Verlaufsprotokoll in die Zwischenablage
		"""
		lProtokollString = self.sViewQView.gibVerlaufsprotokollAlsText()
		lClipboard = QtWidgets.QApplication.clipboard()
		lClipboard.setText(lProtokollString, mode=QtGui.QClipboard.Clipboard)

	def _istLiSCryptBeschaeftigt(self):
		"""
		Interne Methode. Returniert, ob LiSCrypt derzeit bereits beschäftigt ist (true: ja, false: nein)

		:return: Ergebnis
		:rtype Boolean
		"""
		lBeschaeftigtBoolean = False
		if self.sFunktionsStarterThread is not None:
			lBeschaeftigtBoolean = not self.sFunktionsStarterThread.isFinished()
		elif self.sFunktionsausfuehrerThread is not None:
				lBeschaeftigtBoolean = not self.sFunktionsausfuehrerThread.isFinished()
		return lBeschaeftigtBoolean

	# PyQt-Slots für QControllerWorker-Thread:

	def _setzeStatusleisteUndGUIZustand(self, pTextString=None, pAbbrechenButtonAktivBoolean=False):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt.. Veranlasst die View, den Inhalt der Statusleiste zu verändern.

		:param pTextString: Neuer Text für die Statusleiste. Falls None, wird 'Bereit.' eingesetzt
		:type pTextString: String
		:param pAbbrechenButtonAktivBoolean: Angabe, ob der Button 'Abbrechen' in der Statusleiste aktiv sein soll.
		:type pAbbrechenButtonAktivBoolean: Boolean
		"""
		if pTextString == '':
			pTextString = None
		self.sViewQView.setzeStatusleisteUndGUIZustand(pTextString, pAbbrechenButtonAktivBoolean)

	def _ergaenzeBericht(self, pZeileString, pToolTipString=None):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, das Verlaufsportokoll um pZeileString zu ergänzen.

		:param pZeileString: Neue Zeile für das Verlaufsprotokoll
		:type pZeileString: String
		:param pToolTipString: ToolTip für die neue Zeile (i.d.R. vollständige absolute, reduzierte Pfadangabe)
		:type pToolTipString: String
		"""
		self.sViewQView.ergaenzeBericht(pZeileString, pToolTipString)

	def _leereZwischenablage(self):
		"""
		Interne Methode. Leer die Zwischenablage des Betriebssystems.
		"""
		lClipboard = QtWidgets.QApplication.clipboard()
		lClipboard.clear(mode=QtGui.QClipboard.Clipboard)

	def _zeigeWarnDialog(self, pWarnungString):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, einen Warndialog anzuzeigen.

		:param pWarnungString: Anzuzeigende Warnung
		:type pWarnungString: String
		"""
		self.sViewQView.zeigeWarnDialog(pWarnungString)
		if self.sFunktionsausfuehrerThread is not None: # Explizit gewartet werden muss nur, wenn gerade eine Programmfunktion ausgeführt wird
			self.sFunktionsausfuehrerThread.setzeWarnungBestaetigt(True)

	def _zeigeInfoDialog(self, pInformationString):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, einen Infomationsdialog anzuzeigen.

		:param pInformationString: Anzuzeigende Warnung
		:type pInformationString: String
		"""
		self.sViewQView.zeigeInfoDialog(pInformationString)
		if self.sFunktionsausfuehrerThread is not None:  # Explizit gewartet werden muss nur, wenn gerade eine Programmfunktion ausgeführt wird
			self.sFunktionsausfuehrerThread.setzeInformationBestaetigt(True)

	def _zeigeFehlerDialog(self, pFehlermeldungString):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, einen Fehlerdialog anzuzeigen.

		:param pFehlermeldungString: Anzuzeigende Fehlermeldung
		:type pFehlermeldungString: String
		"""
		self.sViewQView.zeigeFehlerDialog(pFehlermeldungString)
		if self.sFunktionsausfuehrerThread is not None: # Explizit gewartet werden muss nur, wenn gerade eine Programmfunktion ausgeführt wird
			self.sFunktionsausfuehrerThread.setzeFehlerBestaetigt(True)
		self._setzeStatusleisteUndGUIZustand()

	def _zeigePasswortDialog(self, pMitBestaetigungBoolean=True):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, einen modalen Dialog zur Passworteingabe anzuzeigen.

		:param pMitBestaetigungBoolean: Angabe, ob das eingegebene Passwort durch Doppeleingabe bestätigt werden muss (True: ja, False: nein)
		:type pMitBestaetigungBoolean: Boolean
		"""
		lPasswortString = self.sViewQView.zeigePasswortDialog(pMitBestaetigungBoolean)
		self.sFunktionsausfuehrerThread.setzePasswort(lPasswortString)

	def _zeigeUeberschreibenDialog(self, pDateinameErweitertString):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, einen modalen Dialog anzuzeigen, in dem der Nutzer
		gefragt wird, ob eine bereits unter gleichem Namen bestehende Zieldatei bei Ver- oder Entschlüsselung
		überschrieben werden soll und gibt die Nutzereingabe durch Methodenaufruf/Attributsetzung an den Thread
		weiter, der die Programmfunktion ausführt.

		:param pDateinameErweitertString: Erweitere Pfadangabe zur bereits existierenden Datei als String
		:type pDateinameErweitertString: String
		"""
		lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pDateinameErweitertString)
		lUeberschreibenInteger = self.sViewQView.zeigeUeberschreibenDialog(lDateinameReduziertString)
		self.sFunktionsausfuehrerThread.setzeUeberschreiben(lUeberschreibenInteger)

	def _macheFunktionUmkehrenButtonSichtbar(self, pErweitertePfadeAllerErzeugtenDateien):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung zum Ende des Threads aufgerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, den Button zur Umkehrung der Funktion auf den im Rahmen der
		Funktionsausführung erzeugten Dateien im Hauptfenster sichtbar/nicht-sichtbar zu machen.

		:param pErweitertePfadeAllerErzeugtenDateien: Erweitere Pfade zu allen bei der letzten Funktionsausführung erzeugten Dateien
		:type pErweitertePfadeAllerErzeugtenDateien: Liste von Strings
		"""
		self.sViewQView.macheFunktionUmkehrenButtonSichtbar(bool(pErweitertePfadeAllerErzeugtenDateien))
		self.sErweitertePfadeAllerZuletztErzeugtenDateienList = pErweitertePfadeAllerErzeugtenDateien

	def _macheFunktionWiederholenButtonSichtbar(self, pDateilistenAnzeigeFehlerImProzessBoolean):
		"""
		Interne Methode, die durch Signal-Slot-Verbindung zum Ende des Threads aufgerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, den Button zur Wiederholung der Funktion auf der identischen
		Auswahl an Dateisystem-Einträgen im Hauptfenster sichtbar/nicht-sichtbar zu machen.
		"""
		lFunktionString = self.sViewQView.gibFunktion()
		lOriginaleVernichtenBoolean = self.sViewQView.gibOriginaleVernichtenStatus()
		lFunktionWiederholenButtonAnzeigenBoolean = lFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL and lOriginaleVernichtenBoolean is False \
													 or pDateilistenAnzeigeFehlerImProzessBoolean is True
		self.sViewQView.macheFunktionWiederholenButtonSichtbar(lFunktionWiederholenButtonAnzeigenBoolean)
		self.sErweitertePfadeAllerZuletztAusgewaehltenEintraegeList = self.sErweitertePfadeAllerAktuellAusgewaehltenEintraegeList

	def _entferneGemerktesPasswortAusProzessspeicherFallsEinzigeReferenz(self):
		"""
		Interne Methode. die durch Signal-Slot-Verbindung aus dem Thread heraus augerufen wird, der eine
		Programmfunktion ausführt. Veranlasst die View, die Klassenvariable UiPasswordDialog.UiPasswordDialog.kGemerktesPasswortString
		zu überschreiben.
		"""
		self.sViewQView.entferneGemerktesPasswortAusProzessspeicherFallsEinzigeReferenz()

	# Weitere Hilfsmethoden:

	def _ermittleZulaessigeDateienUndVerzeichnisse(self, pErweitertePfadeZuAusgewaehltenEintraegenList, pEndeString=None, pVerbotenesEndeString=None):
		"""
		Interne Methode. Returniert eine gefilterte Liste mit Pfadangaben (Strings) zu den vom Nutzer für eine Programmfunktion
		ausgewählten Verzeichnissen und Dateien. Die Verzeichnisse werden ungefiltert übernommen. Die Dateien werden abhängig
		von der ausgewählten Programmfunktion gefiltert (Verschlüsselung: Keine Dateien mit Endung LiSKonstanten.C_DATEIENDUNG, Entschlüsselung:
		Keine Dateien ohne Endung LiSKonstanten.C_DATEIENDUNG, Vernichtung: Keine Filterung)

		:param pErweitertePfadeZuAusgewaehltenEintraegenList: Erweiterte Pfadangaben zu den vom Nutzer ausgewählte Verzeichnisse und Dateien
		:type pErweitertePfadeZuAusgewaehltenEintraegenList: Liste von Strings
		:param pEndeString: ggf. obligatorische Dateiendung
		:type pEndeString: String
		:param pVerbotenesEndeString: ggf. verbotene Dateiendung
		:type pVerbotenesEndeString: String
		:return: Gefilterte Pfadangaben zu den vom Nutzer für eine Programmfunktion	ausgewählten Verzeichnissen und Dateien
		:rtype: Liste von Strings
		"""
		self._setzeStatusleisteUndGUIZustand('Ermittle betroffene Dateien/Ordner...')
		lZulaessigeDateienUndVerzeichnisseList = list()

		for lErweiterterPfadZuEintragString in pErweitertePfadeZuAusgewaehltenEintraegenList:
			if os.path.lexists(lErweiterterPfadZuEintragString):
				if not os.path.isdir(lErweiterterPfadZuEintragString) and (pEndeString is None or lErweiterterPfadZuEintragString.endswith(pEndeString)) \
				and (pVerbotenesEndeString is None or not lErweiterterPfadZuEintragString.endswith(pVerbotenesEndeString)):
					lZulaessigeDateienUndVerzeichnisseList.append(lErweiterterPfadZuEintragString)
				elif os.path.isdir(lErweiterterPfadZuEintragString):
					lZulaessigeDateienUndVerzeichnisseList.append(lErweiterterPfadZuEintragString)
		return lZulaessigeDateienUndVerzeichnisseList

	def erzeugeSchluesseldatei(self):
		"""
		Erzeugt eine Schlüsseldatei mit C_SCHLUESSELDATEI_MINLAENGE bis C_SCHLUESSELDATEI_MAXLAENGE zufälligen Zeichen
		(Buchstaben in Groß- und Kleinschreibung, Ziffern, Interpunktionszeichen, Leerzeichen).
		"""

		lSchluesseldateiNameErweitertString = self.sViewQView.zeigeErzeugeSchluesseldateiDialog()

		if lSchluesseldateiNameErweitertString is not None:
			lErweiterterPfadVerzeichnisString = os.path.dirname(lSchluesseldateiNameErweitertString)
			LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS = lErweiterterPfadVerzeichnisString

			lLaengeSchluesselDateiInteger = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeGanzeZufallszahlZwischen(
				LiSKonstanten.C_GENERIERTE_SCHLUESSELDATEI_MINLAENGE,LiSKonstanten.C_GENERIERTE_SCHLUESSELDATEI_MAXLAENGE)
			lZufaelligerString = LiSWerkzeuge.Stringwerkzeuge.erzeugeZufaelligenStringFuerSchluesseldatei(lLaengeSchluesselDateiInteger)

			try:
				with open(lSchluesseldateiNameErweitertString, 'w') as lSchluesseldatei:
					lSchluesseldatei.write('!QUA')
					lSchluesseldatei.write(lZufaelligerString)
					lSchluesseldatei.write('LiS!')
			except:
				lSchluesseldateiNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(lSchluesseldateiNameErweitertString)
				self.sViewQView.zeigeFehlerDialog('Fehler beim Erzeugen der Schlüsseldatei:\n' + lSchluesseldateiNameReduziertString)
			else:
				lSchluesseldateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(
					lSchluesseldateiNameErweitertString)
				self.sViewQView.zeigeInfoDialog('<p>Schlüsseldatei</p><strong><p>' + lSchluesseldateinameReduziertString + '</p></strong><p>erzeugt.</p>')
			finally:
				LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lZufaelligerString, True)

	def _verbindeFunktionsStarterSlots(self):
		"""
		Interne Methode. Verbindet Widget-Signale (hier: Thread zum Start einer Programmfunktion) mit Slots
		"""
		self.sFunktionsStarterThread.C_FUNKTIONSSTART_SIGNAL.connect(self.fuehreFunktionAus)

	def _verbindeServerSlots(self):
		"""
		Interne Methode. Verbindet Widget-Signale (hier: Serverthread) mit Slots
		"""
		self.sServerQServer.C_LISTENEMPFANG_SIGNAL.connect(self.starteFunktionAusParameterliste)

	def _verbindeFunktionsAusfuehrerSlots(self):
		"""
		Interne Methode. Verbindet Widget-Signale (hier: Thread zur Ausführung einer Programmfunktion) mit Slots
		"""
		self.sFunktionsausfuehrerThread.C_STATUSAENDERUNG_SIGNAL.connect(self._setzeStatusleisteUndGUIZustand)
		self.sFunktionsausfuehrerThread.C_BERICHTERGAENZUNG_SIGNAL.connect(self._ergaenzeBericht)
		self.sFunktionsausfuehrerThread.C_LEEREZWISCHENABLAGE_SIGNAL.connect(self._leereZwischenablage)
		self.sFunktionsausfuehrerThread.C_INFODIALOG_SIGNAL.connect(self._zeigeInfoDialog)
		self.sFunktionsausfuehrerThread.C_WARNDIALOG_SIGNAL.connect(self._zeigeWarnDialog)
		self.sFunktionsausfuehrerThread.C_FEHLERDIALOG_SIGNAL.connect(self._zeigeFehlerDialog)
		self.sFunktionsausfuehrerThread.C_PASSWORTDIALOG_SIGNAL.connect(self._zeigePasswortDialog)
		self.sFunktionsausfuehrerThread.C_UEBERSCHREIBENDIALOG_SIGNAL.connect(self._zeigeUeberschreibenDialog)
		self.sFunktionsausfuehrerThread.C_ENTFERNE_GEMERKTESPASSWORT_SIGNAL.connect(self._entferneGemerktesPasswortAusProzessspeicherFallsEinzigeReferenz)
		self.sFunktionsausfuehrerThread.C_FUNKTION_UMKEHREN_BUTTON_SICHTBAR_SIGNAL.connect(self._macheFunktionUmkehrenButtonSichtbar)
		self.sFunktionsausfuehrerThread.C_FUNKTION_WIEDERHOLEN_BUTTON_SICHTBAR_SIGNAL.connect(self._macheFunktionWiederholenButtonSichtbar)

	# Getter/Setter:

	def setzeLiSCryptBlockiert(self, pBlockiertBoolean):
		self.sLiSCryptBlockiertBoolean = pBlockiertBoolean

	def istLiSCryptBlockiert(self):
		return self.sLiSCryptBlockiertBoolean

class QFunktionsstarterThread(QtCore.QThread):
	"""
	Unterklasse von QtCore.QThread Thread zum Start von Programmfunktionen, für den Fall dass LiSCrypt mit per
	Aufparametern übergebenen Eintragsnamen (Pfaden) aufgerufen wird
	"""
	# PyQt-Signale zur Interaktion mit der GUI definieren:
	C_FUNKTIONSSTART_SIGNAL = QtCore.pyqtSignal(list)

	def __init__(self, pPfadeZuEintraegenList):
		"""
		Initiallisiert ein Objekt der Klasse QFunktionsstarterThread
		:param pPfadeZuEintraegenList: (Ggf. reduzierte) Pfadangaben zu Einträgen des Dateisystems, auf denen eine Programmfunktion ausgeführt werden soll
		:type pPfadeZuEintraegenList: Liste von Strings
		"""
		super(QFunktionsstarterThread, self).__init__()
		self.sPfadeZuEintraegenList = pPfadeZuEintraegenList

	def run(self):
		"""
		Überschriebene Methode der Oberklasse QtCore.QThread. Wird durch Thread.start automatisch aufgerufen.
		"""
		lErweitertePfadeZuEintraegenlist = [LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lPfadString) for lPfadString in self.sPfadeZuEintraegenList]
		self.C_FUNKTIONSSTART_SIGNAL.emit(lErweitertePfadeZuEintraegenlist)

class QControllerWorkerThread(QtCore.QThread):
	"""
	Unterklasse von QtCore.QThread Thread zur die Ausführung von Programmfunktionen
	"""
	# PyQt-Signale zur Interaktion mit der GUI definieren:
	C_STATUSAENDERUNG_SIGNAL = QtCore.pyqtSignal(str, bool)
	C_BERICHTERGAENZUNG_SIGNAL = QtCore.pyqtSignal(str, str)
	C_LEEREZWISCHENABLAGE_SIGNAL = QtCore.pyqtSignal()
	C_INFODIALOG_SIGNAL = QtCore.pyqtSignal(str)
	C_WARNDIALOG_SIGNAL = QtCore.pyqtSignal(str)
	C_FEHLERDIALOG_SIGNAL = QtCore.pyqtSignal(str)
	C_PASSWORTDIALOG_SIGNAL = QtCore.pyqtSignal(bool)
	C_UEBERSCHREIBENDIALOG_SIGNAL = QtCore.pyqtSignal(str)
	C_ENTFERNE_GEMERKTESPASSWORT_SIGNAL = QtCore.pyqtSignal()
	C_FUNKTION_UMKEHREN_BUTTON_SICHTBAR_SIGNAL = QtCore.pyqtSignal(list)
	C_FUNKTION_WIEDERHOLEN_BUTTON_SICHTBAR_SIGNAL = QtCore.pyqtSignal(bool)

	def __init__(self, pSortierteBereinigteDragAndDropsErweitertePfadeList, pFunktionString, pOriginaleVernichtenStatusBoolean, pSchluesselartStrirng, pErweiterterPfadZuSchluesseldateiString):
		"""
		Initiallisiert ein Objekt der Klasse QControllerWorkerThread

		:param pSortierteBereinigteDragAndDropsErweitertePfadeList: Erwieterte Pfadangaben zu namentlich zulässigen
		Verzeichniseinträgen, nach Verzeichnissen und Dateien sortiert
		:type pSortierteBereinigteDragAndDropsErweitertePfadeList: Liste von Strings
		:param pFunktionString: avisierte Programmfunktion ('Verscchlüsseln', LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
		:type pFunktionString: String
		:param pOriginaleVernichtenStatusBoolean: Angabe, ob die Originaldateien vernichtet werden sollen (true: ja, false: nein)
		:type pOriginaleVernichtenStatusBoolean: Boolean
		:param pSchluesselartStrirng: Angabe der Schlüsselart (C_SCHLUESSELART_PASSWORT_LITERAL, C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL)
		:type pSchluesselartStrirng: String
		:param pErweiterterPfadZuSchluesseldateiString: Zur Schlüsseldatei gehörige erweiterte Pfadangabe
		:type pErweiterterPfadZuSchluesseldateiString: String
		"""
		super(QControllerWorkerThread, self).__init__()

		# Allgemeine globale Werte:
		self.sSortierteBereinigteDragAndDropsList = pSortierteBereinigteDragAndDropsErweitertePfadeList
		self.sFunktionString = pFunktionString
		self.sOriginaleVernichtenStatusBoolean = pOriginaleVernichtenStatusBoolean
		self.sSchluesselartString = pSchluesselartStrirng
		self.sErweiterterPfadZuSchluesseldateiString = pErweiterterPfadZuSchluesseldateiString
		self.sStartZeitpunktAusgegebenBoolean = False
		self.sDateilistenAnzeigeFehlerImProzessBoolean = False
		self.sErweitertePfadeAllerErzeugtenDateienList = []

		# Globale Werte zur Schlüsselableitung:
		self.sInitialesScryptSaltBytes = None
		self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN = None # geheim
		self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN = None # geheim
		self.sAESGCMV3SchluesselBytes_LOESCHEN = None # geheim
		self.sChaCha20V3SchluesselBytes_LOESCHEN = None # geheim
		self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN = None # geheim

		# Zähler für die Obergrenze von Dateien, die bei Verwendung von AES-GCM mit demselben Schlüssel
		# verschlüsselt werden dürfen:
		self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger = 0

		# Zähler für die Obergrenze von Dateien, die bei Verwendung von ChaCha20 mit demselben Schlüssel
		# verschlüsselt werden dürfen:
		self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger = 0

		# Flag für Stopp des Threads:
		self.sFunktionsprozessAktivBoolean = False

	def run(self):
		"""
		Überschriebene Methode der Oberklasse QtCore.QThread. Wird durch QThread.start automatisch aufgerufen.
		"""
		self.sFunktionsprozessAktivBoolean = True
		try:
			self.fuehreFunktionAus()
		except Exception as lException:
			self._zeigeFehlerDialogModal('Unbekannter schwerer Fehler.')
			logging.exception(
				datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Funktionsausführung')
		finally:
			self.sFunktionsprozessAktivBoolean = False # Nur relevant, wenn Prozess nicht durch Nutzer ("Abbrechen"-Button) angehalten wurde
			self.setzeStatusleisteUndGUIZustand()
			self.C_FUNKTION_UMKEHREN_BUTTON_SICHTBAR_SIGNAL.emit(self.sErweitertePfadeAllerErzeugtenDateienList)
			self.C_FUNKTION_WIEDERHOLEN_BUTTON_SICHTBAR_SIGNAL.emit(self.sDateilistenAnzeigeFehlerImProzessBoolean)

	def fuehreFunktionAus(self):
		"""
		Führt die in in self.sFunktionString festgelegte Programmfunktion aus.
		"""
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is not None or self.sInitialesScryptSaltBytes is not None: # Vermeidung einer Wiederholung des Scrypt-Hashes
			raise AssertionError('Initialer Scrypt-Hash vor Funktionsausfühurng bereis vorhanden.')

		lPasswortString_LOESCHEN = None
		lSHA512HashwertBytes_LOESCHEN = None
		lSHA256HashwertBytes_LOESCHEN = None
		try: # Absicherung, damit Überschreiben sensibler Informationen auch bei Fehlern in Except-Blöcken stattfindet
			# Entsprechende Funktionsmethode aufrufen:
			if self.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
				for lDragAndDropElementString in self.sSortierteBereinigteDragAndDropsList:
					try: #Durch try und except wird ausgeschlossen, dass Originaldateien ohne Verschlüsselung vernichtet werden
						if self.sSchluesselartString == LiSKonstanten.C_SCHLUESSELART_PASSWORT_LITERAL:
							if lPasswortString_LOESCHEN is None:
								lPasswortString_LOESCHEN = self._zeigePasswortDialog()
								lSHA512HashwertBytes_LOESCHEN = self._berechneSHA512(pPasswortString=lPasswortString_LOESCHEN)
								self._gibStartzeitpunktAus()

								lClipboard = QtWidgets.QApplication.clipboard()
								if lClipboard.text() == lPasswortString_LOESCHEN:
									self._zeigeWarnDialogModal(
										'Die Zwischenablage enthält Ihr Passwort! Aus Sicherheitsgründen wird die Zwischenablage jetzt geleert.')
									self._leereZwischenablage()
									self.ergaenzeBerichtAusgabe('* Zwischenablage geleert')
						else: #d.h. Schlüsseldatei:
							if lSHA512HashwertBytes_LOESCHEN is None:
								self.setzeStatusleisteUndGUIZustand('Schlüsseldatei verarbeiten...')
								lSHA512HashwertBytes_LOESCHEN = self._berechneSHA512(
									pErweiterterPfadZuSchluesseldateiString=self.sErweiterterPfadZuSchluesseldateiString)
								self._gibStartzeitpunktAus()
						self._verschluessle(lDragAndDropElementString, lSHA512HashwertBytes_LOESCHEN)

					except LiSAusnahmen.QNoPasswordError:
						break
					except LiSAusnahmen.QFileListDisplayError as lException:
						if not isinstance(lException, LiSAusnahmen.QFileSkippedByUserError):
							self.sDateilistenAnzeigeFehlerImProzessBoolean = True
						self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Verschlüsselung')
					except LiSAusnahmen.QProcessStoppedByUserError as lException:
						self.ergaenzeBerichtAusgabe('-- Abbruch durch Nutzer --')
						break
					except Exception as lException:
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Verschlüsselung')
						self._zeigeFehlerDialogModal(str(lException))
						break

			elif self.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
				for lDragAndDropElementString in self.sSortierteBereinigteDragAndDropsList:
					try: #Durch try und except wird ausgeschlossen, dass verschlüsselte Dateien ohne Entschlüsselung vernichtet werden
						if self.sSchluesselartString == LiSKonstanten.C_SCHLUESSELART_PASSWORT_LITERAL:
							if lPasswortString_LOESCHEN is None:
								lPasswortString_LOESCHEN = self._zeigePasswortDialog(pMitBestaetigungBoolean=False)
								lSHA256HashwertBytes_LOESCHEN = self._berechneSHA256(pPasswortString=lPasswortString_LOESCHEN)
								lSHA512HashwertBytes_LOESCHEN = self._berechneSHA512(pPasswortString=lPasswortString_LOESCHEN)
								self._gibStartzeitpunktAus()

								lClipboard = QtWidgets.QApplication.clipboard()
								if lClipboard.text() == lPasswortString_LOESCHEN:
									self._zeigeWarnDialogModal(
										'Die Zwischenablage enthält Ihr Passwort! Aus Sicherheitsgründen wird die Zwischenablage jetzt geleert.')
									self._leereZwischenablage()
									self.ergaenzeBerichtAusgabe('* Zwischenablage geleert')
						else:
							if lSHA512HashwertBytes_LOESCHEN is None: # Gedacht: 'or lSHA256Hashwert is None'
								self.setzeStatusleisteUndGUIZustand('Schlüsseldatei verarbeiten...')
								lSHA256HashwertBytes_LOESCHEN = self._berechneSHA256(
									pErweiterterPfadZuSchluesseldateiString=self.sErweiterterPfadZuSchluesseldateiString)
								lSHA512HashwertBytes_LOESCHEN = self._berechneSHA512(
									pErweiterterPfadZuSchluesseldateiString=self.sErweiterterPfadZuSchluesseldateiString)
								self._gibStartzeitpunktAus()
						self._entschluessle(pErweiterterPfadString=lDragAndDropElementString, pSHA256HashwertBytes=lSHA256HashwertBytes_LOESCHEN, pSHA512HashwertBytes=lSHA512HashwertBytes_LOESCHEN)

					except LiSAusnahmen.QNoPasswordError:
						break
					except LiSAusnahmen.QFileListDisplayError as lException:
						if not isinstance(lException, LiSAusnahmen.QFileSkippedByUserError):
							self.sDateilistenAnzeigeFehlerImProzessBoolean = True
						self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Entschlüsselung')
					except LiSAusnahmen.QProcessStoppedByUserError:
						self.ergaenzeBerichtAusgabe('-- Abbruch durch Nutzer --')
						break
					except Exception as lException:
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Entschlüsselung')
						self._zeigeFehlerDialogModal(str(lException))
						break

			else: # d.h. self.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL
				self._gibStartzeitpunktAus()
				for lDragAndDropElementString in self.sSortierteBereinigteDragAndDropsList:
					try:
						self.vernichte(pErweiterterPfadString=lDragAndDropElementString)
					except LiSAusnahmen.QFileListDisplayError as lException:
						self.sDateilistenAnzeigeFehlerImProzessBoolean = True
						self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung')
					except LiSAusnahmen.QProcessStoppedByUserError:
						self.ergaenzeBerichtAusgabe('-- Abbruch durch Nutzer --')
						break
					except Exception as lException:
						logging.exception(
							datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung')
						self._zeigeFehlerDialogModal(str(lException))
						break
		except:
			pass

		finally:
			# Überschreiben aller zuletzt (potentiell) erzeugten geheimen Werte (diese werden
			# im Prozess ebenfalls zunächst mit 0-Bytes überschrieben, wenn es zu einer Neuberechnung kommt)
			if sys.getrefcount(lPasswortString_LOESCHEN) <= 2: # lPasswortString_LOESCHEN und Interning-Verweis
				LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lPasswortString_LOESCHEN, pStringBestaetigungBoolean=True)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA256HashwertBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA512HashwertBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sAESGCMV3SchluesselBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sChaCha20V3SchluesselBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN)

			# Globale Referenzen freigeben (diese werden im Prozess ebenfalls freigegeben, wenn es zu einer
			# Neuberechnung kommt; lokale Variablen werden hier der Klarheit halber auch berücksichtigt,
			# obwohl dies nicht erforderlich wäre, da die Methode hier endet.
			try:
				del lPasswortString_LOESCHEN
			except AttributeError:
				pass
			finally:
				try:
					del lSHA256HashwertBytes_LOESCHEN
				except AttributeError:
					pass
				finally:
					try:
						del lSHA512HashwertBytes_LOESCHEN
					except AttributeError:
						pass
					finally:
						try:
							del self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN
						except AttributeError:
							pass
						finally:
							try:
								del self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN
							except AttributeError:
								pass
							finally:
								try:
									del self.sAESGCMV3SchluesselBytes_LOESCHEN
								except AttributeError:
									pass
								finally:
									try:
										del self.sChaCha20V3SchluesselBytes_LOESCHEN
									except AttributeError:
										pass
									finally:
										try:
											del self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN
										except AttributeError:
											pass
										finally:
											gc.collect() # Am Ende eine komplette Garbage Collection auslösen

			#Ausgabe von Endzeitpunkt und Probleminformationen, falls erforderlich
			self._gibEndzeitpunktAusFallsErforderlich()
			self._zeigeProbleminfoFallsErforderlich()


	def _verschluessle(self, pErweiterterPfadString, pSHA512HashwertBytes):
		"""
		Interne Methode. Analysiert das durch pErweiterterPfadString für die Verschlüsselung bestimmte Element des
		Dateisystems (Datei oder Verzeichnis?) und veranlasst die weitere Verarbeitung.

		:param pErweiterterPfadString: Erweiterte Pfadangabe zum durch pErweiterterPfadString gehörigen Verzeichniseintrag
		:type pErweiterterPfadString: String
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		if not os.path.islink(pErweiterterPfadString) and not LiSWerkzeuge.Dateiwerkzeuge.istFIFO(pErweiterterPfadString) \
				and (not os.name == 'nt' or (not os.path.isfile(pErweiterterPfadString) or not pErweiterterPfadString.lower().endswith('.lnk'))):
			if os.path.exists(pErweiterterPfadString):
				if os.path.isfile(pErweiterterPfadString):
					# Alle Exceptions werden zum Aufrufer weitergereicht
					if self.sSchluesselartString != LiSKonstanten.C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL or self.sErweiterterPfadZuSchluesseldateiString != pErweiterterPfadString:
						self._verschluessleDatei(pErweiterterPfadZuDateiString=pErweiterterPfadString, pSHA512HashwertBytes=pSHA512HashwertBytes)
					else:
						lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
						lNurEndnameString = os.path.basename(lNameReduziertString)
						raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Schlüsseldatei]', lNameReduziertString)
				elif os.path.isdir(pErweiterterPfadString):
					# Alle Exceptions werden zum Aufrufer weitergereicht
					self._verschluessleVerzeichnis(pErweiterterPfadZuVerzeichnisString=pErweiterterPfadString, pSHA512HashwertBytes=pSHA512HashwertBytes)
				else:
					lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
					lNurEndnameString = os.path.basename(lNameReduziertString)
					raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Unbekannter Typ]', lNameReduziertString)
			else:
				lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
				lNurEndnameString = os.path.basename(lNameReduziertString)
				raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Ver-/Entschlüsselung: Nicht gefunden]', lNameReduziertString)
		else:
			lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
			lNurEndnameString = os.path.basename(lNameReduziertString)
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Verknüpfung/FIFO]', lNameReduziertString)

	def _verschluessleDatei(self, pErweiterterPfadZuDateiString, pSHA512HashwertBytes):
		"""
		Interne Methode. Veranlasst die Verschlüsselung der urch pErweitererPfadZuDateiString spezifizierten Datei unter
		Verwendung des Hashes pSHA512HashwertBytes als Schlüsselausgangsmaterial.

		:param pErweiterterPfadZuDateiString: Erweiterte Pfadangabe zu einer Datei
		:type pErweiterterPfadZuDateiString: String
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiString)
		lNurEndnameString = os.path.basename(pErweiterterPfadZuDateiString)

		if self.sOriginaleVernichtenStatusBoolean is False or LiSWerkzeuge.Dateiwerkzeuge.istBeschreibbar(pErweiterterPfadZuDateiString):
			lNurVorPfadString = os.path.dirname(pErweiterterPfadZuDateiString)
			lNurEndnameMitErsetzungString = LiSWerkzeuge.Stringwerkzeuge.rreplace(lNurEndnameString, '.', '-', 1) + LiSKonstanten.C_DATEIENDUNG
			lErweiterterPfadZuZieldateiString = os.path.join(lNurVorPfadString, lNurEndnameMitErsetzungString)

			if not os.path.lexists(lErweiterterPfadZuZieldateiString):
				# Alle Exceptions werden zum Aufrufer weitergereicht
				LiSKrypto.QDatei(self, pErweiterterPfadZuDateiString).verschluesseln(pSHA512HashwertBytes=pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString=lErweiterterPfadZuZieldateiString)
				self.ergaenzeBerichtAusgabe(lNurEndnameString + ': [Verschlüsselung OK]', lDateinameReduziertString)
				self.sErweitertePfadeAllerErzeugtenDateienList.append(lErweiterterPfadZuZieldateiString)  # Wenn die Verschlüsselung gelungen ist, dann wurde auch eine Datei erzeugt
				if self.sOriginaleVernichtenStatusBoolean is True:
					self._vernichteDateiOderVerweisOderFIFO(pErweiterterPfadZuDateiString)
			else:
				lUeberschreibenInteger = self._zeigeUeberschreibenDialog(lErweiterterPfadZuZieldateiString)
				# Alle Exceptions werden zum Aufrufer weitergereicht
				if lUeberschreibenInteger == QtWidgets.QMessageBox.Yes:
					self.vernichte(lErweiterterPfadZuZieldateiString)
					LiSKrypto.QDatei(self, pErweiterterPfadZuDateiString).verschluesseln(pSHA512HashwertBytes=pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString=lErweiterterPfadZuZieldateiString)
					self.ergaenzeBerichtAusgabe(lNurEndnameString + ': [Verschlüsselung OK]', lDateinameReduziertString)
					self.sErweitertePfadeAllerErzeugtenDateienList.append(lErweiterterPfadZuZieldateiString)  # Wenn die Verschlüsselung gelungen ist, dann wurde auch eine Datei erzeugt
					if self.sOriginaleVernichtenStatusBoolean is True:
						self._vernichteDateiOderVerweisOderFIFO(pErweiterterPfadZuDateiString)
				elif lUeberschreibenInteger == QtWidgets.QMessageBox.No:
					raise LiSAusnahmen.QFileListDisplayError((lNurEndnameString + ': [Übersprungen: Nutzer-Auswahl]'), lDateinameReduziertString)
				else: #d.h. lUeberschreibenBoolean=None -Auswahl von 'Abbrechen' im Dialogfenster
					self.stoppeFunktionsprozess()
					raise LiSAusnahmen.QProcessStoppedByUserError()
		else:
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Kein Schreibzugriff]', lDateinameReduziertString)

	def _verschluessleVerzeichnis(self, pErweiterterPfadZuVerzeichnisString, pSHA512HashwertBytes):
		"""
		Interne Methode. Durchläuft das durch pErweitererPfadZuVerzeichnisString spezifizierte Verzeichnis sowie dessen
		Unterverzeichnisse und ruft für alle gefundenen Dateien ohne Endung LiSKonstanten.C_DATEIENDUNG die Methode self._verschluessle(...) auf

		:param pErweiterterPfadZuVerzeichnisString: Erweiterte Pfadangabe zu einem Verzeichnis
		:type pErweiterterPfadZuVerzeichnisString: String
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		for lWurzel, lVerzeichnisse, lDateien in os.walk(pErweiterterPfadZuVerzeichnisString):
			for lDateiname in lDateien:
				if not str.lower(lDateiname).endswith(LiSKonstanten.C_DATEIENDUNG):
					lDateinameMitPfadString = os.path.join(lWurzel, lDateiname)
					lDateinameMitPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lDateinameMitPfadString)
					try:
						self._verschluessle(lDateinameMitPfadErweitertString, pSHA512HashwertBytes)
					except LiSAusnahmen.QFileListDisplayError as lException:
						# Spezielle Behandlung von QFileListDisplayErrors
						# Alle anderen Exceptions werden zum Aufrufer weitergereicht
						self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
						logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Verschlüsselung')

	def _entschluessle(self, pErweiterterPfadString, pSHA256HashwertBytes, pSHA512HashwertBytes):
		"""
		Interne Methode. Analysiert das durch pErweiterterPfadString für die Entschlüsselung bestimmte Element des
		Dateisystems (Datei oder Verzeichnis?) und veranlasst die weitere Verarbeitung.

		:param pErweiterterPfadString: Erweiterte Pfadangabe zum Element des Dateisystems
		:type pErweiterterPfadString: String
		:param pSHA256HashwertBytes: SHA256-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA256HashwertBytes: Bytesequenz
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		if not os.path.islink(pErweiterterPfadString) \
				and not LiSWerkzeuge.Dateiwerkzeuge.istFIFO(pErweiterterPfadString): # Keine Prüfung auf *.lnk, da hier nur Dateien mit Endung LiSKonstanten.C_DATEIENDUNG ankommen:
			if os.path.exists(pErweiterterPfadString):
				if os.path.isfile(pErweiterterPfadString) and str.lower(pErweiterterPfadString).endswith(LiSKonstanten.C_DATEIENDUNG):
						try:
							self._entschluessleDatei(pErweiterterPfadZuDateiString=pErweiterterPfadString, pSHA256HashwertBytes=pSHA256HashwertBytes, pSHA512HashwertBytes=pSHA512HashwertBytes)
						except (LiSAusnahmen.QFileListDisplayError, LiSAusnahmen.QProcessStoppedByUserError):
							raise
				elif os.path.isdir(pErweiterterPfadString):
					try:
						self._entschluessleVerzeichnis(pErweiterterPfadZuVerzeichnisString=pErweiterterPfadString, pSHA256HashwertBytes=pSHA256HashwertBytes, pSHA512HashwertBytes=pSHA512HashwertBytes)
					except (LiSAusnahmen.QFileListDisplayError, LiSAusnahmen.QProcessStoppedByUserError):
						raise
				else:
					lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
					lNurEndnameString = os.path.basename(lNameReduziertString)
					raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Unbekannter Typ]', lNameReduziertString)
			else:
				lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
				lNurEndnameString = os.path.basename(lNameReduziertString)
				raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Ver-/Entschlüsselung: Nicht gefunden]', lNameReduziertString)
		else:
			lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
			lNurEndnameString = os.path.basename(lNameReduziertString)
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Verknüpfung/FIFO]', lNameReduziertString)

	def _entschluessleDatei(self, pErweiterterPfadZuDateiString, pSHA256HashwertBytes, pSHA512HashwertBytes):
		"""
		Interne Methode. Veranlasst die Entschlüsselung der durch pErweitererPfadZuDateiString spezifizierten Datei unter
		Verwendung des Hashes pSHA256HashwertBytes oder des Hashes pSHA512HashwertBytes als Schlüsselausgangsmaterial.

		:param pErweiterterPfadZuDateiString: Erweiterte Pfadangabe zu einer Datei
		:type pErweiterterPfadZuDateiString: String
		:param pSHA256HashwertBytes: SHA256-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA256HashwertBytes: Bytesequenz
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiString)
		lNurEndnameString = os.path.basename(pErweiterterPfadZuDateiString)
		lReduzierterPfadZuDateiString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiString)

		erweiterterPfadZuTempCerzeichnisString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(tempfile.gettempdir())
		if pErweiterterPfadZuDateiString.startswith(erweiterterPfadZuTempCerzeichnisString):
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Entschlüsselungsort nicht zulässig]',
													 lReduzierterPfadZuDateiString)
		else:
			if self.sOriginaleVernichtenStatusBoolean is False or LiSWerkzeuge.Dateiwerkzeuge.istBeschreibbar(pErweiterterPfadZuDateiString):
				# Alle Exceptions werden zum Aufrufer weitergereicht
				lZieldateinameString = None
				while lZieldateinameString is None or os.path.lexists(lZieldateinameString):
					# Erzeuge zufälligen temporären Dateinamen für Entschlüsselung
					lZielNurEndnameString = LiSWerkzeuge.Stringwerkzeuge.erzeugeZufaelligenBuchstabenUndZiffernStringMitMaximalerLaenge(len(lNurEndnameString)) # Wg. Endung 'LiSKonstanten.C_DATEIENDUNG' ist kleinste Maximallänge 5 (sollte im Regelfall ausreichen)
					lZieldateinameVorEndnameString = os.path.split(pErweiterterPfadZuDateiString)[0]
					lZieldateinameString = os.path.join(lZieldateinameVorEndnameString,lZielNurEndnameString)

				lErweiterterPfadZuZieldateiString = LiSKrypto.QDatei(self, pErweiterterPfadZuDateiString).entschluesseln(pSHA256HashwertBytes=pSHA256HashwertBytes, pSHA512HashwertBytes=pSHA512HashwertBytes, pErweiterterPfadZuZieldateiString=lZieldateinameString)
				self.ergaenzeBerichtAusgabe(lNurEndnameString + ': [Entschlüsselung OK]', lDateinameReduziertString)
				self.sErweitertePfadeAllerErzeugtenDateienList.append(lErweiterterPfadZuZieldateiString) # Wenn die Entschlüsselung gelungen ist, dann wurde auch eine Datei erzeugt
				if self.sOriginaleVernichtenStatusBoolean is True:
					self._vernichteDateiOderVerweisOderFIFO(pErweiterterPfadZuDateiString)
			else:
				raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Übersprungen: Kein Schreibzugriff]', lDateinameReduziertString)

	def _entschluessleVerzeichnis(self, pErweiterterPfadZuVerzeichnisString, pSHA256HashwertBytes, pSHA512HashwertBytes):
		"""
		Interne Methode. Durchläuft das durch pErweitererPfadZuVerzeichnisString spezifizierte Verzeichnis sowie dessen
		Unterverzeichnisse und ruft für alle gefundenen Dateien mit Endung LiSKonstanten.C_DATEIENDUNG die Methode self._entschluessle(...) auf

		:param pErweiterterPfadZuVerzeichnisString: Erweiterte Pfadangabe zu einem Verzeichnis
		:type pErweiterterPfadZuVerzeichnisString: String
		:param pSHA256HashwertBytes: SHA256-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA256HashwertBytes: Bytesequenz
		:param pSHA512HashwertBytes: SHA512-Hashwert (zu Passwort oder Schlüsseldatei)
		:type pSHA512HashwertBytes: Bytesequenz
		"""
		for lWurzel, lVerzeichnisse, lDateien in os.walk(pErweiterterPfadZuVerzeichnisString):
			for lDateiname in lDateien:
				if str.lower(lDateiname).endswith(LiSKonstanten.C_DATEIENDUNG):
					lDateinameMitPfadString = os.path.join(lWurzel, lDateiname)
					lDateinameMitPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lDateinameMitPfadString)
					try:
						self._entschluessle(pErweiterterPfadString=lDateinameMitPfadErweitertString, pSHA256HashwertBytes=pSHA256HashwertBytes, pSHA512HashwertBytes=pSHA512HashwertBytes)
					except LiSAusnahmen.QFileListDisplayError as lException:
						# Spezielle Behandlung von QFileListDisplayErrors
						# Alle anderen Exceptions werden zum Aufrufer weitergereicht
						self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
						logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Entschlüsselung')

	def vernichte(self, pErweiterterPfadString, pAusgabeEintragsnameBoolean=True, pIgnoriereFunktionsprozessAktivBoolean=False):
		"""
		Analysiert das durch pErweiterterPfadString für die Vernichtung bestimmte Element des Dateisystems (Datei oder
		Verzeichnis?) und veranlasst die weitere Verarbeitung. Wird intern und von LiSKrypto.Datei()-Instanzen verwendet.

		:param pErweiterterPfadString: Erweiterte Pfadangabe
		:type pErweiterterPfadString: String
		:param pAusgabeEintragsnameBoolean: Angabe, ob die Vernichtung im Berichtsbereich angezeigt werden soll (true: ja, false: nein)
		:type pAusgabeEintragsnameBoolean: Boolean
		"""
		# Alle Exceptions werden zum Aufrufer weitergereicht
		#self.setzeStatusleisteZustand('Vernichtung läuft...', True)
		if os.path.lexists(pErweiterterPfadString):
			if os.path.isdir(pErweiterterPfadString):
				self._vernichteVerzeichnis(pErweiterterPfadZuVerzeichnisString=pErweiterterPfadString,
										   pAusgabeEintragsnameBoolean=pAusgabeEintragsnameBoolean,
										   pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
			else:
				self._vernichteDateiOderVerweisOderFIFO(pErweiterterPfadZuDateiOderVerweisOderFIFOString=pErweiterterPfadString,
														pAusgabeEintragsnameBoolean=pAusgabeEintragsnameBoolean,
														pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
		else:
			lNameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
			lNurEndnameString = os.path.basename(lNameReduziertString)
			raise LiSAusnahmen.QFileListDisplayError(lNurEndnameString + ': [Vernichtung: Nicht gefunden]', lNameReduziertString)

	def _vernichteDateiOderVerweisOderFIFO(self, pErweiterterPfadZuDateiOderVerweisOderFIFOString, pAusgabeEintragsnameBoolean=True, pIgnoriereFunktionsprozessAktivBoolean=False):
		"""
		Interne Methode. Veranlasst die Vernichtung der/des durch pErweitererPfadZuDateiString spezifizierten
		Datei/symbolischen Links

		:param pErweiterterPfadZuDateiOderVerweisOderFIFOString: Erweiterte Pfadangabe zu einer Datei
		:type pErweiterterPfadZuDateiOderVerweisOderFIFOString: String
		:param pAusgabeEintragsnameBoolean: Angabe, ob die Vernichtung im Berichtsbereich angezeigt werden soll (true: ja, false: nein)
		:type pAusgabeEintragsnameBoolean: Boolean
		"""
		lNurEndnameString = os.path.basename(pErweiterterPfadZuDateiOderVerweisOderFIFOString)
		if pAusgabeEintragsnameBoolean is True:
			self.setzeStatusleisteUndGUIZustand(pTextString='Vernichtung: ' + lNurEndnameString, pAbbrechenButtonAktivBoolean=True)
		else:
			self.setzeStatusleisteUndGUIZustand(pTextString='Vernichtung: Temporäre Datei', pAbbrechenButtonAktivBoolean=True)

		# Alle Exceptions werden zum Aufrufer weitergereicht
		lWindowsWipeBoolean = LiSVernichtung.QVerzeichniseintrag(self, pErweiterterPfadZuDateiOderVerweisOderFIFOString).vernichten(pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
		if pAusgabeEintragsnameBoolean is True:
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiOderVerweisOderFIFOString)
			self.ergaenzeBerichtAusgabe(lNurEndnameString + (': [Vernichtung OK]' if lWindowsWipeBoolean is False else ': [Vernichtung  OK]'), lDateinameReduziertString)
		else:
			lDateinameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuDateiOderVerweisOderFIFOString)
			self.ergaenzeBerichtAusgabe('Temporäre Datei' + (': [Vernichtung OK]' if lWindowsWipeBoolean is False else ': [Vernichtung  OK]'), lDateinameReduziertString)

	def _vernichteVerzeichnis(self, pErweiterterPfadZuVerzeichnisString, pAusgabeEintragsnameBoolean, pIgnoriereFunktionsprozessAktivBoolean):
		"""
		Interne Methode. Durchläuft das durch pErweitererPfadZuVerzeichnisString spezifizierte Verzeichnis sowie dessen
		Unterverzeichnisse und ruft für alle gefundenen Verzeichnisse self._vernichteVerzeichnis(...) sowie
		für alle gefundenen Dateien/Verweise self._vernichteDateiOderVerweis(...) auf

		:param pErweiterterPfadZuVerzeichnisString: Erweiterte Pfadangabe zu einem Verzeichnis
		:type pErweiterterPfadZuVerzeichnisString: String
		:param pAusgabeEintragsnameBoolean: Festlegung, ob der Verzeichnisname und die Namen der im Verzeichnis enthaltenen Dateien bei der Vernichtung ausgegeben werden sollen (True: ja, False: nein)
		:type pAusgabeEintragsnameBoolean: Boolean
		:param pIgnoriereFunktionsprozessAktivBoolean: Festlegung, ob die Vernichtung auch durchgeführt werden soll, wenn bereits ein Funktionsprozess läuft (True: ja, False: nein)
		:type pIgnoriereFunktionsprozessAktivBoolean: Boolean

		"""
		for lWurzel, lVerzeichnisse, lDateien in os.walk(pErweiterterPfadZuVerzeichnisString):
			for lVerzeichnisnameString in lVerzeichnisse:
				lVerzeichnisnameMitPfadString = os.path.join(lWurzel, lVerzeichnisnameString)
				lVerzeichnisnameMitPfadErweitertString	= LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lVerzeichnisnameMitPfadString)
				# Weitergabe einer potentiellen Exception des folgenden Befehls an den Aufrufer
				self._vernichteVerzeichnis(lVerzeichnisnameMitPfadErweitertString, pAusgabeEintragsnameBoolean=pAusgabeEintragsnameBoolean, pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
			for lDateinameString in lDateien:
				lDateinameMitPfadString = os.path.join(lWurzel, lDateinameString)
				lDateinameMitPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(lDateinameMitPfadString)
				try:
					self._vernichteDateiOderVerweisOderFIFO(lDateinameMitPfadErweitertString, pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
				except LiSAusnahmen.QFileListDisplayError as lException:
					# Spezielle Behandlung von QFileListDisplayErrors
					# Alle anderen Exceptions werden zum Aufrufer weitergereicht
					self.ergaenzeBerichtAusgabe(str(lException), lException.gibToolTipString())
					logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Exception während Vernichtung')

		# Weitergabe einer potentiellen Exception des folgenden Befehls an den Aufrufer
		LiSVernichtung.QVerzeichniseintrag(self, pErweiterterPfadZuVerzeichnisString).vernichten(pIgnoriereFunktionsprozessAktivBoolean=pIgnoriereFunktionsprozessAktivBoolean)
		lVerzeichnisnameReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadZuVerzeichnisString)
		lNurEndnameString = os.path.basename(lVerzeichnisnameReduziertString)
		if pAusgabeEintragsnameBoolean is True:
			self.ergaenzeBerichtAusgabe(lNurEndnameString + ': [Vernichtung OK]', lVerzeichnisnameReduziertString)
		else:
			self.ergaenzeBerichtAusgabe('Temporäres Verzeichnis: [Vernichtung OK]', lVerzeichnisnameReduziertString)

	# Methoden zur Berechnung eines SHA256-Hashwerts aus Passwort oder Schlüsseldatei:

	def _berechneSHA256(self, pPasswortString=None, pErweiterterPfadZuSchluesseldateiString=None):
		"""
		Interne Methode. Ermittelt und returniert den SHA256-Hashwert zum String pPasswortString oder durch Aufruf von
		self._berechneSHA256VonDatei(...) der durch pErweiterterPfadZuSchluesseldateiString spezifizierten Datei.

		:param pPasswortString: Passwort
		:type pPasswortString: String
		:param pErweiterterPfadZuSchluesseldateiString: Erweiterte Pfadangabe zur Schlüsseldatei
		:type pErweiterterPfadZuSchluesseldateiString: String
		:return: SHA256-Hashwert
		:rtype: Bytesequenz
		"""
		if  pPasswortString == '':
			raise ValueError('SHA256 von leerem Passwort nicht möglich.')
		if pPasswortString is not None and pErweiterterPfadZuSchluesseldateiString is None:
			lSHA256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
			lPasswortBytes_LOESCHEN = pPasswortString.encode()
			lSHA256.update(lPasswortBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lPasswortBytes_LOESCHEN)
		elif pPasswortString is None and pErweiterterPfadZuSchluesseldateiString is not None:
			try:
				lSHA256 = self._berechneSHA256VonDatei(pErweiterterPfadZuSchluesseldateiString)
			except:
				raise
		else:
			raise AssertionError('Unzulässige Kombination von Passwort und/oder Schlüsseldatei! Prozess abgebrochen.')
		return lSHA256.finalize()

	def _berechneSHA256VonDatei(self, pErweiterterPfadZuSchluesseldateiString):
		"""
		Interne Methode. Veranlasst die Ermittlung von den Hashwert der durch pErweiterterPfadZuSchluesseldateiString
		spezifizierten Datei und returniert diesen.

		:param pErweiterterPfadZuSchluesseldateiString: Erweiterte Pfadangabe zur Schlüsseldatei
		:type pErweiterterPfadZuSchluesseldateiString: String
		:return: SHA256-Hashobjekt
		:rtype: Hashobjekt
		"""
		lSHA256 = hashes.Hash(hashes.SHA256(), backend=default_backend())
		try:
			self.setzeStatusleisteUndGUIZustand('Verarbeite Schlüsseldatei...')
			with open(pErweiterterPfadZuSchluesseldateiString, 'rb') as lDatei:
				lBlockBytes_LOESCHEN = lDatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
				while lBlockBytes_LOESCHEN:
					lSHA256.update(lBlockBytes_LOESCHEN)
					LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockBytes_LOESCHEN)
					lBlockBytes_LOESCHEN = lDatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
		except:
			raise OSError('Schlüsseldatei nicht gefunden oder nicht lesbar! Prozess abgebrochen.')
		return lSHA256

	# Methoden zur Berechnung eines SHA512-Hashwerts aus Passwort oder Schlüsseldatei:

	def _berechneSHA512(self, pPasswortString=None, pErweiterterPfadZuSchluesseldateiString=None):
		"""
		Interne Methode. Ermittelt und returniert den SHA512-Hashwert zum String pPasswortString oder durch Aufruf von
		self._berechneSHA512VonDatei(...) der durch pErweiterterPfadZuSchluesseldateiString spezifizierten Datei.

		:param pPasswortString: Passwort
		:type pPasswortString: String
		:param pErweiterterPfadZuSchluesseldateiString: Erweiterte Pfadangabe zur Schlüsseldatei
		:type pErweiterterPfadZuSchluesseldateiString: String
		:return: SHA512-Hashwert
		:rtype: Bytesequenz
		"""
		if  pPasswortString == '':
			raise ValueError('SHA512 von leerem Passwort nicht möglich.')
		if pPasswortString is not None and pErweiterterPfadZuSchluesseldateiString is None:
			lSHA512 = hashes.Hash(hashes.SHA512(), backend=default_backend())
			lPasswortBytes_LOESCHEN = pPasswortString.encode()
			lSHA512.update(lPasswortBytes_LOESCHEN)
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lPasswortBytes_LOESCHEN)
		elif pPasswortString is None and pErweiterterPfadZuSchluesseldateiString is not None:
			try:
				lSHA512 = self._berechneSHA512VonDatei(pErweiterterPfadZuSchluesseldateiString)
			except:
				raise
		else:
			raise AssertionError('Unzulässige Kombination von Passwort und/oder Schlüsseldatei! Prozess abgebrochen.')
		return lSHA512.finalize()

	def _berechneSHA512VonDatei(self, pErweiterterPfadZuSchluesseldateiString):
		"""
		Interne Methode. Veranlasst die Ermittlung von den Hashwert der durch pErweiterterPfadZuSchluesseldateiString
		spezifizierten Datei und returniert diesen.

		:param pErweiterterPfadZuSchluesseldateiString: Erweiterte Pfadangabe zur Schlüsseldatei
		:type pErweiterterPfadZuSchluesseldateiString: String
		:return: SHA512-Hashobjekt
		:rtype: Hashobjekt
		"""
		lSHA512 = hashes.Hash(hashes.SHA512(), backend=default_backend())
		try:
			self.setzeStatusleisteUndGUIZustand('Verarbeite Schlüsseldatei...')
			with open(pErweiterterPfadZuSchluesseldateiString, 'rb') as lDatei:
				lBlockBytes_LOESCHEN = lDatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
				while lBlockBytes_LOESCHEN:
					lSHA512.update(lBlockBytes_LOESCHEN)
					LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lBlockBytes_LOESCHEN)
					lBlockBytes_LOESCHEN = lDatei.read(LiSKonstanten.C_DATEI_BLOCKGROESSE)
		except:
			raise OSError('Schlüsseldatei nicht gefunden oder nicht lesbar. Prozess abgebrochen.')
		return lSHA512

	# Methoden zur Ableitung eines Crypt-Schlüssels aus einem SHA-Hashwert:

	def ermittleAESGCM_V1Schluessel(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pScryptSaltBytes=None):
		"""
		DEPRECATED. Veranlasst die Berechnung eines frischen Schlüssels für AESGCM_V1 und ggf. zufällige Bestimmung eines Saltwerts
		für Scrypt auf Basis der übergebenen Werte.

		:param pSHA256HashwertBytes: SHA256-Hashwert von Passwort oder Schlüsseldatei
		:type pSHA256HashwertBytes: Bytesequenz
		:param pScryptAufwandsfaktorInteger: N-Wert für Scrypt
		:type pScryptAufwandsfaktorInteger: Integer
		:param pScryptBlockgroesseInteger: r-Wert für Scrypt
		:type pScryptBlockgroesseInteger: Integer
		:param pScryptParallelisierungInteger: p-Wert für Scrypt
		:type pScryptParallelisierungInteger: Integer
		:param pScryptSaltBytes: Salt für Scrypt
		:type pScryptSaltBytes: Bytesquenz
		:return: Schlüssel und Scrypt-Salt
		:rtype: Dictionary
		"""
		lScryptSaltBytes = pScryptSaltBytes
		if lScryptSaltBytes is None:
			lScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
		lAESGCMV1SchluesselBytes = self._berechneScryptHashVonStringFuerAESGCM_V1(
			pSHA256HashwertBytes=pSHA256HashwertBytes,
			pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
			pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
			pScryptParallelisierungInteger=pScryptParallelisierungInteger,
			pScryptSaltBytes=pScryptSaltBytes)
		return {'AESGCMV1Schluessel':lAESGCMV1SchluesselBytes, 'ScryptSaltFuerAESGCMV1':lScryptSaltBytes}

	def ermittleAESGCM_V2Schluessel(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pInitialesScryptSaltBytes=None, pHKDFSaltBytes=None):
		"""
		DEPRECATED. Veranlasst die Berechnung eines frischen Schlüssels für AESGCM_V2 und ggf. zufällige Bestimmung eines Saltwerts
		für HKDF und ggf. eines Saltwerts für Scrypt auf Basis der übergebenen Werte.

		:param pSHA256HashwertBytes: SHA256-Hashwert von Passwort oder Schlüsseldatei
		:type pSHA256HashwertBytes: Bytesequenz
		:param pScryptAufwandsfaktorInteger: N-Wert für Scrypt
		:type pScryptAufwandsfaktorInteger: Integer
		:param pScryptBlockgroesseInteger: r-Wert für Scrypt
		:type pScryptBlockgroesseInteger: Integer
		:param pScryptParallelisierungInteger: p-Wert für Scrypt
		:type pScryptParallelisierungInteger: Integer
		:param pInitialesScryptSaltBytes: Salt für initiales Scrypt (für Masterschlüssel)
		:type pInitialesScryptSaltBytes: Bytesquenz
		:param pHKDFSaltBytes: Salt für HKDF (für Datenschutzschlüssel)
		:type pHKDFSaltBytes: Bytesequenz
		:return: Schlüssel, HKDF-Salt und Scrypt-Salt
		:rtype: Dictionary
		"""
		lHKDFSaltBytes = pHKDFSaltBytes
		# Einmal Scrypt als Master für HKDF:
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None or (lHKDFSaltBytes is not None and self.sInitialesScryptSaltBytes != pInitialesScryptSaltBytes):
			if pInitialesScryptSaltBytes is None:
				self.sInitialesScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
			else:
				self.sInitialesScryptSaltBytes = pInitialesScryptSaltBytes
			self.setzeStatusleisteUndGUIZustand('Berechne Masterschlüssel (bitte warten)...', True)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
			self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN = self._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V2(
				pSHAHashwertBytes=pSHA256HashwertBytes,
				pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
				pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
				pScryptParallelisierungInteger=pScryptParallelisierungInteger,
				pScryptSaltBytes=self.sInitialesScryptSaltBytes)

		if lHKDFSaltBytes is None: # D.h. Verschlüsselung
			lHKDFSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_HKDF_SALT_FUER_AES_GCM_V2_LAENGE)

		lAESGCMV2SchluesselBytes = self._berechneHKDFWertVonScryptWertFuerAESGCM_V2(lHKDFSaltBytes)
		return {'AESGCMV2Schluessel':lAESGCMV2SchluesselBytes, 'HKDFSaltFuerAESGCMV2':lHKDFSaltBytes, 'InitialesScryptSalt':self.sInitialesScryptSaltBytes}

	def ermittleAESGCM_V3Schluessel(self, *, pSHA512HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pInitialesScryptSaltBytes=None):
		"""
		Veranlasst die Berechnung eines Schlüssels für AESGCM_V3 und ggf. zufällige Bestimmung eines Saltwerts
		für Scrypt auf Basis der übergebenen Werte.

		:param pSHA512HashwertBytes: SHA512-Hashwert von Passwort oder Schlüsseldatei
		:type pSHA512HashwertBytes: Bytesequenz
		:param pScryptAufwandsfaktorInteger: N-Wert für Scrypt
		:type pScryptAufwandsfaktorInteger: Integer
		:param pScryptBlockgroesseInteger: r-Wert für Scrypt
		:type pScryptBlockgroesseInteger: Integer
		:param pScryptParallelisierungInteger: p-Wert für Scrypt
		:type pScryptParallelisierungInteger: Integer
		:param pInitialesScryptSaltBytes: Salt für initiales Scrypt (Masterschlüssel)
		:type pInitialesScryptSaltBytes: Bytesquenz
		:return: Schlüssel und Scrypt-Salt
		:rtype: Dictionary
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is not None:
			if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleAESGCM_V3Schluessel: Initialer Scrypt-Wert ist Nullbytefolge!')
		# Einmal Scrypt als Master für HKDF:
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None or (pInitialesScryptSaltBytes is not None and self.sInitialesScryptSaltBytes != pInitialesScryptSaltBytes)\
				or self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger > LiSKonstanten.C_AES_GCM_MAXIMALE_DATEIANZAHL_PRO_SCHLUESSEL-1:
			if pInitialesScryptSaltBytes is None: # d.h. Verschlüsselung
				self.sInitialesScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
				self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger = 0
			else:
				self.sInitialesScryptSaltBytes = pInitialesScryptSaltBytes # d.h. Entschlüsselung
			self.setzeStatusleisteUndGUIZustand('Berechne Masterschlüssel (bitte warten)...', True)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
			self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN = self._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3(
				pSHAHashwertBytes=pSHA512HashwertBytes,
				pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
				pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
				pScryptParallelisierungInteger=pScryptParallelisierungInteger,
				pScryptSaltBytes=self.sInitialesScryptSaltBytes)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sAESGCMV3SchluesselBytes_LOESCHEN)
			self.sAESGCMV3SchluesselBytes_LOESCHEN = self._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerAESGCM_V3()

		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleAESGCM_V3Schluessel Scrypt: ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleAESGCM_V3Schluessel AES-Schluessel (vor Rueckgabe an Aufrufer): ' + self.sAESGCMV3SchluesselBytes_LOESCHEN)
		return {'AESGCMV3Schluessel':self.sAESGCMV3SchluesselBytes_LOESCHEN, 'InitialesScryptSalt':self.sInitialesScryptSaltBytes}

	def ermittleChaCha20_V1Schluessel(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pScryptSaltBytes=None):
		"""
		DEPRECATED.
		:param pSHA256HashwertBytes:
		:param pScryptAufwandsfaktorInteger:
		:param pScryptBlockgroesseInteger:
		:param pScryptParallelisierungInteger:
		:param pScryptSaltBytes:
		:return:
		"""
		lScryptSaltBytes = pScryptSaltBytes
		if lScryptSaltBytes is None: # D.h. Verschlüsselung
			lScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
		lChaCha20V1SchluesselBytes = self._berechneScryptHashVonStringFuerChaCha20_V1(
			pSHA256HashwertBytes=pSHA256HashwertBytes,
			pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
			pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
			pScryptParallelisierungInteger=pScryptParallelisierungInteger,
			pScryptSaltBytes=pScryptSaltBytes)
		return {'ChaCha20V1Schluessel':lChaCha20V1SchluesselBytes, 'ScryptSaltFuerChaCha20V1':lScryptSaltBytes}

	def ermittleChaCha20_V2Schluessel(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pInitialesScryptSaltBytes=None, pHKDFSaltBytes=None):
		"""
		DEPRECATED.
		:param pSHA256HashwertBytes:
		:param pScryptAufwandsfaktorInteger:
		:param pScryptBlockgroesseInteger:
		:param pScryptParallelisierungInteger:
		:param pInitialesScryptSaltBytes:
		:param pHKDFSaltBytes:
		:return:
		"""
		lHKDFSaltBytes = pHKDFSaltBytes
		# Einmal Scrypt als Master für HKDF:
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None or (lHKDFSaltBytes is not None and self.sInitialesScryptSaltBytes != pInitialesScryptSaltBytes):
			if pInitialesScryptSaltBytes is None:
				self.sInitialesScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
			else:
				self.sInitialesScryptSaltBytes = pInitialesScryptSaltBytes
			self.setzeStatusleisteUndGUIZustand('Berechne Masterschlüssel (bitte warten)...', True)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
			self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN = self._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V2(
				pSHAHashwertBytes=pSHA256HashwertBytes,
				pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
				pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
				pScryptParallelisierungInteger=pScryptParallelisierungInteger,
				pScryptSaltBytes=self.sInitialesScryptSaltBytes)
		if lHKDFSaltBytes is None: # D.h. Verschlüsselung
			lHKDFSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_HKDF_SALT_FUER_CHACHA20_V2_LAENGE)
		lChaCha20V2SchluesselBytes = self._berechneHKDFWertVonScryptWertFuerChaCha20_V2(lHKDFSaltBytes)
		return {'ChaCha20V2Schluessel':lChaCha20V2SchluesselBytes, 'HKDFSaltFuerChaCha20V2':lHKDFSaltBytes, 'InitialesScryptSalt':self.sInitialesScryptSaltBytes}

	def ermittleChaCha20_V3Schluessel(self, *, pSHA512HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pInitialesScryptSaltBytes=None):
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is not None:
			if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
				LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleChaCha20_V3Schluessel: Initialer Scrypt-Wert ist Nullbytefolge!')
		# Einmal Scrypt als Master für HKDF:
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None or (pInitialesScryptSaltBytes is not None and self.sInitialesScryptSaltBytes != pInitialesScryptSaltBytes)\
				or self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger > LiSKonstanten.C_CHACHA20_MAXIMALE_DATEIANZAHL_PRO_SCHLUESSEL-1:
			if pInitialesScryptSaltBytes is None:
				self.sInitialesScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
				self.sChaCha20V3SchluesselBytes_LOESCHEN = None  # Überflüssig, aber der Sicherheit wegen
				self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger = 0
			else:
				self.sInitialesScryptSaltBytes = pInitialesScryptSaltBytes
			self.setzeStatusleisteUndGUIZustand('Berechne Masterschlüssel (bitte warten)...', True)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
			self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN = self._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3(
				pSHAHashwertBytes=pSHA512HashwertBytes,
				pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
				pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
				pScryptParallelisierungInteger=pScryptParallelisierungInteger,
				pScryptSaltBytes=self.sInitialesScryptSaltBytes)

			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sChaCha20V3SchluesselBytes_LOESCHEN)
			self.sChaCha20V3SchluesselBytes_LOESCHEN = self._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerChaCha20_V3()

			# Schlüssel für HMAC-Berechnung löschen und auf None setzen, da Neuberechnung des Krypto-Schlüssels auch Neuberechnung des HMAC-Schlüssels zur Folge hat
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN)
			self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN = None

		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleChaCha20_V3Schluessel Scrypt-Wert: ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleChaCha20_V3Schluessel ChaCha20V3-Kryptoschluessel (vor Rueckgabe an Aufrufer): ' + self.sChaCha20V3SchluesselBytes_LOESCHEN)
		return {'ChaCha20V3Schluessel':self.sChaCha20V3SchluesselBytes_LOESCHEN, 'InitialesScryptSalt':self.sInitialesScryptSaltBytes}

	# Methoden zur Ableitung eines Authentisierungsschlüssels aus einem SHA-Hashwert:

	def ermittleHMACSchluesselFuerChaCha20_V1(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger=LiSKonstanten.C_SCRYPT_AUFWANDSFAKTOR_WERT, pScryptBlockgroesseInteger=LiSKonstanten.C_SCRYPT_BLOCK_GROESSE, pScryptParallelisierungInteger=LiSKonstanten.C_SCRYPT_PARALLELISIERUNG_WERT, pScryptSaltBytes=None):
		"""
		DEPRECATED.
		:param pSHA256HashwertBytes:
		:param pScryptAufwandsfaktorInteger:
		:param pScryptBlockgroesseInteger:
		:param pScryptParallelisierungInteger:
		:param pScryptSaltBytes:
		:return:
		"""
		lScryptSaltBytes = pScryptSaltBytes
		if lScryptSaltBytes is None: # D.h. Verschlüsselung
			lScryptSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_SCRYPT_SALT_LAENGE)
		lHMACSchluesselBytes = self._berechneScryptHashVonStringFuerAESGCM_V1(pSHA256HashwertBytes=pSHA256HashwertBytes,
			pScryptAufwandsfaktorInteger=pScryptAufwandsfaktorInteger,
			pScryptBlockgroesseInteger=pScryptBlockgroesseInteger,
			pScryptParallelisierungInteger=pScryptParallelisierungInteger,
			pScryptSaltBytes=pScryptSaltBytes)
		return {'HMACSchluessel':lHMACSchluesselBytes, 'ScryptSaltFuerHMAC':lScryptSaltBytes}

	def ermittleHMACSchluesselFuerChaCha20_V2(self, *, pHKDFSaltBytes=None):
		"""
		DEPRECATED.
		:param pHKDFSaltBytes:
		:return:
		"""
		# Methode darf nie ohne erfolgte initiale Scrypt-Berechnung aufgerufen werden, da immer zweiter Schlüssel
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None or self.sInitialesScryptSaltBytes is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA256-Hash für Berechnung von HMAC-Schlüssel ist None oder Salt für HKDF ist None.')
		lHKDFSaltBytes = pHKDFSaltBytes
		if lHKDFSaltBytes is None: # D.h. Verschlüsselung
			lHKDFSaltBytes = LiSWerkzeuge.SichereZufallswerkzeuge.erzeugeZufaelligeBytefolge(LiSKonstanten.C_HKDF_SALT_FUER_HMAC_LAENGE)
		lHMACSchluesselBytes = self._berechneHKDFWertVonScryptWertFuerHMACBeiChaCha20_V1_V2(lHKDFSaltBytes)
		return {'HMACSchluessel':lHMACSchluesselBytes, 'HKDFSaltFuerHMAC':lHKDFSaltBytes}

	def ermittleHMACSchluesselFuerChaCha20_V3(self):
		"""
		DEPRECATED. Muss immer in Kombination mit und _nach_ ermittleChaCha20_V3Schluessel(...) ausgerufen werden.
		:return:
		"""
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None or self.sInitialesScryptSaltBytes is None: # Wird nie ohne erfolgte initiale Scrypt-Berechnung aufgerufen, da immer zweiter Schlüssel
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash für Berechnung von HMAC-Schlüssel existiert nicht.')
		if self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN is None: # wird von ermittleChaCha20_V3Schluessel(...) auf None gesetzt, wenn Neuberechnung des Scrypt-Wertes stattgefunden hat
			self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN = self._berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3()
		return {'HMACSchluessel':self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN}

	def ermittleHMACSchluesselFuerChaCha20_V3_1(self):
		"""
		Muss immer in Kombination mit und _nach_ ermittleChaCha20_V3Schluessel(...) ausgerufen werden.
		:return:
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V3_1: Initialer Scrypt-Wert ist Nullbytefolge!')
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None or self.sInitialesScryptSaltBytes is None: # Wird nie ohne erfolgte initiale Scrypt-Berechnung aufgerufen, da immer zweiter Schlüssel
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash für Berechnung von HMAC-Schlüssel existiert nicht.')
		if self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN is None: # wird von ermittleChaCha20_V3Schluessel(...) auf None gesetzt, wenn Neuberechnung des Scrypt-Wertes stattgefunden hat
			self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN = self._berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3_1()
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread.ermittleHMACSchluesselFuerChaCha20_V3_1 ChaCha20V3-HMAC-Schluessel (vor Rueckgabe an Aufrufer): ' + self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN)
		return {'HMACSchluessel':self.sHMACFuerChaCha20V3SchluesselBytes_LOESCHEN}

	# Methoden zur Schlüsselexpansion (key expansion) und Schlüsselableitung (key derivaton):

	def _berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V2(self, *, pSHAHashwertBytes, pScryptAufwandsfaktorInteger, pScryptBlockgroesseInteger, pScryptParallelisierungInteger, pScryptSaltBytes):
		"""
		DEPERECATED. Interne Methode. Berechnet initialen Scrypt-Wert zu einem aus Passwort oder Schlüsseldatei abgeleiteten, base91-kodierten Hashwert.
		:param pSHAHashwertBytes:
		:param pScryptAufwandsfaktorInteger:
		:param pScryptBlockgroesseInteger:
		:param pScryptParallelisierungInteger:
		:param pScryptSaltBytes:
		:return:
		"""
		lSHAHashwertString_LOESCHEN = base91.encode(pSHAHashwertBytes)
		lSHAHashwertBase91Bytes_LOESCHEN = lSHAHashwertString_LOESCHEN.encode()
		lKDFScrypt = scrypt.Scrypt(
			salt=pScryptSaltBytes,
			length=LiSKonstanten.C_SCRYPT_INITIAL_AUSGABE_LAENGE_V1_V2,
			n=pScryptAufwandsfaktorInteger,
			r=pScryptBlockgroesseInteger,
			p=pScryptParallelisierungInteger,
			backend=default_backend())
		lScryptHashwertBytes = lKDFScrypt.derive(lSHAHashwertBase91Bytes_LOESCHEN)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHAHashwertString_LOESCHEN, pStringBestaetigungBoolean=True)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHAHashwertBase91Bytes_LOESCHEN)
		return lScryptHashwertBytes

	def _berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3(self, *, pSHAHashwertBytes, pScryptAufwandsfaktorInteger, pScryptBlockgroesseInteger, pScryptParallelisierungInteger, pScryptSaltBytes):
		"""
		Interne Methode. Berechnet initialen Scrypt-Wert zu einem aus Passwort oder Schlüsseldatei abgeleiteten Hashwert.
		:param pSHAHashwertBytes:
		:param pScryptAufwandsfaktorInteger:
		:param pScryptBlockgroesseInteger:
		:param pScryptParallelisierungInteger:
		:param pScryptSaltBytes:
		:return:
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, pSHAHashwertBytes) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3: Uebergebener SHA-Hashwert ist Nullbytefolge!')
		lKDFScrypt = scrypt.Scrypt(
			salt=pScryptSaltBytes,
			length=LiSKonstanten.C_SCRYPT_INITIAL_AUSGABE_LAENGE_V3,
			n=pScryptAufwandsfaktorInteger,
			r=pScryptBlockgroesseInteger,
			p=pScryptParallelisierungInteger,
			backend=default_backend())
		lScryptHashwertBytes = lKDFScrypt.derive(pSHAHashwertBytes)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3 Scrypt-Wert (Berechnung): ' + lScryptHashwertBytes)
		return lScryptHashwertBytes

	def _berechneScryptHashVonStringFuerAESGCM_V1(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger, pScryptBlockgroesseInteger, pScryptParallelisierungInteger, pScryptSaltBytes):
		"""
		DEPRECATED. Interne Methode. Ermittelt pLaengeInBytesInteger Bytes des Scrypt-Werts entsprechend der Parameter und returniert diesen.
		"""
		lSHA256HashwertString_LOESCHEN = base91.encode(pSHA256HashwertBytes)
		lSHA256HashwertBase91Bytes_LOESCHEN = lSHA256HashwertString_LOESCHEN.encode()
		lKDFScrypt = scrypt.Scrypt(
			salt=pScryptSaltBytes,
			length=LiSKonstanten.C_AES_GCM_SCHLUESSEL_LAENGE,
			n=pScryptAufwandsfaktorInteger,
			r=pScryptBlockgroesseInteger,
			p=pScryptParallelisierungInteger,
			backend=default_backend())
		lScryptHashwertBytes = lKDFScrypt.derive(lSHA256HashwertBase91Bytes_LOESCHEN)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA256HashwertString_LOESCHEN, pStringBestaetigungBoolean=True)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA256HashwertBase91Bytes_LOESCHEN)
		return lScryptHashwertBytes

	def _berechneScryptHashVonStringFuerChaCha20_V1(self, *, pSHA256HashwertBytes, pScryptAufwandsfaktorInteger, pScryptBlockgroesseInteger, pScryptParallelisierungInteger, pScryptSaltBytes):
		"""
		DEPRECATED. Interne Methode. Ermittelt pLaengeInBytesInteger Bytes des Scrypt-Werts entsprechend der Parameter und returniert diesen.
		"""
		lSHA256HashwertString_LOESCHEN = base91.encode(pSHA256HashwertBytes)
		lSHA256HashwertBase91Bytes_LOESCHEN = lSHA256HashwertString_LOESCHEN.encode()
		lKDFScrypt = scrypt.Scrypt(
			salt=pScryptSaltBytes,
			length=LiSKonstanten.C_CHACHA20_SCHLUESSEL_LAENGE,
			n=pScryptAufwandsfaktorInteger,
			r=pScryptBlockgroesseInteger,
			p=pScryptParallelisierungInteger,
			backend=default_backend())
		lScryptHashwertBytes = lKDFScrypt.derive(lSHA256HashwertBase91Bytes_LOESCHEN)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA256HashwertString_LOESCHEN, pStringBestaetigungBoolean=True)
		LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(lSHA256HashwertBase91Bytes_LOESCHEN)
		return lScryptHashwertBytes

	def _berechneHKDFWertVonScryptWertFuerAESGCM_V2(self, pSaltBytes):
		"""
		DEPRECATED. Interne Methode. Berechnet den HKDF-Wert zum initialiem Scrypt-Wert (Masterschlüssel) für AESGCM_V2

		:param pSaltBytes: Saltwert für HKDF
		:type pSaltBytes: Bytesequenz
		:return: HKDF-Wert
		:rtype: Bytesequenz
		"""
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA256-Hash darf für Berechnung von HKDF nicht None sein.')
		lKDFHKDF = hkdf.HKDF(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_AES_GCM_SCHLUESSEL_LAENGE,
			salt=pSaltBytes,
			info=None,
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDF.derive(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerAESGCM_V3(self):
		"""
		Berechnet den HKDF-Expand-Wert zum initialien Scrypt-Wert (Masterschlüssel) als Daten-Schlüssel für AESGCM_V3

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3: Initialer Scrypt-Wert ist Nullbytefolge!')

		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_AES_GCM_SCHLUESSEL_LAENGE,
			info=b'AES-GCM-V3-key',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerAESGCM_V3 Scrypt-Wert (bei AES-GCM-V3-Schluesselberechnung): ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerAESGCM_V3 AES-GCM-V3-Schluessel aus HKDF-Expand (vor Rueckgabe an Aurufer)' + lHKDFWertBytes)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertAlsNonceFuerAESGCM_V3(self):
		"""
		Berechnet den HKDF-Expand-Wert zum initialien Scrypt-Wert (Masterschlüssel) als Nonce für AESGCM_V3

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneInitialenScryptHashFuerHKDFBeiAESGCMUndChaCha20_V3: Initialer Scrypt-Wert ist Nullbytefolge!')
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_AES_GCM_NONCE_LAENGE,
			info=b'AES-GCM-V3-nonce-' + str(self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger).encode(),
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsNonceFuerAESGCM_V3 Scrypt-Wert (bei AES-GCM-V3-Nonce-Berechnung): ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsNonceFuerAESGCM_V3 AES-GCM-V3-Nonce aus HKDF-Expand: ' + lHKDFWertBytes)
		return lHKDFWertBytes

	def _berechneHKDFWertVonScryptWertFuerChaCha20_V2(self, pSaltBytes):
		"""
		DEPRECATED. Interne Methode. Berechnet den HKDF-Wert zum initialien Scrypt-Wert (Masterschlüssel) für CHACHA20_V2

		:param pSaltBytes: Saltwert für HKDF
		:type pSaltBytes: Bytesequenz
		:return: HKDF-Wert
		:rtype: Bytesequenz
		"""
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA256-Hash darf für Berechnung von HKDF nicht None sein.')
		lKDFHKDF = hkdf.HKDF(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_CHACHA20_SCHLUESSEL_LAENGE,
			salt=pSaltBytes,
			info=b'ChaCha20V2',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDF.derive(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerChaCha20_V3(self):
		"""
		Berechnet den HKDF-Expand-Wert zum initialien Scrypt-Wert (Masterschlüssel) als Daten-Schlüssel für CHACHA20_V3

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerChaCha20_V3: Initialer Scrypt-Wert ist Nullbytefolge!')
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_CHACHA20_SCHLUESSEL_LAENGE,
			info=b'ChaCha20-V3-key',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerChaCha20_V3 Scrypt-Wert (bei ChaCha20-V3-Krypto-Schluesselberechnung): ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsSchluesselFuerChaCha20_V3 ChaCha20-V3-Krypto-Schluessel aus HKDF-Expand: ' + lHKDFWertBytes)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertAlsNonceFuerChaCha20_V3(self):
		"""
		Berechnet den HKDF-Expand-Wert zum initialiem Scrypt-Wert (Masterschlüssel) als Nonce für CHACHA20_V3

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsNonceFuerChaCha20_V3: Initialer Scrypt-Wert ist Nullbytefolge!')
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_CHACHA20_NONCE_LAENGE,
			info=b'ChaCha20-V3-nonce-' + str(self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger).encode(),
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsNonceFuerChaCha20_V3 Scrypt-Wert (bei ChaCha20-V3-Nonceberechnung): ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertAlsNonceFuerChaCha20_V3 ChaCha20-V3-Nonce aus HKDF-Expand: ' + lHKDFWertBytes)
		return lHKDFWertBytes

	def _berechneHKDFWertVonScryptWertFuerHMACBeiChaCha20_V1_V2(self, pSaltBytes):
		"""
		DEPRECATED. Interne Methode. Berechnet den HKDF-Wert zum (bei ..._V2: initialen) Scrypt-Wert (Masterschlüssel) für HMAC bei CHACHA20_V1 oder ..._V2

		:param pSaltBytes: Saltwert für HKDF
		:type pSaltBytes: Bytesequenz
		:return: HKDF-Wert
		:rtype: Bytesequenz
		"""
		if self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA256-Hash darf für Berechnung von HKDF nicht None sein.')
		lKDFHKDF = hkdf.HKDF(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_CHACHA20_SCHLUESSEL_LAENGE,
			salt=pSaltBytes,
			info=b'HMAC',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDF.derive(self.sInitialerScryptWertVonSHA256HashBytes_LOESCHEN)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3(self):
		"""
		DEPRECATED. Interne Methode. Berechnet den HKDF-Expand-Wert zum initialien Scrypt-Wert (Masterschlüssel) für HMAC bei CHACHA20_V3

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_HMAC_SCHLUESSEL_LAENGE,
			info=b'HMAC-ChaCha20-V3-key',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		return lHKDFWertBytes

	def _berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3_1(self):
		"""
		Berechnet den HKDF-Expand-Wert zum initialien Scrypt-Wert (Masterschlüssel) für HMAC bei CHACHA20_V3_1

		:return: HKDF-Expand-Wert
		:rtype: Bytesequenz
		"""
		# Test auf 0-Byte-Folge mit Ausgabe im Log-Level Debug (Wert kann real 0-Byte-Folge sein!):
		if re.match(LiSKonstanten.C_REGEX_NULLBYTES, self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN) is not None:
			LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3_1: Initialer Scrypt-Wert ist Nullbytefolge!')
		if self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN is None:
			raise AssertionError('Initialer Scrypt-Wert von SHA512-Hash darf für Berechnung von HKDF-Expand nicht None sein.')
		lKDFHKDFExpand = hkdf.HKDFExpand(
			algorithm=hashes.SHA512(),
			length=LiSKonstanten.C_HMAC_SHA512_SCHLUESSEL_LAENGE,
			info=b'HMAC-ChaCha20-V3-key',
			backend=default_backend())
		lHKDFWertBytes = lKDFHKDFExpand.derive(self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		# Testausgabe zur Funktionsüberprüfung
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3_1 Scrypt-Wert (bei ChaCha20-V3_1-HMAC-Schluesselberechnung): ' + self.sInitialerScryptWertVonSHA512HashBytes_LOESCHEN)
		LiSWerkzeuge.Loggingwerkzeuge.loggeMitLoglevelDebugWennNichtPaketiert(b'LiSCrypt.QControllerWorkerThread._berechneHKDFExpandWertVonScryptWertFuerHMACBeiChaCha20_V3_1 ChaCha20-V3_1-HMAC-Schluessel aus HKDF-Expand: ' + lHKDFWertBytes)
		return lHKDFWertBytes


	# Signal-emmittierende Methoden zur Kommunikation mit der GUI:
	def setzeStatusleisteUndGUIZustand(self, pTextString=None, pAbbrechenButtonAktivBoolean=False):
		"""
		Emittiert das Signal C_STATUSAENDERUNG_SIGNAL. Wird intern und auch von LiSKrypto.Datei()-Instanzen aufgerufen

		:param pTextString: Text für Statusleiste
		:type pTextString: String
		:param pAbbrechenButtonAktivBoolean: Angabe, ob Abbrechen-Button in der Statusleiste auf aktiv gesetzt werden soll (true: ja, false: nein)
		:type pAbbrechenButtonAktivBoolean: Boolean
		"""
		self.C_STATUSAENDERUNG_SIGNAL.emit(pTextString, pAbbrechenButtonAktivBoolean)

	def ergaenzeBerichtAusgabe(self, pZeileString, pToolTipString=None):
		"""
		Emittiert das Signal C_BERICHTERGAENZUNG_SIGNAL mit Übergabe der neuen Zeile. Wird intern und auch von LiSKrypto()-Instanzen aufgerufen

		:param pZeileString: Text für neue Zeile im Berichtsbereich
		:type pZeileString: String
		:param pToolTipString: Text für Tooltip der neuen Zeile im Berichtsbereich
		:type pToolTipString: String
		"""
		self.C_BERICHTERGAENZUNG_SIGNAL.emit(pZeileString, pToolTipString)

	def _gibStartzeitpunktAus(self):
		"""
		Interne Methode. Emittiert das Signal C_BERICHTERGAENZUNG_SIGNAL mit Übergabe des Startzeitpunkts.
		"""
		self.C_BERICHTERGAENZUNG_SIGNAL.emit('Start: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None)
		self.C_BERICHTERGAENZUNG_SIGNAL.emit('---', None)
		self.sStartZeitpunktAusgegebenBoolean = True

	def _gibEndzeitpunktAusFallsErforderlich(self):
		"""
		Interne Methode. Emittiert das Signal C_BERICHTERGAENZUNG_SIGNAL mit Übergabe des Endzeitpunkts, falls
		zuvor programmatisch ein Startzeitpunkt ausgegeben wurde.
		"""
		if self.sStartZeitpunktAusgegebenBoolean is True:
			self.C_BERICHTERGAENZUNG_SIGNAL.emit('---', None)
			self.C_BERICHTERGAENZUNG_SIGNAL.emit('Ende: ' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None)

	def	_zeigeProbleminfoFallsErforderlich(self):
		"""
		Interne Methode. Zeigt im Bedarfsfall einen Informationsdialog zu aufgetretenen Problemen bei Ausführung der
		Programmfunktion an.
		"""
		if self.sDateilistenAnzeigeFehlerImProzessBoolean is True:
			self._zeigeInfoDialogModal('Es sind Probleme aufgetreten. Bitte beachten Sie die Fehlermeldungen.')

	def _leereZwischenablage(self):
		"""
		Interne Methode. Emittiert das Signal C_LEEREZWISCHENABLAGE_SIGNAL
		"""
		self.C_LEEREZWISCHENABLAGE_SIGNAL.emit()

	def _zeigeInfoDialogModal(self, pInformationString):
		"""
		Interne Methode. Emittiert das Signal C_INFODIALOG_SIGNAL mit Übergabe einer Warnung.

		:param pInformationString: Warnung
		:type pInformationString: String
		"""
		self._sInformationBestaetigtBoolean = False
		self.C_INFODIALOG_SIGNAL.emit(pInformationString)
		while self._sInformationBestaetigtBoolean is False:
			pass
		self.C_FUNKTION_WIEDERHOLEN_BUTTON_SICHTBAR_SIGNAL.emit(self.sDateilistenAnzeigeFehlerImProzessBoolean)

	def _zeigeWarnDialogModal(self, pWarnungString):
		"""
		Interne Methode. Emittiert das Signal C_WARNDIALOG_SIGNAL mit Übergabe einer Warnung.

		:param pWarnungString: Warnung
		:type pWarnungString: String
		"""
		self._sWarnungBestaetigtBoolean = False
		self.C_WARNDIALOG_SIGNAL.emit(pWarnungString)
		while self._sWarnungBestaetigtBoolean is False:
			pass

	def _zeigeFehlerDialogModal(self, pFehlermeldungString):
		"""
		Interne Methode. Emittiert das Signal C_FEHLERDIALOG_SIGNAL mit Übergabe einer Fehlermeldung.

		:param pFehlermeldungString: Fehlermeldung
		:type pFehlermeldungString: String
		"""
		self._sFehlerBestaetigtBoolean = False
		self.C_FEHLERDIALOG_SIGNAL.emit(pFehlermeldungString)
		while self._sFehlerBestaetigtBoolean is False:
			pass

	def _zeigePasswortDialog(self, pMitBestaetigungBoolean=True):
		"""
		Interne Methode. Emittiert das Signal C_PASSWORTDIALOG_SIGNAL mit Übergabe, ob ein Bestätigungsfeld angezeigt
		werden soll. Veranlasst dadurch das Öffnen eines Passwortsdialogs. Ist das in diesem Dialog eingegebene
		Passwort None, ein Leerstring oder beginnt es mit einem 0-Byte, wird eine QNoPasswortd-Exception geworfen.
		Anderenfalls wird dass Passwort returniert.

		:param pMitBestaetigungBoolean: Angabe, ob ein Bestätigungsfeld angezeigt werden soll
		:type pMitBestaetigungBoolean: Boolean
		"""
		self._sPasswortString = None
		self.C_PASSWORTDIALOG_SIGNAL.emit(pMitBestaetigungBoolean)
		while self._sPasswortString is None:
			pass
		if self._sPasswortString is None or self._sPasswortString == '' or self._sPasswortString[0] == '\x00':
			raise LiSAusnahmen.QNoPasswordError('Passwortdialog lieferte leeren String.')
		lPasswortString = self._sPasswortString
		del self._sPasswortString # Löschen der globalen Referenz
		return lPasswortString

	def _zeigeUeberschreibenDialog(self, pDateinameErweitertString):
		"""
		Interne Methode. Emittiert das Signal C_UEBERSCHREIBENDIALOG_SIGNAL mit Übergabe des erweiterten Pfads zu einer Datei

		:param pDateinameErweitertString: Erweiterter Pfad zu einer Datei
		:type pDateinameErweitertString: String
		"""
		self._sUeberschreibenInteger = -1
		self.C_UEBERSCHREIBENDIALOG_SIGNAL.emit(pDateinameErweitertString)
		while self._sUeberschreibenInteger == -1:
			pass
		return self._sUeberschreibenInteger


	# Weitere Hilfsmethoden

	def istFunktionsprozessAktiv(self):
		"""
		Returniert, ob aktuell eine Programmfunktion ausgeführt wird (Verschlüsseln, Entschlüsseln, Vernichten)

		:return: Status der Ausführung einer Programmfunktion (true: aktiv, false: nicht aktiv)
		:rtype: Boolean
		"""
		return self.sFunktionsprozessAktivBoolean

	def stoppeFunktionsprozess(self):
		"""
		Stoppt die aktuell ausgeführte Programmfunktion (Verschlüsseln, Entschlüsseln, Vernichten) und setzt den
		Inhalt der Statusleiste auf 'Abbruch durch Nutzer (bitte warten).'
		"""
		self.setzeStatusleisteUndGUIZustand('Abbruch durch Nutzer (bitte warten).')
		self.sFunktionsprozessAktivBoolean = False

	def gibNeueAESGCMNoncePerHKDF(self):
		"""
		Interne Methode. Veranlasst die Berechnung mittels HKDF des nächsten Nonce-Werts für die Verschlüsselung per AES-GCM.

		:return: Nonce für AESGCM
		:rtype: Bytesequenz
		"""
		if not self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger < LiSKonstanten.C_AES_GCM_MAXIMALE_DATEIANZAHL_PRO_SCHLUESSEL:
			raise AssertionError('Maximal zulässige Aufrufe der AESGCM-Verschlüsselungsfunktion mit identischem Schlüssel überschritten.')
		lNeueAESNonceBytes = self._berechneHKDFExpandWertVonScryptWertAlsNonceFuerAESGCM_V3()
		self.sAESGCMVerschluesselungenMitAktuellemSchluesselInteger+=1
		return lNeueAESNonceBytes

	def gibNeueChaCha20NoncePerHKDF(self):
		"""
		Interne Methode. Veranlasst die Berechnung mittels HKDF des nächsten Nonce-Werts für die Verschlüsselung per ChaCha-20

		:return: Nonce für ChaCha-20
		:rtype: Bytesequenz
		"""
		if not self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger < LiSKonstanten.C_CHACHA20_MAXIMALE_DATEIANZAHL_PRO_SCHLUESSEL:
			raise AssertionError('Maximal zulässige Aufrufe der ChaCha20-Verschlüsselungsfunktion mit identischem Schlüssel überschritten.')
		lNeueChacha20NonceBytes = self._berechneHKDFExpandWertVonScryptWertAlsNonceFuerChaCha20_V3()
		self.sChaCha20VerschluesselungenMitAktuellemSchluesselInteger+=1
		return lNeueChacha20NonceBytes

	def setzeInformationBestaetigt(self, pInformationBestaetigtBoolean):
		"""
		Setzt das den Wert Attributs _sInformationBestaetigtBoolean auf den Wert pInformationBestaetigtBoolean

		:param pInformationBestaetigtBoolean:
		:type pInformationBestaetigtBoolean: Boolean
		"""
		self._sInformationBestaetigtBoolean = pInformationBestaetigtBoolean

	def setzeWarnungBestaetigt(self, pWarnungBestaetigtBoolean):
		"""
		Setzt das den Wert Attributs _sWarnungBestaetigtBoolean auf den Wert pWarnungBestaetigtBoolean

		:param pWarnungBestaetigtBoolean:
		:type pWarnungBestaetigtBoolean: Boolean
		"""
		self._sWarnungBestaetigtBoolean = pWarnungBestaetigtBoolean

	def setzeFehlerBestaetigt(self, pFehlerBestaetigtBoolean):
		"""
		Setzt das den Wert Attributs _sFehlerBestaetigtBoolean auf den Wert pFehlerBestaetigtBoolean

		:param pFehlerBestaetigtBoolean:
		:type pFehlerBestaetigtBoolean: Boolean
		"""
		self._sFehlerBestaetigtBoolean = pFehlerBestaetigtBoolean

	def setzePasswort(self, pPasswortString):
		"""
		Setzt das den Wert Attributs _sPasswortString auf den Wert pPasswortString (entspricht dem vom Nutzer für die Ausführung
		der Programmfunktion eingegebene Passwort).

		:param pPasswortString: Passwort für Programmfunktion
		:type pPasswortString: String
		"""
		self._sPasswortString = pPasswortString

	def setzeUeberschreiben(self, pUeberschreibenInteger):
		"""
		Setzt den Wert des Attributs _sUeberschreibenInteger auf den Wert pUeberschreibenInteger (entspricht der Nutzerauswahl,
		ob eine bereit bestehende Datei überschrieben werden soll.

		:param pUeberschreibenInteger: Nutzerauswahl zur Abfrage, ob bestehende Datei überschrieben werden soll
		:type pUeberschreibenInteger: Integer
		"""
		self._sUeberschreibenInteger = pUeberschreibenInteger
