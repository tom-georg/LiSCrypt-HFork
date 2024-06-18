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
Dieses Modul enthält Klasse zur Modellierung der zentralen View-Komponente.
"""

from Darstellung.GUIKomponenten import Ui_CombinedDialog, Ui_KeyTypeDialog, Ui_ListDialog, Ui_MainWindow, Ui_KeyFileDialog, Ui_PasswordDialog, Ui_SystemTrayIcon
from Modell import LiSApplication, LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtGui, QtWidgets

import os
import subprocess
import sys
import webbrowser

class QView:
	"""
	Modelliert die zentrale View-Komponente von LiSCrypt (Schnittstelle zwischen Controller und UI-Objekten)
	"""
	def __init__(self, pControllerQController):
		"""
		Initialisiert ein Objekt der Klasse QView (zentrale View-Komponente).

		:param pControllerQController: Zentrale Controller-Komponente
		:type pControllerQController: QController
		"""
		self.sControllerQController = pControllerQController
		self.sApp = LiSApplication.QFileOpenEventApplication(self.sControllerQController, sys.argv)
		self.sTranslator = QtCore.QTranslator()
		self.sTranslator.loadFromData(LiSKonstanten.C_LISCRYPT_DEQMDATEI)
		self.sApp.installTranslator(self.sTranslator)
		self.sMainWindow = Ui_MainWindow.Ui_MainWindow(self)

		# Vorgemerkt für zukünftige Versionen
		# self.sSystemTrayIcon = Ui_SystemTrayIcon.Ui_SystemTrayIcon(self.sMainWindow)

	## --- Aufträge/Anfragen Von: Controller, An: View -----------------------------------------------------------------

	def warteAufEreignisse(self):
		"""
		Startet die Haupt-Ereignisschleife in der GUI-Version des Programms (main event loop). Diese wird nicht
		verlassen, bis das Programm beendet wird. Wird vom Controller aufgerufen.
		"""
		self.sApp.exec_()

	def zeigeHauptfensterInNormalgroesseFallsMinimiert(self):
		"""
		Veranlasst das Hauptfenster, sich in Normalgröße zu zeigen, falls es minimiert war.
		"""
		self.sMainWindow.zeigeInNormalgroesseFallsMinimiert()

	def aktiviereVerschluesseln(self):
		"""
		Veranlasst das Hauptfenster, die Programmfunktion "Verschlüsseln" zu aktivieren.
		"""
		self.sMainWindow.aktiviereVerschluesseln(pDurchKlickAufRadiobuttonBoolean=False)

	def aktiviereEntschluesseln(self):
		"""
		Veranlasst das Haupfenster, die Programmfunktion "Entschlüsseln" zu aktivieren.
		"""
		self.sMainWindow.aktiviereEntschluesseln(pDurchKlickAufRadiobuttonBoolean=False)

	def aktiviereVernichten(self):
		"""
		Veranlasst das Hauptfenster, die Programmfunktion "Vernichten" zu aktivieren.
		"""
		self.sMainWindow.aktiviereVernichten(pDurchKlickAufRadiobuttonBoolean=False)

	def setzeOriginaleVernichten(self, pOriginaleVernichtenBoolean):
		"""
		Veranlasst das Hauptfenster, die Option "Originale vernichten" an- oder abzuwählen.

		:param pOriginaleVernichtenBoolean: Option (de)aktivieren (True: aktivieren, False: deaktivieren)
		:type pOriginaleVernichtenBoolean: Boolean
		"""
		self.sMainWindow.setzeOriginaleVernichten(pOriginaleVernichtenBoolean)

	def waehleVerschluesselungMitPasswort_Kommandozeile(self):
		"""
		Veranlasst das Hauptfesnter, die Schlüsselart "Passwort " zu aktivieren.
		"""
		self.sMainWindow.waehleSchluesselartPasswort()

	def waehleVerschluesselungMitSchluesseldatei_Kommandozeile(self):
		"""
		Veranlasst das Hauptfesnter, die Schlüsselart "Schlüsseldatei" zu aktivieren. Es wird in jedem
		Fall ein Dateiauswahldialog geöffnet. Returniert True, wenn tatsächlich eine Schlüsseldatei
		ausgewählt wurde, sonst (= Abbrechen-Button gedrück) False

		:return: Angabe, ob tatsächlich eine Schlüsseldatei ausgewählt wurde (True: ja, False: nein)
		:rtype: Boolean
		"""
		return self.sMainWindow.waehleSchluesselartSchluesseldatei_Kommandozeile()

	def macheFunktionUmkehrenButtonSichtbar(self, pSichtbarBoolean):
		"""
		Veranlasst das Hauptfenster, den Button zur Funktionsumkehrung sichtbar/nicht sichbar zu machen.

		:param pSichtbarBoolean: Gibt an, ob der Button zur Funktionsumkehr sichtbar werden soll (True=ja, False=nein)
		:type pSichtbarBoolean: Boolean
		"""
		self.sMainWindow.macheFunktionUmkehrenButtonSichtbar(pSichtbarBoolean)

	def macheFunktionWiederholenButtonSichtbar(self, pSichtbarBoolean):
		"""
		Veranlasst das Hauptfenster, den Button zur Funktionswiederholung sichtbar/nicht sichbar zu machen.

		:param pSichtbarBoolean: Gibt an, ob der Button zur Funktionswiederholung sichtbar werden soll (True=ja, False=nein)
		:type pSichtbarBoolean: Boolean
		"""
		self.sMainWindow.macheFunktionWiederholenButtonSichtbar(pSichtbarBoolean)

	def erbitteFunktionsbestaetigung(self, pFunktionString, pMoeglicheDateienUndVerzeichnisseList,
									 pOriginaleVernichtenBoolean):
		"""
		Öffnet einen Bestätigungsdialog zur Sicherheitsabfrage zur avisierten Aktion. Die ausgewählten Dateien und Verzeichnisse werden aufgelistet. Wird vom Controller aufgerufen.

		:param pFunktionString: Avisierte Aktion ("Verschlüsseln", "Entschlüsseln", "Vernichten")
		:type pFunktionString: String
		:param pMoeglicheDateienUndVerzeichnisseList: Ausgewählten Dateien und Verzeichnisse als erweiterte Pfade
		:type pMoeglicheDateienUndVerzeichnisseList: Liste von Strings
		:param pOriginaleVernichtenBoolean: Nutzerauswahl der Option "Originale vernichten" (True: ja, False: nein)
		:type pOriginaleVernichtenBoolean: Boolean

		:return: Nutzerauswahl (QtWidgets.QDialogButtonBox.Cancel oder QtWidgets.QDialogButtonBox.Ok)
		:rtype: int
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		if LiSKonstanten.C_IQB_VERSION is False or pFunktionString==LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
			lBestaetigungBoolean = Ui_ListDialog.Ui_ListDialog(self.sMainWindow, pFunktionString, pMoeglicheDateienUndVerzeichnisseList,
															   pOriginaleVernichtenBoolean).erbitteBestaetigung()
		else:
			lBestaetigungBoolean = True
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return lBestaetigungBoolean

	def setzeStatusleisteUndGUIZustand(self, pTextString, pButtonAktivBoolean):
		"""
		Vernlasst das Hauptfenster, den Inhalt der Statusleiste zu ändern, Elemente der GUI entsprechend zu (de-)aktivieren
		und insbesondere den Abbrechen-Button zu (de-)aktivieren

		:param pTextString: Neuer Inhalt der Statusleiste
		:type pTextString: String
		:param pButtonAktivBoolean: Neuer Zustand des Abbrechen-Buttons (True: aktiviert, False: deaktiviert)
		:type pButtonAktivBoolean: Boolean
		"""
		self.sMainWindow.setzeStatusleisteUndGUIZustand(pTextString, pButtonAktivBoolean)
		self._verarbeiteEreignisse()

	def ergaenzeBericht(self, pZeileString, pToolTipString=None):
		"""
		Veranlasst das Hauptfenster, den Bereichtsbereich um eine Zeile zu ergänzen und diese ggf. mit einem Tooltip zu versehen. Sofern
		die neue Zeile mit der Kennung "Start: " beginnt, leert das Hauptfenster zunächst den Berichtsbereich. Wird
		durch den Controller aufgerufen.

		:param pZeileString: Inhalt der neuen Zeile
		:type pZeileString: String
		:param pToolTipString: Inhalt des Tooltips als String (optional)
		:type pToolTipString: String
		"""
		if(pZeileString.startswith('Start: ')):
			self.sMainWindow.loescheBericht()
		self.sMainWindow.ergaenzeBericht(pZeileString, pToolTipString)
		self._verarbeiteEreignisse()

	def zeigeInfoDialog(self, pInformationString):
		"""
		Öffnet einen Nachrichtendialog mit einer Information. Wird durch den Controller aufgerufen.

		:param pInformationString: Information
		:type pInformationString: String
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lQMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lQMessageBox.setIcon(QtWidgets.QMessageBox.Information)
		lQMessageBox.setWindowTitle('Information')
		lQMessageBox.setText(pInformationString)
		lQMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)

	def zeigeWarnDialog(self, pWarnungString):
		"""
		Öffnet einen Nachrichtendialog mit einer Warnung. Wird durch den Controller aufgerufen.

		:param pWarnungString: Warnung
		:type pWarnungString: String
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lQMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lQMessageBox.setIcon(QtWidgets.QMessageBox.Warning)
		lQMessageBox.setWindowTitle('Warnung')
		lQMessageBox.setText(pWarnungString)
		lQMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)

	def zeigeFehlerDialog(self, pFehlermeldungString):
		"""
		Öffnet einen Nachrichtendialog mit einer Fehlermeldung. Wird durch den Controller aufgerufen.

		:param pFehlermeldungString: Fehlermeldung
		:type pFehlermeldungString: String
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lQMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lQMessageBox.setIcon(QtWidgets.QMessageBox.Critical)
		lQMessageBox.setWindowTitle('Fehler')
		lQMessageBox.setText(pFehlermeldungString)
		lQMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)

	def zeigeErzeugeSchluesseldateiDialog(self):
		"""
		Öffnet einen Dialog zur Erzeugung einer neuen Schlüsseldatei und liefert den erweiterten Pfad zum gewählten
		Dateinamen zurück. Wird durch den Controller aufgerufen.
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lErzeugeSchluesseldateiDialog = Ui_KeyFileDialog.SchluesseldateiFileDialog(pParent=self.sMainWindow, pViewQView=self, pFunktionString='Erzeugen')
		lSchluesseldateinameErweitertString = lErzeugeSchluesseldateiDialog.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return(lSchluesseldateinameErweitertString)

	def zeigeUeberschreibenDialog(self, pPfadZuEintragReduziertString, pButtons=QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.Cancel):
		"""
		Öffnet einen Dialog mit einer Sicherheitsabfrage, ob eine bereits bestehende Datei überschrieben werden soll.
		Wird vom Controller aufgerufen.

		:param pPfadZuEintragReduziertString: Reduzierter Pfad zur Datei
		:type pPfadZuEintragReduziertString: String
		:param pButtons: Wert für QMessageBux-Standardbuttons, die im Dialogeingeblendet werden sollen (Default: QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.Cancel)
		:type pButtons: int
		:return: Nutzerauswahl (einer der Buttonwerte)
		:rtype: int
		"""

		lPfadZuEintragErweitert = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(pPfadZuEintragReduziertString)
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lUeberschreibenMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lUeberschreibenMessageBox.setIcon(QtWidgets.QMessageBox.Question)

		lTextZuEintragString = 'eine Verknüpfung' if os.path.islink(lPfadZuEintragErweitert) \
			else 'eine benannte Pipe (FIFO)' if LiSWerkzeuge.Dateiwerkzeuge.istFIFO(lPfadZuEintragErweitert) \
			else 'ein Ordner' if os.path.isdir(lPfadZuEintragErweitert) \
			else 'eine Datei' if os.path.isfile(lPfadZuEintragErweitert) \
			else 'ein Verzeichniseintrag'
		lPronomenZuEintragString = 'diese' if os.path.islink(lPfadZuEintragErweitert) \
			else 'diese' if LiSWerkzeuge.Dateiwerkzeuge.istFIFO(lPfadZuEintragErweitert) \
			else 'dieser' if os.path.isdir(lPfadZuEintragErweitert) \
			else 'diese' if os.path.isfile(lPfadZuEintragErweitert) \
			else 'dieser'
		lAnzeigetextString = 'Es existiert bereits ' + lTextZuEintragString + ' mit dem Namen\n' + \
							 pPfadZuEintragReduziertString + '.' + \
							 '\n\nSoll ' + lPronomenZuEintragString + ' überschrieben werden?'

		lUeberschreibenMessageBox.setText(lAnzeigetextString)
		lUeberschreibenMessageBox.setWindowTitle('Achtung!')
		lUeberschreibenMessageBox.setStandardButtons(pButtons)
		lUeberschreibenInteger = lUeberschreibenMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return lUeberschreibenInteger

	def zeigeSchluesselartwahlDialog(self):
		"""
		Öffnet einen Dialog zur Auswahl einer Schlüsselart (mit Abbruchmöglichkeit).
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lSchluesselartMessageBox = Ui_KeyTypeDialog.SchluesselartMessageBox(pParent=self.sMainWindow)
		lSchluesselartMessageBox.exec_()
		lSchluesselartMessageBoxString = lSchluesselartMessageBox.clickedButton().text()
		lRueckgabeString = LiSKonstanten.C_SCHLUESSELARTKOMMANDOZEILE_SCHLUESSELARTEN[lSchluesselartMessageBoxString]
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return lRueckgabeString

	def zeigePasswortDialog(self, pMitBestaetigungBoolean):
		"""
		Öffnet einen Dialog zur Passworteingabe, optional mit Bestätigungsfeld.

		:param pMitBestaetigungBoolean: Legt fest, ob der Dialog ein Bestätigungsfeld enthalten soll (True: ja, False: nein)
		:type pMitBestaetigungBoolean: Boolean
		:return: Eingegebenes Passwort
		:rtype: String
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lPasswortString = Ui_PasswordDialog.Ui_PasswordDialog(pParent=self.sMainWindow, pMitBestaetigungsfeldBoolean=pMitBestaetigungBoolean).holePasswort()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return (lPasswortString)

	def _zeigeDateiauswahlDialog(self, pFunktionString, pOriginaleVernichtenBoolean):
		"""
		Interne Methode. Zeigt einen Dialog zur Auswahl von Dateien und/oder Ordnern für die Ausführung einer Programmfunktion.

		:param pFunktionString: Avisierte Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL/LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL/LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
		:type pFunktionString: String
		:param pOriginaleVernichtenBoolean: Nutzerauswahl der Option "Originale vernichten" im Hauptfenster (True: ja, False: nein)
		:type pOriginaleVernichtenBoolean: Boolean
		:return: Ausgewählten Dateien/Verzeichnsise. An Index 0 befindet sich die Nutzerauswahl der Option "Originale vernichten" (True/False) im Dateiauswahldialog
		:rtype: Liste von einem Boolean-Wert und Strings
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lDateiauswahlDialog = Ui_CombinedDialog.KombinierterFileDialog(pParent=self.sMainWindow, pFunktionString=pFunktionString, pOriginaleVernichtenBoolean=pOriginaleVernichtenBoolean)
		lErgebnisList = lDateiauswahlDialog.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return lErgebnisList

	def zeigeSchluesseldateiauswahlDialog(self):
		"""
		Öffnet einen Dialog zur Auswahl einer Schlüsseldatei.

		:return: Erweiterter Pfad zur Schlüsseldatei oder None, falls keine Schlüsseldatei ausgewählt wurde
		:rtype: String
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lDateiauswahlDialog = Ui_KeyFileDialog.SchluesseldateiFileDialog(pParent=self.sMainWindow, pViewQView=self, pFunktionString='Auswählen')
		lErgebnisString = lDateiauswahlDialog.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)
		return lErgebnisString

	def entferneGemerktesPasswortAusProzessspeicherFallsEinzigeReferenz(self):
		"""
		Veranlasst die Klasse UiPasswortDialog.UiPasswortDialog, ein ggf. gemerktes Passwort zu überschreiben.
		Wird durch den Controller aufgerufen.
		"""
		Ui_PasswordDialog.Ui_PasswordDialog.entferneAlsBytesequenzGemerktesPasswort()

	# Get-Methoden:
	def gibOriginaleVernichtenStatus(self):
		"""
		Fragt das Hauptfenster nach der Nutzerauswahl für das Vernichten von Originaldateien und gibt diesen zurück.

		:return: Nutzerauswahl für das Vernichten von Originaldateien (True: ja, False: nein)
		:rtype: Boolean
		"""
		return self.sMainWindow.gibOriginaleVernichtenStatus()

	def gibFunktion(self):
		"""
		Fragt das Hauptfenster nach der ausgewählten Programmfunktion und gibt diese zurück.

		:return: Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
		:rtype: String
		"""
		return self.sMainWindow.gibAusgewaehlteFunktion()

	def gibSchluesselart(self):
		"""
		Fragt das Hauptfenster nach der ausgewählten Schlüsselart und gibt diese zurück.

		:return: Schlüsselart (C_SCHLUESSELART_PASSWORT_LITERAL, C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL)
		:rtype: String
		"""
		return self.sMainWindow.gibAusgewaehlteSchluesselart()

	def gibErweitertenPfadZuSchluesseldatei(self):
		"""
		Fragt das Hauptfenster nach dem erweiterten Pfad zur ausgewählten Schlüsseldatei und gibt diesen zurück.

		:return: Erweiterter Pfad zur ausgewählten Schlüsseldatei
		:rtype: String
		"""
		return self.sMainWindow.gibErweiternPfadZuSchluesseldatei()

	def gibVerlaufsprotokollAlsText(self):
		"""
		Fragt das Hauptfenster nach dem Inhalt des Verlaufsprotokoll und gibt diesen zurück

		:return: Inhalt des Verlaufsprotokolls
		:rtype: String
		"""
		return self.sMainWindow.gibVerlaufsprotokollAlsText()

	## --- Aufträge/Anfragen Von: View, An: Controller -----------------------------------------------------------------

	def veranlasseProtokollKopie(self):
		"""
		Veranlasst den Controller, das Verlaufsprotokoll in die Zwischenablage zu kopieren.
		"""
		self.sControllerQController.kopiereVerlaufsprotokollInZwischenablage()

	def veranlasseErzeugungVonSchluesseldatei(self):
		"""
		Veranlasst den Controller, eine Schlüsseldatei zu erzeugen. Wird durch das Hauptfenster aufgerufen (Reaktion
		auf Nutzerwahl).
		"""
		self.sControllerQController.erzeugeSchluesseldatei()

	def veranlasseControllerFunktionNachDragAndDrop(self, pDragAndDropsErweitertePfadeList):
		"""
		Veranlasst den Controller, die im Hauptfenster vom Nutzer ausgewählte Funktion auf den Dateien und Verzeichnissen auszuführen,
		die der Nutzer per Drag-and-Drop in das Ablagefeld gezogen hat. Wird vom Hauptfenster aufgerufen.

		:param pDragAndDropsErweitertePfadeList: Erweiterte Pfade zur den per Drag-and-Drop ausgewählten Dateien und Verzeichnissen
		:type pDragAndDropsErweitertePfadeList: Liste von Strings
		"""
		self.sErweitertePfadeAllerZuletztAusgewaehltenEintraegeList = pDragAndDropsErweitertePfadeList
		self.sControllerQController.fuehreFunktionAus(pErweitertePfadeZuAusgewaehltenEintraegenList=pDragAndDropsErweitertePfadeList)

	def veranlasseControllerFunktionNachHinzufuegenButton(self):
		"""
		Veranlasst die Anzeige eines Auswahldialogs für Dateien und/oder Verzeichnisse. Veranlasst dann den Controller,
		die im Hauptfenster vom Nutzer ausgewählte Funktion auf den gewählten Dateien und Verzeichnissen auszuführen.
		Wird vom Hauptfenster aufgerufen.

		:param pDragAndDropsList: Erweiterte Pfade zur den ausgewählten Dateien und Verzeichnissen
		:type pDragAndDropsList: Liste von Strings
		"""
		lFunktionString = self.sMainWindow.gibAusgewaehlteFunktion()
		lOriginaleVernichtenStatus = self.sMainWindow.gibOriginaleVernichtenStatus()
		lAuswahlList = self._zeigeDateiauswahlDialog(lFunktionString, lOriginaleVernichtenStatus)
		if len(lAuswahlList) > 1:
			self.sMainWindow.setzeFenstereinstellungenFuerFunktion(lFunktionString)
			if lFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
				self.sMainWindow.setzeOriginaleVernichten(lAuswahlList[0])
			self.veranlasseControllerFunktionNachDragAndDrop(pDragAndDropsErweitertePfadeList=lAuswahlList[1:])

	def veranlasseControllerFunktionNachFunktionUmkehrenButton(self):
		"""
		Veranlasst den Controller, die im Hauptfenster vom Nutzer ausgewählte Funktion auf denselben Dateien und
		Verzeichnissen auszuführen, die der bei der vorherigen Funktionsausführung aus gewählt hatte. Wird vom
		Hauptfenster aufgerufen.
		"""
		self.sControllerQController.fuehreFunktionAus(pErweitertePfadeZuAusgewaehltenEintraegenList=None, pSonderfunktionString='Umkehrung')

	def veranlasseControllerFunktionNachFunktionWiederholenButton(self):
		"""
		Veranlasst den Controller, die im Hauptfenster vom Nutzer ausgewählte Funktion auf denselben Dateien und
		Verzeichnissen auszuführen, die der bei der vorherigen Funktionsausführung aus gewählt hatte. Wird vom
		Hauptfenster aufgerufen.
		"""
		self.sControllerQController.fuehreFunktionAus(pErweitertePfadeZuAusgewaehltenEintraegenList=None, pSonderfunktionString='Wiederholung')

	def veranlasseStoppDesFunktionsprozesses(self):
		"""
		Veranlasst den Controller, die gerade laufende Programmfunktion/Verschnlüsselung, Entschlüsselung, Vernichtung)
		(durch Setzen eines Flags) zu unterbrechen. Wird vom Hauptfenster nach Betätigung des Abbrechen-Buttons durch
		den Nutzer aufgerufen.
		"""
		self.sControllerQController.stoppeFunktionsprozess()


	## --- Aufträge/Anfragen Von: View, An: View -----------------------------------------------------------------------

	def _verarbeiteEreignisse(self):
		"""
		Interne Methode. Veranlasst die Abarbeitung aller Ereignisse des aufrufenden Threads.
		"""
		self.sApp.processEvents()

	def zeigeKontaktDialog(self):
		"""
		Öffnet einen Nachrichtendialog mit Kontaktinformationen zu LiSCrypt. Wird durch das Hauptfenster aufgerufen
		(Reaktion auf Nutzerwahl)
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lQMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lQUALiSLogoQPixmap = QtGui.QPixmap()
		lQUALiSLogoQPixmap.loadFromData(LiSKonstanten.C_QUALIS_LOGO, 'PNG')
		lQMessageBox.setIconPixmap(lQUALiSLogoQPixmap)

		lQMessageBox.setWindowTitle('Hilfe/Kontakt')
		lQMessageBox.setText(LiSKonstanten.C_PROGRAMMNAME + ' Version ' + LiSKonstanten.__version__ + ', ' + LiSKonstanten.__year__
							 + '\n\nQUA-LiS NRW'
							 + '\nParadieser Weg 64'
							 + '\n59494 Soest'
							 + '\n\nProjektleitung:'
							 + '\nMartin Weise'
							 + '\nmartin.weise@qua-lis.nrw.de'
							 + '\noder Tel. 02921 / 683 5030'
							 + '\n\nGrafiken, Beta-Tests:'
							 + '\nDr. Albert Kapune')
		lQMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)

	def zeigeUeberDialog(self):
		"""
		Öffnet einen Nachrichtendialog mit Informationen über LiSCrypt. Wird durch das Hauptfenster aufgerufen
		(Reaktion auf Nutzerwahl)
		"""
		lVorherBlockiertBoolean = self.sControllerQController.istLiSCryptBlockiert()
		self.sControllerQController.setzeLiSCryptBlockiert(True)
		lQMessageBox = QtWidgets.QMessageBox(parent=self.sMainWindow)
		lQMessageBox.setWindowTitle('Über LiSCrypt' if LiSKonstanten.C_IQB_VERSION is False else 'Über LiSCrypt IQB')
		lLiSCryptLogoQPixmap = QtGui.QPixmap()
		lLiSCryptLogoQPixmap.loadFromData(LiSKonstanten.C_LISCRYPT_LOGO,'PNG')
		lQMessageBox.setIconPixmap(lLiSCryptLogoQPixmap)
		lQMessageBox.setText('<p><b>' + LiSKonstanten.C_PROGRAMMNAME + ' Version ' + LiSKonstanten.__version__ + ', ' + LiSKonstanten.__year__ + '</b></p>'
							 + '<p>Copyright (C) 2018-' + LiSKonstanten.__year__ + ' QUA-LiS NRW<</p>'
							 + '<p>LiSCrypt ' + ('IQB' if LiSKonstanten.C_IQB_VERSION is True else '')
							 + ' ist ein Werkzeug zur authentisierten Verschlüsselung von '
							 +  'Einzeldateien mittels AES-GCM-256 bzw. ChaCha20+HMAC.</p>'
							 + '<p>Das Werk ist lizenziert unter der GNU General Public License Version 3 (GNU GPL v3).</p>'
							 + '<p>Teile des Werks stammen aus anderen frei nutzbaren Bibliotheken '
							 + 'und unterliegen daher ggf. nicht denselben Lizenzbestimmungen. Nähere Angaben finden '
							 + 'Sie in der Dokumentation und dem korrespondierenden Quelltext des Werks, den Sie an derselben Stelle '
							 + 'erhalten sollten, an der Sie auch die Binärversion des Programms erhalten haben. Zudem wird '
							 + 'der Quelltext von LiSCrypt selbst unter https://github.com/MaWe2019/LiSCrypt_public veröffentlicht.</p>'
							 + '<p>Die Veröffentlichung dieses Werks erfolgt in der Hoffnung, dass es Ihnen von '
							 + 'Nutzen sein wird, aber OHNE IRGENDEINE GARANTIE, sogar ohne die implizite Garantie der '
							 + 'MARKTREIFE oder der VERWENDBARKEIT FÜR EINEN BESTIMMTEN ZWECK. Details finden Sie in '
							 + 'der GNU General Public License.</p>')
		lQMessageBox.exec_()
		self.sControllerQController.setzeLiSCryptBlockiert(lVorherBlockiertBoolean)

	def oeffneDateibrowserMitVerzeichnis(self, pErweiterterPfadString):
		if LiSKonstanten.C_BETRIEBSSYSTEM == 'darwin':
			subprocess.call(["open", "-R", pErweiterterPfadString])
		else:
			webbrowser.open(pErweiterterPfadString)

