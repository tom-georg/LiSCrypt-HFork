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

"""
Dieses Modul enthält die Klassen zur Realisierung eines eigenen Dialogs zur Passworteingabe.
"""

import sys

from Modell import LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtGui, QtWidgets

class CQLineEdit(QtWidgets.QLineEdit):
	"""
	Unterklasse von QLineEdit, deren Instanzen ein Sichtbarmachen des enthaltenen Passworts verhindern.
	"""
	C_CLICKED_SIGNAL = QtCore.pyqtSignal()
	C_KEYPRESSED_SIGNAL = QtCore.pyqtSignal()

	def __init__(self, parent):
		"""
		Initialisiert ein Objekt der Klasse CQLineEdit.
		"""
		super(CQLineEdit, self).__init__(parent)
		self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
		self.customContextMenuRequested.connect(self.zeigeKontextMenueOhneUndo)

	def mousePressEvent(self, pMouseEventQMouseEvent):
		"""
		Überschriebene Methode der Oberklasse. Emittiert das Signal C_CLICKED_SIGNAL.

		:param QMouseEvent: Instanz von QMouseEvent (gem. Spezifikation der Oberklasse)
		:type QMouseEvent: QMouseEvent
		"""
		self.C_CLICKED_SIGNAL.emit()

	def keyPressEvent(self, pKeyEventQKeyEvent):
		"""
		Überschriebene Methode der Oberklasse. Unterbinde die Emittierung des C_KEYPRESSED_SIGNALS, falls eine Undo-
		Tastensequenz gedrückt wurde.

		:param pKeyEventQKeyEvent: Instanz von QKeyEvent (gem. Spezifikation der Oberklasse)
		:type pKeyEventQKeyEvent: QKeyEvent
		"""
		if pKeyEventQKeyEvent.matches(QtGui.QKeySequence.Undo):
			pass
		else:
			super(CQLineEdit, self).keyPressEvent(pKeyEventQKeyEvent)
			self.C_KEYPRESSED_SIGNAL.emit()

	def zeigeKontextMenueOhneUndo(self, pPointQPoint):
		"""
		Zeigt das Kontextmenü des Eingabefeldes ohne Undo-Menüpunkt.
		:param pPointQPoint: Position des Rechtsklicks
		:type pPointQPoint: QPoint
		"""
		# Standard-Kontextmenu besorgen
		lMenuQMenu = self.createStandardContextMenu()
		# Aktion an Index 0 ('Rückgängig') deaktivieren
		lMenuActionsList = lMenuQMenu.actions()
		lMenuActionsList[0].setDisabled(True)
		# Kontexmenu an Position des Rechtsklicks (point) anzeigen
		lMenuQMenu.exec_(self.mapToGlobal(pPointQPoint))

class Ui_PasswordDialog(QtWidgets.QDialog):
	"""
	Ein eigener Dialog zur Passworteigabe.

	Die Klasse Ui_PasswordDialog modelliert einen Bestätigungsdialog für die Ausführung eines Programmfunktions inkl.
	Auflistung der betroffenen Dateien und/oder Verzeichnisse.
	"""
	kGemerktesPasswortBytes_LOESCHEN = None # Bytesequenz wichtig wg. Konflikten beim Überschreiben im Speicher bei Strings

	@classmethod
	def entferneAlsBytesequenzGemerktesPasswort(klass):
		"""
		Veranlasst das Überschreiben eines gemerkten Passworts im Arbeitsspeicher und setzt
		klass.kGemerktesPasswortBytes_LOESCHEN auf None
		"""
		if sys.getrefcount(klass.kGemerktesPasswortBytes_LOESCHEN) <= 2: # Nur überschreiben, falls einzige Referenz
			LiSWerkzeuge.Prozessspeicherwerkzeuge.ueberschreibeBytesequenzOderString(klass.kGemerktesPasswortBytes_LOESCHEN)
		klass.kGemerktesPasswortBytes_LOESCHEN = None

	def __init__(self, pParent, pMitBestaetigungsfeldBoolean):
		"""
		Initialisiert ein Objekt der Klasse Ui_PasswodDialog.
		"""
		super(Ui_PasswordDialog, self).__init__(parent=pParent)
		self.parent = pParent
		self.sMitBestaetigungsfeldBoolean = pMitBestaetigungsfeldBoolean
		self.sBestaetigungsfeldAktiviertBoolean = self.sMitBestaetigungsfeldBoolean
		self.sPasswortString = None
		self._setupUi()

	def _setupUi(self):
		"""
		Interne Methode. Initialisiert die Komponenten des Passwortdialogs (wird von Konstruktor aufgerufen).
		"""
		self.setWindowFlag(QtCore.Qt.WindowStaysOnTopHint)
		self.setWindowTitle("Passworteingabe")
		self.setWindowModality(QtCore.Qt.ApplicationModal)

		self.sLayoutPasswortDialog = QtWidgets.QVBoxLayout()
		self.setLayout(self.sLayoutPasswortDialog)

		self.sGroupBox = QtWidgets.QGroupBox('Passwort eingeben')
		self.sGroupBox.setStyleSheet("QGroupBox {\n"
									 "    border: 1px solid gray;\n"
									 "    border-radius: 2px;\n"
									 "    margin-top: 0.5em;\n"
									 "}\n"
									 "\n"
									 "QGroupBox::title {\n"
									 "    subcontrol-origin: margin;\n"
									 "    left: 3px;\n"
									 "    padding: 3 0 3 0;\n"
									 "}")
		self.sGroupBoxLayout = QtWidgets.QFormLayout()
		self.sGroupBox.setLayout(self.sGroupBoxLayout)

		self.sLayoutPasswortDialog.addWidget(self.sGroupBox)

		self.sPasswortLineEdit = CQLineEdit(self.sGroupBox)
		if LiSKonstanten.C_BETRIEBSSYSTEM.startswith('win32'):
			self.monospaceFont = QtGui.QFont('Courier')
		elif LiSKonstanten.C_BETRIEBSSYSTEM.startswith('darwin'):
			self.monospaceFont = QtGui.QFont('')
			self.monospaceFont.setStyleHint(QtGui.QFont.TypeWriter)
		else: # linux at al.
			self.monospaceFont = QtGui.QFont('monospace')

		self.sPasswortLineEdit.setFont(self.monospaceFont)
		self.sPasswortLineEdit.setEchoMode(QtWidgets.QLineEdit.Password)
		self.sGroupBoxLayout.addRow(self.sPasswortLineEdit)

		if self.sMitBestaetigungsfeldBoolean:
			self.sPasswortBestaetigungLabel = QtWidgets.QLabel('Passwort bestätigen')
			self.sGroupBoxLayout.addRow(self.sPasswortBestaetigungLabel)

			self.sPasswortBestaetigungLineEdit = CQLineEdit(self.sGroupBox)
			self.sPasswortBestaetigungLineEdit.setFont(self.monospaceFont)
			self.sPasswortBestaetigungLineEdit.setEchoMode(QtWidgets.QLineEdit.Password)
			self.sGroupBoxLayout.addRow(self.sPasswortBestaetigungLineEdit)

		self.sFehlermeldungLabel = QtWidgets.QLabel()
		self.sFehlermeldungLabel.setAlignment(QtCore.Qt.AlignCenter)
		self.sGroupBoxLayout.addRow(self.sFehlermeldungLabel)
		self.sFehlermeldungLabel.setStyleSheet("QLabel { color: red; }")
		self.sFehlermeldungLabel.hide()

		self.sPasswortSichtbarCheckBox = QtWidgets.QCheckBox('Passwort anzeigen')
		self.sPasswortSichtbarCheckBox.setChecked(False)
		self.sGroupBoxLayout.addRow(self.sPasswortSichtbarCheckBox)

		self.sPasswortMerkenRadioButton = QtWidgets.QCheckBox('Passwort merken')
		self.sPasswortMerkenRadioButton.setToolTip('Passwort vorübergehend merken.')
		if Ui_PasswordDialog.kGemerktesPasswortBytes_LOESCHEN is None:
			self.sPasswortMerkenRadioButton.setChecked(False)
			self.sGemerktesPasswortNochmalsVerwendenBoolean = False
		else:
			self.sPasswortMerkenRadioButton.setChecked(True)
			self.sPasswortLineEdit.setText('***')
			if self.sMitBestaetigungsfeldBoolean is True:
				self.sPasswortBestaetigungLineEdit.setText('***')
			self.sGemerktesPasswortNochmalsVerwendenBoolean = True
			self._connectSlotsGemerktesPasswortUndDeaktiviereWidgets()
		self.sGroupBoxLayout.addRow(self.sPasswortMerkenRadioButton)

		self.btn1 = QtWidgets.QPushButton("OK")
		self.btn1.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogOkButton))
		self.btn1.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
		self.btn1.clicked.connect(self._ueberpruefeUndReservierePasswort)

		self.btn2 = QtWidgets.QPushButton("Abbrechen")
		self.btn2.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogCancelButton))
		self.btn2.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
		self.btn2.clicked.connect(self.reject)

		self.sGroupBoxLayout.addRow(self.btn1, self.btn2)

		self.resize(self.sizeHint())
		self.setModal(True)

		self._connectSlots()

	def _connectSlots(self):
		"""
		Interne Methode. Verbindet Widget-Signale mit Slots.
		"""
		self.sPasswortSichtbarCheckBox.clicked.connect(self._setzePasswortSichtbarkeit)

	def _connectSlotsGemerktesPasswortUndDeaktiviereWidgets(self):
		"""
		Interne Methode. Verbindet Widget-Signale der Passworteingabefelder mit Slots.
		"""
		self.sPasswortLineEdit.textEdited.connect(self._disconnectSlotsGemerktesPasswortUndAktiviereWidgets)
		self.sPasswortLineEdit.C_CLICKED_SIGNAL.connect(self.sPasswortLineEdit.selectAll)
		self.sPasswortLineEdit.C_KEYPRESSED_SIGNAL.connect(self.sPasswortLineEdit.selectAll)
		self.sPasswortLineEdit.selectAll()
		if self.sMitBestaetigungsfeldBoolean is True:
			self.sPasswortBestaetigungLineEdit.setEnabled(False)
		self.sPasswortSichtbarCheckBox.setEnabled(False)

	def _disconnectSlotsGemerktesPasswortUndAktiviereWidgets(self):
		"""
		Interne Methode. Hebt die Signal-Slot-Verbindungen der Passworteingabefelder auf, leert das Passworteingabefelf,
		aktiviert die Checkbox zum Sichtbarmachen des Passworts und veranlasst das Überschreiben des gemerkten
		Passsworts im Arbeitsspeicher.
		"""
		self.sPasswortLineEdit.textEdited.disconnect(self._disconnectSlotsGemerktesPasswortUndAktiviereWidgets)
		self.sPasswortLineEdit.C_CLICKED_SIGNAL.disconnect(self.sPasswortLineEdit.selectAll)
		self.sPasswortLineEdit.C_KEYPRESSED_SIGNAL.disconnect(self.sPasswortLineEdit.selectAll)
		if self.sMitBestaetigungsfeldBoolean is True:
			self.sPasswortBestaetigungLineEdit.clear()
			self.sPasswortBestaetigungLineEdit.setEnabled(True)
		self.sPasswortSichtbarCheckBox.setEnabled(True)
		self.sGemerktesPasswortNochmalsVerwendenBoolean = False
		Ui_PasswordDialog.entferneAlsBytesequenzGemerktesPasswort()

	def _setzePasswortSichtbarkeit(self):
		"""
		Setzt die Sichtbarkeit des Passworts und die Verfügbarkeit des Passwort-Bestätigungsfelds in Abhängigkeit des
		Auswahlstatus der Checkbox zum Sichtbarmachen des Passworts.
		"""
		if self.sPasswortSichtbarCheckBox.isChecked():
			self.sPasswortLineEdit.setEchoMode(QtWidgets.QLineEdit.Normal)
			if self.sMitBestaetigungsfeldBoolean:
				self.sPasswortBestaetigungLabel.setEnabled(False)
				self.sPasswortBestaetigungLineEdit.setEnabled(False)
				self.sPasswortBestaetigungLineEdit.setEchoMode(QtWidgets.QLineEdit.NoEcho)
				self.sBestaetigungsfeldAktiviertBoolean = False
		else:
			self.sPasswortLineEdit.setEchoMode(QtWidgets.QLineEdit.Password)
			if self.sMitBestaetigungsfeldBoolean:
				self.sPasswortBestaetigungLabel.setEnabled(True)
				self.sPasswortBestaetigungLineEdit.setEnabled(True)
				self.sPasswortBestaetigungLineEdit.setEchoMode(QtWidgets.QLineEdit.Password)
				self.sBestaetigungsfeldAktiviertBoolean = True

	def holePasswort(self):
		"""
		Zeigt den Dialog modal und returniert das eingegebene Passwort. Setzt zudem im Fall einer erfolgreichen
		Passworteingabe den Zustand der Statusleiste auf 'Vorbereitung...'. Wird von der zentralen View-Komponente
		aufgerufen.

		:return: Eingebenes Passwort
		:rtype: String
		"""
		self.parent.setzeStatusleisteUndGUIZustand('Passworteingabe...')
		self.exec_() # Setzt self.sPasswortString durch Aufruf von _ueberpruefeUndReservierePasswort() auf das eingegebene oder das gemerkte Passwort
		if self.sPasswortString is not None:
			if self.sPasswortMerkenRadioButton.isChecked() is True \
					and self.kGemerktesPasswortBytes_LOESCHEN is None: # d.h. falls "Passwort merken" angewählt wurde und  aktuell kein gemerktes Passwort vorgehalten wird,
				Ui_PasswordDialog.kGemerktesPasswortBytes_LOESCHEN = self.sPasswortString.encode() # dann aktuellen Inhalt des Passworteingabefelds merken; dafür Kopie des Strings als Bytesequenz anlegen (wichtig wg. Anzahl der Referenzen -> Überschreiben im Speicher)
			elif self.sPasswortMerkenRadioButton.isChecked() is False \
					and self.kGemerktesPasswortBytes_LOESCHEN is not None:
				self.entferneAlsBytesequenzGemerktesPasswort()
			self.parent.setzeStatusleisteUndGUIZustand('Vorbereitung...')
		return self.sPasswortString if (self.sPasswortString is not None) else ''

	def _ueberpruefeUndReservierePasswort(self):
		"""
		Überprüft das im Dialog eingebebene oder das gemerkte Passwort auf Eignung, merkt das entsprechende Passwort
		für die Funktionsauführung vor und akzeptiert es. Genügt das Passwort nicht den Anforderungen, wird eine
		Fehlermeldung angezeigt.
		"""
		if Ui_PasswordDialog.kGemerktesPasswortBytes_LOESCHEN is None:
			lPasswortZurUeberpruefungString = self.sPasswortLineEdit.text()
		else:
			lPasswortZurUeberpruefungString = Ui_PasswordDialog.kGemerktesPasswortBytes_LOESCHEN.decode() # Als Bytesequenz gemerktes Passwort in String decodieren
		if len(lPasswortZurUeberpruefungString) >= LiSKonstanten.C_PASSWORT_SCHLUESSELDATEI_MINLAENGE \
				or (self.sMitBestaetigungsfeldBoolean is False and len(lPasswortZurUeberpruefungString)) > 0: # self.sMitBestaetigungsfeldBoolean=False bedeutet: Entschlüsselung
			if self.sBestaetigungsfeldAktiviertBoolean and self.sPasswortLineEdit.text() != self.sPasswortBestaetigungLineEdit.text(): # Funktioniert auch mit gemerktem Passwort (Feldinhalte dann: '***')
				self.sFehlermeldungLabel.setText('Eingaben nicht identisch.')
				if not self.sFehlermeldungLabel.isVisible():
					self.sFehlermeldungLabel.show()
					self.setFixedSize(self.sizeHint())
			else:
				self.sPasswortString = lPasswortZurUeberpruefungString
				self.accept()
		else:
			if self.sMitBestaetigungsfeldBoolean is True:
				self.sFehlermeldungLabel.setText('Passwort zu kurz (min. 8 Zeichen).')
			else:
				self.sFehlermeldungLabel.setText('Passwortfeld leer.')
			if not self.sFehlermeldungLabel.isVisible():
				self.sFehlermeldungLabel.show()
				self.setFixedSize(self.sizeHint())

