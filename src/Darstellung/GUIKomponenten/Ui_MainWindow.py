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
Dieses Modul enthält Klassen zur Modellierung des Hauptfensters.
"""

from Modell import LiSKonfiguration, LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtGui, QtWidgets

import logging
import os
import sys

class CQLineEdit(QtWidgets.QLineEdit):
	"""
	Unterklasse von QLineEdit, deren Instanzen zusätzlich Signale beim Anklicken und Drop einer Datei emittieren bzw.
	einen einzelnen	Pfad zu einer Schlüsseldatei z.B. per Drag-and-Drop entgegennehmen und verwalten. Die Klasse
	modelliert das Anzeigefeld für die ausgewählte Schlüsseldatei im Hauptfenster,
	"""
	C_CLICKED_SIGNAL = QtCore.pyqtSignal()
	C_DROPPED_SIGNAL = QtCore.pyqtSignal(str)
	def __init__(self, parent):
		"""
		Initialisiert ein Objekt der Klasse CQLineEdit..
		"""
		super(CQLineEdit, self).__init__(parent)
		self.setAcceptDrops(True)
		self.sPfadErweitertString = ''

	def mousePressEvent(self, QMouseEvent):
		"""
		Überschriebene Methode der Oberklasse. Emittiert das Signal C_CLICKED_SIGNAL.

		:param QMouseEvent: Instanz von QMouseEvent (gem. Spezifikation der Oberklasse)
		:type QMouseEvent: QMouseEvent
		"""
		self.C_CLICKED_SIGNAL.emit()

	def dragEnterEvent(self, event):
		"""
		Überschriebene Methode der Oberklasse. Prüft, ob ein in das Feld gezogenen Objekt den Kriterien für
		eine Schlüsseldatei genügt.

		:param event: Instanz von QEvent (gem. Spezifikation der Oberklasse)
		:tyoe event: QEvent
		"""
		if event.mimeData().hasUrls():
			lURLList = event.mimeData().urls()
			if len(lURLList) == 1:
				lPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(str(lURLList[0].toLocalFile()))
				if os.path.isfile(lPfadErweitertString) and not os.path.islink(lPfadErweitertString) \
						and os.path.getsize(lPfadErweitertString) > 0 \
						and (not os.name == 'nt' or not lPfadErweitertString.lower().endswith('.lnk')):
					event.setDropAction(QtCore.Qt.CopyAction)
					event.accept()
				else:
					event.ignore()
			else:
				event.ignore()
		else:
			event.ignore()

	def dropEvent(self, event):
		"""
		Überschriebene Methode der Oberklasse. Speichert den absoluten Pfad zu einer per Drag-and-Drop in das Feld
		hineingezogenen Datei in erweiterter Darstellung. Emittiert zusätzlich das SIgnar C_DROPPED_SIGNAL und
		übermittelt dabei den erweiterten Pfad zur Datei in erweiterter Darstellung.

		:param event: Instanz von QEvent (gem. Spezifikation der Oberklasse)
		:tyoe event: QEvent
		"""
		lURLList = event.mimeData().urls()
		lPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(str(lURLList[0].toLocalFile()))
		self.sPfadErweitertString = lPfadErweitertString
		LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS = os.path.dirname(lPfadErweitertString)
		event.setDropAction(QtCore.Qt.CopyAction)
		event.accept()
		self.C_DROPPED_SIGNAL.emit(self.sPfadErweitertString)

	# Getter/Setter:

	def gibErweitertenPfad(self):
		"""
		Returniert den Pfad zur Schlüesseldatei (erweiterte Darstellung des absoluten Pfads), der von der
		Instanz von CQLineEdit verwaltet wird.

		:return: Wert des Attribut sPfadErweitertString
		:rtype: String
		"""
		return self.sPfadErweitertString

	def setzeErweitertenPfad(self, pErweiterterPfadString):
		"""
		Setzt den Wert des Attributs sErweiterterPfadString (erweiterte Darstellung des abosoluten Pfads zur Schlüsseldatei,
		der von der Instanz von CQLineEdit verwaltet wird) auf den Wert pErweiterterPfadString.

		:param pErweiterterPfadString: Absoluter Pfad zu einer Schlüsseldatei in erweiterter Darstellung
		:type pErweiterterPfadString: String
		"""
		self.sPfadErweitertString = pErweiterterPfadString
		lPfadReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(pErweiterterPfadString)
		lNurEndNameString = os.path.basename(lPfadReduziertString)
		self.setText(lNurEndNameString)
		self.setToolTip(pErweiterterPfadString)

class DQListWidget(QtWidgets.QListWidget):
	"""
	Unterklasse von QListWidget, deren Instanzen zusätzlich ein Signal beim Drop von Dateisystemeinträgen emittieren
	und dabei eine Liste mit den absoluten Pfaden zu den Dateisystemeintrögen in erweiterter Darstellung übermitteln.
	Die Klasse modelliert den Bereich Dateiablage/Protokoll im Hauptfenster.
	"""
	C_DROPPED_SIGNAL = QtCore.pyqtSignal(list)

	def __init__(self, parent):
		"""
		Initialisiert ein Objekt der Klasse DQListWidget (Dateiablage/Protokoll im Hauptfenster).
		"""
		super(DQListWidget, self).__init__(parent)
		self.setAcceptDrops(True)

	def dragEnterEvent(self, event):
		"""
		Überschriebene Methode der Oberklasse. Prüft, ob es sich bei den ins Feld gezogenen und dort bewegten Objekten
		um Einträge des	Dateisystems handelt (Abprüfung des Vorhandenseins von URLs)

		:param event: Instanz von QEvent (gem. Spezifikation der Oberklasse)
		:tyoe event: QEvent
		"""
		if event.mimeData().hasUrls():
			event.setDropAction(QtCore.Qt.CopyAction)
			event.accept()
		else:
			event.ignore()

	def dragMoveEvent(self, event):
		"""
		Überschriebene Methode der Oberklasse. Prüft, ob es sich bei den in das Feld gezogenen Objekten um Einträge des
		Dateisystems handelt (Abprüfung des Vorhandenseins von URLs)

		:param event: Instanz von QEvent (gem. Spezifikation der Oberklasse)
		:tyoe event: QEvent
		"""
		if event.mimeData().hasUrls():
			event.setDropAction(QtCore.Qt.CopyAction)
			event.accept()
		else:
			event.ignore()

	def dropEvent(self, event):
		"""
		Überschriebene Methode der Oberklasse. Emittiert das Signal C_DROPPED_SIGNAL und übermittelt dabei eine Liste
		der absoluten Pfade zu den Einträgen des Dateisstems in erweiterter Darstellung, die per Drag-and-Drop in den
		Berichtsbereich des	Hauptfensters gezogen.

		:param event: Instanz von QEvent (gem. Spezifikation der Oberklasse)
		:tyoe event: QEvent
		"""
		event.setDropAction(QtCore.Qt.CopyAction)
		event.accept()
		lDateinamenList = []
		for url in event.mimeData().urls():
			lDateinamenList.append(LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(str(url.toLocalFile())))
		self.C_DROPPED_SIGNAL.emit(lDateinamenList)

class SQToolButton(QtWidgets.QToolButton):
	"""
	Unterklasse von QToolButton. Eine von Instanz von QToolButton verwaltet zusätzlich eine Angabe der Programmfunktion,
	die sich mit dem Button ausführen lässt sowie einen Funktionstyp ("Wiederholung" oder "Umkehrung"), die gemeinsam
	die Programmfunktion festlegen, die beim Klick des Buttons ausgelöst wird.	Die Klasse modelliert die Buttons für
	"Wiederholen" und "Umkehren" der letzten Programmfunktion, die im Hauptfenster erst nach Funktionsausführung erscheinen.
	"""
	def __init__(self, parent, pFunktionString, pFunktsionstypString):
		"""
		Initialisiert ein Objekt der Klasse SQToolButton (Wiederholen- und Umkehren-Button).
		"""
		super(SQToolButton, self).__init__(parent)
		self.sFunktionString = pFunktionString
		self.sFunktionstypString = pFunktsionstypString

	def setzeFunktion(self, pFunktionString):
		"""
		Setzt den Wert des Attributs sFunktionstypString auf pFunktionsString.

		:param pFunktionString: Programmfunktion (Verschlüsseln, Entschlüsseln, Vernichten)
		:type pFunktionString: String
		"""
		if pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
			if self.sFunktionstypString == 'Wiederholung':
				self.setToolTip('<b>Verschlüsselung</b> für die letzte Auswahl wiederholen.')
				self.setStyleSheet("QToolButton {\n"
					"    font-size: 25px;\n"
					"    font-weight: bold;\n"
					"    color: black;\n"
					"}")
			else:
				self.setToolTip('Zuletzt entschlüsselte Dateien wieder <b>verschlüsseln.</b>')
				self.setStyleSheet("QToolButton {\n"
								   "    font-size: 25px;\n"
								   "    font-weight: bold;\n"
								   "    color: black;\n"
								   "}")
		elif pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
			if self.sFunktionstypString == 'Wiederholung':
				self.setToolTip('<b>Entschlüsselung</b> für die letzte Auswahl wiederholen.')
				self.setStyleSheet("QToolButton {\n"
					"    font-size: 25px;\n"
					"    font-weight: bold;\n"
					"    color: darkgreen;\n"
					"}")
			else:
				self.setToolTip('Zuletzt verschlüsselte Dateien wieder <b>entschlüsseln.</b>')
				self.setStyleSheet("QToolButton {\n"
								   "    font-size: 25px;\n"
								   "    font-weight: bold;\n"
								   "    color: darkgreen;\n"
								   "}")
		elif self.sFunktionstypString == 'Wiederholung':
			self.setToolTip('<b>Vernichung</b> für die letzte Auswahl wiederholen .')
			self.setStyleSheet("QToolButton {\n"
							   "    font-size: 25px;\n"
							   "    font-weight: bold;\n"
							   "    color: darkred;\n"
							   "}")
		else:
			raise ValueError('SQToolButton.setzeFunktion: Ungültige Kombination von Funktionstyp und Funktion.')
		self.sFunktionString = pFunktionString

	def gibFunktion(self):
		"""
		Returniert den Wert des Attributs sFunktionString

		:return: Wert des Attributs sFunktionsString
		:rtype: String
		"""
		return self.sFunktionString

class Ui_MainWindow(QtWidgets.QMainWindow):
	"""
	Modelliert das Hauptfenster von LiSCrypt.
	"""
	def __init__(self, pViewQView):
		"""
		Initialisiert ein Objekt der Klasse Ui_MainWindow (Hauptfenster von LiSCrypt).
		:param pViewQView: Zentrale View-Komponente
		:type pViewQView: QView
		"""
		super(Ui_MainWindow, self).__init__()
		self.sViewQView = pViewQView
		self.sZuletztAusgewaehlteEintraegeList = []
		self.sAusgewaehlteFunktionString = LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL
		self._setupUi()
		self.show()

	def _setupUi(self):
		"""
		Interne Methode. Initialisiert die Komponenten des Hauptfensters (wird von Konstruktor aufgerufen).
		"""
		self.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
		self.setObjectName('LiSCrypt')

		lLiSCryptIcon16x16QPixmap = QtGui.QPixmap()
		lLiSCryptIcon16x16QPixmap.loadFromData(LiSKonstanten.C_LISCRYPT_ICON16X16,'PNG')
		lLiSCryptIcon16x16QIcon = QtGui.QIcon(lLiSCryptIcon16x16QPixmap)
		self.setWindowIcon(lLiSCryptIcon16x16QIcon)

		self.resize(self.sizeHint())
		self.centralwidget = QtWidgets.QWidget(self)
		self.centralwidget.setObjectName("centralwidget")
		self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.centralwidget)
		self.verticalLayout_10.setObjectName("verticalLayout_10")
		self.verticalLayout_9 = QtWidgets.QVBoxLayout()
		self.verticalLayout_9.setObjectName("verticalLayout_9")

		self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
		self.horizontalLayout_2.setObjectName("horizontalLayout_2")
		self.horizontalLayout_2.setSizeConstraint(QtWidgets.QLayout.SetFixedSize)
		self.groupBox = QtWidgets.QGroupBox(self.centralwidget)
		self.groupBox.setStyleSheet("QGroupBox {\n"
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
		self.groupBox.setObjectName("groupBox")
		if LiSKonstanten.C_IQB_VERSION is True:
			self.groupBox.setSizePolicy(QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding,QtWidgets.QSizePolicy.Preferred))
		self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.groupBox)
		self.verticalLayout_6.setObjectName("verticalLayout_6")
		self.verticalLayout = QtWidgets.QVBoxLayout()
		self.verticalLayout.setObjectName("verticalLayout")
		self.sVerschluesselnRadioButton = QtWidgets.QRadioButton(self.groupBox)
		self.sVerschluesselnRadioButton.setChecked(True)
		self.sVerschluesselnRadioButton.setObjectName("sVerschluesselnRadioButton")
		self.verticalLayout.addWidget(self.sVerschluesselnRadioButton)
		self.sEntschluesselnRadioButton = QtWidgets.QRadioButton(self.groupBox)
		self.sEntschluesselnRadioButton.setObjectName("sEntschluesselnRadioButton")
		self.verticalLayout.addWidget(self.sEntschluesselnRadioButton)
		self.sVernichtenRadioButton = QtWidgets.QRadioButton(self.groupBox)
		self.sVernichtenRadioButton.setObjectName("sVernichtenRadiobutton")
		if LiSKonstanten.C_IQB_VERSION is False:
			self.verticalLayout.addWidget(self.sVernichtenRadioButton)
		else:
			self.sVernichtenRadioButton.setVisible(False)
		self.line = QtWidgets.QFrame(self.groupBox)
		self.line.setFrameShape(QtWidgets.QFrame.HLine)
		self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
		self.line.setObjectName("line")
		if LiSKonstanten.C_IQB_VERSION is False:
			self.verticalLayout.addWidget(self.line)
		else:
			self.line.setVisible(False)
		self.sOriginaleVernichtenCheckBox = QtWidgets.QCheckBox(self.groupBox)
		self.sOriginaleVernichtenCheckBox.setChecked(True)
		self.sOriginaleVernichtenCheckBox.setObjectName("checkBox")
		if LiSKonstanten.C_IQB_VERSION is False:
			self.verticalLayout.addWidget(self.sOriginaleVernichtenCheckBox)
		else:
			self.sOriginaleVernichtenCheckBox.setVisible(False)
		self.verticalLayout_6.addLayout(self.verticalLayout)
		self.horizontalLayout_2.addWidget(self.groupBox)
		self.verticalLayout_7 = QtWidgets.QVBoxLayout()
		self.verticalLayout_7.setObjectName("verticalLayout_7")
		self.groupBox_2 = QtWidgets.QGroupBox(self.centralwidget)
		self.groupBox_2.setStyleSheet("QGroupBox {\n"
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
		self.groupBox_2.setObjectName("groupBox_2")
		self.groupBox_2.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
		self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.groupBox_2)
		self.verticalLayout_5.setObjectName("verticalLayout_5")
		self.verticalLayout_2 = QtWidgets.QVBoxLayout()
		self.verticalLayout_2.setObjectName("verticalLayout_2")
		self.gridLayout = QtWidgets.QGridLayout()
		self.gridLayout.setObjectName("gridLayout")
		self.sPasswortRadioButton = QtWidgets.QRadioButton(self.groupBox_2)
		self.sPasswortRadioButton.setChecked(True)
		self.sPasswortRadioButton.setObjectName("sPasswortRadioButton")
		self.gridLayout.addWidget(self.sPasswortRadioButton, 0, 0, 1, 1)
		self.sSchluesselDateinameLineEdit = CQLineEdit(self.groupBox_2)
		self.sSchluesselDateinameLineEdit.setObjectName("sSchluesselDateinameLineEdit")
		self.sSchluesselDateinameLineEdit.setReadOnly(True)
		self.gridLayout.addWidget(self.sSchluesselDateinameLineEdit, 1, 1, 1, 1)
		self.sSchluesseldateiRadioButton = QtWidgets.QRadioButton(self.groupBox_2)
		self.sSchluesseldateiRadioButton.setObjectName("sSchluesseldateiRadioButton")
		self.gridLayout.addWidget(self.sSchluesseldateiRadioButton, 1, 0, 1, 1)
		self.verticalLayout_2.addLayout(self.gridLayout)
		self.verticalLayout_5.addLayout(self.verticalLayout_2)
		if LiSKonstanten.C_IQB_VERSION is False:
			self.verticalLayout_7.addWidget(self.groupBox_2)
		else:
			self.groupBox_2.setVisible(False)

		self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
		self.horizontalLayout_3.setObjectName("horizontalLayout_3")

		if LiSKonstanten.C_IQB_VERSION is False:
			spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
			self.horizontalLayout_3.addItem(spacerItem)
		else:
			self.horizontalLayout_3.setAlignment(QtCore.Qt.AlignBottom)

		self.sFunktionUmkehrenButton = SQToolButton(self.centralwidget, self.sAusgewaehlteFunktionString, 'Umkehrung')
		self.sFunktionUmkehrenButton.setObjectName("sFunktionUmkehrenButton")
		self.sFunktionUmkehrenButton.setMinimumWidth(40)
		self.sFunktionUmkehrenButton.setMinimumHeight(50)
		self.sFunktionUmkehrenButton.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)

		self.sFunktionUmkehrenButton.setText("⤺")
		if LiSKonstanten.C_PLATTFORM == 'nt':
			self.sFunktionUmkehrenButton.setStyleSheet("QToolButton {\n"
										  "    font-size: 25px;\n" 
										  "    font-weight: bold;\n" 	
										  "}")
		else:
			self.sFunktionUmkehrenButton.setStyleSheet("QToolButton {\n"
										  "    font-size: 25px;\n"
										  "}")

		if LiSKonstanten.C_IQB_VERSION is False:
			self.horizontalLayout_3.addWidget(self.sFunktionUmkehrenButton)
		self.sFunktionUmkehrenButton.setVisible(False)

		self.sFunktionWiederholenButton = SQToolButton(self.centralwidget, self.sAusgewaehlteFunktionString, 'Wiederholung')
		self.sFunktionWiederholenButton.setObjectName("sFunktionWiederholen")
		self.sFunktionWiederholenButton.setMinimumWidth(40)
		self.sFunktionWiederholenButton.setMinimumHeight(50)
		self.sFunktionWiederholenButton.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)

		self.sFunktionWiederholenButton.setText("↻")
		if LiSKonstanten.C_PLATTFORM == 'nt':
			self.sFunktionWiederholenButton.setStyleSheet("QToolButton {\n"
										  "    font-size: 25px;\n"
										  "    font-weight: bold;\n" 
										  "}")
		else:
			self.sFunktionWiederholenButton.setStyleSheet("QToolButton {\n"
										  "    font-size: 25px;\n"
										  "}")
		if LiSKonstanten.C_IQB_VERSION is False:
			self.horizontalLayout_3.addWidget(self.sFunktionWiederholenButton)
		self.sFunktionWiederholenButton.setVisible(False)

		self.sHinzufuegenButton = QtWidgets.QToolButton(self.centralwidget)
		self.sHinzufuegenButton.setObjectName("sHinzufuegenButton")
		self.sHinzufuegenButton.setMinimumWidth(40)
		self.sHinzufuegenButton.setMinimumHeight(50)
		self.sHinzufuegenButton.setToolTip("Dateien/Verzeichnisse auswählen")
		self.sHinzufuegenButton.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
		self.sHinzufuegenButton.setStyleSheet("QToolButton {\n"
									  "    font-size: 25px;\n"
									  "}")
		self.horizontalLayout_3.addWidget(self.sHinzufuegenButton)

		self.verticalLayout_7.addLayout(self.horizontalLayout_3)

		self.horizontalLayout_2.addLayout(self.verticalLayout_7)
		self.verticalLayout_9.addLayout(self.horizontalLayout_2)
		self.verticalLayout_8 = QtWidgets.QVBoxLayout()
		self.verticalLayout_8.setObjectName("verticalLayout_8")

		self.groupBox_3 = QtWidgets.QGroupBox(self.centralwidget)
		self.groupBox_3.setStyleSheet("QGroupBox {\n"
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
		self.groupBox_3.setObjectName("groupBox_3")
		self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.groupBox_3)
		self.verticalLayout_4.setObjectName("verticalLayout_4")
		self.verticalLayout_3 = QtWidgets.QVBoxLayout()
		self.verticalLayout_3.setObjectName("verticalLayout_3")
		self.sBerichtListWidget = DQListWidget(self.groupBox_3)
		self.sBerichtListWidget.setObjectName("sBerichtListWidget")
		self.sBerichtListWidget.setAcceptDrops(True)
		self.sBerichtListWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
		if LiSKonstanten.C_IQB_VERSION is False:
			self.sBerichtListWidget.setMinimumWidth(550)
		else:
			self.sBerichtListWidget.setMinimumWidth(400)
		self.sBerichtListWidget.setMinimumHeight(150)
		self.verticalLayout_3.addWidget(self.sBerichtListWidget)
		self.verticalLayout_4.addLayout(self.verticalLayout_3)
		self.verticalLayout_8.addWidget(self.groupBox_3)
		self.horizontalLayout = QtWidgets.QHBoxLayout()
		self.horizontalLayout.setObjectName("horizontalLayout")
		self.sAbbrechenButton = QtWidgets.QPushButton(self.centralwidget)
		self.sAbbrechenButton.setObjectName("sAbbrechenButton")
		self.sAbbrechenButton.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogCancelButton))
		self.sAbbrechenButton.setEnabled(False)
		self.horizontalLayout.addWidget(self.sAbbrechenButton)
		self.sStatusleisteLabel = QtWidgets.QLabel(self.centralwidget)
		self.sStatusleisteLabel.setObjectName("sStatusleisteLabel")
		self.sStatusleisteLabelOriginalPalette = self.sStatusleisteLabel.palette()
		self.sStatusleisteLabelRedWhitePalette = QtGui.QPalette()
		self.setzeStatusleisteUndGUIZustand()
		self.sStatusleisteLabelRedWhitePalette.setColor(QtGui.QPalette.Background, QtGui.QColor('red'))
		self.sStatusleisteLabelRedWhitePalette.setColor(QtGui.QPalette.Foreground, QtGui.QColor('white'))
		self.horizontalLayout.addWidget(self.sStatusleisteLabel)
		self.horizontalLayout.setStretch(1, 1)
		self.verticalLayout_8.addLayout(self.horizontalLayout)
		self.verticalLayout_9.addLayout(self.verticalLayout_8)
		self.verticalLayout_10.addLayout(self.verticalLayout_9)
		self.setCentralWidget(self.centralwidget)
		self.menubar = QtWidgets.QMenuBar(self)
		self.menubar.setGeometry(QtCore.QRect(0, 0, 628, 23))
		self.menubar.setObjectName("menubar")
		self.menuDatei = QtWidgets.QMenu(self.menubar)
		self.menuDatei.setObjectName("menuDatei")
		self.menuBearbeiten = QtWidgets.QMenu(self.menubar)
		self.menuBearbeiten.setObjectName("menuBearbeiten")
		self.menuHilfe = QtWidgets.QMenu(self.menubar)
		self.menuHilfe.setObjectName("menuHilfe")
		self.setMenuBar(self.menubar)
		self.actionSchluesseldatei_erzeugen = QtWidgets.QAction(self)
		self.actionSchluesseldatei_erzeugen.setObjectName("actionSchluesseldatei_erzeugen")
		self.actionBeenden = QtWidgets.QAction(self)
		self.actionBeenden.setObjectName("actionBeenden")
		self.actionProtokoll_kopieren = QtWidgets.QAction(self)
		self.actionProtokoll_kopieren.setObjectName("actionProtokoll_kopieren")
		self.actionHilfe_Kontakt = QtWidgets.QAction(self)
		self.actionHilfe_Kontakt.setObjectName("actionHilfe_Kontakt")
		self.actionUeber_LisCrypt = QtWidgets.QAction(self)
		self.actionUeber_LisCrypt.setObjectName("actionUeber_LisCrypt")
		if LiSKonstanten.C_IQB_VERSION is False:
			self.menuDatei.addAction(self.actionSchluesseldatei_erzeugen)
			self.menuDatei.addSeparator()
		self.menuDatei.addAction(self.actionBeenden)
		if LiSKonstanten.C_IQB_VERSION is False:
			self.menuBearbeiten.addAction(self.actionProtokoll_kopieren)
		self.menuHilfe.addAction(self.actionHilfe_Kontakt)
		self.menuHilfe.addAction(self.actionUeber_LisCrypt)
		self.menubar.addAction(self.menuDatei.menuAction())
		if LiSKonstanten.C_IQB_VERSION is False:
			self.menubar.addAction(self.menuBearbeiten.menuAction())
		self.menubar.addAction(self.menuHilfe.menuAction())
		self.statusbar = QtWidgets.QStatusBar(self)
		self.statusbar.setObjectName("statusbar")
		self.setStatusBar(self.statusbar)

		self.statusBar().setVisible(False)
		self._center()
		self._retranslateUi()
		QtCore.QMetaObject.connectSlotsByName(self)

		self._connectSlots()

	def _connectSlots(self):
		"""
		Interne Methode. Setzt die Signal-Slot-Verbindungen der Bedienelemente des Hauptfensters.
		"""
		# Pulldown-Menu:
		self.actionSchluesseldatei_erzeugen.triggered.connect(self.sViewQView.veranlasseErzeugungVonSchluesseldatei)
		self.actionBeenden.triggered.connect(sys.exit)
		self.actionProtokoll_kopieren.triggered.connect(self.sViewQView.veranlasseProtokollKopie)
		self.actionHilfe_Kontakt.triggered.connect(self.sViewQView.zeigeKontaktDialog)
		self.actionUeber_LisCrypt.triggered.connect(self.sViewQView.zeigeUeberDialog)

		# RadioButtons
		self.sVerschluesselnRadioButton.clicked.connect(lambda: self.aktiviereVerschluesseln(
			pDurchKlickAufRadiobuttonBoolean=True))
		self.sEntschluesselnRadioButton.clicked.connect(lambda: self.aktiviereEntschluesseln(
			pDurchKlickAufRadiobuttonBoolean=True))
		self.sVernichtenRadioButton.clicked.connect(lambda: self.aktiviereVernichten(
			pDurchKlickAufRadiobuttonBoolean=True))
		self.sPasswortRadioButton.clicked.connect(self.waehleSchluesselartPasswort)
		self.sSchluesseldateiRadioButton.clicked.connect(self._waehleSchluesselartSchluesseldatei)

		# Eingabefelder
		self.sSchluesselDateinameLineEdit.C_CLICKED_SIGNAL.connect(self.waehleSchluesselartSchluesseldatei_KlickAufDateifeld)
		self.sSchluesselDateinameLineEdit.C_DROPPED_SIGNAL.connect(self._waehleSchluesselartSchluesseldatei_DropAufDateifeld)

		# PushButtons
		self.sAbbrechenButton.clicked.connect(self.sViewQView.veranlasseStoppDesFunktionsprozesses)

		# QToolButtons
		self.sHinzufuegenButton.clicked.connect(self.sViewQView.veranlasseControllerFunktionNachHinzufuegenButton)
		self.sFunktionUmkehrenButton.clicked.connect(self._kehreVorherigeFunktionUm)
		self.sFunktionWiederholenButton.clicked.connect(self._wiederholeVorherigeFunktion)

		# DragAndDrop-/Berichtsbereich
		self.sBerichtListWidget.C_DROPPED_SIGNAL.connect(self.sViewQView.veranlasseControllerFunktionNachDragAndDrop)
		self.sBerichtListWidget.itemDoubleClicked.connect(self._oeffneVerzeichnisZuItem)
		lBerichtsListWidgetModel = self.sBerichtListWidget.model()
		lBerichtsListWidgetModel.rowsInserted.connect(self.sBerichtListWidget.scrollToBottom)


	def _retranslateUi(self):
		"""
		Interne Methode. Setzt die Beschriftungen der Elemente des Hauptfensters (Ziel: ggf. spätere Übersetzung).
		"""
		_translate = QtCore.QCoreApplication.translate
		self.setWindowTitle(_translate(LiSKonstanten.C_PROGRAMMNAME + " " + LiSKonstanten.__version__,
									   LiSKonstanten.C_PROGRAMMNAME + " " + LiSKonstanten.__version__))
		self.groupBox.setTitle(_translate("Ui_MainWindow", "Funktion"))
		self.sVerschluesselnRadioButton.setText(_translate("Ui_MainWindow", "Verschlüsseln"))
		self.sEntschluesselnRadioButton.setText(_translate("Ui_MainWindow", "Entschlüsseln"))
		self.sVernichtenRadioButton.setText(_translate("Ui_MainWindow", "Vernichten"))
		self.sOriginaleVernichtenCheckBox.setText(_translate("Ui_MainWindow", "Originale vernichten"))
		self.groupBox_2.setTitle(_translate("Ui_MainWindow", "Schlüsselart"))
		self.sPasswortRadioButton.setText(_translate("Ui_MainWindow", "Passwort"))
		self.sSchluesseldateiRadioButton.setText(_translate("Ui_MainWindow", "Schlüsseldatei"))
		self.sHinzufuegenButton.setText(_translate("Ui_MainWindow", "+"))
		self.groupBox_3.setTitle(_translate("Ui_MainWindow", "Dateiablage/Protokoll"))
		self.sAbbrechenButton.setText(_translate("Ui_MainWindow", "Abbrechen"))
		self.menuDatei.setTitle(_translate("Ui_MainWindow", "Datei"))
		self.menuBearbeiten.setTitle(_translate("Ui_MainWindow", "Bearbeiten"))
		self.menuHilfe.setTitle(_translate("Ui_MainWindow", "Hilfe"))
		self.actionSchluesseldatei_erzeugen.setText(_translate("Ui_MainWindow", "Schlüsseldatei erzeugen"))
		self.actionProtokoll_kopieren.setText(_translate("Ui_MainWindow", "Protokoll in Zwischenablage kopieren"))
		self.actionBeenden.setText(_translate("Ui_MainWindow", "Beenden"))
		self.actionHilfe_Kontakt.setText(_translate("Ui_MainWindow", "Hilfe/Kontakt"))
		self.actionUeber_LisCrypt.setText(_translate("Ui_MainWindow", "Über LiSCrypt" if LiSKonstanten.C_IQB_VERSION is False
				else "Über LiSCrypt IQB"))

	def _center(self):
		"""
		Interne Methode. Zentriert das Hauptfenster auf dem Bildschirm (unabhängig Fenstergröße und Auflösung).
		"""
		# Dimensionen des aktuellen Bildschirms ermitteln
		screen = QtWidgets.QDesktopWidget().screenGeometry()
		# ... und die Dimensionen des Fensters
		mysize = self.geometry()
		# Die horizonzale Position errechnet sich als Bildschirmbreite - Fensterbreite / 2
		hpos = (screen.width() - mysize.width()) / 2
		# Und die vertikale Position analog
		vpos = (screen.height() - mysize.height()) / 2
		

		self.move(hpos, vpos)

	def zeigeInNormalgroesseFallsMinimiert(self):
		"""
		Setzt das Fenster auf seine ursprüngliche Größe zurück.
		"""
		if self.isMinimized():
			self.showNormal()

	def aktiviereVerschluesseln(self, pDurchKlickAufRadiobuttonBoolean=False):
		"""
		Wählt die Programmfunktion Verschlüsseln sichtbar aus. Ist pDurchMausklick True, werden die beiden
		Sonderfunktionsbuttons ('Funktion umkehren', 'Funktion wiederholen') unsichtbar gemacht.

		:param pDurchKlickAufRadiobuttonBoolean: Gibt an, ob die Aktivierung der Programmfunktion durch einen Klick auf den entsprechenden Radiobutton ausgelöst wurde (True: ja, False: nein).
		:type pDurchKlickAufRadiobuttonBoolean: Boolean
		"""
		if self.sAusgewaehlteFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
			self.sBerichtListWidget.clear()
			if self.sVerschluesselnRadioButton.isChecked() is False:
				self.sVerschluesselnRadioButton.setChecked(True)
			if pDurchKlickAufRadiobuttonBoolean is True:
				self.sFunktionUmkehrenButton.setVisible(False)
				self.sFunktionWiederholenButton.setVisible(False)
			self.sBerichtListWidget.setStyleSheet('background-color: white')
			self.sHinzufuegenButton.setStyleSheet("QToolButton {\n"
								   "    font-size: 25px;\n"
								   "    color: black;\n"
								   "}")
			if self.sAusgewaehlteFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
				self.sOriginaleVernichtenCheckBox.setEnabled(True)
				self.sPasswortRadioButton.setAutoExclusive(True)
				self.sSchluesseldateiRadioButton.setAutoExclusive(True)
				self.groupBox_2.setEnabled(True)
				self.sPasswortRadioButton.setChecked(True)
			self.sAusgewaehlteFunktionString = LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL

	def aktiviereEntschluesseln(self, pDurchKlickAufRadiobuttonBoolean=False):
		"""
		Wählt die Programmfunktion Entschlüsseln sichtbar aus. Ist pDurchMausklick True, werden die beiden
		Sonderfunktionsbuttons ('Funktion umkehren', 'Funktion wiederholen') unsichtbar gemacht.

		:param pDurchKlickAufRadiobuttonBoolean: Gibt an, ob die Aktivierung der Programmfunktion durch einen Klick auf den entsprechenden Radiobutton ausgelöst wurde (True: ja, False: nein).
		:type pDurchKlickAufRadiobuttonBoolean: Boolean
		"""
		if self.sAusgewaehlteFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
			if self.sEntschluesselnRadioButton.isChecked() is False:
				self.sEntschluesselnRadioButton.setChecked(True)
			self.sBerichtListWidget.clear()
			if pDurchKlickAufRadiobuttonBoolean is True:
				self.sFunktionUmkehrenButton.setVisible(False)
				self.sFunktionWiederholenButton.setVisible(False)
			self.sBerichtListWidget.setStyleSheet('background-color:  #e6ffe6')
			self.sHinzufuegenButton.setStyleSheet("QToolButton {\n"
								   "    font-size: 25px;\n"
								   "    color: darkgreen;\n"
								   "}")
			if self.sAusgewaehlteFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
				self.sOriginaleVernichtenCheckBox.setEnabled(True)
				self.sPasswortRadioButton.setAutoExclusive(True)
				self.sSchluesseldateiRadioButton.setAutoExclusive(True)
				self.groupBox_2.setEnabled(True)
				self.sPasswortRadioButton.setChecked(True)
			self.sAusgewaehlteFunktionString = LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL


	def aktiviereVernichten(self, pDurchKlickAufRadiobuttonBoolean=False):
		"""
		Wählt die Programmfunktion Vernichten sichtbar aus. Ist pDurchMausklick True, werden die beiden
		Sonderfunktionsbuttons ('Funktion umkehren', 'Funktion wiederholen') unsichtbar gemacht.

		:param pDurchKlickAufRadiobuttonBoolean: Gibt an, ob die Aktivierung der Programmfunktion durch einen Klick auf den entsprechenden Radiobutton ausgelöst wurde (True: ja, False: nein).
		:type pDurchKlickAufRadiobuttonBoolean: Boolean
		"""
		if self.sAusgewaehlteFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
			if self.sVernichtenRadioButton.isChecked() is False:
				self.sVernichtenRadioButton.setChecked(True)
			self.sBerichtListWidget.clear()
			if pDurchKlickAufRadiobuttonBoolean is True:
				self.sFunktionUmkehrenButton.setVisible(False)
				self.sFunktionWiederholenButton.setVisible(False)
			self.sBerichtListWidget.setStyleSheet('background-color:  #ffe6e6')
			self.sHinzufuegenButton.setStyleSheet("QToolButton {\n"
								   "    font-size: 25px;\n"
								   "    color: darkred;\n"
								   "}")
			self.sOriginaleVernichtenCheckBox.setChecked(True)
			self.sOriginaleVernichtenCheckBox.setEnabled(False)
			self.sPasswortRadioButton.setAutoExclusive(False)
			self.sPasswortRadioButton.setChecked(False)
			self.sSchluesseldateiRadioButton.setAutoExclusive(False)
			self.sSchluesseldateiRadioButton.setChecked(False)
			self.sSchluesselDateinameLineEdit.setText('')
			self.groupBox_2.setEnabled(False)
			self.sAusgewaehlteFunktionString = LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL


	def _kehreVorherigeFunktionUm(self):
		"""
		Aktiviert die zur zuletzt ausgeführten Programmfunktion gegenteilige Programmfunktion im Hauptfenster und
		veranlasst die Ausführung der entsprechenden Programmfunktion.
		"""
		if self.sFunktionUmkehrenButton.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
			self.aktiviereEntschluesseln()
			self.sViewQView.veranlasseControllerFunktionNachFunktionUmkehrenButton()
		else:
			self.aktiviereVerschluesseln()
			self.sViewQView.veranlasseControllerFunktionNachFunktionUmkehrenButton()

	def _wiederholeVorherigeFunktion(self):
		"""
		Veranlasst die erneute Ausführung der zuletzt ausgeführten Programmfunktion.
		"""
		self.sViewQView.veranlasseControllerFunktionNachFunktionWiederholenButton()


	def macheFunktionWiederholenButtonSichtbar(self, pSichtbarBoolean):
		"""
		Setzt die Sichtbarkeit des Wiederholen-Buttons auf pSichtbarBoolean (True: ja, False: nein)

		:param pSichtbarBoolean: Neue Sichtbarkeit des Wiederholen-Buttons
		:type pSichtbarBoolean: Boolean
		"""
		if LiSKonstanten.C_IQB_VERSION is False:
			self.sFunktionWiederholenButton.setzeFunktion(self.sAusgewaehlteFunktionString)
			self.sFunktionWiederholenButton.setVisible(pSichtbarBoolean)

	def macheFunktionUmkehrenButtonSichtbar(self, pVerfuegbarBoolean):
		"""
		Setzt die Sichtbarkeit des Umkehren-Buttons auf pSichtbarBoolean (True: ja, False: nein)

		:param pSichtbarBoolean: Neue Sichtbarkeit des Umkehren-Buttons
		:type pSichtbarBoolean: Boolean
		"""
		if LiSKonstanten.C_IQB_VERSION is False:
			self.sFunktionUmkehrenButton.setzeFunktion(LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL if self.sAusgewaehlteFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL else \
															LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL)
			self.sFunktionUmkehrenButton.setVisible(pVerfuegbarBoolean)

	def setzeFenstereinstellungenFuerFunktion(self, pFunktionString):
		"""
		Setzt die Fenstereinstellungen für die Programmfunktion pFunktionString.

		:param pFunktionString: Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL, C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
		:type pFunktionString: String
		"""
		if pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
			self.aktiviereVerschluesseln()
		elif pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
			self.aktiviereEntschluesseln()
		else:
			self.aktiviereVernichten()

	def setzeOriginaleVernichten(self, pOriginaleVernichtenBoolean):
		"""
		Setzt den Auswahlstatus der Originale-Vernichten-Checkbox auf pOriginaleVernichtenBoolean (True: ausgewählt, False: nicht ausgewählt)
		:param pOriginaleVernichtenBoolean: Neuer Auswahlstatus der Originale-Vernichten-Checkbox

		:type pOriginaleVernichtenBoolean: Boolean
		"""
		self.sOriginaleVernichtenCheckBox.setChecked(pOriginaleVernichtenBoolean)

	def setzeStatusleisteUndGUIZustand(self, pTextString=None, pAbbrechenButtonAktivBoolean=False):
		"""
		Setzt den in der Statusleiste angezeigten Text auf pTextstring. Ist pTextString None, wird 'Bereit.' als Text
		gesetzt. Setzt fener den Verfügbarkeitsstatus des Abbrechen-Buttons auf pAbbrechenButtonAktivBoolean und
		aktiviert/deaktiviert weitere GUI-Elemente in Abhängigkeit von diesem Wert.

		:param pTextString: Neuer Inhalt
		:param pAbbrechenButtonAktivBoolean: Boolean
		"""
		if pTextString is not None and pTextString != self.sStatusleisteLabel.text():
			self.sStatusleisteLabel.setAutoFillBackground(True)
			self.sStatusleisteLabel.setPalette(self.sStatusleisteLabelRedWhitePalette)
			self.sStatusleisteLabel.setText(pTextString)
		elif (pTextString is None or pTextString == 'Bereit.') and pTextString != self.sStatusleisteLabel.text():
			self.sStatusleisteLabel.setAutoFillBackground(False)
			self.sStatusleisteLabel.setPalette(self.sStatusleisteLabelOriginalPalette)
			if LiSKonstanten.C_LOGGING_LEVEL == logging.DEBUG:
				self.sStatusleisteLabel.setText('Bereit. -- DEBUGGING MODUS --')
			else:
				self.sStatusleisteLabel.setText('Bereit.')
		if pAbbrechenButtonAktivBoolean is True:
			self.sAbbrechenButton.setEnabled(True)
			self.groupBox.setEnabled(False)
			self.groupBox_2.setEnabled(False)
			self.sHinzufuegenButton.setEnabled(False)
			self.sFunktionWiederholenButton.setEnabled(False)
			self.sFunktionUmkehrenButton.setEnabled(False)
		else:
			self.sAbbrechenButton.setEnabled(False)
			self.groupBox.setEnabled(True)
			if self.sVernichtenRadioButton.isChecked() is False:
				self.groupBox_2.setEnabled(True)
			self.sHinzufuegenButton.setEnabled(True)
			self.sFunktionWiederholenButton.setEnabled(True)
			self.sFunktionUmkehrenButton.setEnabled(True)

	def waehleSchluesselartPasswort(self):
		"""
		Interne Methode. Deaktiviert Inhalt und Tooltip des Schlüsseldatei-Feldes.
		"""
		self.sSchluesselDateinameLineEdit.setText('')
		self.sSchluesselDateinameLineEdit.setToolTip(None)

	def waehleSchluesselartPasswort_Kommandozeile(self):
		"""
		Wählt im Hauptfenster als Schlüsselart Passwort aus und deaktiviert Inhalt und Tooltip des Schlüsseldatei-Feldes.
		"""
		self.sPasswortRadioButton.setChecked(True)
		self.sSchluesselDateinameLineEdit.setText('')
		self.sSchluesselDateinameLineEdit.setToolTip(None)

	def _waehleSchluesselartSchluesseldatei(self):
		"""
		Interne Methode. Zeigt einen Dateiauswahldialog zur Auswahl einer Schlüsseldatei an und übernimmt den Namen der
		ausgewählten Datei in das Schlüsseldatei-Feld sowie deren Pfad in den Tooltip des Schlüsseldateifeldes, falls
		das Schlüsseldatei-Feld zuvor leer war. Wird dabei keine Datei auswählt, wird im Anschluss wieder die
		Schlüsselart Passwort ausgewählt. War das Schlüsseldatei-Feld zuvor nicht leer, geschieht nichts.
		"""
		if not self.sSchluesselDateinameLineEdit.text():
			lDateinameErweitertString = self.sViewQView.zeigeSchluesseldateiauswahlDialog()
			if lDateinameErweitertString is not None:
				self.sSchluesselDateinameLineEdit.setzeErweitertenPfad(lDateinameErweitertString)
				LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS = os.path.dirname(lDateinameErweitertString)
			else:
				self.sPasswortRadioButton.setChecked(True)

	def waehleSchluesselartSchluesseldatei_KlickAufDateifeld(self):
		"""
		Wählt im Hauptfenster als Schlüsselart Schlüsseldatei aus und zeigt einen Dateiauswahldialog zur Auswahl einer
		Schlüsseldatei an und übernimmt den Namen der ausgewählten Datei in das Schlüsseldatei-Feld sowie deren Pfad in
		den Tooltip des	Schlüsseldateifeldes. Wird dabei keine Datei auswählt (Abbrechen), wird im Anschluss wieder die
		Schlüsselart Passwort ausgewählt, sofern diese vorher ausgewählt war.
		"""
		self.sSchluesseldateiRadioButton.setChecked(True)
		lDateinameErweitertString = self.sViewQView.zeigeSchluesseldateiauswahlDialog()
		if lDateinameErweitertString is not None:
			self.sSchluesselDateinameLineEdit.setzeErweitertenPfad(lDateinameErweitertString)
			LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS = os.path.dirname(lDateinameErweitertString)
		elif not self.sSchluesselDateinameLineEdit.text():
			self.sPasswortRadioButton.setChecked(True)

	def waehleSchluesselartSchluesseldatei_Kommandozeile(self):
		"""
		Wählt im Hauptfenster als Schlüsselart Schlüsseldatei aus und zeigt einen Dateiauswahldialog zur Auswahl einer
		Schlüsseldatei an und übernimmt den Namen der ausgewählten Datei in das Schlüsseldatei-Feld sowie deren Pfad in
		den Tooltip des	Schlüsseldateifeldes. Wird eine Datei ausgewählt, returniert die Methode True, sonst False.

		:return: Angabe, ob tatsächlich eine Schlüsseldatei ausgewählt wurde (True: ja, False: nein)
		:rtype: Boolean
		"""
		lSchluesseldateiAusgewaehltBoolean = False
		self.sSchluesseldateiRadioButton.setChecked(True)
		lDateinameErweitertString = self.sViewQView.zeigeSchluesseldateiauswahlDialog()
		if lDateinameErweitertString is not None:
			self.sSchluesselDateinameLineEdit.setzeErweitertenPfad(lDateinameErweitertString)
			LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS = os.path.dirname(lDateinameErweitertString)
			lSchluesseldateiAusgewaehltBoolean = True
		elif not self.sSchluesselDateinameLineEdit.text():
			self.sPasswortRadioButton.setChecked(True)
		return lSchluesseldateiAusgewaehltBoolean

	def _waehleSchluesselartSchluesseldatei_DropAufDateifeld(self, pSchluesseldateiPfadString):
		"""
		Interne Methode Wählt als Schlüsselart Schlüsseldatei aus und übernnimmt den Namen der Datei
		pSchluesseldateiPfadString in das Schlüsseldatei-Feld sowie deren Pfad in den Tooltip des Schlüsseldateifeldes.
		Schlägt dies fehl, wird im Anschluss wieder die Schlüsselart Passwort ausgewählt, sofern diese vorher
		ausgewählt war.
		"""
		self.sSchluesseldateiRadioButton.setChecked(True)
		self.sSchluesselDateinameLineEdit.setzeErweitertenPfad(pSchluesseldateiPfadString)
		if not self.sSchluesselDateinameLineEdit.text():
			self.sPasswortRadioButton.setChecked(True)

	def _oeffneVerzeichnisZuItem(self, pItemQListWidgetItem):
		"""
		Interne Methode. Veranlasst die Hauptviewkomponente, den Pfad von pItemQListWidgetItem in einem Dateibrowser zu
		öffnen.

		:param pItemQListWidgetItem: Eintrag des Berichtsbereichs (Dateiablage/Protokoll)
		:type pItemQListWidgetItem: QListWidgetItem
		"""
		if pItemQListWidgetItem.toolTip() != '':
			lErweiterterPfadZuEintragString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(pItemQListWidgetItem.toolTip())
			lErweiterterPfadZuVerzeichnisString = lErweiterterPfadZuEintragString
			if LiSKonstanten.C_BETRIEBSSYSTEM == 'darwin':
				while(not os.path.lexists(lErweiterterPfadZuVerzeichnisString)):
					lErweiterterPfadZuVerzeichnisString = os.path.dirname(lErweiterterPfadZuVerzeichnisString)
			else:
				while(not os.path.isdir(lErweiterterPfadZuVerzeichnisString)):
					lErweiterterPfadZuVerzeichnisString = os.path.dirname(lErweiterterPfadZuVerzeichnisString)
			self.sViewQView.oeffneDateibrowserMitVerzeichnis(lErweiterterPfadZuVerzeichnisString)

	def ergaenzeBericht(self, pZeileString, pToolTipString):
		"""
		Ergänzt den Bereichtsbereich um eine Zeile mit Inhalt pZeileString und versieht diese Zeile mit dem ToolTip
		pToolTipString

		:param pZeileString: Text für die neue Zeile
		:type pZeileString: String
		:param pToolTipString: Text für den Tooltip der neuen Zeile
		:type pToolTipString: String
		"""
		lNeuerEintrag = QtWidgets.QListWidgetItem(pZeileString)
		if not pZeileString.endswith('OK]')\
				and not pZeileString.startswith('Start: ')\
				and not pZeileString.startswith('Ende: ')\
				and pZeileString != '---':
			lNeuerEintrag.setForeground(QtGui.QColor('red'))
		elif pZeileString.endswith('OK]'):
			lNeuerEintrag.setForeground(QtGui.QColor('blue'))
		if pToolTipString is not None:
			lNeuerEintrag.setToolTip(pToolTipString)
		self.sBerichtListWidget.addItem(lNeuerEintrag)

	def loescheBericht(self):
		"""
		Leert den Berichtsbereich (Dateiablage/Protokoll).
		"""
		self.sBerichtListWidget.clear()

	# Get-Methoden:

	def gibOriginaleVernichtenStatus(self):
		"""
		Returniert den Auswahlstatus der Option 'Original vernichten'.
		"""
		return self.sOriginaleVernichtenCheckBox.isChecked()

	def gibAusgewaehlteFunktion(self):
		"""
		Returniert das Stringliteral zur ausgewählten Programmfunktion.

		:return: Ausgewählte Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL).
		:rtype: String
		"""
		if self.sVerschluesselnRadioButton.isChecked():
			return LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL
		elif self.sEntschluesselnRadioButton.isChecked():
			return LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL
		else:
			return LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL

	def gibAusgewaehlteSchluesselart(self):
		"""
		Returniert das Stringliteral zur ausgewählten Schlüsselart (LiSKonstanten.C_SCHLUESSELART_PASSWORT_LITERAL, LiSKonstanten.C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL).
		:return: Ausgewählte Schlüsselart.

		:rtype: String
		"""
		if self.sPasswortRadioButton.isChecked():
			return LiSKonstanten.C_SCHLUESSELART_PASSWORT_LITERAL
		else:
			return LiSKonstanten.C_SCHLUESSELART_SCHLUESSELDATEI_LITERAL

	def gibErweiternPfadZuSchluesseldatei(self):
		"""
		Returniert den erweiterten Pfad zur aktuell ausgewählten Schlüsseldatei.

		:return: Erweiterte Darstellung des absoluten Pfades zur aktuell ausgewählten Schlüsseldatei
		:rtype: String
		"""
		return self.sSchluesselDateinameLineEdit.gibErweitertenPfad()

	def gibVerlaufsprotokollAlsText(self):
		"""
		Returniert den Inhalt des Berichtsbereichs (Dateiablage/Protokoll) inkl. ToolTips als zusammenhängen String mit
		Zeilentrennern.

		:return: Inhalt des Berichtsbereichs
		:rtype: String
		"""
		lAlleItemsList = [lItem for lItem in self.sBerichtListWidget.findItems("", QtCore.Qt.MatchContains)]
		lProtokollString = ''
		lIstErstesItemBoolean = True
		for lItem in lAlleItemsList:
			if lIstErstesItemBoolean is True:
				lProtokollString += lItem.text() + '\n'
				lIstErstesItemBoolean = False
			else:
				lProtokollString += lItem.text() + ' - ' + lItem.toolTip() + '\n'
		return lProtokollString

	def gibHauptfensterWidget(self):
		"""
		Returniert das Hauptfenster.

		:return: Hautfenster-Widget
		:rtype: Ui_MainWindow
		"""
		return self
