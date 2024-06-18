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

"""Dieses Modul enthält die Klassen zur Realisierung eines Auswahldialogs für eine Schlüsseldatei."""

from Modell import LiSKonfiguration
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtWidgets

import datetime
import os

class SortProxyModel(QtCore.QSortFilterProxyModel):
	"""Ein eigenes ProxyModel zur Filterung von Datei- und Verzeichnisnamen.

	Die Klasse SortProxyModel ist eine Unterklasse der von QtCore.QSortFilterProxyModel. Sie modelliert ein
	ProxyModel für die Sortierung von Dateienamen in einem Dateiauswahldialog.
	"""
	def __init__(self, pParent, pFunktionString):
		"""
		Initialisiert ein Objekt der Klasse SortProxyModel

		:param pParent: Elter gemäß PyQt-Spezifikation
		:type pParent: PyQt5.QtCore.QObject
		"""
		super(SortProxyModel, self).__init__(parent=pParent)
		self.sFunktionString = pFunktionString
		self.setSortCaseSensitivity(QtCore.Qt.CaseInsensitive)

	def lessThan(self, QModelIndex, QModelIndex_1):
		"""Überschriebene Methode der Oberklasse. Ermittelt Anzeigeordnung der Datei- bzw. Verzeichninamen an Position QModelIndex und QModelIndex_1

		  :param QModelIndex: Index eines Datei- oder Verzeichnisnamens
		  :type QModelIndex: PyQt5.QtCore.QModelIndex
		  :param QModelIndex_1: Index eines anderen Datei- oder Verzeichnisnamens
		  :type QModelIndex_1: PyQt5.QtCore.QModelIndex
		  :return: Angabe, ob der Datei-/verzeichnisname an QModelIndex in der Anzeigeordnung vor dem Datei-/Verzeichnisnamen an QModelIndex_1 kommt (True: ja, False: nein)
		  :rtype: Boolean
		  """
		lFileModelQFileSystemModel = self.sourceModel()
		lPfadString1 = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(
			lFileModelQFileSystemModel.filePath(QModelIndex))
		lPfadString2 = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(
			lFileModelQFileSystemModel.filePath(QModelIndex_1))
		lRueckgabeBoolean = False
		if os.path.isdir(lPfadString1) and os.path.isdir(lPfadString2) \
				or not os.path.isdir(lPfadString1) and not os.path.isdir(lPfadString2):
			if str.upper(lPfadString1) < str.upper(lPfadString2):
				lRueckgabeBoolean = True
		elif os.path.isdir(lPfadString1) and not os.path.isdir(lPfadString2):
			lRueckgabeBoolean = True
		return lRueckgabeBoolean

	def filterAcceptsRow(self, source_row, source_parent):
		"""Überschriebene Methode der Oberklasse. Führt die Filterung der Datei- und Verzeichnisnamen auf Zeilenbasis durch.

		:param source_row: Index der aktuellen Zeile
		:type source_row: int
		:param source_parent: Elter der aktuellen Zeile(?)
		:type source_parent: PyQt5.AtCore.QModelIndex
		:return: Angabe, ob aktuelle Zeile angezeigt werden soll (True: ja, False: nein)
		"""
		if(self.sFunktionString == 'Auswählen'):
			lFileModelQFileSystemModel = self.sourceModel()
			lSourceIndexQModelIndex = lFileModelQFileSystemModel.index(source_row, 0, source_parent)
			lPfadErweitertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(
				lFileModelQFileSystemModel.filePath(lSourceIndexQModelIndex))
			try:
				lRueckgabeBoolean = os.path.isdir(lPfadErweitertString) or os.path.getsize(lPfadErweitertString) > 0 \
									and not os.path.islink(lPfadErweitertString) \
									and (not os.name == 'nt' or not lPfadErweitertString.lower().endswith('.lnk'))
			except OSError: # Falls es bei der Abfrage zu einem Fehler kommt (passiert z.B. bei leerem CD-Laufwerk)
				lRueckgabeBoolean = False
		else:
			lRueckgabeBoolean = True
		return lRueckgabeBoolean


class SchluesseldateiFileDialog(QtWidgets.QFileDialog):
	"""
	Ein eigener DateiDialog zur Auswahl einer Schlüsseldatei.

	Die Klasse SchluesseldateiFileDialog ist eine Unterklasse von QtWidgets.QFileDialog. Sie modelliert einen modfizierten
	Dateiauswahldialog, der - je nach Anwendungszweck - die Auswahl eines existenten oder neu zu erstellenden Schlüsseldatei
	ermöglicht.
	"""
	def __init__(self, pParent, pViewQView, pFunktionString):
		"""Initialisiert ein Objekt der Klasse SchluesseldateiFileDialog.

		 :param pParent: Elter-Widget gemäß PyQt-Spezifikation
		 :type pParent:
		 :param pFunktionString: Ausgewählte Programmfunktion ("Verschlüsseln", "Entschlüsseln", "Vernichten")
		 :type pFunktionsStromg: String
		 """
		super(SchluesseldateiFileDialog, self).__init__(parent=pParent)
		self.sViewQView = pViewQView
		self.sFunktionString = pFunktionString

		self.setDirectory(LiSKonfiguration.Konfiguration.G_SCHLUESSELDATEI_VERZEICHNIS)
		self.setOption(QtWidgets.QFileDialog.DontUseNativeDialog, True)
		self.setOption(QtWidgets.QFileDialog.ReadOnly, True)

		self.sFileFilterProxyModel = SortProxyModel(pParent, pFunktionString)
		self.setProxyModel(self.sFileFilterProxyModel)

		self.setViewMode(QtWidgets.QFileDialog.Detail)
		self.setLabelText(QtWidgets.QFileDialog.Accept, pFunktionString)

		self.sListView = self.findChild(QtWidgets.QListView, 'listView')
		self.sListView.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

		self.sTreeView = self.findChild(QtWidgets.QTreeView, 'treeView')
		self.sTreeView.sortByColumn(0,QtCore.Qt.AscendingOrder)
		self.sTreeView.setSortingEnabled(False)
		self.sTreeView.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
		self.sTreeView.setRootIsDecorated(False)
		self.sTreeView.setItemsExpandable(False)

		if pFunktionString == 'Auswählen':
			self.setWindowTitle('Schlüsseldatei auswählen')
			self.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)
			self.setFileMode(QtWidgets.QFileDialog.ExistingFile)

			lFilenameLabel = self.findChild(QtWidgets.QLabel, 'fileNameLabel')
			lFilenameLabel.setVisible(False)

			lFilenameLineEdit = self.findChild(QtWidgets.QLineEdit, 'fileNameEdit')
			lFilenameLineEdit.setVisible(False)

			lFiletypeLabel = self.findChild(QtWidgets.QLabel, 'fileTypeLabel')
			lFiletypeLabel.setVisible(False)

			lFiletypeComboBox = self.findChild(QtWidgets.QComboBox, 'fileTypeCombo')
			lFiletypeComboBox.setVisible(False)

			self.sKeineLeerenDateienLabel = QtWidgets.QLabel('<b>Anzeige ohne Leerdateien und Verknüpfungen!</b>')

			lKeineLeerenDateienLabelVerticalLayout = QtWidgets.QVBoxLayout()
			lKeineLeerenDateienLabelVerticalLayout.setAlignment(QtCore.Qt.AlignCenter)
			lKeineLeerenDateienLabelVerticalLayout.addWidget(self.sKeineLeerenDateienLabel)
			lGridLayout = self.layout()
			lGridLayout.addLayout(lKeineLeerenDateienLabelVerticalLayout, 2, 1, QtCore.Qt.AlignLeft)
		else:
			self.setWindowTitle('Schlüsseldatei erzeugen')
			self.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
			self.setOption(QtWidgets.QFileDialog.DontConfirmOverwrite, False)
			self.setFileMode(QtWidgets.QFileDialog.AnyFile)
			self.setDefaultSuffix('.txt')
			lNeueSchluesseldateiNameString = 'LiSKey_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.txt'
			self.selectFile(lNeueSchluesseldateiNameString)

		self._connectSlots()

	def _connectSlots(self):
		"""
		Interne Methode. Verbindet Widget-Signale mit Slots
		"""
		self.sTreeView.pressed.connect(self._ersetzeTextAufOeffnenButton)
		self.sListView.pressed.connect(self._ersetzeTextAufOeffnenButton)

	def _ersetzeTextAufOeffnenButton(self):
		"""
		Interne Methode. Ersetzt den Text des Akzeptieren-Buttons (notwendig, da sich der Text bei Selektion eines Verzeichnisses ändert). Wird signalgesteuert aufgrufen.
		"""
		self.setLabelText(QtWidgets.QFileDialog.Accept, self.sFunktionString)

	def exec_(self):
		"""
		Überschriebene Methode der Oberklasse. Öffnet den Dialog modal. Returniert Pfad zur ausgewählten Datei als String. Wird der Abbrechen-Button betätigt, returniert die Methode None.
		"""
		if super(SchluesseldateiFileDialog, self).exec_():
			lAusgewaehlteDateiString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(self.selectedFiles()[0])
		else:
			lAusgewaehlteDateiString = None
		return(lAusgewaehlteDateiString)