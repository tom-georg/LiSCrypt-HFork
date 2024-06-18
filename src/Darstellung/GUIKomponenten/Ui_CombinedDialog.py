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

"""Dieses Modul enthält die Klassen zur Realisierung eines eigenen Dateiauswahldialogs."""

from Modell import LiSKonfiguration
from Modell import LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtWidgets, QtCore

import os


class FileFilterProxyModel(QtCore.QSortFilterProxyModel):
    """
    Ein eigenes ProxyModel zur Filterung von Datei- und Verzeichnisnamen.

    Die Klasse FileFilterProxyModel ist eine Unterklasse der von QtCore.QSortFilterProxyModel. Sie modelliert ein
    ProxyModel für die Filterung und Sortierung von Dateienamen in einem Dateiauswahldialog.
    """
    def __init__(self, pParent, pFunktionString, pDateienFiltern=False):
        """Initialisiert ein Objekt der Klasse FileFilterProxyModel

        :param pParent: Elter-Widget gemäß PyQt-Spezifikation
        :type pParent: PyQt5.QtCore.QObject
        :param pFunktionString: Ausgewählte Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
        :type pFunktionString: String
        :param pDateienFiltern: Legt fest, ob Dateien im Dialog ausgefiltert werden sollen (True: ja, False: nein) (optional)
        :type pDateienFiltern: Boolean
        """
        super(FileFilterProxyModel, self).__init__(parent=pParent)
        self.sFunktionString = pFunktionString
        self.sDateienFiltern = pDateienFiltern
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
        if(self.sDateienFiltern is True):
            lFileModelQFileSystemModel = self.sourceModel()
            lSourceIndexQModelIndex = lFileModelQFileSystemModel.index(source_row, 0, source_parent)
            lDateinameString = lFileModelQFileSystemModel.fileName(lSourceIndexQModelIndex)
            lPfadString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(
                lFileModelQFileSystemModel.filePath(lSourceIndexQModelIndex))
            try:
                lRueckgabeBoolean = self.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL and not lDateinameString.endswith(LiSKonstanten.C_DATEIENDUNG) \
                                    or self.sFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL and lDateinameString.endswith(LiSKonstanten.C_DATEIENDUNG) \
                                    or os.path.isdir(lPfadString)
            except OSError: # Falls es bei der Abfrage zu einem Fehler kommt (passiert z.B. bei leerem CD-Laufwerk)
                lRueckgabeBoolean = False
        else:
            lRueckgabeBoolean = True
        return lRueckgabeBoolean

    def setzeDateienFiltern(self, pDateienFilternBoolean):
        """Setzt den Wert des Attributs sDateienFiltern auf den Wert pDateienFiltern. Legt damit fest, ob eine
        Ausfilterung bestimmter Dateinamen stattfinden soll oder nicht.

        :param pDateienFilternBoolean: Legt fest, ob Dateinamen im Dialog ausgefiltert werden sollen (True: ja, False: nein)
        :type pDateienFilternBoolean: Boolean

        """
        self.sDateienFiltern = pDateienFilternBoolean

class KombinierterFileDialog(QtWidgets.QFileDialog):
    """Ein eigener DateiDialog mit erweiterten Auswahlmöglichkeiten.

    Die Klasse KombinierterFileDialog ist eine Unterklasse von QtWidgets.QFileDialog. Sie modelliert einen modfizierten
    Dateiauswahldialog, der die Auswahl mehrerer Dateien und/oder Verzeichnisse sowie die Wahl zusätzlicher Optionen
    ermöglicht. Der akzeptierende Button wird zudem entsprechend der vom Nutzer ausgewählten Programmfunktion beschriftet
    und der Hintergrund der Datei- und Verzeichnisliste entsprechend eingefärbt. Die Implementation basiert auf der
    Non-Native-Variante von QtWidgets.QFileDialog
    """
    def __init__(self, pParent, pFunktionString, pOriginaleVernichtenBoolean):
        """Initialisiert ein Objekt der Klasse KombinierterFileDialog.

        :param pParent: Elter-Widget gemäß PyQt-Spezifikation
        :type pParent: PyQt5.QtWidgets.QWidget
        :param pFunktionString: Ausgewählte Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL, LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
        :type pFunktionString: String
        :param pOriginaleVernichtenBoolean: Nutzerauswahl der Option "Originale vernichten" (True: ja, False: nein)
        :type pOriginaleVernichtenBoolean: Boolean
        """
        super(KombinierterFileDialog, self).__init__(parent=pParent)
        self.sFunktionString = pFunktionString
        self.sEintraegeList = []

        self.setWindowTitle(pFunktionString + ': Dateien und Verzeichnisse auswählen')
        self.setDirectory(LiSKonfiguration.Konfiguration.G_DATEIDIALOG_VERZEICHNIS)
        self.setOption(QtWidgets.QFileDialog.DontUseNativeDialog, True)
        self.setOption(QtWidgets.QFileDialog.ReadOnly, True)

        self.sFileFilterProxyModel = FileFilterProxyModel(pParent, pFunktionString)
        self.setProxyModel(self.sFileFilterProxyModel)

        self.setAcceptMode(QtWidgets.QFileDialog.AcceptOpen)
        self.setLabelText(QtWidgets.QFileDialog.Accept, pFunktionString)

        self.setFileMode(QtWidgets.QFileDialog.ExistingFile)
        self.setViewMode(QtWidgets.QFileDialog.Detail)
        self.setLabelText(QtWidgets.QFileDialog.Accept, pFunktionString)

        self.sListView = self.findChild(QtWidgets.QListView, 'listView')
        self.sListView.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        if pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
            self.sListView.setStyleSheet('background-color:  #e6ffe6')
        elif pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
            self.sListView.setStyleSheet('background-color:  #ffe6e6')

        self.sTreeView = self.findChild(QtWidgets.QTreeView, 'treeView')
        self.sTreeView.sortByColumn(0,QtCore.Qt.AscendingOrder)
        self.sTreeView.setSortingEnabled(False)
        self.sTreeView.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.sTreeView.setRootIsDecorated(False)
        self.sTreeView.setItemsExpandable(False)
        if pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
            self.sTreeView.setStyleSheet('background-color:  #e6ffe6')
        elif pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
            self.sTreeView.setStyleSheet('background-color:  #ffe6e6')

        lFilenameLabel = self.findChild(QtWidgets.QLabel, 'fileNameLabel')
        lFilenameLabel.setVisible(False)

        lFilenameLineEdit = self.findChild(QtWidgets.QLineEdit, 'fileNameEdit')
        lFilenameLineEdit.setVisible(False)

        lFiletypeLabel = self.findChild(QtWidgets.QLabel, 'fileTypeLabel')
        lFiletypeLabel.setVisible(False)

        lFiletypeComboBox = self.findChild(QtWidgets.QComboBox, 'fileTypeCombo')
        lFiletypeComboBox.setVisible(False)

        self.sOriginaleVernichtenCheckBox = QtWidgets.QCheckBox('Originale vernichten')
        self.sOriginaleVernichtenCheckBox.setChecked(pOriginaleVernichtenBoolean)
        if LiSKonstanten.C_IQB_VERSION is True:
            self.sOriginaleVernichtenCheckBox.setVisible(False)

        self.sVerschluesselteDateienAusblendenCheckBox = QtWidgets.QCheckBox('Verschlüsselte Dateien (*' + LiSKonstanten.C_DATEIENDUNG +') ausblenden')
        self.sVerschluesselteDateienAusblendenCheckBox.setChecked(False)

        self.sUnverschluesselteDateienAusblendenCheckBox = QtWidgets.QCheckBox('Nur verschlüsselte Dateien (*' + LiSKonstanten.C_DATEIENDUNG +') anzeigen')
        self.sUnverschluesselteDateienAusblendenCheckBox.setChecked(False)

        if pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL:
            lLiSXDateienVerticalLayout = QtWidgets.QVBoxLayout()
            lLiSXDateienVerticalLayout.setAlignment(QtCore.Qt.AlignCenter)
            lLiSXDateienVerticalLayout.addWidget(self.sVerschluesselteDateienAusblendenCheckBox)
            lGridLayout = self.layout()
            lGridLayout.addLayout(lLiSXDateienVerticalLayout, 3, 1, QtCore.Qt.AlignRight)
        elif pFunktionString == LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL:
            lLiSXDateienVerticalLayout = QtWidgets.QVBoxLayout()
            lLiSXDateienVerticalLayout.setAlignment(QtCore.Qt.AlignCenter)
            lLiSXDateienVerticalLayout.addWidget(self.sUnverschluesselteDateienAusblendenCheckBox)
            lGridLayout = self.layout()
            lGridLayout.addLayout(lLiSXDateienVerticalLayout, 3, 1, QtCore.Qt.AlignRight)
        if pFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
            lOriginaleVernichtenVerticalLayout = QtWidgets.QVBoxLayout()
            lOriginaleVernichtenVerticalLayout.setAlignment(QtCore.Qt.AlignCenter)
            lOriginaleVernichtenVerticalLayout.addWidget(self.sOriginaleVernichtenCheckBox)
            lGridLayout = self.layout()
            lGridLayout.addLayout(lOriginaleVernichtenVerticalLayout, 2,1,QtCore.Qt.AlignRight)

        self._connectSlots()

    def _connectSlots(self):
        """
        Interne Methode. Verbindet Widget-Signale mit Slots.
        """
        self.sVerschluesselteDateienAusblendenCheckBox.clicked.connect(self._setzeDateienFilternInProxyModel)
        self.sUnverschluesselteDateienAusblendenCheckBox.clicked.connect(self._setzeDateienFilternInProxyModel)
        self.sTreeView.pressed.connect(self._ersetzeTextAufOeffnenButton)
        self.sListView.pressed.connect(self._ersetzeTextAufOeffnenButton)

    def _setzeDateienFilternInProxyModel(self, pDateienFilternBoolean):
        """
        Interne Methode. Veranlasst ein Objekt der Klasse FileFilterInProxymodel, das Attribut sDateienFiltern auf
        pAusgewaehltBoolean zu setzen. Führt anschließend einen Refresh der Anzeige durch.

        :param pDateienFilternBoolean: Legt fest, ob Dateinamen im Dialog ausgefiltert werden sollen (True: ja, False: nein)
        :type pDateienFilternBoolean: Boolean
        """
        self.sFileFilterProxyModel.setzeDateienFiltern(pDateienFilternBoolean)
        # Refresh der Dateiliste erzwingen:
        lDirQDir = self.directory()
        self.setDirectory(None)
        self.setDirectory(lDirQDir)

    def _ersetzeTextAufOeffnenButton(self):
        """
        Interne Methode. Ersetzt die Beschriftung des "Öffnen"-Buttons durch self.sFunktionString. Wird signalgesteuert augerufen.
        """
        self.setLabelText(QtWidgets.QFileDialog.Accept, self.sFunktionString)

    def accept(self):
        """Akzeptieren-Methode des Dateidialogs.

        Überschriebene Methode der Oberklasse. Wird beim Akzeptieren der Dateiauswahl durch den Nutzer automatisch
        aufgerufen. Speichert die Nutzerwahl der Vernichtung von Originaldateien (True/False) und dann die UNC-Pfade
        der ausgewählten Dateien und Verzeichnisse im Attribut sEintraegeList. Zudem speichert die Methode das aktuelle
        Verzeichnis des Dateidialogs in der globalen Variablen G_DATEIDIALOG_VERZEICHNIS und schließt den Dateidialog.
        """
        self.sEintraegeList.append(self.sOriginaleVernichtenCheckBox.isChecked())
        lAusgewaehlteIndizesList = self.sTreeView.selectionModel().selectedIndexes()
        for lIndex in lAusgewaehlteIndizesList:
            if lIndex.column() == 0:
                lErweiterterPfadAuswahlString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(
                    os.path.join(str(self.directory().absolutePath()), str(lIndex.data())))
                self.sEintraegeList.append(lErweiterterPfadAuswahlString)
        lErweiterterPfadVerzeichnisString = LiSWerkzeuge.Pfadwerkzeuge.ermittleErweitertenPfad(self.directory().absolutePath())
        LiSKonfiguration.Konfiguration.G_DATEIDIALOG_VERZEICHNIS = lErweiterterPfadVerzeichnisString
        self.close()

    def exec_(self):
        """
        Überschriebene Methode der Oberklasse. Öffnet den Dialog modal. Gibt die Dateiauswahl des Nutzers als erweiterte Pfadangabe zurück.

        :return: Pfadangaben
        :rtype: Liste von Strings
        """
        super(KombinierterFileDialog, self).exec_()
        return(self.sEintraegeList)

