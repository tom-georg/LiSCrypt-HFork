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
Dieses Modul enthält die Klassen zur Realisierung eines eigenen Bestätigungsdialogs für die auszuführende Programmfunktion.
"""

from Modell import LiSKonstanten
from Sonstiges import LiSWerkzeuge

from PyQt5 import QtCore, QtWidgets

import os

class Ui_ListDialog(QtWidgets.QDialog):
    """Ein eigener Bestätigungsdialog für die Ausführung einer Programmfunktion.

    Die Klasse SortProxyModel ist eine Unterklasse der von tWidgets.QDialog Sie modelliert einen
    Bestätigungsdialog für die Ausführung eines Programmfunktions inkl. Auflistung der betroffenen Dateien und/oder Verzeichnisse.
    """
    def __init__(self, pParent, pFunktionString, pDateienUndVerzeichnisseList, pOriginaleVernichtenBoolean):
        """
        Initialisiert ein Objekt der Klasse Ui_ListDialog (Bestätigungsdialog für Ausführung einer Programmfunktion)

        :param pParent: Elter gemäß PyQt-Spezifikation
        :type pParent: PyQt5.QtCore.QObject
        :param pFunktionString: Programmfunktion (LiSKonstanten.C_PROGRAMMFUNKTION_VERSCHLUESSELN_LITERAL/LiSKonstanten.C_PROGRAMMFUNKTION_ENTSCHLUESSELN_LITERAL/LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL)
        :type pFunktionString: String
        :param pDateienUndVerzeichnisseList: Pfadnamen der ausgewählten Dateien und/oder Verzeichnisse (reduziert oder erweitert)
        :type pDateienUndVerzeichnisseList: Liste von Strings
        :param pOriginaleVernichtenBoolean: Nutzerauswahl der Option "Originale vernichten" (True: ja, False: nein)
        :type pOriginaleVernichtenBoolean: Boolean
        """
        super(Ui_ListDialog, self).__init__(parent=pParent)
        self.sParent = pParent
        self.sDateienUndVerzeichnisseList = pDateienUndVerzeichnisseList

        lLabelText = 'Folgende Dateien/Verzeichnisse '
        if pOriginaleVernichtenBoolean is True and pFunktionString != LiSKonstanten.C_PROGRAMMFUNKTION_VERNICHTEN_LITERAL:
            lLabelText += '<strong>' + pFunktionString.lower() + '</strong> und die Originaldateien <strong>vernichten</strong>''?'
        else:
            lLabelText += '<strong>' + pFunktionString.lower() + '</strong>?'
        self.sLabeltextString = lLabelText

        self._setupUi()

    def _setupUi(self):
        """
        Interne Methode. Initialisiert die GUI-Elemente des Dialogs.
        """
        self.setWindowFlag(QtCore.Qt.WindowStaysOnTopHint)
        self.setObjectName("Dialog")
        self.setWindowModality(QtCore.Qt.ApplicationModal)
        self.setMinimumSize(350,265)
        #self.setMaximumSize(700,265)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(self)
        self.label.setWordWrap(True)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.listWidget = QtWidgets.QListWidget(self)
        self.listWidget.setObjectName("listWindget")
        self.listWidget.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)

        for lPfadString in self.sDateienUndVerzeichnisseList:
            lPfadReduziertString = LiSWerkzeuge.Pfadwerkzeuge.ermittleReduziertenPfad(lPfadString)
            lEndnameString = os.path.basename(lPfadReduziertString)
            if os.path.isdir(lPfadString):
                lNeuerEintrag = QtWidgets.QListWidgetItem('(Ordner)\t' + lEndnameString)
            else:
                lNeuerEintrag = QtWidgets.QListWidgetItem('(Datei)\t' + lEndnameString)
            lNeuerEintrag.setToolTip(lPfadString)
            self.listWidget.addItem(lNeuerEintrag)

        self.verticalLayout.addWidget(self.listWidget)
        self.buttonBox = QtWidgets.QDialogButtonBox(self)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.button(QtWidgets.QDialogButtonBox.Cancel).setText('Abbrechen')
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)
        self.verticalLayout_2.addLayout(self.verticalLayout)

        self._retranslateUi()
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        QtCore.QMetaObject.connectSlotsByName(self)

    def _retranslateUi(self):
        """
        Interne Methode. Übersetzung der GUI-Elemente, die per QtDesigner erstellt wurden
        """
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("Ui_ListDialog", "Bestätigung"))
        self.label.setText(_translate("Ui_ListDialog", self.sLabeltextString))

    def erbitteBestaetigung(self):
        """
        Öffnet den initialisierten Dialog und returniert die Nutzerauswahl

        :return: Nutzerauswahl (True=OK, False=Abbrechen)
        :rtype: Boolean
        """
        self.sParent.setzeStatusleisteUndGUIZustand('Sicherheitsabfrage...')
        lBestaetigung = self.exec_()
        return(lBestaetigung == QtWidgets.QDialog.Accepted)
