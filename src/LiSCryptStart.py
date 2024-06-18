from Modell import LiSKonfiguration, LiSKonstanten


from Steuerung.LiSCrypt import QController

from PyQt5 import QtWidgets, QtCore

import datetime
import logging
import traceback


# Top-level Skript-Umgebung ("Hauptprogramm"):
if __name__ == '__main__':

	QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, False)
	try:
		LiSKonfiguration.Konfiguration.liesKonfigurationEin()
	except OSError:
		lFehlermeldungString = 'Fehler beim Zugriff auf Temporärverzeichnis ' + LiSKonstanten.C_KONFIG_UND_LOG_PFAD
		print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': ' + lFehlermeldungString)
		traceback.print_exc()
	else:
		try:
			lControllerQController = QController()
			if lControllerQController.istMaster():
				lAufrufparameterList = LiSKonfiguration.Konfiguration.gibAurufparameterAlsGeordneteListe()
				lControllerQController.starteFunktionAusParameterliste(lAufrufparameterList) # Wird auch bei Start ohne Parameterübergabe über default-Werte aufgerufen (Parameteranzahlen <= 4 werden in Methode übersprungen)
				lControllerQController.warteAufViewEreignisse() # Veranlasst den Start der Haupt-Ereignisschleife
			else:
				lAufrufparameterList = LiSKonfiguration.Konfiguration.gibAurufparameterAlsGeordneteListe()
				lControllerQController.sendeAufrufparameterAnMaster()
		except Exception:
			if logging.getLogger('root'):
				logging.exception(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Fataler Fehler')
			else:
				print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Fataler Fehler')
				traceback.print_exc()
		else:
			if lControllerQController is not None:
				lControllerQController.stoppeServerThread()
		LiSKonfiguration.Konfiguration.speichereKonfiguration()

