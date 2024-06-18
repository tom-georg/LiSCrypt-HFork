# LiSCrypt - File encryption program using AES-GCM-256 or ChaCha20+HMAC (the latter for particularly large files)
# Copyright(C) 2018-2022 QUA-LiS NRW

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
Dieses Modul enthält eine Klasse zur Verwaltung der Konfiguration inkl. Aufrufparametern.
"""

from cryptography.fernet import Fernet

from Modell import LiSKonstanten

import argparse
import base91
import datetime
import logging
import os
import traceback
import yaml

class Konfiguration:
	"""
	Diese Klasse modelliert die Verwaltung der Konfiguration inkl. Aufrufparametern.
	"""
	# Globale aus Kommandozeile:
	G_AUFRUF_PARAMETER = None

	# Globale (mit Defaultwerten) aus Konfigurationsdatei:
	G_SCHLUESSELDATEI_VERZEICHNIS = LiSKonstanten.C_HOME_PFAD
	G_DATEIDIALOG_VERZEICHNIS = LiSKonstanten.C_HOME_PFAD
	G_SERVER_PORT = None

	@classmethod
	def liesKonfigurationEin(klass):
		"""
		Liest die Konfigurationsdatei und Aufrufparameter ein. Kann die Konfigurationsdatei nicht eingelesen werden,
		wird geprüft, ob dass Konfigurationsverzeichnis bereits	existiert; falls nicht, wird es angelegt.
		:return:
		"""
		try:
			with open(LiSKonstanten.C_KONFIGURATION_DATEINAME, 'r') as lKonfigurationsdatei:
				lKonfigurationsdaten = yaml.load(lKonfigurationsdatei, Loader=yaml.SafeLoader)
				if 'VERSCHLEIERT' in lKonfigurationsdaten:
					lSchluesseldateiVerzeichnisVerschluesseltBytes = bytes(base91.decode(lKonfigurationsdaten['VERZEICHNIS_SCHLUESSELDATEI']))
					lDateidialogVerzeichnisVerschluesseltBytes = bytes(base91.decode(lKonfigurationsdaten['VERZEICHNIS_DATEIDIALOG']))
					lServerPortVerschleiertBytes = bytes(base91.decode(lKonfigurationsdaten['SERVER_PORT']))
					lKonfigurationsentschleiererFernet = Fernet(LiSKonstanten.C_KONFIGURATION_FERNET_SCHLUESSEL)
					lSchluesseldateiVerzeichnisString = lKonfigurationsentschleiererFernet.decrypt(lSchluesseldateiVerzeichnisVerschluesseltBytes).decode()
					lDateidialogVerzeichnisString = lKonfigurationsentschleiererFernet.decrypt(lDateidialogVerzeichnisVerschluesseltBytes).decode()
					lServerPortInt = int(lKonfigurationsentschleiererFernet.decrypt(lServerPortVerschleiertBytes).decode())
				else:
					lSchluesseldateiVerzeichnisString = lKonfigurationsdaten['VERZEICHNIS_SCHLUESSELDATEI']
					lDateidialogVerzeichnisString = lKonfigurationsdaten['VERZEICHNIS_DATEIDIALOG']
					lServerPortInt = int(lKonfigurationsdaten['SERVER_PORT'])
				klass.G_SCHLUESSELDATEI_VERZEICHNIS = lSchluesseldateiVerzeichnisString
				klass.G_DATEIDIALOG_VERZEICHNIS = lDateidialogVerzeichnisString
				klass.G_SERVER_PORT = lServerPortInt
		except: # Kann Konfigurationssdatei nicht auslesen (nicht vorhanden, Verzeichnis existiert gar nicht, Entschleierung klappt nicht etc.)
			if LiSKonstanten.C_BETRIEBSSYSTEM.startswith('linux') or LiSKonstanten.C_BETRIEBSSYSTEM == 'darwin' or LiSKonstanten.C_BETRIEBSSYSTEM == 'win32':
				if not os.path.exists(LiSKonstanten.C_KONFIG_UND_LOG_PFAD) and not os.path.isfile(LiSKonstanten.C_KONFIG_UND_LOG_PFAD):
					try:
						os.mkdir(LiSKonstanten.C_KONFIG_UND_LOG_PFAD)
					except OSError: # Konfigurations- und Logverzeichnis existiert nicht. Kann es auch nicht anlegen.
						raise
		klass.parseAufrufparameter()

	@classmethod
	def speichereKonfiguration(klass):
		"""
		Schreibt die aktuelle Konfiguration verschleiert in die Konfigurationsdatei.
		"""
		lKonfigruationsverschleiererFernet = Fernet(LiSKonstanten.C_KONFIGURATION_FERNET_SCHLUESSEL)

		lSchluesseldateiVerzeichnisVerschleiertBytes = lKonfigruationsverschleiererFernet.encrypt(klass.G_SCHLUESSELDATEI_VERZEICHNIS.encode())
		lDateidialogVerzeichnisVerschleiertBytes = lKonfigruationsverschleiererFernet.encrypt(klass.G_DATEIDIALOG_VERZEICHNIS.encode())
		lServerPortVerschleiertBytes = lKonfigruationsverschleiererFernet.encrypt(str(klass.G_SERVER_PORT).encode())

		lSchluesseldateiVerzeichnisVerschleiertBase91String = base91.encode(lSchluesseldateiVerzeichnisVerschleiertBytes)
		lDateidialogVerzeichnisVerschleiertBase91String = base91.encode(lDateidialogVerzeichnisVerschleiertBytes)
		lServerPortVerschleiertBase91String = base91.encode(lServerPortVerschleiertBytes)

		lKonfigurationsdaten = {
			'VERZEICHNIS_SCHLUESSELDATEI': lSchluesseldateiVerzeichnisVerschleiertBase91String,
			'VERZEICHNIS_DATEIDIALOG': lDateidialogVerzeichnisVerschleiertBase91String,
			'SERVER_PORT': lServerPortVerschleiertBase91String,
			'VERSCHLEIERT': 'true'
		}
		try:
			with open(LiSKonstanten.C_KONFIGURATION_DATEINAME, 'w') as lKonfigurationsdatei:
				yaml.dump(lKonfigurationsdaten, lKonfigurationsdatei)
		except:
			if logging.getLogger('root'):
				logging.exception(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': Fehler beim Schreiben der Konfigurationsdatei')
			else:
				print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': Fehler beim Schreiben der Konfigurationsdatei')
				traceback.print_exc()

	@classmethod
	def gibAurufparameterAlsGeordneteListe(klass):
		"""
		Returniert die Aufrufparameter als nach festen Regeln geordnete Liste von String.

		:return: Geordnete Liste der Aufrufparameter
		:rtype: Liste von Strings
		"""
		lAufrufparameterList = [klass.G_AUFRUF_PARAMETER.logging]
		lAufrufparameterList.append(klass.G_AUFRUF_PARAMETER.action)
		lAufrufparameterList.append(klass.G_AUFRUF_PARAMETER.originals)
		lAufrufparameterList.append(klass.G_AUFRUF_PARAMETER.keytype)
		lAufrufparameterList.extend(klass.G_AUFRUF_PARAMETER.items)
		return lAufrufparameterList

	@classmethod
	def parseAufrufparameter(klass):
		"""
		Wertet die Aufrufparameter aus und legt den Ergebnis-Namespace global ab.
		"""
		lParserArgumentParser = argparse.ArgumentParser()
		lParserArgumentParser.add_argument_group('group')
		lParserArgumentParser.add_argument('-f', '--logfile', action='store_const', help='log exceptions to file', dest='logging', const='file')

		lFunktionsgruppeGroup = lParserArgumentParser.add_mutually_exclusive_group()
		lFunktionsgruppeGroup.add_argument('-e', '--encrypt', action='store_const',
										   help='set program action: encryption', dest='action', const='encrypt')
		lFunktionsgruppeGroup.add_argument('-d', '--decrypt', action='store_const', help='set program action: decryption (default)',
										   dest='action', const='decrypt')
		if LiSKonstanten.C_IQB_VERSION is False:
			lFunktionsgruppeGroup.add_argument('-w', '--wipe', action='store_const',
											   help='set program action: wipe', dest='action', const='wipe')
			lOriginaleVernichtenGroup = lParserArgumentParser.add_mutually_exclusive_group()
			lOriginaleVernichtenGroup.add_argument('-o', '--originals', action='store_const',
											   help='set option: wipe original files (default) (no effect when program action is set to wipe)', dest='originals', const='wipeoriginals')
			lOriginaleVernichtenGroup.add_argument('-l', '--leave', action='store_const',
											   help='set option: keep original files (no effect when program action is set to wipe)', dest='originals', const='keeporiginals')
			lSchluesselartgruppeGroup = lParserArgumentParser.add_mutually_exclusive_group()
			lSchluesselartgruppeGroup.add_argument('-p', '--password', action='store_const',
												   help='set key type: password (no effect when program action is set to wipe)', dest='keytype', const='password')
			lSchluesselartgruppeGroup.add_argument('-k', '--keyfile', action='store_const', help='set key type: key file (no effect when program action is set to wipe)',
												   dest='keytype', const='keyfile')
			lSchluesselartgruppeGroup.add_argument('-c', '--choose', action='store_const',
												   help='set key type: choose later (default) (no effect when program action is set to wipe)',
												   dest='keytype', const='choose')
			lParserArgumentParser.set_defaults(logging='screen', action='decrypt', originals='wipeoriginals', keytype='choose') # 'decrypt' wg. Doppelklick auf .lisx-Dateien
		else:
			lParserArgumentParser.set_defaults(logging='screen', action='decrypt', originals='wipeoriginals', keytype='password') # 'decrypt' wg. Doppelklick auf .lisx-Dateien

		lParserArgumentParser.add_argument('items', metavar='file|directory', nargs='*',
										   help='file or directory to be processed')
		klass.G_AUFRUF_PARAMETER = lParserArgumentParser.parse_args()