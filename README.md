# LiSCrypt 1.0.10
LiSCrypt ist ein Programm zur symmetrischen Verschlüsselung von Einzeldateien unter Verwendung von AES-GCM-256 bzw. einer Kombination von ChaCha20 und HMAC für sehr große Dateien.

Es wurde ursprünglich von der Qualitäts- und UnterstützungsAgentur - Landesinstitut für Schule in Nordrhein-Westfalen entwickelt.

## Prozedere
Die folgenden Ausführungen sollen Ihnen helfen, eine lokale Kopie von LiSCrypt auf Ihrem Rechner zu starten, die Sie für eigene Weiterentlickungen oder zu Testzwecken verwenden wollen. Falls Sie LiSCrypt in Ihrer Umgebung als ausführbares Programm ausrollen möchten, berücksichtigen Sie bitte die Hinweise unter "Ausrollen".

### Voraussetzungen
Voraussetzungen für die Verwendung von LiSCrypt

* Python 3.9.x
* Windows, macOS oder Linux

### Benötigte Bibliotheken
LiSCrypt 1.0.10 wurde u.a. mit den im Folgenden angegebenen Versionen getestet. Möglicherweise funktionieren insb. neuere Versionen ebenfalls.

* [base91, Version 1.0.1](https://github.com/aberaud/base91-python) - Base91-Kodiere/-Dekodierer
* [pyca/cryptography, Version 36.0.1](https://cryptography.io/en/latest/) - Kryptografie-Backend
* [psutil, Version 5.9.0](https://psutil.readthedocs.io) - Bibliothek für die Ermittlung von Systeminformationen
* [PyQt 5, Version 5.15.6](https://riverbankcomputing.com/software/pyqt/intro) - Python-Schnittstelle zum GUI-Framework Qt 5
* Unter Windows: [pywin32, Version 303](https://github.com/mhammond/pywin32) - Bibliothek für Zugriff auf die Windows API
* [PyYAML, Version 6.0](https://pyyaml.org/) - Bibliothek für Im- und Export von YAML-Dateien

Nähere Informationen zu den benötigten Fremdquellen finden sich in der Dokumentation.

### Installation
# Anleitung zur Installation und Einrichtung

Diese Anleitung beschreibt die Schritte zur Installation von Python, pip, und zur Einrichtung einer virtuellen Umgebung. Anschließend wird erklärt, wie die Abhängigkeiten aus der Datei `requirements.txt` installiert werden.

## Schritt 1: Python installieren

1. Besuchen der offiziellen Python-Website: [https://www.python.org/](https://www.python.org/)
2. Herunterladen der neuesten Python-Version (Python 3.12 wird empfohlen).
3. Installieren von Python:
   - Unter Windows: Den Installer starten und die Option "Add Python to PATH" aktivieren, bevor auf "Install Now" geklickt wird.
   - Unter macOS/Linux: Den Anweisungen auf der Website folgen oder einen Paketmanager verwenden (z.B. `brew install python` für Homebrew auf macOS oder `sudo apt-get install python3` für Ubuntu/Debian-basierte Systeme).

## Schritt 2: pip installieren

1. Überprüfen, ob pip bereits installiert ist, indem der folgende Befehl im Terminal eingegeben wird:
   ```sh
   pip --version
   ```
2. Wenn pip nicht installiert ist, das Installations-Skript von [https://bootstrap.pypa.io/get-pip.py](https://bootstrap.pypa.io/get-pip.py) herunterladen.
3. Das Installations-Skript ausführen:
   ```sh
   python get-pip.py
   ```

## Schritt 3: Virtuelle Umgebung einrichten

1. Erstellen einer virtuellen Umgebung:
   ```sh
   python -m venv venv
   ```
   Dies erstellt ein Verzeichnis namens `venv`, das die virtuelle Umgebung enthält.

2. Aktivieren der virtuellen Umgebung:
   - Unter Windows:
     ```sh
     .\venv\Scripts\activate
     ```
   - Unter macOS/Linux:
     ```sh
     source venv/bin/activate
     ```

## Schritt 4: Abhängigkeiten installieren

1. Sicherstellen, dass die virtuelle Umgebung aktiviert ist (es sollte `(venv)` in der Kommandozeile zu sehen sein).
2. Installieren der Abhängigkeiten aus der `requirements.txt`-Datei:
   ```sh
   pip install -r requirements.txt
   ```

## Zusätzliche Hinweise

- Um die virtuelle Umgebung zu deaktivieren, den Befehl `deactivate` eingeben.
- Um sicherzustellen, dass alle Abhängigkeiten korrekt installiert wurden, überprüfen, ob keine Fehlermeldungen während der Installation aufgetreten sind.

### Start des Programms
1. Starten des Programms:
    ```
    python3 -m Steuerung.LiSCrypt
    ```
    oder Import in eine beliebige Python-IDE. Entwickelt wurde LiSCrypt mit der Community-Variante von [PyCharm](https://www.jetbrains.com/pycharm/download/).
    
2. Test aller Programmfunktionen (Verschlüsseln, Entschlüsseln, Vernichten) mit Dummy-Dateien.

### Ausrollen

Zum Ausrollen von LiSCrypt in ausführbarer Form kann [PyInstaller](https://www.pyinstaller.org/) verwendet werden. Dabei ist insbesondere auf *hidden imports* und die Einbeziehung der [Visual C++ Runtime-Biblitoheken](https://support.microsoft.com/de-de/help/2977003/the-latest-supported-visual-c-downloads) zu achten.

### LiSCrypt Shell-Erweiterung (Windows)

Unter Windows existiert seit Version 1.0.0 von LiSCrypt eine Shell-Erweiterung. Damit können die wesentlichen Programmfunktionen auch per Rechtsklick auf Dateien/Ordner ausgeführt werden. Die Shell-Erweiterung wurde mit Visual Studio 2019 in C++ unter Verwendung von ATL erstellt. Der Quelltext ist ebenfalls unter https://github.com/MaWe2019/LiSCrypt_public/releases verfübar.

## Beiträge zur Weiterentwicklung

Sie möchten uns bei der Weiterentwicklung von LiSCrypt unterstützen? Wenden Sie sich an Martin Weise bei [QUA-LiS NRW](https://www.qua-lis.nrw.de)

### Quelltext-Formatierung

* Weitestgehende Verwendung von camelCase (entgegen der PEP8-Spezifikation)
* Einrückungen mit Tabs (entgegen der PEP8-Spezifikation)
* Modul- und Klassennamen beginnen mit einem Großbuchstaben
* Konstanten und globale Variablen werden komplett in Großbuchstaben geschrieben
* Methodennamen beginnen mit einem Kleinbuchstaben und beschreiben sematisch eine Tätigkeit
* Modulnamen beginnen mit 'LiS'
* Klassennamen beginnen mit 'Q', Klassennamen für GUI-Komponenten beginnen mit 'Ui_'
* Verwendung von Präfixen zur Unterscheidung von Attributen/Bezugsobjekten ('s'), Parametern ('p') und lokalen Variablen ('l')
* Attribute/Bezugsobjekte, Parameter und lokale Varaiblen enden mit einer Typangabe (z.B. lNachrichtString)
* Bezeichner und Kommentare in deutscher Sprache (ohne Umlaute)
* Ansätze des MVC-Prinzips

## Versionierung und Updates

Die Versionierung von LiSCrypt folgt dem [SemVer](http://semver.org/)-Schema. Der [Quelltext zu den verschiedenen Versionen](https://github.com/MaWe2019/LiSCrypt_public/releases) wird in Form von zip-Archiven in diesem Repository zur Verfügung gestellt.

## Copyright

* [QUA-LiS NRW](https://www.qua-lis.nrw.de), **Projektleitung:** Martin Weise

## Lizenz

LiSCrypt ist lizenziert unter der GNU General Public License Version 3 (GNU GPL v3). Den Lizenztext finden Sie in der Datei [COPYING](COPYING).

## Sicherheitsaudits

Für die Version 0.9.5 von LiSCrypt wurden zwei externe Sicherheitsprüfungen durchgeführt, bei denen auch das Verschlüsselungsverfahren in den Blick genommen wurde.

## Mitwirkende

* Dr. Albert Kapune, Tests
* Arbeitsbereich 5 von [QUA-LiS NRW](https://www.qua-lis.nrw.de), Verbesserungsvorschläge

## ToDo

* Verhalten bei parallelem Doppelklick auf mehrere verschlüsselte Dokumente
* Egränzung/Ausschwärfung der Quelltext-Dokumentation