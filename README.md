[ENGLISH]

<#
  This script is free software: you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This script is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  <https://www.gnu.org/licenses/>.
#>

# Pi Node Windows Setup Helper Script

**Version:** 2025-07-26
**Author:** Fingerkrampf / t.me/PiNetzwerkDeutschland
**License:** GNU General Public License v3.0

## Overview

This PowerShell script simplifies and automates the setup of a Pi Node on Windows 11 (using PowerShell 5.1). It offers a comprehensive solution covering both basic node installation and advanced configurations, such as WireGuard tunnels for operation behind IPv6 connections.

The script is designed to be user-friendly, guiding the user through an interactive menu.

## 🌟 Key Features

* **Interactive Menu:** Easy navigation and control of all setup steps.
* **Automated Installation & Configuration:**
    * Windows Updates
    * WSL2 (Windows Subsystem for Linux Version 2) setup
    * Docker Desktop installation and autostart configuration
    * Pi Node software installation
    * Firewall port openings (31400-31409 TCP)
    * PuTTY installation
    * WireGuard Windows Client installation and key generation
* **WireGuard Server Automation:**
    * Automatic setup of a WireGuard server on a Linux vServer via SSH (password or key authentication).
    * Generation and transfer of necessary configuration files.
    * Automatic configuration of the WireGuard client on Windows.
    * Ideal for users with a pure IPv6 internet connection at home to obtain a public IPv4 address for the node.
* **PiCheck Integration:** Download, unpack, and start the latest version of the PiCheck analysis tool.
* **Robust Error Handling:**
    * The script does not abruptly terminate on most errors.
    * Detailed error messages are logged with timestamps in a separate file (`pi_node_setup_ERROR_log.txt`).
    * The user is informed about errors and has the option to return to the main menu.
* **Comprehensive Logging:** All important actions are logged in the `pi_node_setup_log.txt` file in the script directory.
* **Undo Options:** Options to uninstall individual components or completely remove all changes made by the script.

## 🛠️ Prerequisites

* Windows 11 (tested on Home versions with current patches).
* PowerShell 5.1 (included by default in Windows 11).
* **Administrator rights** are mandatory for executing the script. The script will attempt to restart itself with elevated privileges if necessary.
* For WireGuard server setup:
    * A Linux vServer (tested with Debian-based systems) with a public IPv4 address and root access (via password or SSH key).
    * The vServer should be fundamentally set up (SSH access possible).

## 🚀 Usage

1.  Download the `pi_node_setup_helper_script-main.zip` file. 
2.  Extract it.
3.  Right-click the "start.bat" file and select "Run as Administrator".
    * If you are not already logged in as an administrator, the script will ask if it should restart with administrator rights. Confirm this.
4.  Follow the instructions in the menu to perform the desired setup steps. It is recommended to work through the steps in numerical order (at least 1-5 for basic node setup).

## 📝 Logging

The script creates two log files in the same directory where it is executed:

* `pi_node_setup_log.txt`: Contains a log of all actions performed by the script and status messages.
* `pi_node_setup_ERROR_log.txt`: Contains detailed information about critical errors that occurred during script execution, including StackTrace and timestamps. This is useful for troubleshooting.

## ⚠️ Disclaimer

Use of this script is at your own risk. Although it has been carefully developed and tested on Windows 10/11 Home with current patches, no guarantee can be given for its functionality or for any problems or damages that may arise from its use. It is recommended to back up important data before use.

## 📜 License

This script is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This script is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details: <https://www.gnu.org/licenses/>.








[GERMAN]

<#
  Dieses Skript ist freie Software: Sie können es unter den Bedingungen
  der GNU General Public License, wie von der Free Software Foundation veröffentlicht,
  weiterverbreiten und/oder modifizieren, entweder gemäß Version 3 der Lizenz oder
  (nach Ihrer Wahl) jeder späteren Version.

  Dieses Skript wird in der Hoffnung verteilt, dass es nützlich sein wird,
  aber OHNE JEDE GEWÄHRLEISTUNG – sogar ohne die implizite Gewährleistung
  der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.

  Siehe die GNU General Public License für weitere Details.
  <https://www.gnu.org/licenses/>.
#>

# Pi Node Windows Setup Helper Skript

**Version:** 2025-07-26
**Autor:** Fingerkrampf / t.me/PiNetzwerkDeutschland
**Lizenz:** GNU General Public License v3.0

## Übersicht

Dieses PowerShell-Skript dient zur Vereinfachung und Automatisierung der Einrichtung eines Pi Nodes unter Windows 11 (mit PowerShell 5.1). Es bietet eine umfassende Lösung, die sowohl die grundlegende Node-Installation als auch erweiterte Konfigurationen wie WireGuard-Tunnel für den Betrieb hinter IPv6-Anschlüssen abdeckt.

Das Skript ist darauf ausgelegt, benutzerfreundlich zu sein und führt den Anwender durch ein interaktives Menü.

## 🌟 Hauptmerkmale

* **Interaktives Menü:** Einfache Navigation und Steuerung aller Setup-Schritte.
* **Automatisierte Installation & Konfiguration:**
    * Windows Updates
    * WSL2 (Windows Subsystem für Linux Version 2) Einrichtung
    * Docker Desktop Installation und Autostart-Konfiguration
    * Pi Node Software Installation
    * Firewall-Portfreigaben (31400-31409 TCP)
    * PuTTY Installation
    * WireGuard Windows Client Installation und Schlüsselgenerierung
* **WireGuard Server Automatisierung:**
    * Automatische Einrichtung eines WireGuard-Servers auf einem Linux vServer via SSH (Passwort- oder Schlüsselauthentifizierung).
    * Generierung und Übertragung der notwendigen Konfigurationsdateien.
    * Automatische Konfiguration des WireGuard-Clients unter Windows.
    * Ideal für Nutzer mit reinem IPv6-Internetzugang zuhause, um eine öffentliche IPv4-Adresse für den Node zu erhalten.
* **PiCheck Integration:** Download, Entpacken und Starten der neuesten Version des PiCheck-Analysewerkzeugs.
* **Robuste Fehlerbehandlung:**
    * Das Skript bricht bei den meisten Fehlern nicht abrupt ab.
    * Detaillierte Fehlermeldungen werden in einer separaten Datei (`pi_node_setup_ERROR_log.txt`) mit Zeitstempel protokolliert.
    * Der Benutzer wird über Fehler informiert und hat die Möglichkeit, zum Hauptmenü zurückzukehren.
* **Umfassendes Logging:** Alle wichtigen Aktionen werden in der Datei `pi_node_setup_log.txt` im Skriptverzeichnis protokolliert.
* **Rückgängigmachung:** Optionen zur Deinstallation einzelner Komponenten oder zur vollständigen Entfernung aller durch das Skript vorgenommenen Änderungen.

## 🛠️ Voraussetzungen

* Windows 11 (getestet unter Home-Versionen mit aktuellen Patches).
* PowerShell 5.1 (standardmäßig in Windows 11 enthalten).
* **Administratorrechte** sind für die Ausführung des Skripts zwingend erforderlich. Das Skript versucht, sich bei Bedarf selbst mit erhöhten Rechten neu zu starten.
* Für die WireGuard-Server-Einrichtung:
    * Ein Linux vServer (getestet mit Debian-basierten Systemen) mit öffentlicher IPv4-Adresse und Root-Zugriff (via Passwort oder SSH-Schlüssel).
    * Der vServer sollte grundlegend eingerichtet sein (SSH-Zugriff möglich).

## 🚀 Anwendung

1.  Laden Sie die `pi_node_setup_helper_script-main.zip`-Datei herunter.
2.  Extrahieren Sie sie.
3.  Klicken Sie mit der rechten Maustaste auf die Datei "start.bat" und wählen Sie "Als Administrator ausführen" aus.
    * Wenn Sie nicht bereits als Administrator angemeldet sind, wird das Skript Sie fragen, ob es mit Administratorrechten neu gestartet werden soll. Bestätigen Sie dies.
4.  Folgen Sie den Anweisungen im Menü, um die gewünschten Setup-Schritte auszuführen. Es wird empfohlen, die Schritte in der nummerischen Reihenfolge (zumindest 1-5 für die Basis-Node-Einrichtung) abzuarbeiten.

## 📝 Logging

Das Skript erstellt zwei Logdateien im selben Verzeichnis, in dem es ausgeführt wird:

* `pi_node_setup_log.txt`: Enthält ein Protokoll aller vom Skript durchgeführten Aktionen und Statusmeldungen.
* `pi_node_setup_ERROR_log.txt`: Enthält detaillierte Informationen zu kritischen Fehlern, die während der Skriptausführung aufgetreten sind, inklusive StackTrace und Zeitstempel. Dies ist nützlich für die Fehlersuche.

## ⚠️ Haftungsausschluss

Die Nutzung dieses Skripts erfolgt auf eigene Gefahr. Obwohl es sorgfältig entwickelt und unter Windows 10/11 Home mit aktuellen Patches getestet wurde, kann keine Gewähr für die Funktionsfähigkeit oder für etwaige durch die Nutzung entstehende Probleme oder Schäden übernommen werden. Es wird empfohlen, vor der Nutzung wichtige Daten zu sichern.

## 📜 Lizenz

Dieses Skript ist freie Software: Sie können es unter den Bedingungen der GNU General Public License, wie von der Free Software Foundation veröffentlicht, weiterverbreiten und/oder modifizieren, entweder gemäß Version 3 der Lizenz oder (nach Ihrer Wahl) jeder späteren Version.

Dieses Skript wird in der Hoffnung verteilt, dass es nützlich sein wird, aber OHNE JEDE GEWÄHRLEISTUNG – sogar ohne die implizite Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.

Siehe die GNU General Public License für weitere Details: <https://www.gnu.org/licenses/>.
