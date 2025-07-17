﻿param([switch]$resumeWSL)

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

<#
--------------------------------------------------------------------------------------
Pi Network Windows Node Setup Helper – von Fingerkrampf / PiNetzwerkDeutschland.de
Version: 2025-05-24 (Modifiziert zur Entfernung der WG-Dienstprüfschleife)
Dieses PowerShell-Skript ermöglicht eine vollständig automatisierte Installation,
Konfiguration und Aktivierung eines Pi Network Nodes unter Windows 10/11 mit
PowerShell 5.1. Es unterstützt zusätzlich die Einrichtung eines WireGuard-Tunnels
zu einem Linux-vServer mit öffentlicher IPv4 – ideal bei reinem IPv6 zuhause.

🧩 Enthaltene Features:
- Interaktives Menüsystem zur Steuerung aller Setup-Schritte
- Automatisierte Prüfung von Installationszuständen (WSL2, Docker, etc.)
- WireGuard-Tunnelaufbau mit automatischem Server-Setup via SSH (inkl. Key-Handling)
- Logging aller Aktionen mit Zeitstempel
- Rückbau-Optionen für einzelne Komponenten

⚠️ Nutzung auf eigene Gefahr – getestet unter Windows 10/11 Home mit aktuellen Patches
--------------------------------------------------------------------------------------
#>

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ((Read-Host 'Administratorrechte erforderlich. Neu starten? (J/N)') -match '^[Jj]$') {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    }
    exit
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Host.UI.RawUI.BackgroundColor = "Black"
$Host.UI.RawUI.ForegroundColor = "Gray"
Clear-Host

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    if ($PSCommandPath) {
        $scriptDir = Split-Path -Parent $PSCommandPath
    } else {
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
    }

    $logFile = Join-Path $scriptDir "pi_node_setup_log.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp][$Level] $Message"

    Add-Content -Path $logFile -Value $logEntry

    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "DEBUG" { Write-Host $logEntry -ForegroundColor DarkGray }
        default { Write-Host $logEntry -ForegroundColor Gray }
    }
}

function Is-WSL2Enabled {
    $wsl = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    $vm  = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
    return ($wsl.State -eq "Enabled" -and $vm.State -eq "Enabled")
}

function Get-WGDir {
    foreach ($path in 'C:\Program Files\WireGuard', 'C:\Program Files (x86)\WireGuard') {
        if (Test-Path (Join-Path $path 'wg.exe')) { return $path }
    }
    return $null
}

function Get-PuTTYDir {
    foreach ($path in 'C:\Program Files\PuTTY', 'C:\Program Files (x86)\PuTTY') {
        if ((Test-Path (Join-Path $path 'putty.exe')) -and (Test-Path (Join-Path $path 'plink.exe')) -and (Test-Path (Join-Path $path 'pscp.exe'))) {
            return $path
        }
    }
    return $null
}

function Are-NodeFirewallRulesPresent {
    $requiredPorts = 31400..31409
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'PiNode_TCP_In_*' -or $_.DisplayName -like 'PiNode_TCP_Out_*' }

    $existingPorts = @()
    foreach ($rule in $rules) {
        if ($rule.DisplayName -match '_(\d+)$') {
            $existingPorts += [int]$matches[1]
        }
    }

    if (-not ($existingPorts -is [System.Array])) {
        $existingPorts = @($existingPorts)
    }

    $foundPorts = $requiredPorts | Where-Object { $existingPorts -contains $_ }

    if (-not ($foundPorts -is [System.Array])) {
        $foundPorts = @($foundPorts)
    }

    return ($foundPorts.Count -eq $requiredPorts.Count)
}

function Is-WGConnectionActive {
    try {
        $wgServices = Get-Service | Where-Object { $_.Name -like 'WireGuardTunnel$*' -and $_.Status -eq 'Running' }
        return $wgServices -ne $null
    } catch {
        Write-Log "Fehler beim Prüfen des WireGuard Dienststatus: $_" "WARN"
        return $false
    }
}

function Refresh-InstallationStatus {
    $global:DockerInstalled     = (Get-Command docker -ErrorAction SilentlyContinue) -ne $null
    $global:PiNodeInstalled     = Test-Path "$env:LOCALAPPDATA\Programs\pi-network-desktop"
    $global:PuTTYInstalled      = Get-PuTTYDir
    $global:WireGuardInstalled  = Get-WGDir
    $global:WSL2Enabled         = Is-WSL2Enabled
    $global:WGKeysPresent       = Check-WGKeysExist
    $global:WGConnectionActive  = Is-WGConnectionActive
    $global:FirewallPortsOpen   = Are-NodeFirewallRulesPresent
}

function Do-WindowsUpdates {
    Write-Log "Starte Suche nach Windows Updates..." "INFO"
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
    } catch {
        Write-Log "Fehler bei COM-Initialisierung oder Updatesuche: $_" "ERROR"
        return
    }

    $updateCount = $searchResult.Updates.Count
    Write-Log "$updateCount Updates gefunden." "INFO"

    if ($updateCount -eq 0) {
        Write-Host "Keine neuen Updates gefunden." -ForegroundColor Green
        Write-Log "Keine neuen Updates gefunden." "INFO"
        Pause
        return
    }

    $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $searchResult.Updates) {
        try {
            if (-not $update.EulaAccepted) {
                $update.AcceptEula()
                Write-Log "EULA akzeptiert für: $($update.Title)"
            }
            $null = $updatesToDownload.Add($update)
            Write-Log "Update hinzugefügt zur Downloadliste: $($update.Title)"
        } catch {
            Write-Log "Fehler bei EULA oder Hinzufügen von Update '$($update.Title)': $_" "WARN"
        }
    }

    try {
        $downloader = $updateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload
        $downloader.Download()
        Write-Log "Updates erfolgreich heruntergeladen." "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen der Updates: $_" "ERROR"
        return
    }

    try {
        Write-Host "Updates heruntergeladen. Installation startet …" -ForegroundColor Cyan
        $installer = $updateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToDownload
        $installationResult = $installer.Install()

        if ($installationResult.ResultCode -eq 2) {
            Write-Log "Update bereits installiert – kein weiterer Installationsbedarf." "INFO"
            Write-Host "Updates waren bereits installiert oder wurden nicht erneut angewendet." -ForegroundColor Yellow
        } else {
            Write-Log "Installations-ResultCode: $($installationResult.ResultCode)" "INFO"
            Write-Host "Installation abgeschlossen. Ergebniscode: $($installationResult.ResultCode)" -ForegroundColor Green
        }
    } catch {
        Write-Log "Fehler bei der Updateinstallation: $_" "ERROR"
    }

    Pause
}

function Do-EnableWSL2 {
    param([switch]$resumeWSL)

    $flagPath = "$env:ProgramData\wsl2_setup_flag.txt"
    $pathFile = "$env:ProgramData\wsl2_script_path.txt"
    $taskName = "ResumeWSL2Setup"

    if ($resumeWSL -or (Test-Path $flagPath)) {
        Write-Host "`n Fortsetzungs-Flag erkannt – Setup wird fortgesetzt..." -ForegroundColor Cyan
        Write-Log "Fortsetzungs-Flag erkannt: $flagPath" "INFO"

$wslUpdateUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$tempMsiPath = Join-Path $env:TEMP "wsl_update_x64.msi"

try {
    Write-Host "Lade WSL2 Kernel Update herunter mit curl von: $wslUpdateUrl"
    Write-Log "Starte Download des WSL2 Kernel Updates mit curl von $wslUpdateUrl" "INFO"

    $curlCommand = "curl.exe -L -s -S --fail -o `"$tempMsiPath`" `"$wslUpdateUrl`""
    Write-Log "Führe curl Befehl aus: $curlCommand" "INFO"
    Invoke-Expression $curlCommand

    if (Test-Path $tempMsiPath -PathType Leaf) {
        $fileInfo = Get-Item $tempMsiPath
        if ($fileInfo.Length -gt 0) {
            Write-Log "Download des WSL2 Kernel Updates mit curl abgeschlossen. Gespeichert unter: $tempMsiPath" "INFO"
            Write-Host "Download abgeschlossen. Starte Installation..." -ForegroundColor Green
        } else {
            Write-Log "Fehler: Download des WSL2 Kernel Updates mit curl fehlgeschlagen. Die heruntergeladene Datei ist leer: $tempMsiPath" "ERROR"
            Write-Warning "Fehler: Download des WSL2 Kernel Updates mit curl fehlgeschlagen. Die heruntergeladene Datei ist leer."
            throw "Download des WSL2 Kernel Updates mit curl fehlgeschlagen (Datei ist leer)."
        }
    } else {
        Write-Log "Fehler: Download des WSL2 Kernel Updates mit curl fehlgeschlagen. Datei nicht gefunden: $tempMsiPath" "ERROR"
        Write-Warning "Fehler: Download des WSL2 Kernel Updates mit curl fehlgeschlagen. Datei nicht gefunden."
        throw "Download des WSL2 Kernel Updates mit curl fehlgeschlagen (Datei nicht gefunden)."
    }

    Write-Log "Starte Installation des WSL2 Kernel Updates von $tempMsiPath" "INFO"
    $process = Start-Process msiexec.exe -ArgumentList "/i `"$tempMsiPath`" /quiet /norestart" -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Log "WSL2 Kernel Update erfolgreich installiert." "INFO"
        Write-Host "WSL2 Kernel Update erfolgreich installiert." -ForegroundColor Green
    } else {
        Write-Log "Fehler bei der Installation des WSL2 Kernel Updates. Exit Code: $($process.ExitCode)" "ERROR"
        Write-Warning "Fehler bei der Installation des WSL2 Kernel Updates. Exit Code: $($process.ExitCode)"
        throw "Installation des WSL2 Kernel Updates fehlgeschlagen."
    }

} catch {
    Write-Log "Fehler im Prozess: $($_.Exception.Message)" "ERROR"
    Write-Warning "Ein Fehler ist aufgetreten: $($_.Exception.Message)"
pause
return
} finally {
    if (Test-Path $tempMsiPath -PathType Leaf) {
        Write-Log "Entferne temporäre MSI-Datei: $tempMsiPath" "INFO"
        Remove-Item $tempMsiPath -ErrorAction SilentlyContinue
    }
}


        try {
            wsl --set-default-version 2
            Write-Log "WSL2 wurde als Standardversion gesetzt." "INFO"
            Write-Host "`nWSL2 wurde als Standardversion gesetzt." -ForegroundColor Green
        } catch {
            Write-Log "Fehler beim Setzen der Standardversion: $_" "ERROR"
            Write-Warning "Fehler beim Setzen der Standardversion: $_"
        }

        Remove-Item $flagPath -Force -ErrorAction SilentlyContinue
        Remove-Item $pathFile -Force -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Fortsetzungs-Dateien und geplante Aufgabe entfernt." "INFO"
        Pause
        Show-Menu
        return
    }

    $scriptPath = $PSCommandPath
    Set-Content -Path $pathFile -Value "`"$scriptPath`""

    Write-Host "`n Prüfe WSL2-Status..." -ForegroundColor Cyan
    Write-Log "Prüfe aktuellen Status der WSL2-Komponenten..." "INFO"

    try {
        $wslEnabled = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -eq "Enabled"
        $vmEnabled  = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -eq "Enabled"
    } catch {
        Write-Log "Fehler beim Abrufen des Feature-Status: $_" "ERROR"
        return
    }

    if ($wslEnabled -and $vmEnabled) {
        Write-Host "WSL2 ist bereits vollständig aktiviert." -ForegroundColor Green
        Write-Log "WSL2 bereits vollständig aktiviert." "INFO"
        Pause
        return
    }

    Write-Host "`nAktiviere benötigte Windows-Features für WSL2..." -ForegroundColor Yellow
    Write-Log "Aktiviere Windows-Features für WSL2 (per Hintergrund-Job)..." "INFO"
    Write-Host "(dies kann einen kleinen Moment dauern)" -ForegroundColor DarkYellow

    $job = Start-Job -ScriptBlock {
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -All | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -All | Out-Null
    }

    $maxWait = 60
    $elapsed = 0
    while ($elapsed -lt $maxWait) {
        if ($job.State -eq 'Completed') {
            Write-Host "`nWindows-Features wurden aktiviert." -ForegroundColor Green
            Write-Log "Windows-Feature-Job erfolgreich abgeschlossen." "INFO"
            break
        }
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 5
        $elapsed += 5
    }

    if ($job.State -ne 'Completed') {
        Write-Host "`nKomponenten wurden nach $maxWait Sekunden nicht vollständig aktiviert."
        Write-Log "WSL2-Komponenten wurden nach Timeout nicht aktiviert. Einen Augenblick bitte..." "INFO"
        Stop-Job $job | Out-Null
        Remove-Job $job | Out-Null

        $restartNow = Read-Host "Soll ein Neustart durchgeführt werden, um die Aktivierung abzuschließen? (J/N)"
        if ($restartNow -match '^[Jj]$') {
            try {
                Set-Content -Path $flagPath -Value "resume"

                $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Normal -ExecutionPolicy Bypass -File `"$scriptPath`" -resumeWSL"
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -LogonType Interactive -RunLevel Highest
                $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal

                Register-ScheduledTask -TaskName $taskName -InputObject $task -Force

                Write-Log "Geplante Aufgabe zur Fortsetzung eingerichtet: $taskName" "INFO"
               	Write-Host "`nBeachten Sie dass Sie zur vollständigen Aktivierung Menüpunkt 2 nach dem Neustart NOCHMALS ausführen müssen!" -ForegroundColor White -BackgroundColor Red
                Write-Log "System wird neu gestartet." "INFO"
                Pause
                Restart-Computer -Force
            } catch {
                Write-Log "Fehler beim Einrichten der geplanten Aufgabe: $_" "ERROR"
            }
        } else {
            Write-Host "Bitte führen Sie nachträglich einen Neustart durch und starten Sie das Skript Menüpunkt 2 erneut manuell aus um WSL2 zu aktivieren." -ForegroundColor Yellow -Backgroundcolor Red
        }
    } else {
        Remove-Job $job | Out-Null
    }

    Pause
}

function Do-InstallWireGuard {
    Write-Host "Installiere WireGuard mit winget..." -ForegroundColor Cyan
    Write-Log "Beginne Installation von WireGuard mit winget..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }
    } catch {
        Write-Log "Winget nicht gefunden oder nicht verfügbar: $_" "ERROR"
        return
    }

    try {
        Write-Host "Starte Silent-Installation von WireGuard..." -ForegroundColor Yellow
        Write-Log "Führe winget-Installation aus: WireGuard.WireGuard" "INFO"

        winget install -e --id WireGuard.WireGuard --silent --accept-package-agreements --accept-source-agreements
        $exitCode = $LASTEXITCODE
        Write-Log "Winget-Installations-ExitCode: $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: winget-Installation meldete ExitCode $exitCode" "WARN"
        }

        Start-Process "C:\Program Files\Wireguard\Wireguard.exe" -ErrorAction Stop
        Write-Log "WireGuard erfolgreich gestartet." "INFO"
        Write-Host "WireGuard wurde erfolgreich installiert und gestartet!" -ForegroundColor Green
    } catch {
        Write-Log "Fehler bei der Installation oder dem Start von WireGuard: $_" "ERROR"
        return
    }

    try {
        $wgDir = Get-WGDir
        if ($wgDir) {
            Gen-WGKeys $wgDir
            Write-Log "WireGuard-Verzeichnis gefunden: $wgDir – Schlüssel wurden generiert." "INFO"
        } else {
            Write-Warning "WireGuard-Verzeichnis nicht gefunden."
            Write-Log "WireGuard-Verzeichnis nicht gefunden – Schlüssel wurden nicht generiert." "WARN"
        }
    } catch {
        Write-Log "Fehler beim Generieren der WireGuard-Schlüssel: $_" "ERROR"
    }

    Pause
}

function Do-FirewallPorts {
    Write-Host 'Setze Firewall-Regeln für Ports 31400-31409 …' -ForegroundColor Cyan
    Write-Log "Beginne mit dem Erstellen von Firewallregeln für Ports 31400–31409..." "INFO"

    foreach ($p in 31400..31409) {
        try {
            New-NetFirewallRule -DisplayName "PiNode_TCP_In_$p"  -Direction Inbound  -Protocol TCP -LocalPort $p -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            New-NetFirewallRule -DisplayName "PiNode_TCP_Out_$p" -Direction Outbound -Protocol TCP -LocalPort $p -Action Allow -Profile Any -ErrorAction Stop | Out-Null
            Write-Log "Firewallregeln für Port $p erfolgreich erstellt." "INFO"
        } catch {
            Write-Warning "Fehler beim Erstellen der Firewallregel für Port ${p}: $_"
            Write-Log "Fehler beim Erstellen der Firewallregel für Port ${p}: $_" "ERROR"
        }
    }

    Write-Host 'Firewall-Regeln erstellt.' -ForegroundColor Green
    Write-Log "Alle Firewall-Regeln wurden abgearbeitet." "INFO"
    Pause
}

function Do-InstallPuTTY {
    Write-Host 'Installiere PuTTY...' -ForegroundColor Cyan
    Write-Log "Beginne Installation von PuTTY mit winget..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte sicherstellen, dass es installiert ist."
        }

        $process = Start-Process 'winget' -ArgumentList 'install', '--id', 'PuTTY.PuTTY', '-e', '--accept-source-agreements', '--accept-package-agreements' -Wait -PassThru
        $exitCode = $process.ExitCode
        Write-Log "PuTTY-Installation abgeschlossen mit ExitCode $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: PuTTY winget-Installation meldete ExitCode $exitCode" "WARN"
        }
    } catch {
        Write-Log "Fehler bei der Installation von PuTTY: $_" "ERROR"
    }

    Pause
}

function Do-InstallDocker {
    Write-Host "Installiere Docker Desktop.." -ForegroundColor Cyan
    Write-Log "Starte Installation von Docker Desktop..." "INFO"

    try {
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            throw "Winget ist nicht verfügbar. Bitte stellen Sie sicher, dass es installiert ist."
        }

        Write-Host "Starte Silent-Installation von Docker Desktop..." -ForegroundColor Yellow
        Write-Log "Führe winget-Installation aus: Docker.DockerDesktop" "INFO"
        winget install --id Docker.DockerDesktop -e --silent --accept-package-agreements --accept-source-agreements
        $exitCode = $LASTEXITCODE
        Write-Log "Docker winget-Installations-ExitCode: $exitCode" "INFO"

        if ($exitCode -ne 0) {
            Write-Log "Warnung: winget meldete ExitCode $exitCode" "WARN"
        }

        $global:DockerInstalled = (Get-Command docker -ErrorAction SilentlyContinue) -ne $null
        Refresh-InstallationStatus

        Start-Sleep -Seconds 5

        $dockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        if (Test-Path $dockerExe) {
            Start-Process $dockerExe -ErrorAction Stop
            Write-Host "Docker Desktop wurde erfolgreich installiert und gestartet!" -ForegroundColor Green
            Write-Log "Docker Desktop erfolgreich gestartet." "INFO"
	        Refresh-InstallationStatus

            $startupFolder = [Environment]::GetFolderPath("Startup")
            $shortcutPath = Join-Path $startupFolder "Docker Desktop.lnk"

            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $dockerExe
            $shortcut.WorkingDirectory = Split-Path $dockerExe
            $shortcut.WindowStyle = 1
            $shortcut.Description = "Startet Docker Desktop automatisch"
            $shortcut.Save()

            Write-Host "Docker Desktop wurde dauerhaft im Autostart eingerichtet." -ForegroundColor Green
            Write-Log "Docker Desktop Autostart-Verknüpfung erstellt: $shortcutPath" "INFO"
            Refresh-InstallationStatus
        } else {
            Write-Warning "Docker Desktop wurde nicht gefunden unter: $dockerExe – Autostart nicht eingerichtet."
            Write-Log "Docker nicht gefunden – Autostart übersprungen." "WARN"
        }
    }
    catch {
        Write-Host "FEHLER: $_" -ForegroundColor Red
        Write-Host "Tipp: Stellen Sie sicher, dass winget verfügbar und aktuell ist." -ForegroundColor Yellow
        Write-Log "Fehler bei der Docker-Installation: $_" "ERROR"
    }
     Pause
Refresh-InstallationStatus
}

function Do-InstallPiNode {
    Write-Host "Installiere Pi Network Node Software..." -ForegroundColor Cyan
    Write-Log "Beginne Installation der Pi Network Node Software..." "INFO"

    $url = "https://downloads.minepi.com/Pi%20Network%20Setup%200.5.0.exe"
    $installerPath = "$env:TEMP\PiNetworkSetup050.exe"

    try {
        & curl.exe -L $url -o $installerPath
        $exitCode = $LASTEXITCODE
        Write-Log "curl.exe Download abgeschlossen mit ExitCode $exitCode" "INFO"

        if ($exitCode -ne 0 -or -not (Test-Path $installerPath)) {
            throw "Download fehlgeschlagen oder Datei nicht vorhanden."
        }
        Write-Log "Pi Node Installer erfolgreich heruntergeladen: $installerPath" "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen des Installers: $_" "ERROR"
        return
    }

    try {
        Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait -ErrorAction Stop
        Write-Log "Installer wurde erfolgreich im Silent-Modus ausgeführt." "INFO"
        Write-Host "Pi Network Node erfolgreich installiert und gestartet!" -ForegroundColor Green
    } catch {
        Write-Log "Fehler beim Starten des Installers: $_" "ERROR"
    }

    Pause
}


function DownloadAndStartPiCheck {
    Write-Host 'Lade PiCheck-Archiv mit curl herunter ...' -ForegroundColor Cyan
    Write-Log "Starte Download von PiCheck-Archiv..." "INFO"

    $url = "https://github.com/muratyurdakul75/picheck/archive/refs/heads/main.zip"
    $tempPath = "$env:TEMP"
    $zipPath = Join-Path $tempPath "picheck-main.zip"
    $unzipPath = Join-Path $tempPath "picheck-unpacked"
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    $targetPath = Join-Path $desktopPath "PiCheck"

    try {
        if (Test-Path $unzipPath) { Remove-Item -Path $unzipPath -Recurse -Force -ErrorAction Stop }
        if (Test-Path $targetPath) { Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop }

        if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
            throw "curl.exe wurde nicht gefunden."
        }

        $curlCmd = "curl.exe -L -o `"$zipPath`" `"$url`""
        cmd.exe /c $curlCmd

        if (-not (Test-Path $zipPath)) {
            throw "ZIP-Datei wurde nicht erstellt. Download fehlgeschlagen."
        }

        Write-Host "Entpacke Hauptarchiv ..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $unzipPath -Force
        Write-Log "Archiv erfolgreich entpackt: $zipPath → $unzipPath" "INFO"

        $versionZips = Get-ChildItem -Path $unzipPath -Recurse -Filter "*.zip" | ForEach-Object {
            if ($_.Name -match '(\d+\.\d+\.\d+)') {
                [PSCustomObject]@{ File = $_; Version = [version]$matches[1] }
            }
        }

        if (-not $versionZips) {
            throw "Keine gültigen PiCheck-Versionen gefunden."
        }

        $latest = $versionZips | Sort-Object Version -Descending | Select-Object -First 1
        Write-Log "PiCheck-Version gefunden: $($latest.Version) – $($latest.File.FullName)" "INFO"

        Expand-Archive -Path $latest.File.FullName -DestinationPath $targetPath -Force

        $exePath = Get-ChildItem -Path $targetPath -Filter "picheck.exe" -Recurse | Select-Object -First 1
        if (-not $exePath) {
            throw "picheck.exe wurde nicht gefunden im Zielverzeichnis."
        }

        $vcInstaller = Get-ChildItem -Path $targetPath -Filter "VC_redist.x64.exe" -Recurse | Select-Object -First 1
        if ($vcInstaller) {
            Write-Host "Installiere VC_redist.x64.exe im Silent-Mode ..." -ForegroundColor Cyan
            Start-Process -FilePath $vcInstaller.FullName -ArgumentList "/quiet", "/norestart" -Wait
            Write-Log "VC_redist.x64.exe wurde ausgeführt." "INFO"
        } else {
            Write-Log "VC_redist.x64.exe nicht gefunden – wird übersprungen." "WARN"
        }

        Write-Host "Starte picheck.exe /auto ..." -ForegroundColor Green
        Start-Process -FilePath $exePath.FullName -ArgumentList "/auto"
        Write-Log "picheck.exe gestartet mit Argument /auto." "INFO"

        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $unzipPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Temporäre Dateien entfernt." "INFO"
    } catch {
        Write-Log "Fehler beim Herunterladen oder Ausführen von PiCheck: $_" "ERROR"
    }
    Write-Host "Zurück zum Hauptmenü..." -ForegroundColor Gray
    Pause
}

function Show-UninstallMenu {
    Clear-Host
    Write-Host '===[ Rückgängig machen / Deaktivieren ]===' -ForegroundColor Red
    Write-Host ''
    Write-Host '0) Alles entfernen (komplett)' -ForegroundColor DarkRed
    Write-Host '1) Deinstalliere Docker Desktop'
    Write-Host '2) Entferne Pi Network Node'
    Write-Host '3) Entferne PuTTY'
    Write-Host '4) Entferne WireGuard'
    Write-Host '5) Entferne Firewall-Regeln (31400–31409)'
    Write-Host '6) Deaktiviere WSL2'
    Write-Host '7) Entferne PiCheck-Verzeichnis vom Desktop'
    Write-Host '8) Zurück zum Hauptmenü'
    Write-Host ''
}

function Undo-Docker {
    $confirm = Read-Host "Bist du sicher, dass du Docker Desktop entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-Docker abgebrochen." "INFO"
        Pause
        return
    }

    Write-Host "Beende Docker-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Write-Host "Deinstalliere Docker Desktop..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von Docker Desktop..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "Docker.DockerDesktop", "-e", "--silent" -Wait
        Write-Log "Docker Desktop wurde deinstalliert." "INFO"
    } catch {
        Write-Log "Fehler bei Docker-Deinstallation: $_" "ERROR"
    }

    try {
        $startupFolder = [Environment]::GetFolderPath("Startup")
        $shortcutPath = Join-Path $startupFolder "Docker Desktop.lnk"

        if (Test-Path $shortcutPath) {
            Remove-Item $shortcutPath -Force
            Write-Host "Autostart-Verknüpfung für Docker Desktop entfernt." -ForegroundColor Green
            Write-Log "Autostart-Verknüpfung entfernt: $shortcutPath" "INFO"
        } else {
            Write-Log "Keine Autostart-Verknüpfung gefunden – nichts zu entfernen." "INFO"
        }
    } catch {
        Write-Warning "Fehler beim Entfernen der Autostart-Verknüpfung: $_"
        Write-Log "Fehler beim Entfernen von Docker Autostart: $_" "ERROR"
    }

    Pause
}

function Undo-PiNode {
    $confirm = Read-Host "Bist du sicher, dass du Pi Network Node entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PiNode abgebrochen." "INFO"
        Pause
        return
    }

    Write-Host "Beende Pi Node-Prozesse..." -ForegroundColor DarkGray
    Get-Process | Where-Object {
        $_.Path -like "*pi-network-desktop*" -or
        $_.ProcessName -like "*pi*" -or
        $_.ProcessName -like "*node*" -or
        $_.ProcessName -like "*electron*"
    } | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            Write-Log "Prozess beendet: $($_.Name) (ID: $($_.Id))" "INFO"
        } catch {
            Write-Log "Fehler beim Beenden des Prozesses $($_.Name): $_" "WARN"
        }
    }

    Start-Sleep -Seconds 2

    $path = "$env:LOCALAPPDATA\Programs\pi-network-desktop"
    Write-Host "Entferne Pi Network Node..." -ForegroundColor Cyan
    Write-Log "Beginne Entfernung von Pi Network Node..." "INFO"

    try {
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force -ErrorAction Stop
            Write-Log "Pi Network Node wurde entfernt." "INFO"
            Write-Host "Pi Node-Verzeichnis erfolgreich gelöscht." -ForegroundColor Green
        } else {
            Write-Log "Pi Network Node-Verzeichnis nicht gefunden: $path – vermutlich bereits entfernt." "WARN"
            Write-Host "Verzeichnis nicht vorhanden – vermutlich bereits gelöscht." -ForegroundColor Yellow
        }
    } catch {
        Write-Log "Fehler beim Entfernen des Pi Node: $_" "ERROR"
        Write-Host "Fehler beim Entfernen: $_" -ForegroundColor Red
    }

    Pause
}

function Undo-PuTTY {
    $confirm = Read-Host "Bist du sicher, dass du PuTTY entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PuTTY abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Beende PuTTY-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "putty" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Deinstalliere PuTTY..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von PuTTY..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "PuTTY.PuTTY", "-e", "--silent" -Wait
        Write-Log "PuTTY wurde deinstalliert." "INFO"
    } catch {
        Write-Log "Fehler bei PuTTY-Deinstallation: $_" "ERROR"
    }
    Pause
}

function Undo-WireGuard {
    $confirm = Read-Host "Bist du sicher, dass du WireGuard entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-WireGuard abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Beende WireGuard-Prozesse..." -ForegroundColor DarkGray
    Get-Process -Name "wireguard" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Deinstalliere WireGuard..." -ForegroundColor Cyan
    Write-Log "Starte Deinstallation von WireGuard..." "INFO"
    try {
        Start-Process "winget" -ArgumentList "uninstall", "--id", "WireGuard.WireGuard", "-e", "--silent" -Wait
        Write-Log "WireGuard wurde deinstalliert." "INFO"
        $wg = Get-WGDir
        if ($wg) {
            Remove-Item -Path $wg -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "WireGuard-Verzeichnis entleert: $wg" "INFO"
        }
    } catch {
        Write-Log "Fehler bei WireGuard-Deinstallation: $_" "ERROR"
    }
    Pause
}

function Undo-FirewallRules {
    $confirm = Read-Host "Bist du sicher, dass du die Firewall-Regeln entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-FirewallRules abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Entferne Firewall-Regeln für Ports 31400–31409..." -ForegroundColor Cyan
    Write-Log "Beginne Entfernung von Firewallregeln..." "INFO"
    foreach ($p in 31400..31409) {
        Remove-NetFirewallRule -DisplayName "PiNode_TCP_In_$p" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "PiNode_TCP_Out_$p" -ErrorAction SilentlyContinue
    }
    Write-Log "Firewallregeln entfernt." "INFO"
    Pause
}

function Undo-WSL2 {
    $confirm = Read-Host "Bist du sicher, dass du WSL2 deaktivieren möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-WSL2 abgebrochen." "INFO"
        Pause
        return
    }
    Write-Host "Deaktiviere WSL2-Funktionalität..." -ForegroundColor Cyan
    Write-Log "Beginne Deaktivierung von WSL2..." "INFO"
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart -ErrorAction Stop
        Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart -ErrorAction Stop
        Write-Log "WSL2 wurde deaktiviert." "INFO"
    } catch {
        Write-Log "Fehler bei der WSL2-Deaktivierung: $_" "ERROR"
    }
    Pause
}

function Undo-All {
    $confirm = Read-Host "Bist du sicher, dass du ALLE Komponenten entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-All abgebrochen." "INFO"
        Pause
        return
    }

    Undo-PiCheck
    Undo-WireGuard
    Undo-Docker
    Undo-PuTTY
    Undo-PiNode
    Undo-FirewallRules
    Undo-WSL2

    Write-Host "Alle Komponenten wurden entfernt (soweit möglich)." -ForegroundColor Green
    Write-Log "Alle Komponenten wurden im Rahmen von Undo-All entfernt." "INFO"
    Pause
}

function Undo-PiCheck {
    $confirm = Read-Host "Bist du sicher, dass du das PiCheck-Verzeichnis entfernen möchtest? (J/N)"
    if ($confirm -notmatch '^[Jj]$') {
        Write-Host "Aktion abgebrochen." -ForegroundColor Yellow
        Write-Log "Benutzer hat Undo-PiCheck abgebrochen." "INFO"
        Pause
        return
    }

    Write-Host "Beende ggf. laufenden PiCheck-Prozess..." -ForegroundColor DarkGray
    try {
        $proc = Get-Process -Name "PiCheck" -ErrorAction SilentlyContinue
        if ($proc) {
            Stop-Process -Name "PiCheck" -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-Log "PiCheck-Prozess wurde erfolgreich beendet." "INFO"
        } else {
            Write-Log "Kein laufender PiCheck-Prozess gefunden." "INFO"
        }
    } catch {
        Write-Log "Fehler beim Beenden des PiCheck-Prozesses: $_" "ERROR"
    }

    Write-Host "Entferne PiCheck-Verzeichnis vom Desktop..." -ForegroundColor Cyan
    Write-Log "Entferne PiCheck-Verzeichnis vom Desktop..." "INFO"
    try {
        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $targetPath = Join-Path $desktopPath "PiCheck"
        if (Test-Path $targetPath) {
            Get-ChildItem -Path $targetPath -Recurse -Force | ForEach-Object {
                if ($_.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                    $_.Attributes = $_.Attributes -bxor [System.IO.FileAttributes]::ReadOnly
                }
            }
            Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop
            Write-Log "PiCheck-Verzeichnis wurde entfernt: $targetPath" "INFO"
        } else {
            Write-Log "PiCheck-Verzeichnis war nicht vorhanden: $targetPath" "INFO"
        }
    } catch {
        Write-Log "Fehler beim Entfernen des PiCheck-Verzeichnisses: $_" "ERROR"
    }
    Pause
}

function Check-WGKeysExist {
    $dir = Get-WGDir
    if (-not $dir) { return $false }
    $keyDir = Join-Path $dir 'keys'
    return (Test-Path (Join-Path $keyDir 'wg_private.key')) -and (Test-Path (Join-Path $keyDir 'wg_public.key'))
}

function Remove-AllHostKeysForIP($serverIp) {
    $hostKeyPath = "HKCU:\Software\SimonTatham\PuTTY\SshHostKeys"
    $prefixes = @('rsa2', 'dsa', 'ecdsa', 'ed25519', 'ssh-ed25519')
    foreach ($prefix in $prefixes) {
        $entryName = "${prefix}@22:$serverIp"
        Remove-ItemProperty -Path $hostKeyPath -Name $entryName -ErrorAction SilentlyContinue
    }
}

function Ensure-HostKeyAccepted {
    param (
        [string]$serverIp,
        [string]$user = "root",
        [string]$password,
        [string]$privateKeyPath
    )

    $pu = Get-PuTTYDir
    if (-not $pu) {
        Write-Warning "PuTTY nicht gefunden."
        return
    }

    $plink = Join-Path $pu 'plink.exe'

    Remove-AllHostKeysForIP -serverIp $serverIp

    Write-Host "Akzeptiere SSH-Hostkey von $serverIp automatisch..." -ForegroundColor Yellow

    $responseFile = [System.IO.Path]::GetTempFileName()
    "y`n" | Out-File -FilePath $responseFile -Encoding ASCII
    $plinkArgs = @()
    if ($privateKeyPath) {
        $plinkArgs += "-i", "`"$privateKeyPath`""
    } else {
        $plinkArgs += "-pw", $password
    }
    $plinkArgs += "$user@$serverIp", "exit"

    $process = Start-Process -FilePath $plink `
        -ArgumentList $plinkArgs `
        -Wait -NoNewWindow -RedirectStandardInput $responseFile -PassThru

    Remove-Item $responseFile -Force

    if ($process.ExitCode -ne 0) {
        Write-Warning "Hostkey konnte nicht automatisch akzeptiert werden. Exit-Code: $($process.ExitCode)"
    }
}

function Convert-OpenSSHKeyToPPK {
    param (
        [string]$opensshKeyPath,
        [string]$puttygenPath,
        [string]$ppkOutPath
    )

    Write-Log "Starte Konvertierung von OpenSSH-Key nach PPK..." "INFO"
    Write-Log "Eingabe: $opensshKeyPath | Ziel: $ppkOutPath" "INFO"

    if (-not (Test-Path $puttygenPath)) {
        Write-Error "puttygen.exe nicht gefunden. Bitte sicherstellen, dass PuTTY installiert ist."
        Write-Log "Fehlender puttygen.exe Pfad: $puttygenPath" "ERROR"
        return $null
    }

    if (-not (Test-Path $opensshKeyPath)) {
        Write-Error "OpenSSH-Schlüssel nicht gefunden: $opensshKeyPath"
        Write-Log "OpenSSH-Key fehlt: $opensshKeyPath" "ERROR"
        return $null
    }

    try {
        Write-Host "Konvertiere OpenSSH-Key nach PuTTY-Format (.ppk)..." -ForegroundColor Cyan
        & $puttygenPath "`"$opensshKeyPath`"" -o "`"$ppkOutPath`"" | Out-Null

        if (Test-Path $ppkOutPath) {
            Write-Host "Konvertierung erfolgreich: $ppkOutPath" -ForegroundColor Green
            Write-Log "Konvertierung erfolgreich abgeschlossen: $ppkOutPath" "INFO"
            return $ppkOutPath
        } else {
            throw "PPK-Datei wurde nicht erstellt."
        }
    } catch {
        Write-Error "Konvertierung fehlgeschlagen: $_"
        Write-Log "Fehler bei der Konvertierung zu PPK: $_" "ERROR"
        return $null
    }
}

function Gen-WGKeys($dir) {
    $keyDir = Join-Path $dir 'keys'
    if (-not (Test-Path $keyDir)) {
        try {
            New-Item -Path $keyDir -ItemType Directory -ErrorAction Stop | Out-Null
            Write-Log "Key-Verzeichnis erstellt: $keyDir" "INFO"
        } catch {
            Write-Log "Fehler beim Erstellen des Key-Verzeichnisses: $_" "ERROR"
            return
        }
    }

    $wgExe = Join-Path $dir 'wg.exe'
    if (-not (Test-Path $wgExe)) {
        Write-Log "wg.exe nicht gefunden im Pfad $wgExe" "ERROR"
        return
    }

    try {
        $priv = & $wgExe genkey
        if ([string]::IsNullOrWhiteSpace($priv)) {
            throw "Private Key konnte nicht generiert werden."
        }

        $pub = $priv | & $wgExe pubkey
        if ([string]::IsNullOrWhiteSpace($pub)) {
            throw "Public Key konnte nicht generiert werden."
        }

        $privPath = Join-Path $keyDir 'wg_private.key'
        $pubPath  = Join-Path $keyDir 'wg_public.key'

        if ((Test-Path $privPath) -or (Test-Path $pubPath)) {
            $overwrite = Read-Host "Schlüssel existieren bereits. Überschreiben? (J/N)"
            if ($overwrite -notmatch '^[Jj]$') {
                Write-Log "Abbruch: Benutzer will vorhandene Schlüssel nicht überschreiben." "WARN"
                return
            }
        }

        $priv | Out-File $privPath -Encoding ASCII
        $pub  | Out-File $pubPath  -Encoding ASCII

        Write-Log "WireGuard-Schlüssel erfolgreich erstellt: $privPath & $pubPath" "INFO"
    } catch {
        Write-Log "Fehler bei der WireGuard-Keygenerierung: $_" "ERROR"
    }
}

function Do-SetupWGServer {
    $wg = Get-WGDir
    $pu = Get-PuTTYDir
    if (-not $pu) { Write-Warning 'PuTTY nicht installiert.'; Write-Log 'PuTTY nicht installiert.' 'ERROR'; return }
    if (-not $wg) { Write-Warning 'WireGuard nicht installiert.'; Write-Log 'WireGuard nicht installiert.' 'ERROR'; return }

    $serverIp = Read-Host 'IPv4 Adresse des vServers'
    Write-Log "Server-IP eingegeben: $serverIp" 'INFO'

    $authChoice = Read-Host 'Authentifizierungsmethode? (pw für Passwort / key für SSH-Key)'
    $plinkAuthArgs = @()

    if ($authChoice -eq 'pw') {
       $cred = Read-Host 'Root-Passwort' -AsSecureString
       $pwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred))

       Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -password $pwd
       $plinkAuthArgs += '-pw', $pwd
    }
    elseif ($authChoice -eq 'key') {
        $scriptDir = if ($PSCommandPath) {
            Split-Path -Parent $PSCommandPath
        } else {
            Split-Path -Parent $MyInvocation.MyCommand.Definition
        }

        $keyFiles = Get-ChildItem -Path $scriptDir -File | Where-Object {
            $_.Extension -in ".key", "" -and -not $_.Name.EndsWith(".ppk")
        }

        if (@($keyFiles).Count -eq 0) {
            Write-Error "Keine geeigneten SSH-Key-Dateien im Skriptverzeichnis gefunden."
            Write-Log "Keine SSH-Keys gefunden im Verzeichnis $scriptDir" "ERROR"
            return
        }

        Write-Host "`nVerfügbare SSH-Key-Dateien:" -ForegroundColor Cyan
        for ($i = 0; $i -lt @($keyFiles).Count; $i++) {
            Write-Host "$i`t$($keyFiles[$i].Name)"
        }
        [int]$sel = Read-Host "`nBitte Nummer der gewünschten Key-Datei eingeben"
        if ($sel -lt 0 -or $sel -ge @($keyFiles).Count) {
            Write-Error "Ungültige Auswahl."
            Write-Log "Benutzer wählte ungültigen Index $sel bei Key-Auswahl." "WARN"
            return
        }

        $opensshKey = $keyFiles[$sel].FullName
        $ppkKey     = [System.IO.Path]::ChangeExtension($opensshKey, ".ppk")
        $ppkWasTemporary = $false

        if (-not (Test-Path $ppkKey)) {
            $puttygen = Join-Path $pu 'puttygen.exe'
            if (-not (Test-Path $puttygen)) {
                Write-Error "puttygen.exe nicht gefunden: $puttygen"
                Write-Log "puttygen.exe nicht gefunden für Konvertierung" "ERROR"
                return
            }
            $convertedKey = Convert-OpenSSHKeyToPPK -opensshKeyPath $opensshKey -puttygenPath $puttygen -ppkOutPath $ppkKey
            if (-not $convertedKey) { return }
            $ppkWasTemporary = $true
        }

        Ensure-HostKeyAccepted -serverIp $serverIp -user "root" -privateKeyPath $ppkKey
        $plinkAuthArgs += '-i', "`"$ppkKey`""

        if ($ppkWasTemporary) {
        }
    } else {
        Write-Error "Ungültige Auswahl. Bitte 'pw' oder 'key' eingeben."
        Write-Log "Ungültige Authentifizierungsmethode: $authChoice" 'WARN'
        return
    }

    $wgExePath = Join-Path $wg 'wg.exe'
    $keyDir = Join-Path $wg 'keys'
    $clientPrivPath = Join-Path $keyDir 'wg_private.key'
    $clientPubPath  = Join-Path $keyDir 'wg_public.key'

    if (-not (Test-Path $clientPrivPath) -or -not (Test-Path $clientPubPath)) {
        Write-Error "Client WireGuard-Schlüssel nicht gefunden. Bitte zuerst generieren (Menüpunkt 7)."
        Write-Log "Client-Keys nicht gefunden: $clientPrivPath oder $clientPubPath fehlen." 'ERROR'
        return
    }

    $clientPriv = Get-Content $clientPrivPath -Raw
    $clientPub  = Get-Content $clientPubPath -Raw

    $serverPriv = & $wgExePath genkey
    $serverPub  = $serverPriv | & $wgExePath pubkey

    $bash = @'
#!/bin/bash
set -euo pipefail
apt update -y
apt install -y wireguard iproute2 iptables curl ca-certificates gnupg
apt-mark hold openssh-client openssh-server
apt update && sudo apt upgrade -y

echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf
sysctl --system

mkdir -p /etc/wireguard
chmod 700 /etc/wireguard
umask 077

SERVER_PRIVATE="{{SERVER_PRIV}}"
SERVER_PUBLIC="{{SERVER_PUB}}"
CLIENT_PUBLIC="{{CLIENT_PUB}}"

DEFAULT_INTERFACE=$(ip route | awk '/default/ {print $5; exit}')
SERVER_IP=$(curl -s https://ifconfig.me)

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 192.168.200.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE
PostUp = iptables -A FORWARD -i %i -o $DEFAULT_INTERFACE -j ACCEPT; iptables -A FORWARD -i $DEFAULT_INTERFACE -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o $DEFAULT_INTERFACE -j ACCEPT; iptables -D FORWARD -i $DEFAULT_INTERFACE -o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC
AllowedIPs = 192.168.200.2/32
EOF

wg-quick up wg0
systemctl enable wg-quick@wg0

echo "Firewall-Regeln einrichten..."
iptables -A INPUT -i $DEFAULT_INTERFACE -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT 
iptables -A INPUT -i $DEFAULT_INTERFACE -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P INPUT DROP

iptables -A FORWARD -i wg0 -o $DEFAULT_INTERFACE -j ACCEPT
iptables -A FORWARD -i $DEFAULT_INTERFACE -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A PREROUTING -i $DEFAULT_INTERFACE -p tcp -m multiport --dport 31400:31409 -j DNAT --to-destination 192.168.200.2

iptables -P FORWARD ACCEPT
'@

    $bash = $bash -replace '{{SERVER_PRIV}}', $serverPriv.Trim()
    $bash = $bash -replace '{{SERVER_PUB}}', $serverPub.Trim()
    $bash = $bash -replace '{{CLIENT_PUB}}', $clientPub.Trim()

    $tempScript = Join-Path $env:TEMP "wg_setup.sh"
    $bashMitUnixZeilenenden = $bash -replace "`r`n", "`n"
    [System.IO.File]::WriteAllText($tempScript, $bashMitUnixZeilenenden, (New-Object System.Text.UTF8Encoding($false)))

    $pscp = Join-Path $pu 'pscp.exe'
    $plink = Join-Path $pu 'plink.exe'

    if ($authChoice -eq 'pw') {
        & $pscp -batch -pw $pwd $tempScript "root@${serverIp}:/tmp/wg_setup.sh"
        & $plink -batch -pw $pwd "root@${serverIp}" "bash /tmp/wg_setup.sh"
    }
    elseif ($authChoice -eq 'key') {
        & $pscp -batch -i $plinkAuthArgs[1] $tempScript "root@${serverIp}:/tmp/wg_setup.sh"
        & $plink -batch -i $plinkAuthArgs[1] "root@${serverIp}" "bash /tmp/wg_setup.sh"
    }

    $clientConfFileName = "client.conf"

    $clientConfDirFinal = $wg
    $clientConfPathFinal = Join-Path $clientConfDirFinal $clientConfFileName

    if (-not (Test-Path $clientConfDirFinal)) {
        try {
            New-Item -ItemType Directory -Path $clientConfDirFinal -Force -ErrorAction Stop | Out-Null
            Write-Log "WireGuard Konfigurationsverzeichnis erstellt: $clientConfDirFinal" "INFO"
        } catch {
            Write-Warning "Fehler beim Erstellen des WireGuard Konfigurationsverzeichnisses: $clientConfDirFinal. $_"
            Write-Log "Fehler beim Erstellen des WG Konfig-Verzeichnisses $clientConfDirFinal : $_" "ERROR"
            Pause
            return
        }
    }

    $clientConfContent = @"
[Interface]
PrivateKey = $clientPriv
Address = 192.168.200.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = $serverPub
Endpoint = ${serverIp}:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"@

    Set-Content -Path $clientConfPathFinal -Value $clientConfContent -Encoding ASCII
    Write-Log "WireGuard Client-Konfiguration gespeichert unter: $clientConfPathFinal" "INFO"

    Write-Host "Versuche WireGuard-Tunneldienst zu installieren und zu starten..." -ForegroundColor Cyan

    try {
        $process = Start-Process -FilePath (Join-Path $wg 'wireguard.exe') -ArgumentList "/installtunnelservice", "`"$clientConfPathFinal`"" -Wait -PassThru -ErrorAction Stop
        Write-Log "wg.exe /installtunnelservice ausgeführt mit ExitCode $($process.ExitCode) für $clientConfPathFinal" "INFO"

        if ($process.ExitCode -eq 0) {
            Write-Host "WireGuard-Tunneldienst für '$((Get-Item $clientConfPathFinal).BaseName)' wurde erfolgreich (neu)initialisiert (ExitCode 0)." -ForegroundColor Green
            Write-Log "WireGuard-Tunneldienst für '$((Get-Item $clientConfPathFinal).BaseName)' erfolgreich (neu)initialisiert mit ExitCode 0." "INFO"
        } else {
            Write-Warning "Fehler beim Installieren/Starten des WireGuard-Tunneldienstes. ExitCode: $($process.ExitCode)"
            Write-Log "Fehler beim Installieren/Starten des WireGuard-Tunneldienstes für $clientConfPathFinal. ExitCode: $($process.ExitCode)" "ERROR"
        }
    }
    catch {
        Write-Warning "Schwerwiegender Fehler beim Ausführen von wireguard.exe /installtunnelservice: $_"
        Write-Log "Schwerwiegender Fehler beim Ausführen von wireguard.exe /installtunnelservice für ${clientConfPathFinal}: $_" "ERROR"
    }

    Refresh-InstallationStatus

    Write-Host "WIREGUARD-SETUP ERFOLGREICH ABGESCHLOSSEN." -ForegroundColor White -BackgroundColor Green
    Write-Host "HINWEIS: Bitte beachten Sie, dass gegebenenfalls der WireGuard-UDP-Port 51820 sowie die TCP-Ports 31400 bis 31409 für den Pi Network Node im Kundeninterface Ihres Serveranbieters freigegeben werden müssen bzw. bereits eingetragen sind!" -ForegroundColor White -BackgroundColor Red
    Write-Host " "
    Write-Host "Importieren Sie jetzt die WireGuard Client Konfigurationsdatei in den WireGuard Client." -ForegroundColor Yellow
    Write-Host "Dazu im WireGuard Client auf: Importiere Tunnel aus Datei" -ForegroundColor Yellow
    Write-Host "Zu finden ist die Konfigurationsdatei unter:" -ForegroundColor Yellow
    Write-Host "C:\Program Files\WireGuard\client.conf" -ForegroundColor Yellow
    Write-Host " " 
    Pause
}

function Show-Menu {
    Clear-Host
    Refresh-InstallationStatus

    Write-Host '===[ Pi Network Windows Node Setup Helper Script ]===' -ForegroundColor White -BackgroundColor Green
    Write-Host ''

    Write-Host '1) Windows-Updates' -ForegroundColor Cyan

    if ($WSL2Enabled) {
        Write-Host "2) WSL2 (" -ForegroundColor Cyan -NoNewline
        Write-Host "aktiviert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "2) WSL2 einrichten" -ForegroundColor Cyan
    }

    if ($DockerInstalled) {
        Write-Host "3) Docker Desktop (" -ForegroundColor Cyan -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
        Refresh-InstallationStatus
    } else {
        Write-Host "3) Docker Desktop installieren" -ForegroundColor Cyan
    }

    if ($PiNodeInstalled) {
        Write-Host "4) Pi Network Node (" -ForegroundColor Cyan -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "4) Pi Network Node installieren" -ForegroundColor Cyan
    }

    if ($FirewallPortsOpen) {
        Write-Host "5) Firewall-Ports (" -ForegroundColor Cyan -NoNewline
        Write-Host "freigegeben" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Cyan
    } else {
        Write-Host "5) Firewall-Ports freigeben" -ForegroundColor Cyan
    }

    if ($PuTTYInstalled) {
        Write-Host "6) PuTTY (" -ForegroundColor Yellow -NoNewline
        Write-Host "installiert" -ForegroundColor Green -NoNewline
        Write-Host ")" -ForegroundColor Yellow
    } else {
        Write-Host "6) PuTTY installieren" -ForegroundColor Yellow
    }

    if ($WireGuardInstalled) {
        if ($WGKeysPresent) {
            Write-Host "7) WireGuard (" -ForegroundColor Yellow -NoNewline
            Write-Host "installiert, Schlüssel vorhanden" -ForegroundColor Green -NoNewline
            Write-Host ")" -ForegroundColor Yellow
        } else {
            Write-Host "7) WireGuard (" -ForegroundColor Yellow -NoNewline
            Write-Host "installiert, keine Schlüssel" -ForegroundColor DarkYellow -NoNewline
            Write-Host ")" -ForegroundColor Yellow
        }
    } else {
        Write-Host "7) WireGuard Windows Client installieren" -ForegroundColor Yellow
    }

    Write-Host '8) Automatisch WireGuard Server einrichten & Client verbinden ' -ForegroundColor Yellow -NoNewline
    if ($WGConnectionActive) {
        Write-Host '(' -ForegroundColor Yellow -NoNewline
        Write-Host 'aktiv' -ForegroundColor Green -NoNewline
        Write-Host ')' -ForegroundColor Yellow
    } else {
        Write-Host ''
    }

    Write-Host '9) PiCheck herunterladen, entpacken und starten' -ForegroundColor White

    Write-Host '10) Aktionen rückgängig machen (Uninstall/Deaktivieren)' -ForegroundColor DarkRed

    Write-Host '11) Hilfe / Info' -ForegroundColor DarkGreen
    Write-Host '12) Beenden' -ForegroundColor DarkGreen

    Write-Host ''
}


while ($true) {
    Refresh-InstallationStatus
    Show-Menu
    $choice = Read-Host 'Auswahl'

    switch ($choice) {
        '1' { Do-WindowsUpdates }
        '2' { Do-EnableWSL2 -resumeWSL:$resumeWSL }
        '3' {
            if (-not $DockerInstalled) { Do-InstallDocker }
            else { Write-Host 'Docker Desktop bereits installiert.' -ForegroundColor Green; Pause }
        }
        '4' {
            if (-not $PiNodeInstalled) { Do-InstallPiNode }
            else { Write-Host 'Pi Network Node bereits installiert.' -ForegroundColor Green; Pause }
        }
        '5' { Do-FirewallPorts }
        '6' {
            if (-not $PuTTYInstalled) { Do-InstallPuTTY }
            else { Write-Host 'PuTTY bereits installiert.' -ForegroundColor Green; Pause }
        }
        '7' {
            if (-not $WireGuardInstalled) {
                Do-InstallWireGuard
            } else {
                Write-Host 'WireGuard bereits installiert.' -ForegroundColor Green
                $wgDir = Get-WGDir
                if ($wgDir) {
                    Gen-WGKeys $wgDir
                } else {
                    Write-Warning "WireGuard-Verzeichnis nicht gefunden – keine Schlüssel generiert."
                }
                Pause
            }
        }
        '8' { Do-SetupWGServer }
        '9' { DownloadAndStartPiCheck }
        '10' {
            $runningUninstallMenu = $true
            while ($runningUninstallMenu) {
                Show-UninstallMenu
                $undoChoice = Read-Host 'Auswahl'
                switch ($undoChoice) {
                    '0' { Undo-All }
                    '1' { Undo-Docker }
                    '2' { Undo-PiNode }
                    '3' { Undo-PuTTY }
                    '4' { Undo-WireGuard }
                    '5' { Undo-FirewallRules }
                    '6' { Undo-WSL2 }
                    '7' { Undo-PiCheck }
                    '8' { $runningUninstallMenu = $false }
                    default { Write-Warning 'Ungültige Eingabe'; Pause }
                }
            }
        }
        '11' {
            Write-Host ' ' -ForegroundColor Green
            Write-Host 'Die Schritte 1 bis 5 unterstützen Sie bei der grundlegenden Einrichtung eines Pi Network Nodes.' -ForegroundColor Green
            Write-Host 'Die Schritte 6 bis 8 helfen Ihnen dabei, einen WireGuard-Server unter Linux automatisch zu installieren und zu konfigurieren,' -ForegroundColor Green
            Write-Host 'damit Ihr Pi Network Node über eine öffentliche IPv4-Adresse erreichbar ist und eingehende Verbindungen empfangen kann.' -ForegroundColor Green
            Write-Host 'Schritt 9 lädt die aktuellste Version der PiCheck-Software herunter, entpackt sie und startet das Programm.' -ForegroundColor Green
            Write-Host 'PiCheck ist ein nützliches Analysetool für alle Pi-Network-Node-Betreiber.' -ForegroundColor Green
            Write-Host ' '
            Write-Host 'Schritt 10 ermöglicht es, alle Aktionen und Installationen rückgängig zu machen.' -ForegroundColor Green
            Write-Host ' '
            Write-Host 'Wenn Sie Unterstützung benötigen, erreichen Sie uns über folgenden Link in unserer Telegram Gruppe:' -ForegroundColor Green
            Write-Host 'Telegram: https://t.me/PiNetzwerkDeutschland' -ForegroundColor Yellow
            Write-Host ' '
            Pause
        }
        '12' {
            Write-Log "`nBeende das Skript. Vielen Dank für die Nutzung!" 'INFO'
            Write-Host 'Setup beendet.'
            exit
        }
        default {
            Write-Warning 'Ungültige Eingabe. Bitte eine Zahl von 1 bis 12 eingeben.'
            Pause
        }
    }

    Refresh-InstallationStatus
}


function Cleanup-TemporaryFiles {
    param (
        [string]$ppkPath = $null
    )

    try {
        if ($ppkPath -and (Test-Path $ppkPath)) {
            Write-Host "Bereinige temporäre Datei: $ppkPath" -ForegroundColor DarkGray
            Remove-Item $ppkPath -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "Fehler beim Bereinigen temporärer Dateien: $_"
    }
}

if ($resumeWSL) {
    Do-EnableWSL2 -resumeWSL
    return
}
