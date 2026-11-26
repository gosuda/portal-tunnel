$ErrorActionPreference = "Stop"
$OfficialBaseUrl = "https://github.com/gosuda/portal-tunnel/releases/latest/download"
$BaseUrl = if ($env:BASE_URL) { $env:BASE_URL } else { $OfficialBaseUrl }
$RelayUrl = if ($env:RELAY_URL) { $env:RELAY_URL } else { "https://your-relay.example.com" }
# Portal Desktop is opt-in: set PORTAL_WITH_GUI=1 before the installer runs.
# Without it the installer installs the CLI alone.
$WithGui = -not [string]::IsNullOrWhiteSpace($env:PORTAL_WITH_GUI) -and @("0", "false") -notcontains $env:PORTAL_WITH_GUI.Trim().ToLowerInvariant()
$OriginalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$WorkDir = $null

function Assert-Checksum($Path, $ChecksumUrl, $Label) {
    $ChecksumResponse = Invoke-WebRequest -UseBasicParsing -Uri $ChecksumUrl
    if ($ChecksumResponse.Content -is [byte[]]) {
        $ChecksumPayload = [System.Text.Encoding]::UTF8.GetString($ChecksumResponse.Content)
    } else {
        $ChecksumPayload = [string]$ChecksumResponse.Content
    }
    $ChecksumMatch = [regex]::Match($ChecksumPayload, '([A-Fa-f0-9]{64})')
    if (-not $ChecksumMatch.Success) {
        throw "Invalid checksum payload from $ChecksumUrl. Expected '<sha256>  <filename>'."
    }

    $ExpectedHash = $ChecksumMatch.Groups[1].Value.ToLowerInvariant()
    $ActualHash = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "Checksum mismatch for $Label."
    }
}

try {
    $Arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($Arch -eq "ARM64") {
        $PortalArch = "arm64"
    } elseif ($Arch -eq "AMD64" -or $Arch -eq "x86_64") {
        $PortalArch = "amd64"
    } else {
        throw "Unsupported architecture: $Arch"
    }

    $BinPathPrefix = if ($env:BIN_PATH_PREFIX) { $env:BIN_PATH_PREFIX.Trim() } else { "" }
    if ($WithGui -and -not [string]::IsNullOrWhiteSpace($BinPathPrefix)) {
        throw "This relay serves the portal CLI only, not Portal Desktop. Install both from the official release: `$env:PORTAL_WITH_GUI = '1'; irm $OfficialBaseUrl/install.ps1 | iex"
    }
    # The CLI and the desktop must come from one release. Pin "latest" once,
    # so a release published between the two downloads cannot split the pair.
    $Release = $null
    if ($WithGui -and $BaseUrl -eq $OfficialBaseUrl -and -not $env:BIN_URL) {
        $Request = [System.Net.WebRequest]::Create("$BaseUrl/portal-windows-$PortalArch.exe")
        $Request.Method = "HEAD"
        $Request.AllowAutoRedirect = $false
        $Response = $Request.GetResponse()
        $Location = $Response.Headers["Location"]
        $Response.Close()
        if ($Location -notmatch '^https://github\.com/gosuda/portal-tunnel/releases/download/v[^/]+/portal-windows-') {
            throw "Could not find the latest release."
        }
        $BaseUrl = $Location.Substring(0, $Location.LastIndexOf('/'))
        $Release = $BaseUrl.Substring($BaseUrl.LastIndexOf('/') + 1)
    }

    if ($env:BIN_URL) {
        $BinUrl = $env:BIN_URL
    } elseif ([string]::IsNullOrWhiteSpace($BinPathPrefix)) {
        $BinUrl = "$BaseUrl/portal-windows-$PortalArch.exe"
    } else {
        $BinUrl = "$BaseUrl/$BinPathPrefix/windows-$PortalArch"
    }
    $ChecksumUrl = if ($env:CHECKSUM_URL) { $env:CHECKSUM_URL } else { "$BinUrl.sha256" }
    $DesktopUrl = if ($env:DESKTOP_URL) { $env:DESKTOP_URL } else { "$BaseUrl/portal-desktop-windows-$PortalArch.exe" }
    $WorkDir = Join-Path $env:TEMP ("portal-install-" + [Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    $BinPath = Join-Path $WorkDir "portal.exe"
    $DesktopDownload = Join-Path $WorkDir "portal-desktop.exe"

    Write-Host "Downloading portal (windows/$PortalArch)..."
    Invoke-WebRequest -UseBasicParsing -Uri $BinUrl -OutFile $BinPath

    Write-Host "Verifying SHA256 checksum..."
    Assert-Checksum $BinPath $ChecksumUrl "portal binary"

    # Everything is downloaded and verified before anything is installed.
    if ($WithGui) {
        Write-Host "Downloading Portal Desktop (windows/$PortalArch)..."
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $DesktopUrl -OutFile $DesktopDownload
        } catch {
            throw "Could not download Portal Desktop from $DesktopUrl. Nothing was installed. A release publishes Portal Desktop shortly after the CLI. Try again later, or install the CLI alone without PORTAL_WITH_GUI."
        }

        Write-Host "Verifying SHA256 checksum..."
        Assert-Checksum $DesktopDownload "$DesktopUrl.sha256" "Portal Desktop"
    }

    $InstallDir = Join-Path $env:LOCALAPPDATA "portal\bin"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $InstallPath = Join-Path $InstallDir "portal.exe"
    $DesktopPath = Join-Path $InstallDir "portal-desktop.exe"
    $DesktopBackup = $null

    # The desktop goes in first, beside the CLI; the one it replaces, which
    # may be running, is moved aside until the CLI is installed too.
    if ($WithGui) {
        # Portal Desktop needs the CLI of its own release, so an older CLI is
        # updated with it.
        if ($Release -and (Test-Path $InstallPath)) {
            Write-Host "Replacing portal at $InstallPath with portal $Release, the release of Portal Desktop."
        }
        if (Test-Path $DesktopPath) {
            $DesktopBackup = "$DesktopPath.old"
            Remove-Item -Force -ErrorAction SilentlyContinue $DesktopBackup
            Move-Item -Force $DesktopPath $DesktopBackup
        }
        try {
            Copy-Item -Force $DesktopDownload $DesktopPath
        } catch {
            if ($DesktopBackup) { Move-Item -Force $DesktopBackup $DesktopPath }
            throw
        }
    }
    try {
        Copy-Item -Force $BinPath $InstallPath
    } catch {
        if ($WithGui) {
            Remove-Item -Force -ErrorAction SilentlyContinue $DesktopPath
            if ($DesktopBackup) { Move-Item -Force $DesktopBackup $DesktopPath }
        }
        throw
    }
    if ($DesktopBackup) {
        # A desktop that is still running keeps its file until it exits.
        Remove-Item -Force -ErrorAction SilentlyContinue $DesktopBackup
    }

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $UserEntries = @()
    if (-not [string]::IsNullOrWhiteSpace($UserPath)) {
        $UserEntries = @($UserPath -split ';' | Where-Object { $_ -ne "" })
    }
    if (-not ($UserEntries -contains $InstallDir)) {
        $NewUserPath = if ([string]::IsNullOrWhiteSpace($UserPath)) {
            $InstallDir
        } else {
            "$InstallDir;$UserPath"
        }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    }

    $SessionEntries = @($env:Path -split ';' | Where-Object { $_ -ne "" })
    if (-not ($SessionEntries -contains $InstallDir)) {
        $env:Path = "$InstallDir;$env:Path"
    }

    Write-Host "Installed portal to $InstallPath"
    if ($WithGui) {
        $Shell = New-Object -ComObject WScript.Shell
        $Shortcut = $Shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath("Programs")) "Portal Desktop.lnk"))
        $Shortcut.TargetPath = $DesktopPath
        $Shortcut.WorkingDirectory = $InstallDir
        $Shortcut.Description = "Portal Desktop"
        $Shortcut.Save()
        Write-Host "Installed Portal Desktop to $DesktopPath and added it to the Start menu"
        if ($DesktopBackup) {
            Write-Host "Reopen Portal Desktop if it is running."
        }
    }
    Write-Host "Next step:"
    Write-Host "  portal expose 3000 --relays $RelayUrl"
    if ($WithGui) {
        Write-Host "  portal gui"
    }
} finally {
    [System.Net.ServicePointManager]::SecurityProtocol = $OriginalSecurityProtocol
    if ($WorkDir -and (Test-Path $WorkDir)) {
        Remove-Item -Recurse -Force $WorkDir
    }
}
