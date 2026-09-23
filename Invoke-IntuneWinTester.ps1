#Requires -Version 5.1

<#
.SYNOPSIS
    Decodes an .intunewin file and opens a persistent PowerShell window in the extracted folder.

.DESCRIPTION
    Extracts and decrypts an .intunewin package using the AES-256-CBC key/IV embedded in
    Detection.xml, then opens a new PowerShell window (pwsh or powershell) in the extracted
    directory. Optionally runs a script block string in that window.

    On repeated runs the script computes a SHA-256 of the source .intunewin file and compares
    it against a hash stored in the extraction folder (._intunewin_source.sha256). When the
    hashes match the decryption step is skipped entirely and the window opens immediately.
    Use -Force to ignore the cache and re-decrypt unconditionally.

.PARAMETER IntuneWinFile
    Path to the .intunewin file to decode.

.PARAMETER ScriptBlock
    Script block content (as a string) to run in the new window.
    The new window stays open after the script block finishes (-NoExit).

.PARAMETER ExtractPath
    Destination folder for the decoded contents.
    Defaults to <baseName>_decoded next to the .intunewin file (deterministic, no timestamp).

.PARAMETER ConfigFile
    Path to a JSON file describing the app package. Required fields: display_name,
    install_type, install_command, uninstall_command, detection_rule.
    When supplied the new window shows a banner and defines Invoke-Install,
    Invoke-Uninstall, and Invoke-Detection helpers automatically.

.PARAMETER Force
    Re-decrypt even if the source file hash matches the cached hash.

.EXAMPLE
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin

.EXAMPLE
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json

.EXAMPLE
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json -ScriptBlock 'Invoke-Install'

.EXAMPLE
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -Force

.PARAMETER PsExecPath
    Path to psexec.exe / PsExec64.exe. Only needed when install_type is 'system'.
    If omitted the script looks for PsExec64.exe or psexec.exe next to itself, then
    falls back to PATH. An error is raised if it cannot be found.

.EXAMPLE
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ExtractPath C:\Temp\MyApp -ScriptBlock 'Get-ChildItem | Select-Object Name'

.EXAMPLE
    # system context — PsExec next to the script
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json

.EXAMPLE
    # system context — explicit PsExec location
    .\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json -PsExecPath 'C:\Tools\PsExec64.exe'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$IntuneWinFile,

    [Parameter(Mandatory = $false)]
    [string]$ScriptBlock = '',

    [Parameter(Mandatory = $false)]
    [string]$ExtractPath = '',

    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = '',

    [Parameter(Mandatory = $false)]
    [string]$PsExecPath = '',

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region ── Helpers ──────────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Skip {
    param([string]$Message)
    Write-Host "[~] $Message" -ForegroundColor DarkCyan
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

function Get-FileSHA256 {
    param([string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs  = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha.ComputeHash($fs)
        return [System.BitConverter]::ToString($hashBytes) -replace '-'
    }
    finally {
        $fs.Dispose()
        $sha.Dispose()
    }
}

#endregion

#region ── Validate input ───────────────────────────────────────────────────────

$IntuneWinFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($IntuneWinFile)

if (-not (Test-Path -LiteralPath $IntuneWinFile -PathType Leaf)) {
    Write-Fail "File not found: $IntuneWinFile"
    exit 1
}

if ([System.IO.Path]::GetExtension($IntuneWinFile) -ne '.intunewin') {
    Write-Fail "File does not have a .intunewin extension: $IntuneWinFile"
    exit 1
}

#endregion

#region ── Resolve paths ────────────────────────────────────────────────────────

$baseName  = [System.IO.Path]::GetFileNameWithoutExtension($IntuneWinFile)
$parentDir = [System.IO.Path]::GetDirectoryName($IntuneWinFile)

$userSpecifiedExtractPath = ($ExtractPath -ne '')

if ($ExtractPath -eq '') {
    $ExtractPath = Join-Path $parentDir "${baseName}_decoded"
}
$ExtractPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExtractPath)

# Sentinel file that stores the SHA-256 of the last successfully decoded source
# (may be updated below once the app name subfolder is known)
$hashSentinel = Join-Path $ExtractPath '._intunewin_source.sha256'

#endregion

#region ── Load app config (optional) ───────────────────────────────────────────

$appConfig = $null

if ($ConfigFile -ne '') {
    $ConfigFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFile)

    if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
        Write-Fail "Config file not found: $ConfigFile"
        exit 1
    }

    try {
        $appConfig = Get-Content -LiteralPath $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Write-Fail "Failed to parse JSON config: $_"
        exit 1
    }

    $requiredFields = @('display_name', 'install_type', 'install_command', 'uninstall_command', 'detection_rule')
    $missingFields  = $requiredFields | Where-Object {
        -not $appConfig.PSObject.Properties[$_] -or
        [string]::IsNullOrWhiteSpace($appConfig.PSObject.Properties[$_].Value)
    }

    if ($missingFields) {
        Write-Fail "Config is missing required field(s): $($missingFields -join ', ')"
        exit 1
    }

    Write-OK "Config loaded: $($appConfig.display_name)"
}

# When the caller supplied an explicit -ExtractPath, scope it to a subfolder
# named after the app so multiple packages can share the same root directory.
if ($userSpecifiedExtractPath) {
    $subfolder    = $baseName
    $ExtractPath  = Join-Path $ExtractPath $subfolder
    $ExtractPath  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExtractPath)
    $hashSentinel = Join-Path $ExtractPath '._intunewin_source.sha256'
}

#endregion

#region ── Cache check ──────────────────────────────────────────────────────────

Write-Step "Computing SHA-256 of source file..."
$currentHash = Get-FileSHA256 -Path $IntuneWinFile
Write-OK "SHA-256: $currentHash"

$needsDecode = $true

if (-not $Force -and (Test-Path -LiteralPath $ExtractPath -PathType Container) -and (Test-Path -LiteralPath $hashSentinel -PathType Leaf)) {
    $cachedHash = (Get-Content -LiteralPath $hashSentinel -Raw).Trim()
    if ($cachedHash -eq $currentHash) {
        Write-Skip "Source file unchanged — skipping decryption (use -Force to override)."
        $needsDecode = $false
    }
    else {
        Write-Step "Source file has changed — re-decoding..."
        Remove-Item -LiteralPath $ExtractPath -Recurse -Force
    }
}

#endregion

#region ── Decode (only when needed) ────────────────────────────────────────────

if ($needsDecode) {

    $runId      = [System.Guid]::NewGuid().ToString('N').Substring(0, 8)
    $stagingDir = Join-Path $env:TEMP "intunewin_stage_$runId"

    #region ── Stage: unzip outer .intunewin ────────────────────────────────────

    Write-Step "Expanding outer ZIP: $IntuneWinFile"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($IntuneWinFile, $stagingDir)
        Write-OK "Staged to: $stagingDir"
    }
    catch {
        Write-Fail "Failed to unzip outer container: $_"
        exit 1
    }

    #endregion

    #region ── Parse Detection.xml for AES key / IV ─────────────────────────────

    $detectionXmlPath = Join-Path $stagingDir 'Detection.xml'
    if (-not (Test-Path $detectionXmlPath)) {
        $detectionXmlPath = Get-ChildItem -Path $stagingDir -Filter 'Detection.xml' -Recurse -ErrorAction SilentlyContinue |
                            Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $detectionXmlPath -or -not (Test-Path $detectionXmlPath)) {
        Write-Fail 'Detection.xml not found inside the .intunewin package.'
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    Write-Step "Parsing encryption info from: $detectionXmlPath"
    [xml]$xml = Get-Content $detectionXmlPath -Raw -Encoding UTF8

    $encInfo = $xml.ApplicationInfo.EncryptionInfo
    if (-not $encInfo) {
        Write-Fail 'EncryptionInfo element not found in Detection.xml.'
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Field names vary between Intune versions
    $keyB64 = $encInfo.EncryptionKey
    $ivB64  = if ($encInfo.InitializationVector) { $encInfo.InitializationVector } else { $encInfo.IV }

    if (-not $keyB64 -or -not $ivB64) {
        $foundKeys = ($encInfo | Get-Member -MemberType Property | Select-Object -ExpandProperty Name) -join ', '
        Write-Fail "Could not locate EncryptionKey or IV in Detection.xml (found: $foundKeys)"
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    $keyBytes = [System.Convert]::FromBase64String($keyB64)
    $ivBytes  = [System.Convert]::FromBase64String($ivB64)
    Write-OK "Key length: $($keyBytes.Length * 8) bits  |  IV length: $($ivBytes.Length * 8) bits"

    #endregion

    #region ── Locate encrypted inner package ───────────────────────────────────

    $encryptedPkg = Join-Path $stagingDir 'IntunePackage.intunewin'
    if (-not (Test-Path $encryptedPkg)) {
        $encryptedPkg = Get-ChildItem -Path $stagingDir -Filter 'IntunePackage.intunewin' -Recurse -ErrorAction SilentlyContinue |
                        Select-Object -First 1 -ExpandProperty FullName
    }

    if (-not $encryptedPkg -or -not (Test-Path $encryptedPkg)) {
        Write-Fail 'IntunePackage.intunewin not found inside the package.'
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }

    #endregion

    #region ── AES-256-CBC decryption ───────────────────────────────────────────

    Write-Step "Decrypting: $encryptedPkg"

    $decryptedZip = Join-Path $env:TEMP "intunewin_decrypted_$runId.zip"

    try {
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key     = $keyBytes
        $aes.IV      = $ivBytes
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        # PaddingMode.None: Intune does not use standard PKCS7 padding.
        # PKCS7 would silently strip real ZIP bytes from the end (EOCD truncation).
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

        $decryptor = $aes.CreateDecryptor()

        $fsIn  = [System.IO.File]::OpenRead($encryptedPkg)
        $fsOut = [System.IO.File]::Create($decryptedZip)
        $cs    = [System.Security.Cryptography.CryptoStream]::new($fsIn, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)

        $cs.CopyTo($fsOut)

        $cs.Close();    $cs.Dispose()
        $fsIn.Close();  $fsIn.Dispose()
        $fsOut.Close(); $fsOut.Dispose()
        $decryptor.Dispose()
        $aes.Dispose()

        Write-OK "Decrypted to: $decryptedZip ($((Get-Item $decryptedZip).Length) bytes)"
    }
    catch {
        Write-Fail "Decryption failed: $_"
        Remove-Item $stagingDir   -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $decryptedZip -Force          -ErrorAction SilentlyContinue
        exit 1
    }

    #endregion

    #region ── Validate ZIP magic & find data offset ────────────────────────────

    # ZIP local-file-header magic: PK\x03\x04
    $zipMagic  = [byte[]](0x50, 0x4B, 0x03, 0x04)
    $zipOffset = 0L

    $probeFs  = [System.IO.File]::OpenRead($decryptedZip)
    $probeBuf = New-Object byte[] 64
    $probeFs.Read($probeBuf, 0, 64) | Out-Null
    $probeFs.Close()

    $firstBytes = ($probeBuf[0..3] | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-Step "First 4 decrypted bytes: $firstBytes"

    if ($probeBuf[0] -ne 0x50 -or $probeBuf[1] -ne 0x4B) {
        # Scan up to the first 64 bytes for the PK signature
        for ($i = 1; $i -lt 61; $i++) {
            if ($probeBuf[$i]   -eq 0x50 -and $probeBuf[$i+1] -eq 0x4B -and
                $probeBuf[$i+2] -eq 0x03 -and $probeBuf[$i+3] -eq 0x04) {
                $zipOffset = $i
                break
            }
        }
        if ($zipOffset -gt 0) {
            Write-Skip "ZIP magic found at byte offset $zipOffset — trimming $zipOffset-byte prefix."
            # Rewrite the file without the prefix so ZipArchive can seek normally
            $allBytes   = [System.IO.File]::ReadAllBytes($decryptedZip)
            $trimmed    = $allBytes[$zipOffset..($allBytes.Length - 1)]
            [System.IO.File]::WriteAllBytes($decryptedZip, $trimmed)
            Remove-Variable allBytes, trimmed
        }
        else {
            Write-Fail "ZIP magic (PK) not found in first 64 bytes of decrypted output. Decryption may have used the wrong key or IV."
            Remove-Item $stagingDir   -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $decryptedZip -Force          -ErrorAction SilentlyContinue
            exit 1
        }
    }
    else {
        Write-OK "ZIP magic confirmed at byte 0."
    }

    #endregion

    #region ── Extract decrypted ZIP (entry-by-entry via ZipArchive) ─────────────

    Write-Step "Extracting decoded package to: $ExtractPath"
    $zipFs = $null
    $za    = $null
    try {
        if (-not (Test-Path $ExtractPath)) {
            New-Item -ItemType Directory -Path $ExtractPath | Out-Null
        }

        $zipFs = [System.IO.File]::OpenRead($decryptedZip)
        $za    = [System.IO.Compression.ZipArchive]::new($zipFs, [System.IO.Compression.ZipArchiveMode]::Read, $false)

        $entryCount = 0
        foreach ($entry in $za.Entries) {
            $destPath = Join-Path $ExtractPath $entry.FullName

            # Directory entry
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                if (-not (Test-Path $destPath)) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                }
                continue
            }

            # File entry — ensure parent directory exists
            $destDir = [System.IO.Path]::GetDirectoryName($destPath)
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }

            $entryStream = $entry.Open()
            $outStream   = [System.IO.File]::Create($destPath)
            $entryStream.CopyTo($outStream)
            $outStream.Dispose()
            $entryStream.Dispose()
            $entryCount++
        }

        Write-OK "Extracted $entryCount file(s) successfully."
    }
    catch {
        Write-Fail "Failed to extract decrypted ZIP: $_"
        Remove-Item $stagingDir   -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $decryptedZip -Force          -ErrorAction SilentlyContinue
        exit 1
    }
    finally {
        if ($za)    { $za.Dispose() }
        if ($zipFs) { $zipFs.Dispose() }
        Remove-Item $stagingDir   -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $decryptedZip -Force          -ErrorAction SilentlyContinue
    }

    #endregion

    #region ── Persist hash sentinel ────────────────────────────────────────────

    Set-Content -LiteralPath $hashSentinel -Value $currentHash -Encoding ASCII -NoNewline
    Write-OK "Hash sentinel written: $hashSentinel"

    #endregion
}

#endregion

#region ── Launch persistent PowerShell window ──────────────────────────────────

Write-Step "Launching new PowerShell window in: $ExtractPath"

# Lines are collected into a List then joined and Base64-encoded for
# -EncodedCommand, which eliminates all argument-quoting issues and supports
# Unicode (emoji, box-drawing chars) in any config field.
$initLines = [System.Collections.Generic.List[string]]::new()

$escapedPath = $ExtractPath -replace "'", "''"
$initLines.Add("Set-Location -LiteralPath '$escapedPath'")

if ($appConfig) {

    #-- Embed config values (expand variables here, at build time) ----------
    $dn      = $appConfig.display_name     -replace "'", "''"
    $it      = $appConfig.install_type     -replace "'", "''"
    $ic      = $appConfig.install_command   -replace "'", "''"
    $uc      = $appConfig.uninstall_command -replace "'", "''"
    $dr      = $appConfig.detection_rule   -replace "'", "''"
    $pub     = if ($appConfig.publisher)     { $appConfig.publisher -replace "'","''" } else { $null }
    $restart = if ($appConfig.restart)       { $appConfig.restart   -replace "'","''" } else { $null }

    $ver = $null
    if ($appConfig.major_version) {
        $ver = $appConfig.major_version
        if ($appConfig.minor_version) { $ver += ".$($appConfig.minor_version)" }
        if ($appConfig.hotfix)        { $ver += ".$($appConfig.hotfix)" }
    }

    # Prefix plain filenames with .\ so they run from the extracted folder
    $drCall = if ($dr -match '[/\\]') { $dr } else { ".\$dr" }

    # Resolve full on-disk paths for the banner (expand relative tokens against ExtractPath)
    $resolveFullCmd = {
        param([string]$Cmd, [string]$Base)
        $parts = $Cmd.Trim() -split '\s+', 2
        $exe   = $parts[0] -replace '^\.[\\/]', ''
        $args_ = if ($parts.Count -gt 1) { ' ' + $parts[1] } else { '' }
        $full  = if ([System.IO.Path]::IsPathRooted($exe)) { $exe } else { Join-Path $Base $exe }
        return ("$full$args_" -replace "'", "''")
    }
    $icFullBanner = & $resolveFullCmd $appConfig.install_command   $ExtractPath
    $ucFullBanner = & $resolveFullCmd $appConfig.uninstall_command $ExtractPath
    $drFullBanner = & $resolveFullCmd $appConfig.detection_rule    $ExtractPath

    #-- Window title & config banner ----------------------------------------
    $initLines.Add("`$host.UI.RawUI.WindowTitle = '$dn'")
    $initLines.Add("Write-Host ''")
    $initLines.Add("Write-Host ('─' * 62) -ForegroundColor DarkCyan")
    $initLines.Add("Write-Host '  $dn' -ForegroundColor White")
    $initLines.Add("Write-Host ('─' * 62) -ForegroundColor DarkCyan")
    if ($pub)     { $initLines.Add("Write-Host '  Publisher    : $pub' -ForegroundColor Gray") }
    if ($ver)     { $initLines.Add("Write-Host '  Version      : $ver' -ForegroundColor Gray") }
    if ($it -eq 'system') {
        $initLines.Add("Write-Host '  Install as   : SYSTEM  [running via PsExec]' -ForegroundColor Magenta")
    } else {
        $initLines.Add("Write-Host '  Install as   : $it' -ForegroundColor Gray")
    }
    if ($restart) { $initLines.Add("Write-Host '  Restart      : $restart' -ForegroundColor Gray") }
    $initLines.Add("Write-Host ''")
    $initLines.Add("Write-Host '  Install      : $icFullBanner' -ForegroundColor Gray")
    $initLines.Add("Write-Host '  Uninstall    : $ucFullBanner' -ForegroundColor Gray")
    $initLines.Add("Write-Host '  Detection    : $drFullBanner' -ForegroundColor Gray")
    $initLines.Add("Write-Host ('─' * 62) -ForegroundColor DarkCyan")
    $initLines.Add("Write-Host ''")

    #-- Script-scope command variables (used by Invoke-Phase) ---------------
    $initLines.Add("`$script:_ic = '$ic'")
    $initLines.Add("`$script:_uc = '$uc'")
    $initLines.Add("`$script:_dr = '$drCall'")

    #-- Process-tree wait helper (single-quoted) ----------------------------
    # Win32_Process.ParentProcessId is set at spawn time and is not cleared when
    # the parent exits, so a BFS from the root PID finds all descendants even
    # after the root has already returned (PSADT pattern: Deploy-Application.exe
    # launches powershell.exe and exits early while the real install runs).
    $initLines.Add(@'
function Wait-ProcessTree {
    param([int]$RootPid, [int]$PollMs = 2000)
    $spinner   = [char[]]@('|', '/', '-', '\')
    $spinIdx   = 0
    $startTime = [datetime]::UtcNow
    do {
        Start-Sleep -Milliseconds $PollMs
        $visited = [System.Collections.Generic.HashSet[int]]::new()
        $queue   = [System.Collections.Generic.Queue[int]]::new()
        $queue.Enqueue($RootPid)
        while ($queue.Count -gt 0) {
            $pid_ = $queue.Dequeue()
            if ($visited.Add($pid_)) {
                Get-CimInstance -ClassName Win32_Process `
                    -Filter "ParentProcessId = $pid_" `
                    -ErrorAction SilentlyContinue |
                    ForEach-Object { $queue.Enqueue([int]$_.ProcessId) }
            }
        }
        $alive = @($visited | Where-Object {
            try   { $null = [System.Diagnostics.Process]::GetProcessById($_); $true }
            catch { $false }
        })
        if ($alive.Count -gt 0) {
            $elapsed = [int]([datetime]::UtcNow - $startTime).TotalSeconds
            $spin    = $spinner[$spinIdx % $spinner.Length]
            $spinIdx++
            $names = @($alive | ForEach-Object {
                try   { $p = Get-Process -Id $_ -ErrorAction SilentlyContinue; if ($p) { "$($p.Name) ($_)" } else { "PID $_" } }
                catch { "PID $_" }
            } | Select-Object -First 3)
            $nameStr = $names -join '  '
            $padded  = "  [~] Waiting $spin  $nameStr  (${elapsed}s)".PadRight(80)
            Write-Host "`r$padded" -NoNewline -ForegroundColor DarkGray
        }
    } while ($alive.Count -gt 0)
    Write-Host ("`r" + ' ' * 80 + "`r") -NoNewline
}
'@)

    #-- Phase runner (single-quoted: no build-time expansion) ---------------
    $initLines.Add(@'
function Invoke-Phase {
    param(
        [string]$Label,
        [string]$Cmd,
        [int]$ExpectedExit = 0,
        [switch]$Informational
    )
    Write-Host ''
    Write-Host "  [ $Label ]" -ForegroundColor Cyan
    Write-Host "  > $Cmd"     -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 58)) -ForegroundColor DarkGray

    $tokens     = $Cmd.Trim() -split '\s+', 2
    $firstToken = $tokens[0]
    $argStr     = if ($tokens.Count -gt 1) { $tokens[1] } else { $null }

    $phaseStart = [datetime]::UtcNow

    if ($firstToken -match '\.ps1$') {
        $psExe  = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $psArgs = [System.Collections.Generic.List[string]]::new()
        $psArgs.AddRange([string[]]@('-NonInteractive', '-NoProfile', '-File', $firstToken))
        if ($argStr) { $psArgs.Add($argStr) }
        $proc = Start-Process -FilePath $psExe -ArgumentList $psArgs -Wait -PassThru -NoNewWindow
        $ec   = $proc.ExitCode
    } else {
        try {
            $absExe = if ([System.IO.Path]::IsPathRooted($firstToken)) {
                $firstToken
            } else {
                Join-Path (Get-Location).Path $firstToken
            }
            $startArgs = @{ FilePath = $absExe; PassThru = $true; WorkingDirectory = (Get-Location).Path }
            if ($argStr) { $startArgs['ArgumentList'] = $argStr }
            $proc = Start-Process @startArgs
            Wait-ProcessTree -RootPid $proc.Id
            $proc.WaitForExit(500) | Out-Null
            $ec = $proc.ExitCode
        } catch {
            Write-Host "  ERROR: $_" -ForegroundColor Red
            $ec = -1
        }
    }

    $span       = [datetime]::UtcNow - $phaseStart
    $elapsedStr = if ($span.TotalMinutes -ge 1) {
        '{0}m {1:00}s' -f [int]$span.TotalMinutes, $span.Seconds
    } else {
        '{0}s' -f [int]$span.TotalSeconds
    }

    Write-Host ('  ' + ('-' * 58)) -ForegroundColor DarkGray
    if ($Informational) {
        $resultText = if ($ec -eq 0) { 'Detected' } else { 'Not detected' }
        $color      = if ($ec -eq 0) { 'Cyan' } else { 'DarkYellow' }
        Write-Host "  $resultText  (exit: $ec, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
    } else {
        $success    = ($ec -eq $ExpectedExit)
        $resultText = if ($success) { 'OK' } else { 'FAILED' }
        $color      = if ($success) { 'Green' } else { 'Red' }
        Write-Host "  $resultText  (exit: $ec, expected: $ExpectedExit, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
    }

    $script:_cycleResults += [PSCustomObject]@{
        Label      = $Label
        ResultText = $resultText
        ExitCode   = $ec
        Elapsed    = $elapsedStr
        IsOK       = if ($Informational) { $null } else { $success }
    }

    return $ec
}
'@)

    #-- Looped flow menu (single-quoted: all $vars are runtime) -------------
    $initLines.Add(@'
function Show-CycleSummary {
    param([string]$Title, [datetime]$StartTime)
    $ts     = [datetime]::UtcNow - $StartTime
    $total  = if ($ts.TotalMinutes -ge 1) { '{0}m {1:00}s' -f [int]$ts.TotalMinutes, $ts.Seconds } else { '{0}s' -f [int]$ts.TotalSeconds }
    $header = "─ $Title ─── $total "
    $fill   = [Math]::Max(0, 51 - $header.Length)
    Write-Host ''
    Write-Host "  ┌$header$('─' * $fill)┐" -ForegroundColor DarkCyan
    foreach ($r in $script:_cycleResults) {
        $lbl = $r.Label.PadRight(26)
        $res = $r.ResultText.PadRight(14)
        $ela = $r.Elapsed.PadLeft(7)
        $clr = switch ($r.IsOK) { $true { 'Green' } $false { 'Red' } default { 'Cyan' } }
        Write-Host "  │  $lbl$res$ela  │" -ForegroundColor $clr
    }
    Write-Host "  └$('─' * 51)┘" -ForegroundColor DarkCyan
    Write-Host ''
}

$script:_runCount     = 0
$script:_cycleResults = @()

while ($true) {
    Write-Host '  Select a flow to run:' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '    [1]  Install Cycle    (Detection >> Install >> Detection)' -ForegroundColor White
    Write-Host '    [2]  Uninstall Cycle  (Detection >> Uninstall >> Detection)' -ForegroundColor White
    Write-Host '    [3]  Detection Only' -ForegroundColor White
    Write-Host '    [4]  Install Only' -ForegroundColor White
    Write-Host '    [5]  Uninstall Only' -ForegroundColor White
    Write-Host '    [0]  Exit menu' -ForegroundColor DarkGray
    Write-Host ''
    $choice = Read-Host '  Choice (0-5)'
    Write-Host ''

    if ($choice.Trim() -eq '0') { break }

    $script:_runCount++
    $script:_cycleResults = @()
    $cycleStart = [datetime]::UtcNow
    $cycleTime  = Get-Date -Format 'HH:mm:ss'

    switch ($choice.Trim()) {
        '1' {
            Write-Host "  ════ Run #$($script:_runCount) · Install Cycle · $cycleTime ════════════════" -ForegroundColor Magenta
            $preEc = Invoke-Phase 'Detection (pre-install)' $script:_dr -Informational
            if ($preEc -eq 0) {
                Write-Host ''
                Write-Host '  [~] App already detected — install skipped.' -ForegroundColor Yellow
            } else {
                Invoke-Phase 'Install' $script:_ic
                Invoke-Phase 'Detection (post-install)' $script:_dr
            }
            Show-CycleSummary 'Install Cycle' $cycleStart
        }
        '2' {
            Write-Host "  ════ Run #$($script:_runCount) · Uninstall Cycle · $cycleTime ══════════════" -ForegroundColor Magenta
            $preEc = Invoke-Phase 'Detection (pre-uninstall)' $script:_dr -Informational
            if ($preEc -ne 0) {
                Write-Host ''
                Write-Host '  [~] App not detected — uninstall skipped.' -ForegroundColor Yellow
            } else {
                Invoke-Phase 'Uninstall' $script:_uc
                Invoke-Phase 'Detection (post-uninstall)' $script:_dr -ExpectedExit 1
            }
            Show-CycleSummary 'Uninstall Cycle' $cycleStart
        }
        '3' {
            Write-Host "  ════ Run #$($script:_runCount) · Detection Only · $cycleTime ════════════════" -ForegroundColor Magenta
            Invoke-Phase 'Detection' $script:_dr -Informational
        }
        '4' {
            Write-Host "  ════ Run #$($script:_runCount) · Install Only · $cycleTime ══════════════════" -ForegroundColor Magenta
            Invoke-Phase 'Install' $script:_ic
        }
        '5' {
            Write-Host "  ════ Run #$($script:_runCount) · Uninstall Only · $cycleTime ════════════════" -ForegroundColor Magenta
            Invoke-Phase 'Uninstall' $script:_uc
        }
        default {
            Write-Host "  [!] Invalid choice: '$choice'" -ForegroundColor Red
            $script:_runCount--
        }
    }

    Write-Host ''
    Write-Host '  ─── Done. Select another flow or [0] to exit the menu. ───' -ForegroundColor DarkCyan
    Write-Host ''
}
Write-Host ''
Write-Host '  Menu closed. Window stays open for manual inspection.' -ForegroundColor DarkGray
Write-Host ''
'@)
}
# No config: Set-Location is already queued; ScriptBlock (if any) is appended below.
# This restores the original behaviour — a clean PS window in the extracted folder.

if ($ScriptBlock -ne '') {
    $initLines.Add($ScriptBlock)
}

# Encode as UTF-16LE Base64 for -EncodedCommand
$initScript = $initLines -join "`n"
$encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($initScript))

$shell    = if (Get-Command 'pwsh' -ErrorAction SilentlyContinue) { 'pwsh' } else { 'powershell' }
$isSystem = $appConfig -and ($appConfig.install_type -eq 'system')

if ($isSystem) {

    #-- Administrator rights check ------------------------------------------
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Fail "install_type is 'system' — re-run this script as Administrator (right-click > Run as administrator)."
        exit 1
    }
    Write-OK "Administrator rights confirmed."

    #-- Locate PsExec -------------------------------------------------------
    $psexec = $null

    # Priority 1 — explicit -PsExecPath argument
    if ($PsExecPath -ne '') {
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PsExecPath)
        if (Test-Path -LiteralPath $resolved -PathType Leaf) {
            $psexec = $resolved
        } else {
            Write-Fail "-PsExecPath specified but file not found: $resolved"
            exit 1
        }
    }

    # Priority 2 — next to this script (prefer 64-bit)
    if (-not $psexec) {
        foreach ($name in @('PsExec64.exe', 'psexec.exe', 'PsExec.exe')) {
            $candidate = Join-Path $PSScriptRoot $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $psexec = $candidate
                break
            }
        }
    }

    # Priority 3 — anywhere in PATH
    if (-not $psexec) {
        foreach ($name in @('PsExec64.exe', 'psexec.exe')) {
            $found = Get-Command $name -ErrorAction SilentlyContinue
            if ($found) { $psexec = $found.Source; break }
        }
    }

    if (-not $psexec) {
        Write-Fail "PsExec not found. To fix:"
        Write-Host "  1. Drop PsExec64.exe or psexec.exe next to this script: $PSScriptRoot" -ForegroundColor Yellow
        Write-Host "  2. Pass -PsExecPath '<full path>'" -ForegroundColor Yellow
        Write-Host "  3. Download: https://learn.microsoft.com/en-us/sysinternals/downloads/psexec" -ForegroundColor Yellow
        exit 1
    }

    Write-OK "PsExec        : $psexec"
    Write-Step "Launching window as SYSTEM via PsExec..."

    # -accepteula : suppress the EULA dialog
    # -s          : run under the SYSTEM account
    # -i          : interactive — window appears on the current desktop session
    # -d          : don't wait for the child process to exit (return immediately)
    Start-Process -FilePath $psexec -ArgumentList @(
        '-accepteula', '-s', '-i', '-d',
        $shell, '-NoExit', '-EncodedCommand', $encodedCmd
    )

} else {
    Start-Process -FilePath $shell -ArgumentList @('-NoExit', '-EncodedCommand', $encodedCmd)
}

Write-OK "New $shell window launched."
Write-Host ''
Write-Host "  Extracted path : $ExtractPath" -ForegroundColor Yellow
if ($appConfig) {
    $contextLabel = if ($isSystem) { 'SYSTEM (via PsExec)' } else { $appConfig.install_type }
    Write-Host "  App            : $($appConfig.display_name)" -ForegroundColor Yellow
    Write-Host "  Context        : $contextLabel"              -ForegroundColor $(if ($isSystem) { 'Magenta' } else { 'Yellow' })
}

#endregion
