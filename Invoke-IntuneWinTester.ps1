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

.PARAMETER IgnoreReturnCodes
    By default, Install/Uninstall results recognize the standard Intune Win32
    return codes (0/1707 Success, 3010 Soft Reboot, 1641 Hard Reboot, 1618 Retry)
    and show an informative message instead of FAILED — matching how IME
    classifies them (none of these trigger an actual reboot or retry in this
    tester). Pass -IgnoreReturnCodes to disable this and compare strictly
    against -ExpectedExit (default 0) instead.

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
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$IgnoreReturnCodes
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
    # Optional fields may be absent from config.json entirely — under StrictMode,
    # $appConfig.<name> throws "property cannot be found" rather than returning $null,
    # so probe with PSObject.Properties first.
    $getOpt = {
        param($Name)
        if ($appConfig.PSObject.Properties[$Name]) { $appConfig.PSObject.Properties[$Name].Value } else { $null }
    }

    $pubRaw     = & $getOpt 'publisher'
    $restartRaw = & $getOpt 'restart'
    $majorRaw   = & $getOpt 'major_version'
    $minorRaw   = & $getOpt 'minor_version'
    $hotfixRaw  = & $getOpt 'hotfix'

    $pub     = if ($pubRaw)     { $pubRaw     -replace "'","''" } else { $null }
    $restart = if ($restartRaw) { $restartRaw -replace "'","''" } else { $null }

    $ver = $null
    if ($majorRaw) {
        $ver = $majorRaw
        if ($minorRaw)  { $ver += ".$minorRaw" }
        if ($hotfixRaw) { $ver += ".$hotfixRaw" }
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
    $initLines.Add("`$script:_ignoreReturnCodes = `$$($IgnoreReturnCodes.IsPresent)")

    #-- Standard Intune Win32 return-code table (single-quoted: static) -----
    # Matches the default return codes shown in the Intune admin center when adding
    # a Win32 app. None of these trigger an actual reboot or retry in this tester —
    # they're surfaced as informative messages instead, mirroring how IME classifies them.
    $initLines.Add(@'
$script:_returnCodes = @{
    0    = 'Success'
    1707 = 'Success'
    3010 = 'SoftReboot'
    1641 = 'HardReboot'
    1618 = 'Retry'
}
'@)

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
    $lineDrawn = $false
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
            # Clamp to the console width so the line never wraps — a wrapped line
            # leaves stray characters behind on the next row when cleared with just '\r'.
            $width = try { [Math]::Max(20, $Host.UI.RawUI.WindowSize.Width - 1) } catch { 79 }
            $elapsed = [int]([datetime]::UtcNow - $startTime).TotalSeconds
            $spin    = $spinner[$spinIdx % $spinner.Length]
            $spinIdx++
            $names = @($alive | ForEach-Object {
                try   { $p = Get-Process -Id $_ -ErrorAction SilentlyContinue; if ($p) { "$($p.Name) ($_)" } else { "PID $_" } }
                catch { "PID $_" }
            } | Select-Object -First 3)
            $nameStr = $names -join '  '
            $line    = "  [~] Waiting $spin  $nameStr  (${elapsed}s)"
            if ($line.Length -gt $width) { $line = $line.Substring(0, $width - 1) + '…' }
            $lineDrawn = $true
            Write-Host ("`r" + $line.PadRight($width)) -NoNewline -ForegroundColor DarkGray
        }
    } while ($alive.Count -gt 0)
    if ($lineDrawn) {
        $width = try { [Math]::Max(20, $Host.UI.RawUI.WindowSize.Width - 1) } catch { 79 }
        Write-Host ("`r" + (' ' * $width) + "`r") -NoNewline
    }
}
'@)

    #-- Live-streamed process runner (single-quoted) -------------------------
    # Redirects stdout/stderr and prints each line with the same "  │ " left
    # margin used for captured detection output, so live and captured text
    # share one visual language instead of streamed text breaking to column 0.
    $initLines.Add(@'
function Start-IndentedProcess {
    param([string]$FilePath, [string]$Arguments, [string]$WorkingDirectory)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    if ($Arguments)        { $psi.Arguments        = $Arguments }
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $psi.UseShellExecute        = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true

    $proc                     = [System.Diagnostics.Process]::new()
    $proc.StartInfo           = $psi
    $proc.EnableRaisingEvents = $true

    $outSub = Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived -Action {
        if ($null -ne $Event.SourceEventArgs.Data) { Write-Host "  │ $($Event.SourceEventArgs.Data)" -ForegroundColor Gray }
    }
    $errSub = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
        if ($null -ne $Event.SourceEventArgs.Data) { Write-Host "  │ $($Event.SourceEventArgs.Data)" -ForegroundColor Red }
    }

    $proc.Start() | Out-Null
    $proc.BeginOutputReadLine()
    $proc.BeginErrorReadLine()

    [PSCustomObject]@{ Process = $proc; Subscriptions = @($outSub, $errSub) }
}
'@)

    #-- Phase runner (single-quoted: no build-time expansion) ---------------
    $initLines.Add(@'
function Get-ResultGlyph {
    param([string]$ResultText)
    switch -regex ($ResultText) {
        '\(.*reboot\)$' { '⚠'; break }
        '^RETRY'        { '⚠'; break }
        '^OK$'          { '✓'; break }
        '^Detected$'    { '✓'; break }
        '^Not detected$'{ '○'; break }
        '^FAILED$'      { '✗'; break }
        default         { '•' }
    }
}

function Invoke-Phase {
    param(
        [string]$Label,
        [string]$Cmd,
        [int]$ExpectedExit = 0,
        [switch]$Informational,      # wording only: Detected/Not detected vs OK/FAILED
        [switch]$IsDetection,        # behaviour: capture + label stdout/stderr, apply IME 3-condition rule
        [switch]$IgnoreReturnCodes,  # Install/Uninstall only: skip the standard return-code table
        [int]$Step = 0,              # optional "(Step/TotalSteps)" progress tag on the header
        [int]$TotalSteps = 0
    )
    Write-Host ''
    $stepTag = if ($TotalSteps -gt 1) { "  ($Step/$TotalSteps)" } else { '' }
    Write-Host "  [ $Label ]$stepTag" -ForegroundColor Cyan
    Write-Host "  > $Cmd"     -ForegroundColor DarkGray
    Write-Host ('  ' + ('─' * 58)) -ForegroundColor DarkGray

    $tokens     = $Cmd.Trim() -split '\s+', 2
    $firstToken = $tokens[0]
    $argStr     = if ($tokens.Count -gt 1) { $tokens[1] } else { $null }

    $phaseStart = [datetime]::UtcNow
    $stdout     = ''
    $stderr     = ''
    $psExe      = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    if ($firstToken -match '\.ps1$') {
        if ($IsDetection) {
            # Detection script: capture stdout+stderr and label their source explicitly
            # so it's clear which stream produced the text, and to replicate IME's exact
            # logic: exit 0 + non-empty stdout + empty stderr = Detected. Any stderr data
            # → Not detected, even with exit 0 and non-empty stdout.
            $absScript = if ([System.IO.Path]::IsPathRooted($firstToken)) {
                $firstToken
            } else {
                Join-Path (Get-Location).Path ($firstToken -replace '^\.[\\/]', '')
            }
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName               = $psExe
            $psi.Arguments              = "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($absScript.Replace('"','\"'))`""
            if ($argStr) { $psi.Arguments += " $argStr" }
            $psi.UseShellExecute        = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow         = $true

            $proc       = [System.Diagnostics.Process]::Start($psi)
            $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
            $stderrTask = $proc.StandardError.ReadToEndAsync()
            $proc.WaitForExit()
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            $ec     = $proc.ExitCode

            $scriptName = Split-Path -Leaf $absScript
            if ($stdout.Trim()) {
                Write-Host "  ↳ stdout (from $scriptName)" -ForegroundColor DarkCyan
                $stdout.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  │ $_" -ForegroundColor Gray }
            }
            if ($stderr.Trim()) {
                Write-Host "  ↳ stderr (from $scriptName)" -ForegroundColor DarkRed
                $stderr.Trim() -split "`r?`n" | ForEach-Object { Write-Host "  │ $_" -ForegroundColor Red }
            }
            if (-not $stdout.Trim() -and -not $stderr.Trim()) {
                Write-Host "  (no stdout or stderr produced by $scriptName)" -ForegroundColor DarkGray
            }
        } else {
            # Install / uninstall .ps1: stream output live, indented to match the rest of the UI.
            # ProcessStartInfo doesn't inherit the session's current directory, so relative
            # paths like ".\Script.ps1" must be resolved before being handed to -File.
            $absScript = if ([System.IO.Path]::IsPathRooted($firstToken)) {
                $firstToken
            } else {
                Join-Path (Get-Location).Path ($firstToken -replace '^\.[\\/]', '')
            }
            $psArgs = "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$($absScript.Replace('"','\"'))`""
            if ($argStr) { $psArgs += " $argStr" }
            $handle = Start-IndentedProcess -FilePath $psExe -Arguments $psArgs -WorkingDirectory (Get-Location).Path
            $handle.Process.WaitForExit()
            $ec = $handle.Process.ExitCode
            $handle.Subscriptions | ForEach-Object {
                Unregister-Event -SourceIdentifier $_.Name -ErrorAction SilentlyContinue
                Remove-Job -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
    } else {
        try {
            $absExe = if ([System.IO.Path]::IsPathRooted($firstToken)) {
                $firstToken
            } else {
                Join-Path (Get-Location).Path $firstToken
            }
            $handle = Start-IndentedProcess -FilePath $absExe -Arguments $argStr -WorkingDirectory (Get-Location).Path
            Wait-ProcessTree -RootPid $handle.Process.Id
            $handle.Process.WaitForExit(500) | Out-Null
            $ec = $handle.Process.ExitCode
            $handle.Subscriptions | ForEach-Object {
                Unregister-Event -SourceIdentifier $_.Name -ErrorAction SilentlyContinue
                Remove-Job -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
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

    Write-Host ('  ' + ('─' * 58)) -ForegroundColor DarkGray

    if ($IsDetection) {
        # Apply IME's three-condition rule regardless of which wording we'll display.
        $hasStdout   = -not [string]::IsNullOrWhiteSpace($stdout)
        $hasStderr   = -not [string]::IsNullOrWhiteSpace($stderr)
        $imeDetected = ($ec -eq 0) -and $hasStdout -and (-not $hasStderr)
        $rawEc       = $ec
        # Return the IME-effective code so short-circuit logic and -ExpectedExit both work.
        $ec          = if ($imeDetected) { 0 } else { 1 }

        if ($Informational) {
            $resultText = if ($imeDetected) { 'Detected' } else { 'Not detected' }
            $color      = if ($imeDetected) { 'Cyan' } else { 'DarkYellow' }
        } else {
            $success    = ($ec -eq $ExpectedExit)
            $resultText = if ($success) { 'OK' } else { 'FAILED' }
            $color      = if ($success) { 'Green' } else { 'Red' }
        }
        $glyph = Get-ResultGlyph $resultText
        Write-Host "  $glyph $resultText  (exit: $rawEc, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
        if (-not $imeDetected -and $rawEc -eq 0) {
            if (-not $hasStdout) {
                Write-Host "  [!] exit 0 but no stdout — IME requires Write-Output to signal detection" -ForegroundColor DarkYellow
            } elseif ($hasStderr) {
                Write-Host "  [!] stderr present — IME treats any stderr output as not detected" -ForegroundColor DarkYellow
            }
        }
    } elseif ($Informational) {
        $resultText = if ($ec -eq 0) { 'Detected' } else { 'Not detected' }
        $color      = if ($ec -eq 0) { 'Cyan' } else { 'DarkYellow' }
        $glyph      = Get-ResultGlyph $resultText
        Write-Host "  $glyph $resultText  (exit: $ec, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
    } elseif ($ec -eq $ExpectedExit) {
        $success    = $true
        $resultText = 'OK'
        $color      = 'Green'
        $glyph      = Get-ResultGlyph $resultText
        Write-Host "  $glyph $resultText  (exit: $ec, expected: $ExpectedExit, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
    } elseif (-not $IgnoreReturnCodes -and $script:_returnCodes.ContainsKey($ec)) {
        # Standard Intune Win32 return code — informative only, no reboot/retry is triggered.
        $category = $script:_returnCodes[$ec]
        $success  = $true
        switch ($category) {
            'Success' {
                $resultText = 'OK'
                $color      = 'Green'
            }
            'SoftReboot' {
                $resultText = 'OK (soft reboot)'
                $color      = 'Yellow'
            }
            'HardReboot' {
                $resultText = 'OK (hard reboot)'
                $color      = 'Yellow'
            }
            'Retry' {
                $resultText = 'RETRY code'
                $color      = 'DarkYellow'
                $success    = $false
            }
        }
        $glyph = Get-ResultGlyph $resultText
        Write-Host "  $glyph $resultText  (exit: $ec, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
        switch ($category) {
            'SoftReboot' {
                Write-Host "  [i] Exit $ec = Soft Reboot" -ForegroundColor DarkGray
                Write-Host "      IME lets the next app install without reboot; a restart is still needed to finish this one (not triggered here)." -ForegroundColor DarkGray
            }
            'HardReboot' {
                Write-Host "  [i] Exit $ec = Hard Reboot" -ForegroundColor DarkGray
                Write-Host "      IME blocks the next app install until reboot (not triggered here)." -ForegroundColor DarkGray
            }
            'Retry' {
                Write-Host "  [i] Exit $ec = Retry" -ForegroundColor DarkGray
                Write-Host "      IME would retry up to 3 times, 5 minutes apart (not retried automatically here)." -ForegroundColor DarkGray
            }
            'Success' {
                Write-Host "  [i] Exit $ec = recognized success code" -ForegroundColor DarkGray
                Write-Host "      e.g. an MSI 'restart already scheduled' code." -ForegroundColor DarkGray
            }
        }
    } else {
        $success    = $false
        $resultText = 'FAILED'
        $color      = 'Red'
        $glyph      = Get-ResultGlyph $resultText
        Write-Host "  $glyph $resultText  (exit: $ec, expected: $ExpectedExit, elapsed: $elapsedStr)  [$Label]" -ForegroundColor $color
    }

    $script:_cycleResults += [PSCustomObject]@{
        Label       = $Label
        ResultText  = $resultText
        ExitCode    = $ec
        Elapsed     = $elapsedStr
        IsOK        = if ($Informational) { $null } else { $success }
        IsDetection = $IsDetection.IsPresent
    }

    return $ec
}
'@)

    #-- Looped flow menu (single-quoted: all $vars are runtime) -------------
    $initLines.Add(@'
function Write-RunHeader {
    param([int]$RunNumber, [string]$Title, [string]$Time)
    $width  = try { [Math]::Max(40, [Math]::Min(80, $Host.UI.RawUI.WindowSize.Width - 1)) } catch { 62 }
    $text   = " Run #$RunNumber " + [char]0x00B7 + " $Title " + [char]0x00B7 + " $Time "
    $fill   = [Math]::Max(0, $width - 2 - $text.Length)
    $left   = [int]($fill / 2)
    $right  = $fill - $left
    Write-Host ('  ' + ('═' * $left) + $text + ('═' * $right)) -ForegroundColor Magenta
}

function Show-CycleSummary {
    param([string]$Title, [datetime]$StartTime)
    $ts     = [datetime]::UtcNow - $StartTime
    $total  = if ($ts.TotalMinutes -ge 1) { '{0}m {1:00}s' -f [int]$ts.TotalMinutes, $ts.Seconds } else { '{0}s' -f [int]$ts.TotalSeconds }

    # PadRight never truncates and never adds a gap once the string already fills the
    # column, so each width must exceed the longest real value by at least 1 character:
    # "Detection (post-uninstall)" is 26 chars; "OK (soft reboot)"/"OK (hard reboot)" are 16.
    $colLabel   = 27
    $colResult  = 17
    $colElapsed = 7
    # Row is "  │ $mark $lbl$res$ela  │" — a 6-char prefix (vs. 5 without the mark
    # column) and a 3-char suffix around the label/result/elapsed content.
    $innerWidth = $colLabel + $colResult + $colElapsed + 5

    $header = "─ $Title ─── $total "
    $fill   = [Math]::Max(0, $innerWidth - $header.Length)
    Write-Host ''
    Write-Host "  ┌$header$('─' * $fill)┐" -ForegroundColor DarkCyan
    $maxSeverity = -1
    foreach ($r in $script:_cycleResults) {
        $mark = if ($r.IsDetection) { '›' } else { '▶' }
        $lbl  = $r.Label.PadRight($colLabel)
        $res  = $r.ResultText.PadRight($colResult)
        $ela  = $r.Elapsed.PadLeft($colElapsed)
        $clr  = switch ($r.IsOK) { $true { 'Green' } $false { 'Red' } default { 'Cyan' } }
        Write-Host "  │ $mark $lbl$res$ela  │" -ForegroundColor $clr

        # Severity drives the overall verdict: FAILED > RETRY > reboot-required > clean pass > informational-only.
        $sev = switch -regex ($r.ResultText) {
            '^FAILED$'      { 3; break }
            '^RETRY'        { 2; break }
            '\(.*reboot\)$' { 1; break }
            default         { if ($null -eq $r.IsOK) { -1 } else { 0 } }
        }
        if ($sev -gt $maxSeverity) { $maxSeverity = $sev }
    }
    Write-Host "  └$('─' * $innerWidth)┘" -ForegroundColor DarkCyan

    $verdictText, $verdictColor = switch ($maxSeverity) {
        3       { 'FAILED',          'Red';        break }
        2       { 'RETRY REQUIRED',  'DarkYellow'; break }
        1       { 'REBOOT REQUIRED', 'Yellow';     break }
        0       { 'PASSED',          'Green';      break }
        default { 'SKIPPED',         'DarkGray' }
    }
    Write-Host "  Result: $verdictText" -ForegroundColor $verdictColor
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
            Write-RunHeader $script:_runCount 'Install Cycle' $cycleTime
            $preEc = Invoke-Phase 'Detection (pre-install)' $script:_dr -Informational -IsDetection -Step 1 -TotalSteps 3
            if ($preEc -eq 0) {
                Write-Host ''
                Write-Host '  [~] App already detected — install skipped.' -ForegroundColor Yellow
            } else {
                $null = Invoke-Phase 'Install' $script:_ic -IgnoreReturnCodes:$script:_ignoreReturnCodes -Step 2 -TotalSteps 3
                $null = Invoke-Phase 'Detection (post-install)' $script:_dr -IsDetection -Step 3 -TotalSteps 3
            }
            Show-CycleSummary 'Install Cycle' $cycleStart
        }
        '2' {
            Write-RunHeader $script:_runCount 'Uninstall Cycle' $cycleTime
            $preEc = Invoke-Phase 'Detection (pre-uninstall)' $script:_dr -Informational -IsDetection -Step 1 -TotalSteps 3
            if ($preEc -ne 0) {
                Write-Host ''
                Write-Host '  [~] App not detected — uninstall skipped.' -ForegroundColor Yellow
            } else {
                $null = Invoke-Phase 'Uninstall' $script:_uc -IgnoreReturnCodes:$script:_ignoreReturnCodes -Step 2 -TotalSteps 3
                $null = Invoke-Phase 'Detection (post-uninstall)' $script:_dr -ExpectedExit 1 -IsDetection -Step 3 -TotalSteps 3
            }
            Show-CycleSummary 'Uninstall Cycle' $cycleStart
        }
        '3' {
            Write-RunHeader $script:_runCount 'Detection Only' $cycleTime
            $null = Invoke-Phase 'Detection' $script:_dr -Informational -IsDetection
        }
        '4' {
            Write-RunHeader $script:_runCount 'Install Only' $cycleTime
            $null = Invoke-Phase 'Install' $script:_ic -IgnoreReturnCodes:$script:_ignoreReturnCodes
        }
        '5' {
            Write-RunHeader $script:_runCount 'Uninstall Only' $cycleTime
            $null = Invoke-Phase 'Uninstall' $script:_uc -IgnoreReturnCodes:$script:_ignoreReturnCodes
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

# Write init script to a temp file — avoids the Windows 32 KB command-line limit
# that -EncodedCommand hits once the script grows large enough.
# The script deletes itself on first run via $PSCommandPath.
$initLines.Insert(0, 'Remove-Item -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue')
$initScript = $initLines -join "`n"
$tempInit   = Join-Path $env:TEMP "intunewin_init_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).ps1"
[System.IO.File]::WriteAllText($tempInit, $initScript, [System.Text.Encoding]::UTF8)

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
        $shell, '-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $tempInit
    )

} else {
    Start-Process -FilePath $shell -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-File', $tempInit)
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
