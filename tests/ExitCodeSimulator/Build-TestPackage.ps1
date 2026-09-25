<#
.SYNOPSIS
    Builds ExitCodeSimulator.intunewin from the scripts in .\source, replicating
    the format produced by the Microsoft Win32 Content Prep Tool (IntuneWinAppUtil.exe):
    an outer ZIP containing IntuneWinPackage/Metadata/Detection.xml (AES key/IV) and
    IntuneWinPackage/Contents/IntunePackage.intunewin (AES-256-CBC encrypted inner ZIP,
    zero-padded to a 16-byte boundary, PaddingMode.None).

    Re-run this any time the scripts in .\source change.
#>

[CmdletBinding()]
param(
    [string]$SourceDir = (Join-Path $PSScriptRoot 'source'),
    [string]$OutFile   = (Join-Path $PSScriptRoot 'ExitCodeSimulator.intunewin')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$work = Join-Path $env:TEMP "build_intunewin_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    #-- 1. Zip the source scripts into the inner (plaintext) content ZIP -------
    $innerZip = Join-Path $work 'inner.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $SourceDir, $innerZip,
        [System.IO.Compression.CompressionLevel]::Optimal, $false
    )
    $plainBytes = [System.IO.File]::ReadAllBytes($innerZip)
    Remove-Item -LiteralPath $innerZip -Force
    Write-Host "Inner ZIP: $($plainBytes.Length) bytes"

    #-- 2. Zero-pad to a 16-byte boundary (Intune uses PaddingMode.None) -------
    $blockSize = 16
    $padLen    = ($blockSize - ($plainBytes.Length % $blockSize)) % $blockSize
    if ($padLen -gt 0) {
        $padded = New-Object byte[] ($plainBytes.Length + $padLen)
        [Array]::Copy($plainBytes, $padded, $plainBytes.Length)
        $plainBytes = $padded
    }
    Write-Host "Padded to: $($plainBytes.Length) bytes (+$padLen)"

    #-- 3. Generate a random AES-256 key/IV and encrypt -------------------------
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize  = 256
    $aes.Mode     = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding  = [System.Security.Cryptography.PaddingMode]::None
    $aes.GenerateKey()
    $aes.GenerateIV()

    $encryptor    = $aes.CreateEncryptor()
    $cipherBytes  = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    $encryptor.Dispose()

    $keyB64 = [Convert]::ToBase64String($aes.Key)
    $ivB64  = [Convert]::ToBase64String($aes.IV)
    $aes.Dispose()

    #-- 4. Assemble the IntuneWinPackage folder structure -----------------------
    $pkgRoot     = Join-Path $work 'IntuneWinPackage'
    $metadataDir = Join-Path $pkgRoot 'Metadata'
    $contentsDir = Join-Path $pkgRoot 'Contents'
    New-Item -ItemType Directory -Path $metadataDir -Force | Out-Null
    New-Item -ItemType Directory -Path $contentsDir -Force | Out-Null

    [System.IO.File]::WriteAllBytes((Join-Path $contentsDir 'IntunePackage.intunewin'), $cipherBytes)

    $detectionXml = @"
<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo ToolVersion="1.8.6.0">
  <Name>ExitCodeSimulator</Name>
  <UnencryptedContentSize>$($plainBytes.Length - $padLen)</UnencryptedContentSize>
  <FileName>inner.zip</FileName>
  <SetupFile>Simulate-Install.ps1</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>$keyB64</EncryptionKey>
    <InitializationVector>$ivB64</InitializationVector>
    <MacKey></MacKey>
    <Mac></Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest></FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
"@
    Set-Content -LiteralPath (Join-Path $metadataDir 'Detection.xml') -Value $detectionXml -Encoding UTF8

    #-- 5. Zip IntuneWinPackage/* into the final .intunewin --------------------
    if (Test-Path $OutFile) { Remove-Item $OutFile -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $work, $OutFile,
        [System.IO.Compression.CompressionLevel]::Optimal, $false
    )

    Write-Host "Built: $OutFile ($((Get-Item $OutFile).Length) bytes)" -ForegroundColor Green
}
finally {
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
