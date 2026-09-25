[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$ExitCode = 0
)

# Codes that Intune/IME treats as a form of success (see the return-code table
# in Invoke-IntuneWinTester.ps1): 0/1707 Success, 3010 Soft Reboot, 1641 Hard Reboot.
# 1618 (Retry) and any other code leave the app "not installed".
$successCodes = @(0, 1707, 3010, 1641)

$flagPath = Join-Path $env:LOCALAPPDATA 'IntuneWinTesterSimulator.flag'

if ($ExitCode -in $successCodes) {
    Set-Content -LiteralPath $flagPath -Value "installed @ $(Get-Date -Format 'o')" -Force
    Write-Host "Simulated install: wrote flag to $flagPath"
} else {
    Write-Host "Simulated install: exit code $ExitCode is not a success code — no flag written"
}

Write-Host "Exiting with code $ExitCode"
exit $ExitCode
