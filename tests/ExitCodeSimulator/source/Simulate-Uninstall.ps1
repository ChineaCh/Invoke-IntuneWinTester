[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$ExitCode = 0
)

$successCodes = @(0, 1707, 3010, 1641)

$flagPath = Join-Path $env:LOCALAPPDATA 'IntuneWinTesterSimulator.flag'

if ($ExitCode -in $successCodes) {
    Remove-Item -LiteralPath $flagPath -Force -ErrorAction SilentlyContinue
    Write-Host "Simulated uninstall: removed flag at $flagPath"
} else {
    Write-Host "Simulated uninstall: exit code $ExitCode is not a success code — flag left in place"
}

Write-Host "Exiting with code $ExitCode"
exit $ExitCode
