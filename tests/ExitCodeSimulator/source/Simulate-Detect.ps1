# IME-compliant detection rule: exit 0 + non-empty stdout + empty stderr = Detected.
$flagPath = Join-Path $env:LOCALAPPDATA 'IntuneWinTesterSimulator.flag'

if (Test-Path -LiteralPath $flagPath) {
    Write-Output "Simulator app detected (flag: $flagPath)"
    exit 0
} else {
    exit 1
}
