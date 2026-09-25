# IntuneWin Tester

A PowerShell utility for decoding `.intunewin` packages and running install, uninstall, and detection cycles locally — without deploying through Intune. Detection, return-code handling, and process waiting are designed to replicate how the Intune Management Extension (IME) actually behaves, so results seen here match what you'd see in the Intune admin center.

## Requirements

- Windows 10/11
- PowerShell 5.1 or later (`pwsh` is used automatically when available)
- Administrator rights (required when `install_type` is `system`)
- [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) — only when `install_type` is `system`

## Usage

```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile <path> [-ConfigFile <path>] [-ExtractPath <dir>] [-PsExecPath <path>] [-ScriptBlock <string>] [-Force] [-IgnoreReturnCodes]
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-IntuneWinFile` | Yes | Path to the `.intunewin` file to decode |
| `-ConfigFile` | No | Path to the app JSON config file (enables the interactive flow menu) |
| `-ExtractPath` | No | Root directory for extraction. When supplied, contents are placed in `<ExtractPath>\<basename>`. Defaults to `<intunewin dir>\<basename>_decoded` |
| `-PsExecPath` | No | Path to `psexec.exe` or `PsExec64.exe`. Required only when `install_type` is `system` and PsExec is not next to the script or on `PATH` |
| `-Force` | No | Re-decrypt even if the source file hash matches the cached hash |
| `-IgnoreReturnCodes` | No | Disable the standard Intune Win32 return-code table for Install/Uninstall and require an exact match against the internal expected exit code (`0`) instead |
| `-ScriptBlock` | No | Script content (as a string) to run in the new window after it opens. The window stays open (`-NoExit`) once it finishes |

## Quick start

**Inspect package contents only:**
```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin
```

Opens a PowerShell window in the extracted folder. No config needed.

**Run the interactive flow menu:**
```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json
```

**Force a fresh extraction:**
```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json -Force
```

**Extract to a shared folder (creates `C:\IntuneTest\MyApp\`):**
```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ExtractPath C:\IntuneTest
```

## App config file

When `-ConfigFile` is provided the child window shows a banner and an interactive flow menu. The file is a JSON object with the following fields:

```json
{
  "display_name":      "My Application",
  "install_type":      "user",
  "install_command":   ".\\Deploy-Application.exe -DeployMode Interactive",
  "uninstall_command": ".\\Deploy-Application.exe -DeploymentType Uninstall",
  "detection_rule":    "detection_rule.ps1",

  "publisher":         "Contoso",
  "major_version":     "1",
  "minor_version":     "0",
  "hotfix":            "0",
  "restart":           "false"
}
```

### Required fields

| Field | Description |
|---|---|
| `display_name` | Human-readable app name shown in the banner and window title |
| `install_type` | `user` or `system`. Use `system` to run the window as the SYSTEM account via PsExec |
| `install_command` | Command to install the app (relative to the extracted folder) |
| `uninstall_command` | Command to uninstall the app |
| `detection_rule` | PowerShell script that detects whether the app is present (see [Detection logic](#detection-logic) below) |

### Optional fields

`publisher`, `major_version`, `minor_version`, `hotfix`, `restart` — displayed in the banner only. Any of these may be omitted from the JSON entirely.

The banner resolves `install_command`, `uninstall_command`, and `detection_rule` to their full on-disk path, so you always see exactly which file will run regardless of whether the JSON used a relative path.

## Detection logic

The detection script's rule matches IME's actual behavior, not a simplified exit-code check:

> The app is **Detected** when the script exits with code `0` **and** writes at least one line to **stdout**. If anything is written to **stderr**, the result is **Not detected** — even with exit `0` and non-empty stdout.

```powershell
# Detected
Write-Output 'App is installed'
exit 0

# Not detected
exit 1
```

Both stdout and stderr are captured and printed with their source labeled (`↳ stdout (from detection_rule.ps1)` / `↳ stderr (from ...)`), so it's always clear which stream produced what. If a script exits `0` but prints nothing, the tester tells you exactly why it didn't count as detected (`[!] exit 0 but no stdout — IME requires Write-Output to signal detection`).

## Return codes for Install/Uninstall

By default, Install and Uninstall results are classified using the same return codes shown in the Intune admin center when adding a Win32 app:

| Exit code | Category | Shown as |
|---|---|---|
| `0`, `1707` | Success | `OK` |
| `3010` | Soft Reboot | `OK (soft reboot)` — IME lets the next app install without reboot; a restart is still needed to finish this one |
| `1641` | Hard Reboot | `OK (hard reboot)` — IME blocks the next app install until reboot |
| `1618` | Retry | `RETRY code` — IME would retry up to 3 times, 5 minutes apart |
| anything else | — | `FAILED` |

None of these trigger an actual reboot or retry in this tester — they're informative only. Pass `-IgnoreReturnCodes` to disable the table; results are then `OK` only on an exact match against the internal expected exit code (`0` for Install/Uninstall) and `FAILED` otherwise.

## Interactive flow menu

When a config file is loaded the child window presents a numbered menu:

```
  [1]  Install Cycle    (Detection >> Install >> Detection)
  [2]  Uninstall Cycle  (Detection >> Uninstall >> Detection)
  [3]  Detection Only
  [4]  Install Only
  [5]  Uninstall Only
  [0]  Exit menu
```

Each run gets a numbered, timestamped header (`Run #2 · Install Cycle · 10:02:55`), and each phase within a cycle shows a step counter (`(2/3)`). Result lines carry a status glyph (`✓` OK/Detected, `✗` FAILED, `⚠` reboot/retry, `○` Not detected) so pass/fail is scannable without relying on color.

After cycles `[1]` and `[2]` a summary box lists every phase — `›` marks a detection check, `▶` marks an install/uninstall action — with its result and elapsed time, followed by an overall verdict:

```
  ┌─ Install Cycle ─── 1s ────────────────────────────────┐
  │ › Detection (pre-install)   Not detected          0s  │
  │ ▶ Install                   ✓ OK (soft reboot)    0s  │
  │ › Detection (post-install)  ✓ OK                   0s  │
  └────────────────────────────────────────────────────────┘
  Result: REBOOT REQUIRED
```

The verdict is the worst outcome among the cycle's rows: `FAILED` > `RETRY REQUIRED` > `REBOOT REQUIRED` > `PASSED`, or `SKIPPED` when the cycle short-circuited and no action ran.

### Short-circuit logic

- **Install Cycle**: if pre-install detection reports Detected, the install step is skipped.
- **Uninstall Cycle**: if pre-uninstall detection reports Not detected, the uninstall step is skipped.

### Live output

Install/uninstall output streams live to the console as it happens, indented with a `│` margin to match the rest of the UI, rather than dumping everything at the end.

### Process tree waiting

For `.exe`-based install/uninstall commands, the tester polls WMI (`Win32_Process`) every 2 seconds and waits until the **entire process tree** exits — including child processes spawned by the installer (e.g. PSADT's `Deploy-Application.exe` launching `powershell.exe` and exiting early). A live spinner shows running process names and elapsed time while waiting.

If `install_command`/`uninstall_command` instead points at a `.ps1` script, this process-tree wait does not apply — the tester only waits for that PowerShell process itself to exit.

## Caching

After a successful extraction the SHA-256 hash of the `.intunewin` source file is stored in `._intunewin_source.sha256` inside the extraction folder. On the next run:

- If the hash matches → extraction is skipped, the window opens immediately.
- If the hash differs → the old folder is deleted and the package is re-extracted.
- `-Force` → always re-extracts regardless of the hash.

## SYSTEM context

When `install_type` is `system` the script:

1. Verifies it is running as Administrator (exits with an error if not).
2. Locates PsExec (`-PsExecPath` → next to the script → PATH).
3. Launches the child window using `psexec -accepteula -s -i -d`, which runs the PowerShell session as the `SYSTEM` account.

```powershell
# Run as admin first, then:
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json
# PsExec next to the script is found automatically.

# Or specify PsExec explicitly:
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\MyApp.intunewin -ConfigFile .\app.json -PsExecPath 'C:\Tools\PsExec64.exe'
```

## Test fixture

[`tests/ExitCodeSimulator`](tests/ExitCodeSimulator) is a self-contained `.intunewin` package for exercising the tester without a real app:

- [`source/Simulate-Install.ps1`](tests/ExitCodeSimulator/source/Simulate-Install.ps1) / [`Simulate-Uninstall.ps1`](tests/ExitCodeSimulator/source/Simulate-Uninstall.ps1) — accept `-ExitCode <int>`, write/remove a flag file for success codes (`0`, `1707`, `3010`, `1641`), and exit with the requested code
- [`source/Simulate-Detect.ps1`](tests/ExitCodeSimulator/source/Simulate-Detect.ps1) — IME-compliant detection based on the flag file
- [`Build-TestPackage.ps1`](tests/ExitCodeSimulator/Build-TestPackage.ps1) — rebuilds `ExitCodeSimulator.intunewin` from `source/` (real AES-256-CBC encryption, matching the Win32 Content Prep Tool's format)
- [`config.json`](tests/ExitCodeSimulator/config.json) — edit the `-ExitCode` value on `install_command`/`uninstall_command` to test a specific return code (`0`, `3010`, `1641`, `1618`, or any failure code)

```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile .\tests\ExitCodeSimulator\ExitCodeSimulator.intunewin -ConfigFile .\tests\ExitCodeSimulator\config.json
```
