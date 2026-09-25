# IntuneWin Tester

A PowerShell utility for decoding `.intunewin` packages and running install, uninstall, and detection cycles locally — without deploying through Intune.

## Requirements

- Windows 10/11
- PowerShell 5.1 or later (`pwsh` is used automatically when available)
- Administrator rights (required when `install_type` is `system`)
- [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) — only when `install_type` is `system`

## Usage

```powershell
.\Invoke-IntuneWinTester.ps1 -IntuneWinFile <path> [-ConfigFile <path>] [-ExtractPath <dir>] [-PsExecPath <path>] [-ScriptBlock <string>] [-Force]
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `-IntuneWinFile` | Yes | Path to the `.intunewin` file to decode |
| `-ConfigFile` | No | Path to the app JSON config file (enables interactive flow menu) |
| `-ExtractPath` | No | Root directory for extraction. When supplied, contents are placed in `<ExtractPath>\<basename>`. Defaults to `<intunewin dir>\<basename>_decoded` |
| `-PsExecPath` | No | Path to `psexec.exe` or `PsExec64.exe`. Required only when `install_type` is `system` and PsExec is not next to the script or on `PATH` |
| `-ScriptBlock` | No | Script content (as a string) to run in the new window after it opens. The window stays open (`-NoExit`) once it finishes |
| `-Force` | No | Re-decrypt even if the source file hash matches the cached hash |

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
  "uninstall_command": ".\\Deploy-Application.exe -DeployMode Interactive -DeploymentType Uninstall",
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
| `detection_rule` | PowerShell script that exits `0` when the app is detected and `1` when it is not |

### Optional fields

`publisher`, `major_version`, `minor_version`, `hotfix`, `restart` — displayed in the banner only.

## How the detection script works

The detection script must follow this convention:

```powershell
# App is installed
exit 0

# App is NOT installed
exit 1
```

The tester interprets exit `0` as **Detected** and any other exit code as **Not detected**.

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

Each run is numbered and timestamped. After cycles `[1]` and `[2]` a summary box shows all phases with their results and elapsed times.

### Short-circuit logic

- **Install Cycle**: if pre-install detection returns `0` (already installed) the install step is skipped.
- **Uninstall Cycle**: if pre-uninstall detection returns `1` (not installed) the uninstall step is skipped.

### Process tree waiting

After launching the installer or uninstaller the tester polls WMI (`Win32_Process`) every 2 seconds and waits until the **entire process tree** exits — including child processes spawned by the installer (e.g. PSADT's `Deploy-Application.exe` launching `powershell.exe`). A live spinner shows running process names and elapsed time.

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
