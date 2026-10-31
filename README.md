# RansomwareChecker v. 1.0.0

A portable Windows tool for **fast triage after a ransomware attack**. It looks for persistence, post-exploitation
tools, weakened security settings and traces of exfiltration, then writes a report and a recommended remediation plan.

The checks cover techniques typical of human-operated ransomware: initial access, persistence, post-exploitation,
data exfiltration and ransomware deployment.

## Highlights

- **Read-only**: it never deletes, changes or fixes anything, so evidence stays intact.
- **Portable**: no installation, only Windows PowerShell 5.1 is needed.
- **Explains every finding**: why it was flagged, why the check exists, the MITRE ATT&CK technique and recommended steps.
- **Report and remediation plan** in HTML and Markdown, plus CSV and JSON for further processing.
- **Desktop app or script**: interactive review, or automation via GPO / RMM.

## Requirements

- Windows 10/11 or Windows Server 2016+
- Windows PowerShell 5.1 (included in Windows)
- Administrator rights for full coverage

## Download

Download everything at once:

- **ZIP**: on the repository page click **Code → Download ZIP**, or use
  [main.zip](https://github.com/dotjuice2/ransomwareChecker/archive/refs/heads/main.zip).
  Before extracting, unblock the archive (right-click → Properties → **Unblock**), or run:

  ```powershell
  Unblock-File "$env:USERPROFILE\Downloads\ransomwareChecker-main.zip"
  ```

- **Git**:

  ```powershell
  git clone https://github.com/dotjuice2/ransomwareChecker.git
  ```

These files must stay together in one folder:

| File | Purpose |
|---|---|
| `RansomwareChecker.exe` | desktop app |
| `RansomwareChecker.ps1` | check engine (the app runs it) |
| `config\` | indicators, reasons for checks, remediation steps |
| `RansomwareChecker.ini` | settings (created automatically if missing) |
| `Run-RansomwareChecker.bat` | optional: run the script without the app |

## Usage

### Desktop app

Start `RansomwareChecker.exe` and confirm the administrator prompt. The app shows the last report and immediately
runs a new check. Further checks run only on demand (**Run check again**).

- Filter by **High / Medium / Low / Info** and search the findings.
- Click a finding to expand it: details, *Flagged because*, *Why checked*, *Remediation*, MITRE technique, category and time.
- Right-click to copy a finding, copy all findings, or expand / collapse all.
- **Remediation plan**, **HTML report** and **Report folder** open the outputs of the shown report.
- *Coverage notes* in the footer list anything that could not be checked.

Settings in `RansomwareChecker.ini`:

| Setting | Meaning |
|---|---|
| `DaysBack` | time window in days for event logs and "recently created" heuristics |
| `Quick` | `1` = skip the slower file system sweep |
| `RunOnStart` | `1` = run a check when the app starts |

### Script

```powershell
# asks for administrator rights and opens the report
Run-RansomwareChecker.bat
Run-RansomwareChecker.bat -DaysBack 60 -Quick

# or directly
powershell -ExecutionPolicy Bypass -File .\RansomwareChecker.ps1 -DaysBack 30 -OpenReport
```

| Parameter | Meaning |
|---|---|
| `-DaysBack` | time window for event logs and "recently created" heuristics (default 30) |
| `-OutputPath` | where to save the report (default `.\Reports\<PC>_<time>`) |
| `-RemediationPath` | where to save the remediation plan (default `.\Remediation\<PC>_<time>`) |
| `-Quick` | skip the slower file system sweep |
| `-NoHtml` | write CSV and JSON only |
| `-OpenReport` | open the HTML report when finished |

**Exit codes:** `0` = no Medium/High findings, `1` = Medium findings, `2` = High findings.
Useful for running at scale, e.g. via GPO or an RMM with a shared folder as `-OutputPath`.

> **Run as administrator.** Without elevation the Security log, Prefetch, other users' data, command lines of other
> processes and Defender exclusions are not available. Anything that could not be checked is listed under *Coverage notes*.

## Output

Every run creates two folders with the same name:

| Folder | Files |
|---|---|
| `Reports\<PC>_<time>\` | `report.html` (severity filter, search, findings grouped by category), `report.md`, `findings.csv`, `findings.json` |
| `Remediation\<PC>_<time>\` | `remediation.html`, `remediation.md` |

The remediation plan follows the incident response process: 1) preserve evidence, 2) containment, 3) eradication
per category (findings + recommended steps), 4) recovery, 5) post-incident measures. The tool fixes nothing itself;
an administrator carries out the steps after validating each finding.

## What is checked

| Area | Checks | MITRE ATT&CK |
|---|---|---|
| Autostart | Run/RunOnce (HKLM + loaded user hives), Winlogon Shell/Userinit, IFEO Debugger (sticky keys), AppInit_DLLs, BootExecute, Startup folders | T1547, T1546 |
| Scheduled tasks | non-Microsoft tasks, GUID names (Qakbot), hidden and newly registered tasks, suspicious commands | T1053.005 |
| Services | binary outside standard locations, `%COMSPEC% /c powershell` (Cobalt Strike psexec_psh), PSEXESVC | T1543.003 |
| WMI | CommandLine/ActiveScript event consumers | T1546.003 |
| BITS | persistent BITS jobs | T1197 |
| Remote access | AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, SupRemo, … plus MEGAsync, WinSCP | T1219 |
| Running processes | encoded PowerShell, rundll32 with a non-DLL file (Emotet), binaries in staging folders, masquerading (svchost.exe outside System32), external connections | T1059, T1218, T1036 |
| Configuration | WDigest UseLogonCredential, RDP enabled / NLA disabled, LocalAccountTokenFilterPolicy, RestrictedAdmin, netsh portproxy, firewall disabled, IOC registry keys (REvil `BlackLivesMatter`) | T1112, T1021 |
| Defender | real-time protection disabled, policies (LockBit GPO), exclusions, Tamper Protection | T1562.001 |
| Recovery | shadow copies, VSS service, `bcdedit recoveryenabled No` / `IgnoreAllFailures` | T1490 |
| Accounts | members of local Administrators, Guest, recently set passwords | T1078, T1136 |
| Event logs | 1102/104 (log cleared), 7045 (new services), 4720/4732/4728/4756, 4625 (brute force by IP), 4624 type 10 + LSM 21/25 (RDP from public IPs), Defender 1116/1117/5001/5007, PowerShell 4104 and 400, Task Scheduler 106, firewall changes | T1070, T1110, T1133 |
| Evidence of execution | Prefetch (tools even after the binary was deleted), UserAssist (ROT13), BAM | – |
| Command history | PSReadLine `ConsoleHost_history.txt` (comsvcs MiniDump, Rubeus, vssadmin, wevtutil cl, …) | T1059.001, T1003 |
| Exfiltration | `rclone.conf`, MEGAsync logs and account | T1567 |
| File system | staging folders (ProgramData, Users\Public, PerfLogs, Temp, C:\, C:\Windows, Roaming): unsigned binaries, attack scripts, AdFind output, lsass.dmp; user folders: tool names; SHA256 for VirusTotal lookups | T1105, T1074 |
| Ransom notes | `how_to_decrypt.hta`, `*-read-me.txt`, `RESTORE-MY-FILES.txt`, …; the earliest one serves as the timeline pivot | T1486 |
| GPO deployment | on a domain controller: recently modified `ScheduledTasks.xml`, `Files.xml`, `Registry.pol` and binaries in SYSVOL\scripts (LockBit) | T1484.001 |

## Reading the results

| Severity | Meaning |
|---|---|
| **High** | very likely an attack artifact; validate it and preserve evidence first (image or KAPE collection), clean up afterwards |
| **Medium** | suspicious, but may be legitimate administration (PsExec, AnyDesk, admin scripts) |
| **Low / Info** | context for the analyst (RDP enabled, list of admins, new services) |

The tool **does not replace forensic analysis**. Use it to find a pivot (the first ransom note or detection), then
build a timeline from $MFT (MFTECmd), event logs (EvtxECmd), Amcache, ShimCache and SRUM, and reconstruct the attack
phase by phase: initial access → persistence → lateral movement → exfiltration → deployment.

## Configuration

All rules live in `config\` and can be edited or translated without touching the code:

| File | Content |
|---|---|
| `indicators.json` | attacker and dual-use tools, remote access tools, suspicious and allowed paths, command keywords (.NET regex), ransom note patterns, brute force threshold |
| `check_reasons.json` | why each check exists (shown as *Why checked*) |
| `remediation.json` | recommended steps per finding category |

## Digital signature

`RansomwareChecker.exe` and `RansomwareChecker.ps1` are signed with a self-signed certificate:

| | |
|---|---|
| Subject | `CN=RansomwareChecker Code Signing` |
| SHA1 thumbprint | `9F82EBC12B1EE794B4BFEA8ECBBA552E30E116A9` |
| Valid until | 31 Oct 2031 |
| Public certificate | `cert\RansomwareChecker.cer` (the private key is not in the repository) |

Verify the signature:

```powershell
Get-AuthenticodeSignature .\RansomwareChecker.exe, .\RansomwareChecker.ps1
```

To make Windows report the signature as `Valid`, import the certificate once (PowerShell as administrator):

```powershell
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Without the import the status is `UnknownError` (untrusted), but you can still check the thumbprint.

## Building from source

The source code is in `src\`. Run `src\build.cmd`; it uses `csc.exe` from .NET Framework 4.x, so nothing needs to be
installed. If the signing certificate is present in `Cert:\CurrentUser\My`, `src\sign.ps1` signs the exe and the
script after the build.

## Known limitations

- User registry hives are read only for **logged-on** users; offline `NTUSER.DAT` files are not loaded.
- Amcache, ShimCache, SRUM, $MFT and Prefetch contents are not parsed (only Prefetch names and times).
- BAM paths (`\Device\HarddiskVolumeX`) are mapped to the system drive heuristically.
- More noise on developer and admin machines (custom PowerShell scripts, RMM tools).
- Antivirus engines may flag the tool heuristically, because it looks for the same things attackers use.

## Roadmap

- Offline mode over a mounted image or KAPE output
- Parsing of Amcache, ShimCache and SRUM
- Comparing `C:\Windows\System32\Tasks` against the registry (hidden tasks)
- Remote execution over WinRM with result collection
- YARA rules and hash IOCs
- Comparing two runs (baseline diff)

## Sources

The checks, the reasons behind them and the remediation steps are based on:

- Oleg Skulkin: *Incident Response Techniques for Ransomware Attacks*, Packt Publishing, 2022.

## License

The code is licensed under the MIT License (see `LICENSE`). The embedded Oswald font is licensed under the
SIL Open Font License 1.1 (`licenses\Oswald-OFL.txt`).
