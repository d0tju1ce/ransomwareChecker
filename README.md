# RansomwareChecker v. 1.0.0

A portable Windows tool for **fast triage of persistence and other artifacts left behind by a ransomware attack**.
The checks cover techniques typical of human-operated ransomware: initial access, persistence,
post-exploitation, data exfiltration and ransomware deployment.

* **Read-only**: it never deletes, changes or fixes anything.
* No installation: Windows PowerShell 5.1 is all it needs (Windows 10/11, Server 2016+).
* Output: a report (`report.html` + `report.md`, in the same format as the remediation plan; the HTML has a severity filter
  and full-text search, with findings grouped by category and expandable), plus `findings.csv` and `findings.json`, all in the `Reports\` folder.
* A recommended remediation plan (`remediation.html` + `remediation.md`) in the `Remediation\` folder next to `Reports\`.

## Usage

### App

* The header shows the status (a spinner while a check runs).
* **High / Medium / Low / Info** filters and full-text search.
* Click a row to expand it: full details, *Flagged because* (why the finding was flagged), *Why checked*
  (why the check exists), *Remediation* (recommended steps), MITRE technique, category and time.
  Section text uses the monospaced Consolas font.
  Right-click to copy a finding (including the reason and remediation steps), copy everything, or expand / collapse all.
* Buttons: **Remediation plan** (the plan for the report shown), **HTML report** and **Report folder**. The footer shows *Coverage notes* (click to see the list).
* Settings are in `RansomwareChecker.ini` next to the exe: `DaysBack`, `Quick`, `RunOnStart`.
* The reasons for each check are in `config\check_reasons.json` and the remediation steps in `config\remediation.json` (key = finding category).
  You can edit or translate them without recompiling.
* The Oswald font (Google Fonts, Regular and SemiBold) is embedded in the exe. Its SIL OFL license is in `licenses\Oswald-OFL.txt`.

The exe needs `RansomwareChecker.ps1` and `config\` next to it. The source is in `src\`. Build it with `src\build.cmd`
(it uses csc.exe from .NET Framework 4.x, so nothing needs to be installed).

### Script
```
Run-RansomwareChecker.bat                      (asks for admin rights, opens the report)
Run-RansomwareChecker.bat -DaysBack 60 -Quick
```

or directly:

```powershell
powershell -ExecutionPolicy Bypass -File .\RansomwareChecker.ps1 -DaysBack 30 -OpenReport
```

| Parameter     | Meaning                                                                    |
|---------------|----------------------------------------------------------------------------|
| `-DaysBack`   | time window for event logs and "recently created" heuristics (default 30)  |
| `-OutputPath` | where to save the report (default `.\Reports\<PC>_<time>`)                 |
| `-Quick`      | skips the slower file system sweep                                         |
| `-NoHtml`     | CSV + JSON only                                                            |
| `-OpenReport` | opens the HTML report when finished                                        |
| `-RemediationPath` | where to save the remediation plan (default `.\Remediation\<PC>_<time>` next to `Reports`) |

**Exit code:** `0` = no Medium/High findings, `1` = Medium findings, `2` = High findings. Useful for running at scale,
e.g. via GPO or an RMM with a shared folder as `-OutputPath`.

> Run it as **administrator**. Without elevation, the Security log, Prefetch, other users, command lines of
> other users' processes and Defender exclusions are missing. Anything that could not be checked is listed in the report under *Coverage notes*.

## What is checked

| Area | Checks | MITRE ATT&CK |
|---|---|---|
| Autostart | Run/RunOnce (HKLM + loaded user hives), Winlogon Shell/Userinit, IFEO Debugger (sticky keys), AppInit_DLLs, BootExecute, Startup folders | T1547, T1546 |
| Scheduled tasks | non-Microsoft tasks, GUID names (Qakbot), hidden and newly registered tasks, suspicious commands | T1053.005 |
| Services | binary outside standard locations, `%COMSPEC% /c powershell` (Cobalt Strike psexec_psh), PSEXESVC | T1543.003 |
| WMI | CommandLine/ActiveScript event consumers | T1546.003 |
| BITS | persistent BITS jobs | T1197 |
| Remote access | AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, SupRemo, … plus MEGAsync, WinSCP (installed, or installed recently) | T1219 |
| Running processes | encoded PowerShell, rundll32 with a non-DLL file (Emotet), binaries in staging folders, masquerading (svchost.exe outside System32), external connections | T1059, T1218, T1036 |
| Configuration | WDigest UseLogonCredential, RDP enabled / NLA disabled, LocalAccountTokenFilterPolicy, RestrictedAdmin, netsh portproxy, firewall disabled, IOC registry keys (REvil `BlackLivesMatter`) | T1112, T1021 |
| Defender | real-time protection disabled, policies (LockBit GPO), exclusions, Tamper Protection | T1562.001 |
| Recovery | shadow copies, VSS service, `bcdedit recoveryenabled No` / `IgnoreAllFailures` | T1490 |
| Accounts | members of local Administrators, Guest, recently set passwords | T1078, T1136 |
| Event logs | 1102/104 (log cleared), 7045 (new services), 4720/4732/4728/4756, 4625 (brute force by IP), 4624 type 10 + LSM 21/25 (RDP from public IPs), Defender 1116/1117/5001/5007, PowerShell 4104 and 400, Task Scheduler 106, firewall changes (netsh + Remote Desktop) | T1070, T1110, T1133 |
| Evidence of execution | Prefetch (tools even after the binary was deleted, `.cr_hand.exe`), UserAssist (ROT13), BAM | – |
| Command history | PSReadLine `ConsoleHost_history.txt` (comsvcs MiniDump, Rubeus, vssadmin, wevtutil cl, …) | T1059.001, T1003 |
| Exfiltration | `rclone.conf`, MEGAsync logs and account | T1567 |
| File system | staging folders (ProgramData, Users\Public, PerfLogs, Temp, C:\, C:\Windows, Roaming): unsigned binaries, scripts with attack commands (a.bat with AdFind, rdp.bat), AdFind output, lsass.dmp; user folders (Desktop, Downloads, Pictures…): tool names; SHA256 for VirusTotal lookups | T1105, T1074 |
| Ransom notes | `how_to_decrypt.hta`, `*-read-me.txt`, `RESTORE-MY-FILES.txt`, …: the earliest one serves as the timeline pivot | T1486 |
| GPO deployment | on a DC: recently modified `ScheduledTasks.xml`, `Files.xml`, `Registry.pol` and binaries in SYSVOL\scripts (LockBit) | T1484.001 |

## Configuration

Indicators live in `config\indicators.json` and can be edited without touching the script:
`AttackerTools`, `DualUseTools`, `RemoteAccessTools`, paths (`SuspiciousPathPatterns`, `AllowedPathPatterns`),
command keywords (`CommandKeywords`, .NET regex), ransom note patterns and the brute force threshold.

## Remediation plan (Remediation folder)

Every check creates `Remediation\<PC>_<time>` next to `Reports\<PC>_<time>`, with the same name. The plan follows
the standard incident response process: 1) preserve evidence, 2) containment, 3) eradication by category
(list of findings + recommended steps), 4) recovery, 5) post-incident measures. The tool itself fixes nothing; an
administrator carries out the steps after validating each finding.

## Reading the results

* **High**: very likely an attack artifact. Validate it and preserve evidence (take an image or KAPE collection first, clean up afterwards).
* **Medium**: suspicious, but may be legitimate administration (PsExec, AnyDesk, admin scripts).
* **Low / Info**: context for the analyst (RDP enabled, list of admins, new services).

The tool **does not replace forensic analysis**. Recommended approach: first find a pivot (the first ransom note or
detection), then build a timeline from $MFT (MFTECmd), event logs (EvtxECmd), Amcache, ShimCache and SRUM, and reconstruct
the attack phase by phase (initial access → persistence → lateral movement → exfiltration → deployment).

## Known limitations

* User hives are read only for **logged-on** users (HKEY_USERS). Offline NTUSER.DAT files are not loaded.
* Amcache, ShimCache, SRUM, $MFT and Prefetch contents are not parsed (only Prefetch names and times).
* BAM maps `\Device\HarddiskVolumeX` to the system drive (heuristic).
* More noise on developer and admin machines (custom PowerShell scripts, RMM tools).
* Defender may heuristically flag an unsigned `RansomwareChecker.exe` as a threat (false positive).

## Ideas for future versions

Offline mode over a mounted image or KAPE output, parsing of Amcache/ShimCache/SRUM, comparing
`C:\Windows\System32\Tasks` against the registry (hidden tasks), remote execution over WinRM with result collection,
YARA and hash IOCs, comparing two runs (baseline diff).

## Digital signature

Both `RansomwareChecker.exe` and `RansomwareChecker.ps1` are signed with a self-signed certificate
`CN=RansomwareChecker Code Signing`, SHA1 thumbprint `9F82EBC12B1EE794B4BFEA8ECBBA552E30E116A9`, valid until 31 Oct 2031.
The public part of the certificate is in `cert\RansomwareChecker.cer` (the private key is not in the repository).

Verify the signature:

```powershell
Get-AuthenticodeSignature .\RansomwareChecker.exe, .\RansomwareChecker.ps1
```

For Windows to accept the signature as valid (`Valid`), import the certificate once (PowerShell as administrator):

```powershell
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Without the import the signature shows as untrusted (`UnknownError`), but you can still verify file integrity by the thumbprint.

## Sources

The checks, the reasons behind them and the remediation steps are based on:

* Oleg Skulkin: *Incident Response Techniques for Ransomware Attacks*, Packt Publishing, 2022.

## License

The code is licensed under MIT (see `LICENSE`). The Oswald font is licensed under the SIL Open Font License 1.1 (`licenses\Oswald-OFL.txt`).
