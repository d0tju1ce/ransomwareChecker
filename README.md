# RansomwareChecker v. 1.2.2

A portable Windows tool for **fast triage after a ransomware attack**. It looks for persistence, post-exploitation
tools, weakened security settings and traces of exfiltration, then writes a report and a recommended remediation plan.

The checks cover techniques typical of human-operated ransomware: initial access, persistence, post-exploitation,
data exfiltration and ransomware deployment.

## Highlights

- **Read-only**: it never deletes, changes or fixes anything on the analysed system (see [Footprint](#footprint) for the traces a run leaves).
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
  [main.zip](https://github.com/d0tju1ce/ransomwareChecker/archive/refs/heads/main.zip).
  Before extracting, unblock the archive (right-click → Properties → **Unblock**), or run:

  ```powershell
  Unblock-File "$env:USERPROFILE\Downloads\ransomwareChecker-main.zip"
  ```

- **Git**:

  ```powershell
  git clone https://github.com/d0tju1ce/ransomwareChecker.git
  ```

These files must stay together in one folder:

| File | Purpose |
|---|---|
| `RansomwareChecker.exe` | desktop app |
| `RansomwareChecker.ps1` | check engine (the app runs it) |
| `config\` | indicators, reasons for checks, remediation steps |
| `RansomwareChecker.ini` | settings (created automatically if missing) |
| `marks.json` | false positive / suspicious marks from the app (created on the first mark) |
| `Run-RansomwareChecker.bat` | optional: run the script without the app |

## Usage

### Desktop app

Start `RansomwareChecker.exe` and confirm the administrator prompt. The app shows the last report and immediately
runs a new check. Further checks run only on demand (**Run check again**).

- Filter by **High / Medium / Low / Info** and search the findings.
- **False positive** / **Suspicious** filters show only findings with that mark (one at a time; combined with the severity filter and search).
- Click a finding to expand it: details, *Flagged because*, *Why checked*, *Remediation*, MITRE technique, category and time.
- Right-click to copy a finding, copy all findings, or expand / collapse all.
- Right-click → **Mark as false positive** snoozes a finding: its text turns dark, it moves to the end of the list in the
  next report and it no longer counts towards the severity counts and the headline. **Mark as suspicious** highlights
  the row in muted red. Choosing the same item again removes the mark. Marks are kept in `marks.json` next to the exe,
  separately for each computer (computer + category + item): a finding keeps its mark in later reports of the same
  computer, but a copy of the tool taken to another computer hides nothing there. They affect only the app, not the HTML report.
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

### Footprint

The tool changes no configuration, but a run is not invisible: the reports are written next to the tool, and
Windows records the execution itself (Prefetch, BAM, PowerShell logs 400/4104). During incident response run it from
an external drive and write the output there too (`-OutputPath`, `-RemediationPath`), and note the time of the run
so these traces are not mistaken for attacker activity.

## What is checked

| Area | Checks | MITRE ATT&CK |
|---|---|---|
| Autostart | Run/RunOnce (HKLM + loaded user hives, incl. Entra ID accounts), Winlogon Shell/Userinit, IFEO Debugger (sticky keys), AppInit_DLLs, BootExecute, Startup folders | T1547, T1546 |
| Scheduled tasks | non-Microsoft tasks, GUID names (Qakbot), hidden and newly registered tasks, suspicious commands | T1053.005 |
| Services | binary outside standard locations, `%COMSPEC% /c powershell` (Cobalt Strike psexec_psh), PSEXESVC | T1543.003 |
| Kernel drivers | known vulnerable drivers used to kill EDR (BYOVD: RTCore64, aswArPot, gdrv, zam64, …), drivers outside System32, unsigned or new drivers | T1068, T1562.001 |
| WMI | CommandLine/ActiveScript event consumers | T1546.003 |
| BITS | persistent BITS jobs | T1197 |
| Remote access | AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, SupRemo, … plus MEGAsync, WinSCP | T1219 |
| Running processes | encoded PowerShell, rundll32 with a non-DLL file (Emotet), binaries in staging folders, masquerading (svchost.exe outside System32), external connections | T1059, T1218, T1036 |
| Configuration | WDigest UseLogonCredential, RDP enabled / NLA disabled, LocalAccountTokenFilterPolicy, RestrictedAdmin, netsh portproxy, firewall disabled (effective policy incl. GPO), IOC registry keys (REvil `BlackLivesMatter`) | T1112, T1021 |
| Defender | real-time protection disabled (passive mode next to another AV recognised), policies (LockBit GPO), exclusions, Tamper Protection | T1562.001 |
| Recovery | shadow copies, VSS service, `bcdedit recoveryenabled No` / `IgnoreAllFailures` | T1490 |
| Accounts | members of local Administrators, Guest, recently set passwords | T1078, T1136 |
| Event logs | 1102/104 (log cleared), 7045 (new services), 4720/4732/4728/4756, 4625 (brute force by IP), 4624 type 10 + LSM 21/25 (RDP from public IPs), Defender 1116/1117/5001/5007, PowerShell 4104 (multi-part script blocks joined) and 400, Task Scheduler 106, firewall changes | T1070, T1110, T1133 |
| Evidence of execution | Prefetch (tools even after the binary was deleted), UserAssist (ROT13), BAM (volumes mapped to their drive letters) | – |
| Command history | PSReadLine `ConsoleHost_history.txt` (comsvcs MiniDump / `#24`, Rubeus, vssadmin, wevtutil cl, …) | T1059.001, T1003 |
| Exfiltration | `rclone.conf`, MEGAsync logs and account | T1567 |
| File system | staging folders (ProgramData incl. first-level subfolders, Users\Public, PerfLogs, Temp, root of every fixed drive, C:\Windows, Roaming): unsigned binaries, attack scripts, AdFind output, lsass.dmp; user folders: tool names; SHA256 for VirusTotal lookups | T1105, T1074 |
| Ransom notes | `how_to_decrypt.hta`, `*-read-me.txt`, `RESTORE-MY-FILES.txt`, … on the system drive and all other fixed drives; the earliest one serves as the timeline pivot | T1486 |
| GPO deployment | on a domain controller (SYSVOL location read from Netlogon): recently modified `ScheduledTasks.xml`, `Files.xml`, `Registry.pol` (parsed - Defender / firewall disabled by policy) and binaries in SYSVOL\scripts (LockBit) | T1484.001 |

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

`indicators.json` and `remediation.json` are pinned in the exe together with the script (see
[Integrity check](#integrity-check)). After editing them, rebuild with `src\build.cmd`, otherwise the app asks for
confirmation before every run. `check_reasons.json` is only displayed and can be edited freely.

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

If Group Policy enforces the execution policy `AllSigned` (or `RemoteSigned` for downloaded files), it overrides
`-ExecutionPolicy Bypass`. Import the certificate as shown above and unblock the files (`Unblock-File`); the app
shows this hint when the script is blocked.

### Integrity check

The app runs the script with administrator rights, so whoever can write to the tool folder (a share, a USB stick,
a copy on a compromised host) could swap the script or blind it with an empty indicator list. The exe therefore
contains the SHA-256 of `RansomwareChecker.ps1`, `config\indicators.json` and `config\remediation.json` from the
build. Before each run it opens these files so that nobody can modify, rename or delete them until the check has
finished, and compares them. If they differ, it warns you and runs only after explicit confirmation.

## Building from source

The source code is in `src\`. Run `src\build.cmd`; it uses `csc.exe` from .NET Framework 4.x, so nothing needs to be
installed. The build signs the script, pins its hash and the config hashes into the exe (`src\make_integrity.ps1`),
compiles and signs the exe. Signing is skipped if the certificate is not present in `Cert:\CurrentUser\My`.
Rebuild after every change of the script or the pinned config files.

`src\make_dist.ps1` then builds the distribution package `dist\RansomwareChecker-<version>.zip` (+ `.sha256`). It checks
that the exe and the script have the same version and valid signatures, and leaves out local data: `marks.json`,
`RansomwareChecker.ini` (the app creates default settings), `Reports\`, `Remediation\`, `src\` and `docs\`.

## Known limitations

- User registry hives are read only for **logged-on** users. Loading an offline `NTUSER.DAT` would change the system,
  so profiles that were not checked are listed under *Coverage notes* for offline review.
- Amcache, ShimCache, SRUM, $MFT and Prefetch contents are not parsed (only Prefetch names and times). Prefetch is
  disabled by default on Windows Server; the report says so.
- Event log queries have a maximum number of events; when it is reached, a coverage note is written.
- More noise on developer and admin machines (custom PowerShell scripts, RMM tools).
- Antivirus engines may flag the tool heuristically, because it looks for the same things attackers use.

## Roadmap

- Offline mode over a mounted image or KAPE output
- Parsing of Amcache, ShimCache and SRUM
- Comparing `C:\Windows\System32\Tasks` against the registry (hidden tasks)
- Remote execution over WinRM with result collection
- YARA rules and hash IOCs
- Comparing two runs (baseline diff)

## Changelog

### 1.2.2

- Fixed: on computers with diacritics in the path (e.g. in the user name) the app reported *Check did not finish -
  the script did not produce a report* although the report was written. The script now writes its output for the app in
  UTF-8 and the app reads it as UTF-8; as a fallback the app opens the newest report written during the run.

### 1.2.1

- Marks are stored per computer. Before, `marks.json` travelled with a copied tool folder and a false positive marked
  on one computer snoozed the same finding on another computer. Marks from 1.2.0 are assigned to the computer they were made on.
- `src\make_dist.ps1` builds a clean distribution ZIP without local data (marks, settings, reports).

### 1.2.0

Analyst marks in the desktop app.

- Right-click a finding: **Mark as false positive** snoozes the detection (dimmed text, sorted last, not counted in
  the severity counts and the headline); **Mark as suspicious** highlights the row in muted red. Choosing the same
  item again removes the mark; the two marks exclude each other.
- Marks are kept in `marks.json` next to the exe (key = category + item), so findings keep their marks in later reports.
- New **False positive** / **Suspicious** filter chips show only the marked findings (combined with severity filter and search).
- Expanded findings show a *Marked* row; copied findings include the mark.

### 1.1.0

Security and detection fixes based on a code review.

**Security**
- The app verifies the SHA-256 of the script, `indicators.json` and `remediation.json` against the hashes baked in at
  build time and keeps the files locked while the elevated script runs; it warns before running modified files.
- Code signature downgrade only when *every* flagged file is signed (a signed argument no longer hides an unsigned binary).
- CSV output neutralises formulas; Markdown output renders finding text literally.
- Regular expressions from the config have a timeout (ReDoS).

**Detection**
- New check: kernel drivers (BYOVD - known vulnerable drivers, drivers outside System32, unsigned or new drivers).
- PowerShell 4104: multi-part script blocks are joined before matching; the tool's own code is recognised by content.
- Encoded PowerShell in all forms (`-e`, `-en`, `-enc`, `-ec`, typographic dashes); `comsvcs.dll #24` LSASS dumps.
- Firewall state read from the effective policy (incl. GPO); Defender passive mode next to another AV recognised.
- Masquerading check anchored to the real System32 (`C:\ProgramData\Windows\System32\svchost.exe` is flagged).
- BAM paths mapped to the correct drive letter; ransom notes and staging folders searched on all fixed drives;
  ProgramData first-level subfolders included.
- Domain controllers: SYSVOL location read from Netlogon, `Registry.pol` parsed for disabled Defender / firewall.
- Entra ID accounts included; logged-off profiles listed under *Coverage notes*.
- Tool names must end at a word boundary (`adfind_report.txt` no longer matches `adfind`); generic file names
  (`list.txt`, `ips.txt`) lowered to Medium/Low.
- CGNAT (100.64.0.0/10) and the whole fe80::/10 treated as private addresses.

**Robustness**
- One malformed value (invalid install date, `|<>` in a path) no longer aborts a whole check.
- Empty event logs detected independently of the Windows language; localized Remote Desktop rule names.
- Coverage notes when an event log limit is reached or Prefetch is disabled; 4625 analysis faster.
- Self-exclusion limited to the tool's own processes and files (also when run from a drive root).
- The app reads the number of checks and the report folder from the script output; clear hint when Group Policy
  (AllSigned) blocks the script; unused `DarkMode` setting removed.

### 1.0.0

First public release.

## Sources

The checks, the reasons behind them and the remediation steps are based on:

- Oleg Skulkin: *Incident Response Techniques for Ransomware Attacks*, Packt Publishing, 2022.

## License

The code is licensed under the MIT License (see `LICENSE`). The embedded Oswald font is licensed under the
SIL Open Font License 1.1 (`licenses\Oswald-OFL.txt`).
