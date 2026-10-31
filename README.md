# RansomwareChecker v. 1.0.0

Přenosný (portable) nástroj pro Windows na **rychlou triáž persistence a artefaktů po ransomware útoku**.
Kontroly pokrývají techniky typické pro ransomware útoky řízené člověkem: initial access, persistence,
post-exploitation, exfiltraci dat a nasazení ransomwaru.

* **Pouze čte**: nic nemaže, nemění ani neopravuje.
* Bez instalace, stačí Windows PowerShell 5.1 (Windows 10/11, Server 2016+).
* Výstup: report (`report.html` + `report.md`, ve stejném formátu jako postup nápravy; HTML s filtrem podle závažnosti
  a fulltextem, nálezy seskupené po kategoriích a rozbalitelné), `findings.csv` a `findings.json` ve složce `Reports\`.
* Doporučený postup nápravy (`remediation.html` + `remediation.md`) ve složce `Remediation\` vedle `Reports\`.

## Spuštění

### Aplikace

* Hlavička ukazuje stav (spinner během kontroly, červený křížek = High, oranžový vykřičník = Medium, zelená fajfka).
* Filtry **High / Medium / Low / Info** a fulltextové hledání.
* Kliknutí na řádek ho rozbalí: celé detaily, *Flagged because* (proč byl nález označen), *Why checked*
  (proč kontrola existuje), *Remediation* (doporučené kroky nápravy), MITRE technika, kategorie a čas.
  Text sekcí je v neproporcionálním písmu Consolas.
  Pravé tlačítko myši umožňuje kopírovat nález (včetně důvodu a kroků nápravy), kopírovat vše a rozbalit nebo sbalit vše.
* Tlačítka **Remediation plan** (postup nápravy k zobrazenému reportu), **HTML report** a **Report folder**, v patičce *Coverage notes* (kliknutím zobrazíte seznam).
* Nastavení je v `RansomwareChecker.ini` vedle exe: `DaysBack`, `Quick`, `RunOnStart`.
* Důvody kontrol jsou v `config\check_reasons.json` a kroky nápravy v `config\remediation.json` (klíč = kategorie nálezu).
  Lze je upravit nebo přeložit bez nové kompilace.
* Font Oswald (Google Fonts, řezy Regular a SemiBold) je vložený v exe, licence SIL OFL je v `licenses\Oswald-OFL.txt`.

Exe potřebuje vedle sebe `RansomwareChecker.ps1` a `config\`. Zdroj je ve složce `src\`, sestavení přes `src\build.cmd`
(používá csc.exe z .NET Frameworku 4.x, nic se neinstaluje).

### Skript
```
Run-RansomwareChecker.bat                      (vyžádá si admin práva, otevře report)
Run-RansomwareChecker.bat -DaysBack 60 -Quick
```

nebo přímo:

```powershell
powershell -ExecutionPolicy Bypass -File .\RansomwareChecker.ps1 -DaysBack 30 -OpenReport
```

| Parametr      | Význam                                                                 |
|---------------|------------------------------------------------------------------------|
| `-DaysBack`   | časové okno pro event logy a heuristiky „nově vytvořeno“ (výchozí 30)  |
| `-OutputPath` | kam uložit report (výchozí `.\Reports\<PC>_<čas>`)                     |
| `-Quick`      | přeskočí pomalejší průchod souborovým systémem                         |
| `-NoHtml`     | jen CSV + JSON                                                         |
| `-OpenReport` | po doběhnutí otevře HTML report                                        |
| `-RemediationPath` | kam uložit postup nápravy (výchozí `.\Remediation\<PC>_<čas>` vedle `Reports`) |

**Exit code:** `0` bez nálezů Medium/High, `1` jsou nálezy Medium, `2` jsou nálezy High. Hodí se pro hromadné
spouštění, např. přes GPO nebo RMM se sdílenou složkou jako `-OutputPath`.

> Spouštějte jako **správce**. Bez elevace chybí Security log, Prefetch, ostatní uživatelé, příkazové řádky
> cizích procesů a výjimky v Defenderu. Co se nepodařilo zkontrolovat, je uvedeno v reportu v sekci *Coverage notes*.

## Co se kontroluje

| Oblast | Kontroly | MITRE ATT&CK |
|---|---|---|
| Autostart | Run/RunOnce (HKLM + načtené uživatelské hive), Winlogon Shell/Userinit, IFEO Debugger (sticky keys), AppInit_DLLs, BootExecute, složky Startup | T1547, T1546 |
| Naplánované úlohy | jiné než Microsoft úlohy, GUID názvy (Qakbot), skryté a nově registrované úlohy, podezřelé příkazy | T1053.005 |
| Služby | binárka mimo standardní umístění, `%COMSPEC% /c powershell` (Cobalt Strike psexec_psh), PSEXESVC | T1543.003 |
| WMI | CommandLine/ActiveScript event consumers | T1546.003 |
| BITS | perzistentní BITS joby | T1197 |
| Vzdálený přístup | AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, SupRemo, … a MEGAsync, WinSCP (instalace, příp. nedávná) | T1219 |
| Běžící procesy | kódovaný PowerShell, rundll32 s ne-DLL souborem (Emotet), binárky ve staging složkách, maskování (svchost.exe mimo System32), externí spojení | T1059, T1218, T1036 |
| Konfigurace | WDigest UseLogonCredential, RDP zapnuté / NLA vypnuté, LocalAccountTokenFilterPolicy, RestrictedAdmin, netsh portproxy, vypnutý firewall, IOC klíče v registru (REvil `BlackLivesMatter`) | T1112, T1021 |
| Defender | vypnutá ochrana v reálném čase, policy (LockBit GPO), výjimky, Tamper Protection | T1562.001 |
| Obnova | stínové kopie, služba VSS, `bcdedit recoveryenabled No` / `IgnoreAllFailures` | T1490 |
| Účty | členové lokálních Administrators, Guest, nedávno nastavená hesla | T1078, T1136 |
| Event logy | 1102/104 (smazání logů), 7045 (nové služby), 4720/4732/4728/4756, 4625 (brute force podle IP), 4624 typ 10 + LSM 21/25 (RDP z veřejných IP), Defender 1116/1117/5001/5007, PowerShell 4104 a 400, Task Scheduler 106, změny firewallu (netsh + Remote Desktop) | T1070, T1110, T1133 |
| Důkazy spuštění | Prefetch (nástroje i po smazání binárky, `.cr_hand.exe`), UserAssist (ROT13), BAM | – |
| Historie příkazů | PSReadLine `ConsoleHost_history.txt` (comsvcs MiniDump, Rubeus, vssadmin, wevtutil cl, …) | T1059.001, T1003 |
| Exfiltrace | `rclone.conf`, MEGAsync logy a účet | T1567 |
| Souborový systém | staging složky (ProgramData, Users\Public, PerfLogs, Temp, C:\, C:\Windows, Roaming) – nepodepsané binárky, skripty s útočnými příkazy (a.bat s AdFind, rdp.bat), výstupy AdFind, lsass.dmp; uživatelské složky (Desktop, Downloads, Pictures…) – názvy nástrojů; SHA256 pro dohledání na VirusTotal | T1105, T1074 |
| Ransom notes | `how_to_decrypt.hta`, `*-read-me.txt`, `RESTORE-MY-FILES.txt`, … – nejstarší výskyt slouží jako pivot pro timeline | T1486 |
| GPO deployment | na DC: nedávno změněné `ScheduledTasks.xml`, `Files.xml`, `Registry.pol` a binárky v SYSVOL\scripts (LockBit) | T1484.001 |

## Konfigurace

Indikátory jsou v `config\indicators.json` a lze je upravovat bez zásahu do skriptu:
`AttackerTools`, `DualUseTools`, `RemoteAccessTools`, cesty (`SuspiciousPathPatterns`, `AllowedPathPatterns`),
klíčová slova příkazů (`CommandKeywords` – .NET regex), vzory ransom notes a práh pro brute force.

## Postup nápravy (složka Remediation)

Každá kontrola vytvoří vedle `Reports\<PC>_<čas>` i `Remediation\<PC>_<čas>` se stejným názvem. Postup odpovídá
standardnímu procesu reakce na incident: 1) zajištění důkazů, 2) containment, 3) eradication po kategoriích
(seznam nálezů + doporučené kroky), 4) recovery, 5) post-incident opatření. Nástroj sám nic neopravuje - kroky provádí
správce po ověření nálezu.

## Jak číst výsledky

* **High**: s vysokou pravděpodobností artefakt útoku. Ověřit a zajistit důkazy (nejdřív image nebo KAPE, až potom čištění).
* **Medium**: podezřelé, ale může jít o legitimní administraci (PsExec, AnyDesk, admin skripty).
* **Low / Info**: kontext pro analytika (RDP zapnuté, seznam adminů, nové služby).

Nástroj **nenahrazuje forenzní analýzu**. Doporučený postup: nejdřív najít pivot (první ransom note nebo
detekci), potom timeline z $MFT (MFTECmd), event logy (EvtxECmd), Amcache, ShimCache a SRUM, a útok rekonstruovat
po jednotlivých fázích (initial access → persistence → laterální pohyb → exfiltrace → nasazení).

## Známá omezení

* Uživatelské hive se čtou jen pro **přihlášené** uživatele (HKEY_USERS). Offline NTUSER.DAT se nenačítá.
* Neparsuje se Amcache, ShimCache, SRUM, $MFT ani obsah Prefetch (jen názvy a čas).
* BAM mapuje `\Device\HarddiskVolumeX` na systémový disk (heuristika).
* Vyšší šum na vývojářských a admin strojích (vlastní PowerShell skripty, RMM nástroje).
* Defender může nepodepsané `RansomwareChecker.exe` heuristicky označit jako hrozbu (falešná detekce).

## Nápady na další verze

Offline režim nad připojeným image nebo KAPE výstupem, parsování Amcache/ShimCache/SRUM, kontrola
`C:\Windows\System32\Tasks` proti registru (skryté úlohy), vzdálené spuštění přes WinRM se sběrem výsledků,
YARA a hash IOC, porovnání dvou běhů (baseline diff).

## Digitální podpis

`RansomwareChecker.exe` i `RansomwareChecker.ps1` jsou podepsané vlastním (self-signed) certifikátem
`CN=RansomwareChecker Code Signing`, SHA1 thumbprint `9F82EBC12B1EE794B4BFEA8ECBBA552E30E116A9`, platnost do 31. 10. 2031.
Veřejná část certifikátu je v `cert\RansomwareChecker.cer` (soukromý klíč v repozitáři není).

Ověření podpisu:

```powershell
Get-AuthenticodeSignature .\RansomwareChecker.exe, .\RansomwareChecker.ps1
```

Aby Windows podpis uznal jako platný (`Valid`), je potřeba certifikát jednou importovat (PowerShell jako správce):

```powershell
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-Certificate -FilePath .\cert\RansomwareChecker.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

Bez importu se podpis zobrazí jako nedůvěryhodný (`UnknownError`), ale integritu souborů lze i tak ověřit podle thumbprintu.
## Licence

Kód je pod licencí MIT (viz `LICENSE`). Font Oswald je pod licencí SIL Open Font License 1.1 (`licenses\Oswald-OFL.txt`).
