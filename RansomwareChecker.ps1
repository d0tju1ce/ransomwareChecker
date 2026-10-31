#Requires -Version 5.1
<#
.SYNOPSIS
    RansomwareChecker - portable, read-only triage of persistence and post-exploitation
    artifacts left behind by human-operated ransomware attacks.

.DESCRIPTION
    Checks cover the TTPs and forensic artifacts typical for human-operated ransomware:
    autoruns, scheduled tasks, services, WMI subscriptions, remote access tools,
    Defender tampering, RDP / WDigest changes, inhibited recovery, event logs
    (7045, 4624/4625, 1102, 4720/4732, 1116, 4104 ...), evidence of execution
    (Prefetch, UserAssist, BAM), PSReadLine history, staging folders, ransom notes
    and GPO-based deployment.

    The tool does NOT change anything on the system. Run it elevated for full coverage.

.PARAMETER DaysBack
    Time window (days) for event logs and "recently created" heuristics. Default 30.

.PARAMETER OutputPath
    Where to write the report. Default: <script folder>\Reports

.PARAMETER Quick
    Skip slower file system sweeps (staging folders, ransom note search).

.PARAMETER NoHtml
    Do not produce the HTML report (CSV and JSON are always written).

.PARAMETER OpenReport
    Open the HTML report when finished.

.PARAMETER RemediationPath
    Where to write the recommended remediation plan. Default: a "Remediation" folder next to the
    Reports folder (Remediation\<PC>_<time>\remediation.html + remediation.md, same name as the report).

.EXAMPLE
    .\RansomwareChecker.ps1 -DaysBack 60 -OpenReport
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$DaysBack = 30,
    [string]$OutputPath,
    [switch]$Quick,
    [switch]$NoHtml,
    [switch]$OpenReport,
    [string]$RemediationPath
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:Version   = '1.0.0'
$script:Root      = $PSScriptRoot
$script:Since     = (Get-Date).AddDays(-$DaysBack)
$script:Findings  = New-Object System.Collections.Generic.List[object]
$script:Notes     = New-Object System.Collections.Generic.List[object]
$script:SigCache  = @{}
$script:SevNames  = @{ 0 = 'Info'; 1 = 'Low'; 2 = 'Medium'; 3 = 'High' }
$script:IsAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                        [Security.Principal.WindowsBuiltInRole]::Administrator)

$configPath = Join-Path $script:Root 'config\indicators.json'
if (-not (Test-Path -LiteralPath $configPath)) {
    Write-Error "Indicator file not found: $configPath"
    exit 10
}
$script:Ioc = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$script:KeywordRegex = @($script:Ioc.CommandKeywords | ForEach-Object {
    New-Object System.Text.RegularExpressions.Regex($_, 'IgnoreCase')
})

#region ---------------------------------------------------------------- helpers

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][int]$Level,
        [Parameter(Mandatory)][string]$Item,
        [string]$Details = '',
        [string]$Mitre = '',
        [string]$Timestamp = ''
    )
    $script:Findings.Add([pscustomobject][ordered]@{
        Severity  = $script:SevNames[[Math]::Min([Math]::Max($Level, 0), 3)]
        Rank      = $Level
        Category  = $Category
        Item      = $Item
        Details   = $Details
        Mitre     = $Mitre
        Timestamp = $Timestamp
    })
}

function Add-Note {
    param([string]$Check, [string]$Message)
    $script:Notes.Add([pscustomobject]@{ Check = $Check; Message = $Message })
}

function Format-Time {
    param($Value)
    if ($null -eq $Value) { return '' }
    try { return ([datetime]$Value).ToString('yyyy-MM-dd HH:mm:ss') } catch { return [string]$Value }
}

function Join-Details {
    param([string]$Text, $Reasons)
    $r = @($Reasons | Where-Object { $_ })
    if ($r.Count -eq 0) { return $Text }
    return ('{0}  [{1}]' -f $Text, ($r -join '; '))
}

function Test-PrivateAddress {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip) -or $Ip -in @('-', '::1', '127.0.0.1', 'LOCAL', '0.0.0.0', '::')) { return $true }
    $Ip = $Ip -replace '^::ffff:', ''
    return ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|fe80:|fc|fd)')
}

function Find-Keywords {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    $hits = foreach ($rx in $script:KeywordRegex) { if ($rx.IsMatch($Text)) { $rx.ToString() } }
    return @($hits)
}

function Get-UserHives {
    Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object {
            $sid = $_.PSChildName
            $name = $sid
            try { $name = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount]).Value } catch { }
            [pscustomobject]@{ Sid = $sid; Name = $name; Root = "Registry::HKEY_USERS\$sid" }
        }
}

function Get-UserProfileDirs {
    Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('All Users', 'Default User', 'Default') -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }
}

function Convert-ImagePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim()
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '(?i)^\\SystemRoot\\', ($env:SystemRoot + '\')
    $p = $p -replace '(?i)^system32\\', ($env:SystemRoot + '\System32\')
    return [Environment]::ExpandEnvironmentVariables($p)
}

function Get-PathCandidates {
    param([string]$Command)
    $expanded = Convert-ImagePath $Command
    $exts = 'exe|dll|sys|bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|scr|com|cpl|msi|jar|wsf|lnk|ocx'
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($m in [regex]::Matches($expanded, '"([^"]+?)"')) {
        $p = $m.Groups[1].Value.Trim()
        if ($p -match '^[a-zA-Z]:\\[^\s]|^\\\\') {
            # only quoted paths that look like files - skip folders such as --user-data-dir="C:\...\Roaming\App"
            $isFile = $p -match "(?i)\.($exts)$"
            if (-not $isFile) { try { $isFile = Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue } catch { } }
            if ($isFile) { [void]$set.Add($p) }
        }
    }
    foreach ($m in [regex]::Matches($expanded, "(?i)((?:[a-z]:|\\\\[^\\""\s]+)\\[^""<>|*?\r\n]*?\.($exts))(?=[\s,""]|$)")) {
        [void]$set.Add($m.Groups[1].Value)
    }
    return @($set)
}

function Get-SignatureInfo {
    param([string]$Path)
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $info = [pscustomobject]@{ Valid = $false; Signer = '' }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $info.Valid = ($sig.Status -eq 'Valid')
        if ($sig.SignerCertificate) {
            $info.Signer = ($sig.SignerCertificate.Subject -replace '^CN="?([^",]+).*$', '$1')
        }
    } catch { }
    $script:SigCache[$Path] = $info
    return $info
}

function Test-NameList {
    # Matches tool names at a path / argument boundary, e.g. "\adfind.exe", " rclone ", "=mimikatz"
    param([string]$Text, $Names)
    foreach ($n in $Names) {
        $pattern = '(^|[\\/\s"'',=(])' + [regex]::Escape($n.ToLowerInvariant())
        if ($Text -match $pattern) { return $n }
    }
    return $null
}

function Get-CommandAssessment {
    <#
        Scores a command line / path. Levels: 0 Info, 1 Low, 2 Medium, 3 High.
        "Behaviour" reasons (tool names, encoded PowerShell, masquerading...) cannot be
        downgraded; "location" reasons are downgraded to Low when the file has a valid signature.
    #>
    param([string]$Command, [switch]$CheckSignature)

    $reasons = New-Object System.Collections.Generic.List[string]
    $behaviour = 0
    $location = 0
    if ([string]::IsNullOrWhiteSpace($Command)) {
        return [pscustomobject]@{ Level = 0; Behaviour = 0; Location = 0; Reasons = @(); Paths = @() }
    }
    $c = (Convert-ImagePath $Command).ToLowerInvariant()

    $hit = Test-NameList $c $script:Ioc.AttackerTools
    if ($hit) { $reasons.Add("attacker tool '$hit'"); $behaviour = 3 }
    $hit = Test-NameList $c $script:Ioc.DualUseTools
    if ($hit) { $reasons.Add("dual-use tool '$hit'"); $behaviour = [Math]::Max($behaviour, 2) }
    foreach ($t in $script:Ioc.RemoteAccessTools) {
        if ($c.Contains($t.ToLowerInvariant())) { $reasons.Add("remote access software '$t'"); $behaviour = [Math]::Max($behaviour, 2); break }
    }

    if ($c -match '(powershell|pwsh)') {
        if ($c -match '\s[-/](e|ec|enc\w*)\s') {
            $reasons.Add('encoded PowerShell'); $behaviour = 3
            $b64 = [regex]::Match($Command, '(?i)\s[-/](?:e|ec|enc\w*)\s+"?([A-Za-z0-9+/=]{16,})')
            if ($b64.Success) {
                try {
                    $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64.Groups[1].Value)) -replace '\s+', ' '
                    if ($decoded.Length -gt 300) { $decoded = $decoded.Substring(0, 300) + '...' }
                    $reasons.Add("decoded: $decoded")
                    foreach ($k in (Find-Keywords $decoded)) { $reasons.Add("decoded keyword: $k") }
                } catch { }
            }
        }
        if ($c -match '(iex\b|invoke-expression|downloadstring|downloadfile|frombase64string|invoke-webrequest|net\.webclient|start-bitstransfer)') {
            $reasons.Add('download/execute cradle'); $behaviour = 3
        }
        if ($c -match '\s-w(indowstyle|in\w*)?\s+(hidden|1)\b') { $reasons.Add('hidden window'); $behaviour = [Math]::Max($behaviour, 2) }
        if ($c -match 'bypass') { $reasons.Add('execution policy bypass'); $behaviour = [Math]::Max($behaviour, 1) }
    }
    if ($c -match '(%comspec%|cmd(\.exe)?"?\s+/[ckr]\b).*(powershell|\\\\|rundll32|start\s+/b)') {
        $reasons.Add('cmd.exe wrapper launching payload'); $behaviour = [Math]::Max($behaviour, 2)
    }
    if ($c -match 'comsvcs(\.dll)?["'',\s]+#?\s*mini?dump') { $reasons.Add('LSASS dump via comsvcs.dll'); $behaviour = 3 }
    if ($c -match '\bmshta(\.exe)?\b') { $reasons.Add('mshta'); $behaviour = [Math]::Max($behaviour, 2) }
    if ($c -match 'certutil.*(-decode|-urlcache)') { $reasons.Add('certutil decode/download'); $behaviour = 3 }
    if ($c -match 'bitsadmin.*/transfer') { $reasons.Add('bitsadmin transfer'); $behaviour = 3 }
    if ($c -match 'regsvr32.*/i:\s*https?') { $reasons.Add('regsvr32 remote scriptlet'); $behaviour = 3 }

    $m = [regex]::Match($c, 'rundll32(\.exe)?"?\s+"?([^",]+?)"?\s*,')
    if ($m.Success) {
        $arg = $m.Groups[2].Value.Trim()
        $ext = [IO.Path]::GetExtension($arg)
        if ($ext -and $ext -notin @('.dll', '.cpl', '.ocx', '.drv')) {
            $reasons.Add("rundll32 loads non-DLL file '$arg'"); $behaviour = 3
        }
    }

    $paths = Get-PathCandidates $Command
    $flaggedPath = $null
    foreach ($p in $paths) {
        $pl = $p.ToLowerInvariant()
        $allowed = $false
        foreach ($a in $script:Ioc.AllowedPathPatterns) { if ($pl -match $a) { $allowed = $true; break } }
        if (-not $allowed) {
            $matched = $false
            foreach ($s in $script:Ioc.SuspiciousPathPatterns) {
                if ($pl -match $s) { $reasons.Add("suspicious location"); $location = [Math]::Max($location, 2); $flaggedPath = $p; $matched = $true; break }
            }
            if (-not $matched) {
                foreach ($s in $script:Ioc.UnusualPathPatterns) {
                    if ($pl -match $s) { $reasons.Add("user-writable location"); $location = [Math]::Max($location, 1); if (-not $flaggedPath) { $flaggedPath = $p }; break }
                }
            }
        }
        try {
            $leaf = [IO.Path]::GetFileName($pl)
            $dir  = [IO.Path]::GetDirectoryName($pl)
            if ($script:Ioc.SystemBinaryNames -contains $leaf -and $dir -and
                $dir -notmatch '\\windows\\(system32|syswow64|winsxs|servicing)' -and
                -not ($leaf -eq 'explorer.exe' -and $dir -match '^[a-z]:\\windows$') -and
                -not ($leaf -eq 'msedgeupdater.exe')) {
                $reasons.Add("system binary name outside System32 (masquerading): $p"); $behaviour = 3
            }
            if ($leaf -eq 'msedgeupdater.exe' -and $dir -notmatch '\\microsoft\\edge') {
                $reasons.Add("fake Edge updater name (REvil case): $p"); $behaviour = 3
            }
        } catch { }
        try {
            if (-not ($p.StartsWith('\\')) -and -not (Test-Path -LiteralPath $p -PathType Leaf -ErrorAction SilentlyContinue)) {
                $reasons.Add("target missing: $p"); $location = [Math]::Max($location, 1)
            }
        } catch { }
    }

    if ($CheckSignature -and $flaggedPath -and $location -ge 1 -and $behaviour -lt 2) {
        $exists = $false
        try { $exists = Test-Path -LiteralPath $flaggedPath -PathType Leaf -ErrorAction SilentlyContinue } catch { }
        if ($exists) {
            $sig = Get-SignatureInfo $flaggedPath
            if ($sig.Valid) { $reasons.Add("signed: $($sig.Signer)"); $location = [Math]::Min($location, 1) }
            else { $reasons.Add('unsigned') }
        }
    }

    return [pscustomobject]@{
        Level     = [Math]::Max($behaviour, $location)
        Behaviour = $behaviour
        Location  = $location
        Reasons   = @($reasons | Select-Object -Unique)
        Paths     = $paths
    }
}

function Get-EventsXPath {
    param([string]$LogName, [string]$XPath, [int]$Max = 5000)
    try {
        return @(Get-WinEvent -LogName $LogName -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -notmatch 'No events were found|Nebyly nalezeny|Es wurden keine') {
            Add-Note "EventLog $LogName" $_.Exception.Message
        }
        return @()
    }
}

function Get-XPathWindow {
    param([int[]]$Ids)
    $ms = [long]$DaysBack * 86400000
    $idPart = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    return "*[System[($idPart) and TimeCreated[timediff(@SystemTime) <= $ms]]]"
}

function Get-EventDataMap {
    param($Evt)
    $h = @{}
    try {
        $x = [xml]$Evt.ToXml()
        if ($x.Event.EventData) {
            foreach ($d in @($x.Event.EventData.ChildNodes)) {
                if ($d -is [System.Xml.XmlElement]) {
                    $n = $d.GetAttribute('Name')
                    if ($n) { $h[$n] = $d.InnerText }
                }
            }
        }
        if ($x.Event.UserData) {
            foreach ($n in $x.Event.UserData.ChildNodes) {
                foreach ($c in $n.ChildNodes) { if ($c -is [System.Xml.XmlElement]) { $h[$c.LocalName] = $c.InnerText } }
            }
        }
    } catch { }
    return $h
}

function Get-FileSha256 {
    param([string]$Path)
    try {
        $f = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($f.Length -gt 200MB) { return 'skipped (>200MB)' }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return 'n/a' }
}

function ConvertFrom-Rot13 {
    param([string]$Text)
    $chars = foreach ($ch in $Text.ToCharArray()) {
        $i = [int]$ch
        if ($i -ge 65 -and $i -le 90)      { [char](((($i - 65) + 13) % 26) + 65) }
        elseif ($i -ge 97 -and $i -le 122) { [char](((($i - 97) + 13) % 26) + 97) }
        else { $ch }
    }
    return -join $chars
}

#endregion

#region ---------------------------------------------------------------- checks: persistence

function Test-RunKeys {
    $cat = 'Persistence: Run keys'
    $rel = @(
        'Software\Microsoft\Windows\CurrentVersion\Run',
        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    $roots = @([pscustomobject]@{ Name = 'HKLM'; Root = 'Registry::HKEY_LOCAL_MACHINE' })
    $roots += @(Get-UserHives | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Root = $_.Root } })

    foreach ($r in $roots) {
        foreach ($k in $rel) {
            $path = "$($r.Root)\$k"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            if (-not $key) { continue }
            foreach ($v in $key.GetValueNames()) {
                $data = [string]$key.GetValue($v, $null, 'DoNotExpandEnvironmentNames')
                $a = Get-CommandAssessment -Command $data -CheckSignature
                $name = if ($v) { $v } else { '(Default)' }
                Add-Finding -Category $cat -Level $a.Level -Item "$($r.Name)\$k -> $name" `
                    -Details (Join-Details $data $a.Reasons) -Mitre 'T1547.001'
            }
        }
    }
}

function Test-WinlogonAndIfeo {
    $cat = 'Persistence: Winlogon / IFEO / AppInit'
    $wl = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $p = Get-ItemProperty -LiteralPath $wl -ErrorAction SilentlyContinue
    if ($p) {
        if ($p.Shell -and $p.Shell.Trim().ToLowerInvariant() -notin @('explorer.exe')) {
            Add-Finding -Category $cat -Level 3 -Item 'HKLM Winlogon\Shell modified' -Details $p.Shell -Mitre 'T1547.004'
        }
        if ($p.Userinit -and ($p.Userinit.Trim().TrimEnd(',').ToLowerInvariant() -notmatch '^[a-z]:\\windows\\system32\\userinit\.exe$')) {
            Add-Finding -Category $cat -Level 3 -Item 'HKLM Winlogon\Userinit modified' -Details $p.Userinit -Mitre 'T1547.004'
        }
    }
    foreach ($h in Get-UserHives) {
        $up = Get-ItemProperty -LiteralPath "$($h.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
        if ($up -and $up.PSObject.Properties['Shell'] -and $up.Shell) {
            Add-Finding -Category $cat -Level 3 -Item "User Winlogon\Shell ($($h.Name))" -Details $up.Shell -Mitre 'T1547.004'
        }
    }

    $accessibility = @('sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe')
    foreach ($base in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = $_.GetValue('Debugger')
            if ($dbg) {
                $lvl = if ($accessibility -contains $_.PSChildName.ToLowerInvariant()) { 3 } else { 2 }
                Add-Finding -Category $cat -Level $lvl -Item "IFEO Debugger: $($_.PSChildName)" -Details $dbg -Mitre 'T1546.012 / T1546.008'
            }
        }
    }

    foreach ($w in @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                     'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $ai = Get-ItemProperty -LiteralPath $w -ErrorAction SilentlyContinue
        if ($ai -and $ai.PSObject.Properties['AppInit_DLLs'] -and $ai.AppInit_DLLs) {
            $lvl = if ($ai.PSObject.Properties['LoadAppInit_DLLs'] -and $ai.LoadAppInit_DLLs -eq 1) { 3 } else { 1 }
            Add-Finding -Category $cat -Level $lvl -Item 'AppInit_DLLs configured' -Details "$w : $($ai.AppInit_DLLs)" -Mitre 'T1546.010'
        }
    }

    $sm = Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    if ($sm -and $sm.BootExecute) {
        $be = (@($sm.BootExecute) -join ' | ')
        if ($be.Trim() -ne 'autocheck autochk *') {
            Add-Finding -Category $cat -Level 2 -Item 'Session Manager BootExecute not default' -Details $be -Mitre 'T1547.001'
        }
    }
}

function Test-StartupFolders {
    $cat = 'Persistence: Startup folders'
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($u in Get-UserProfileDirs) {
        $folders += Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($f in $folders) {
        Get-ChildItem -LiteralPath $f -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
                $target = $_.FullName
                if ($_.Extension -eq '.lnk' -and $shell) {
                    try { $lnk = $shell.CreateShortcut($_.FullName); $target = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim() } catch { }
                }
                $a = Get-CommandAssessment -Command $target -CheckSignature
                $lvl = $a.Level
                $reasons = @($a.Reasons)
                if ($_.Extension -match '^\.(bat|cmd|ps1|vbs|vbe|js|jse|hta|wsf)$') { $lvl = [Math]::Max($lvl, 2); $reasons += 'script in Startup' }
                if ($_.CreationTime -ge $script:Since) { $lvl = [Math]::Max($lvl, 1); $reasons += 'created within window' }
                Add-Finding -Category $cat -Level $lvl -Item $_.FullName -Details (Join-Details $target $reasons) `
                    -Mitre 'T1547.001' -Timestamp (Format-Time $_.CreationTime)
            }
    }
}

function Test-ScheduledTasks {
    $cat = 'Persistence: Scheduled tasks'
    $tasks = Get-ScheduledTask -ErrorAction Stop
    foreach ($t in $tasks) {
        $isMs = $t.TaskPath -like '\Microsoft\*'
        foreach ($act in @($t.Actions)) {
            if (-not $act.PSObject.Properties['Execute'] -or -not $act.Execute) { continue }
            $cmd = ('{0} {1}' -f $act.Execute, $act.Arguments).Trim()
            $a = Get-CommandAssessment -Command $cmd -CheckSignature
            $lvl = $a.Level
            $reasons = @($a.Reasons)
            if (-not $isMs -and $t.TaskName -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$') {
                $lvl = [Math]::Max($lvl, 2); $reasons += 'GUID-like task name (Qakbot pattern)'
            }
            if ($t.Settings -and $t.Settings.Hidden) { $lvl = [Math]::Max($lvl, 1); $reasons += 'hidden task' }
            $reg = $null
            if ($t.Date) { [datetime]$tmp = 0; if ([datetime]::TryParse($t.Date, [ref]$tmp)) { $reg = $tmp } }
            if ($reg -and $reg -ge $script:Since) { $lvl = [Math]::Max($lvl, 1); $reasons += 'registered within window' }
            if ($isMs -and $lvl -lt 2) { continue }
            $details = Join-Details ("{0}  (Author: {1}; State: {2}; RunAs: {3})" -f $cmd, $t.Author, $t.State, $t.Principal.UserId) $reasons
            Add-Finding -Category $cat -Level $lvl -Item "$($t.TaskPath)$($t.TaskName)" -Details $details `
                -Mitre 'T1053.005' -Timestamp (Format-Time $reg)
        }
    }
}

function Test-Services {
    $cat = 'Persistence: Services'
    foreach ($s in Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) {
        $path = Convert-ImagePath $s.PathName
        $a = Get-CommandAssessment -Command $path -CheckSignature
        $lvl = $a.Level
        $reasons = @($a.Reasons)
        if ($s.Name -match '^(PSEXESVC|PAEXEC|csexecsvc|RemComSvc|winexesvc)') { $lvl = [Math]::Max($lvl, 2); $reasons += 'remote execution service (PsExec-like)' }
        if ($s.PathName -match '(?i)(%comspec%|cmd(\.exe)?\s+/[bc]|powershell)') { $lvl = 3; $reasons += 'service runs shell command (Cobalt Strike psexec_psh / deployment)' }
        if ($lvl -lt 1) { continue }
        $details = Join-Details ("{0}  (State: {1}; Start: {2}; Account: {3})" -f $s.PathName, $s.State, $s.StartMode, $s.StartName) $reasons
        Add-Finding -Category $cat -Level $lvl -Item "$($s.Name) ($($s.DisplayName))" -Details $details -Mitre 'T1543.003'
    }
}

function Test-WmiPersistence {
    $cat = 'Persistence: WMI subscriptions'
    $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
    $bindings  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue)
    $filters   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue)
    foreach ($c in $consumers) {
        $cls = $c.CimClass.CimClassName
        if ($c.Name -eq 'SCM Event Log Consumer') { continue }
        $text = $cls
        $lvl = 1
        if ($cls -eq 'CommandLineEventConsumer')  { $text = ('{0} {1}' -f $c.ExecutablePath, $c.CommandLineTemplate).Trim(); $lvl = 3 }
        if ($cls -eq 'ActiveScriptEventConsumer') { $text = ('{0} {1}' -f $c.ScriptFileName, $c.ScriptText).Trim(); $lvl = 3 }
        $bound = @($bindings | Where-Object { $_.Consumer -and $_.Consumer.Name -eq $c.Name } | ForEach-Object { $_.Filter.Name }) -join ', '
        $query = @($filters | Where-Object { $_.Name -in ($bound -split ', ') } | ForEach-Object { $_.Query }) -join ' | '
        if ($text.Length -gt 600) { $text = $text.Substring(0, 600) + '...' }
        Add-Finding -Category $cat -Level $lvl -Item "$cls : $($c.Name)" -Details "$text  [filter: $bound $query]" -Mitre 'T1546.003'
    }
}

function Test-BitsJobs {
    $cat = 'Persistence: BITS jobs'
    if (-not (Get-Command Get-BitsTransfer -ErrorAction SilentlyContinue)) { Add-Note 'BITS' 'BitsTransfer module not available'; return }
    $jobs = if ($script:IsAdmin) { @(Get-BitsTransfer -AllUsers -ErrorAction Stop) } else { @(Get-BitsTransfer -ErrorAction Stop) }
    foreach ($j in $jobs) {
        $files = @($j.FileList | ForEach-Object { "$($_.RemoteName) -> $($_.LocalName)" }) -join ' | '
        $lvl = 1
        if ($files -match '(?i)\.(exe|dll|ps1|bat|hta|vbs)\b') { $lvl = 2 }
        Add-Finding -Category $cat -Level $lvl -Item "$($j.DisplayName) [$($j.OwnerAccount)]" -Details "$($j.JobState): $files" `
            -Mitre 'T1197' -Timestamp (Format-Time $j.CreationTime)
    }
}

#endregion

#region ---------------------------------------------------------------- checks: tools, config, accounts

function Test-RemoteAccessSoftware {
    $cat = 'Persistence: Remote access / exfil software'
    $keys = @('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
              'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in Get-UserHives) { $keys += "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    $names = @($script:Ioc.RemoteAccessTools) + @($script:Ioc.DualUseTools | ForEach-Object { $_ -replace '\.exe$', '' })

    foreach ($k in $keys) {
        Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue | ForEach-Object {
            $dn = $_.GetValue('DisplayName')
            if (-not $dn) { return }
            $dnl = ([string]$dn).ToLowerInvariant() -replace '\s', ''
            $match = $names | Where-Object { $dnl.Contains(($_.ToLowerInvariant() -replace '\s', '')) } | Select-Object -First 1
            if (-not $match) { return }
            $inst = $_.GetValue('InstallDate')
            $instDate = $null
            if ($inst -match '^\d{8}$') { $instDate = [datetime]::ParseExact($inst, 'yyyyMMdd', $null) }
            $lvl = 2
            $reasons = @("matches '$match'")
            if ($instDate -and $instDate -ge $script:Since.Date) { $lvl = 3; $reasons += 'installed within window' }
            Add-Finding -Category $cat -Level $lvl -Item "$dn $($_.GetValue('DisplayVersion'))" `
                -Details (Join-Details ("Location: {0}" -f $_.GetValue('InstallLocation')) $reasons) `
                -Mitre 'T1219' -Timestamp (Format-Time $instDate)
        }
    }
}

function Test-RunningProcesses {
    $cat = 'Live: Suspicious processes'
    $conns = @{}
    try {
        Get-NetTCPConnection -State Established -ErrorAction Stop | ForEach-Object {
            if (-not (Test-PrivateAddress $_.RemoteAddress)) {
                $k = [int]$_.OwningProcess
                if (-not $conns.ContainsKey($k)) { $conns[$k] = New-Object System.Collections.Generic.List[string] }
                $conns[$k].Add("$($_.RemoteAddress):$($_.RemotePort)")
            }
        }
    } catch { Add-Note 'Processes' "Get-NetTCPConnection failed: $($_.Exception.Message)" }

    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    # exclude this checker and the processes that launched it
    $self = @{}
    $cur = $PID
    for ($i = 0; $i -lt 6 -and $cur; $i++) {
        $self[[int]$cur] = $true
        $parent = $procs | Where-Object { $_.ProcessId -eq $cur } | Select-Object -First 1
        $cur = if ($parent) { $parent.ParentProcessId } else { $null }
    }
    foreach ($p in $procs) {
        if ($self.ContainsKey([int]$p.ProcessId)) { continue }
        $cmd =if ($p.CommandLine) { $p.CommandLine } elseif ($p.ExecutablePath) { $p.ExecutablePath } else { $null }
        if (-not $cmd) { continue }
        $a = Get-CommandAssessment -Command $cmd -CheckSignature
        if ($a.Level -lt 2) { continue }
        $net = ''
        if ($conns.ContainsKey([int]$p.ProcessId)) { $net = ' | external connections: ' + (($conns[[int]$p.ProcessId] | Select-Object -Unique) -join ', ') }
        $c = if ($cmd.Length -gt 500) { $cmd.Substring(0, 500) + '...' } else { $cmd }
        Add-Finding -Category $cat -Level $a.Level -Item "$($p.Name) (PID $($p.ProcessId), PPID $($p.ParentProcessId))" `
            -Details ((Join-Details $c $a.Reasons) + $net) -Mitre 'T1059 / T1218' -Timestamp (Format-Time $p.CreationDate)
    }
}

function Test-SecurityConfiguration {
    $cat = 'Config: Security settings'
    $hklm = 'Registry::HKEY_LOCAL_MACHINE'

    $wd = Get-ItemProperty -LiteralPath "$hklm\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue
    if ($wd -and $wd.PSObject.Properties['UseLogonCredential'] -and $wd.UseLogonCredential -eq 1) {
        Add-Finding -Category $cat -Level 3 -Item 'WDigest UseLogonCredential = 1' -Details 'Cleartext credentials cached in LSASS (seen in Hive ransomware attacks)' -Mitre 'T1112 / T1003.001'
    }

    $ts = Get-ItemProperty -LiteralPath "$hklm\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
    $rdpOn = $ts -and $ts.fDenyTSConnections -eq 0
    if ($rdpOn) {
        $tcp = Get-ItemProperty -LiteralPath "$hklm\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue
        $nlaOff = $tcp -and $tcp.PSObject.Properties['UserAuthentication'] -and $tcp.UserAuthentication -eq 0
        $port = if ($tcp) { $tcp.PortNumber } else { '?' }
        $lvl = if ($nlaOff) { 2 } else { 1 }
        $d = "RDP enabled (port $port)" + $(if ($nlaOff) { '; NLA disabled (UserAuthentication=0, typical attacker rdp.bat)' } else { '' })
        Add-Finding -Category $cat -Level $lvl -Item 'Remote Desktop enabled' -Details $d -Mitre 'T1021.001'
    }

    $lsa = Get-ItemProperty -LiteralPath "$hklm\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue
    if ($lsa) {
        if ($lsa.PSObject.Properties['DisableRestrictedAdmin'] -and $lsa.DisableRestrictedAdmin -eq 0) {
            Add-Finding -Category $cat -Level 1 -Item 'RDP Restricted Admin enabled' -Details 'Enables pass-the-hash over RDP' -Mitre 'T1550.002'
        }
        if (-not ($lsa.PSObject.Properties['RunAsPPL'] -and $lsa.RunAsPPL -ge 1)) {
            Add-Finding -Category $cat -Level 0 -Item 'LSA protection (RunAsPPL) not enabled' -Details 'LSASS can be dumped by admin tools' -Mitre 'T1003.001'
        }
    }
    $pol = Get-ItemProperty -LiteralPath "$hklm\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue
    if ($pol -and $pol.PSObject.Properties['LocalAccountTokenFilterPolicy'] -and $pol.LocalAccountTokenFilterPolicy -eq 1) {
        Add-Finding -Category $cat -Level 2 -Item 'LocalAccountTokenFilterPolicy = 1' -Details 'Remote UAC filtering disabled (admin shares / PsExec with local accounts)' -Mitre 'T1021.002'
    }

    $pp = "$hklm\SYSTEM\CurrentControlSet\Services\PortProxy"
    Get-ChildItem -LiteralPath $pp -ErrorAction SilentlyContinue | ForEach-Object {
        $k = $_
        foreach ($v in $k.GetValueNames()) {
            Add-Finding -Category $cat -Level 2 -Item "netsh portproxy ($($k.PSChildName))" -Details "$v -> $($k.GetValue($v))" -Mitre 'T1090'
        }
    }

    try {
        foreach ($fp in Get-NetFirewallProfile -ErrorAction Stop) {
            if (-not $fp.Enabled) { Add-Finding -Category $cat -Level 2 -Item "Windows Firewall disabled ($($fp.Name) profile)" -Mitre 'T1562.004' }
        }
    } catch { Add-Note 'Firewall' $_.Exception.Message }

    foreach ($k in $script:Ioc.RegistryIocKeys) {
        if (Test-Path -LiteralPath "Registry::$k") {
            Add-Finding -Category 'IOC: Registry' -Level 3 -Item $k -Details 'Known ransomware registry artifact (REvil/Sodinokibi)' -Mitre 'T1112'
        }
    }
}

function Test-Defender {
    $cat = 'Defense evasion: Defender'
    $pol = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender'
    $p = Get-ItemProperty -LiteralPath $pol -ErrorAction SilentlyContinue
    if ($p -and $p.PSObject.Properties['DisableAntiSpyware'] -and $p.DisableAntiSpyware -eq 1) {
        Add-Finding -Category $cat -Level 3 -Item 'Policy DisableAntiSpyware = 1' -Details $pol -Mitre 'T1562.001'
    }
    $rtp = Get-ItemProperty -LiteralPath "$pol\Real-Time Protection" -ErrorAction SilentlyContinue
    if ($rtp) {
        foreach ($n in 'DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning') {
            if ($rtp.PSObject.Properties[$n] -and $rtp.$n -eq 1) {
                Add-Finding -Category $cat -Level 3 -Item "Policy $n = 1" -Details "$pol\Real-Time Protection (LockBit GPO / Registry.pol pattern)" -Mitre 'T1562.001'
            }
        }
    }
    $pex = "$pol\Exclusions"
    Get-ChildItem -LiteralPath $pex -ErrorAction SilentlyContinue | ForEach-Object {
        $k = $_
        foreach ($v in $k.GetValueNames()) { Add-Finding -Category $cat -Level 2 -Item "Policy exclusion ($($k.PSChildName))" -Details $v -Mitre 'T1562.001' }
    }

    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { Add-Note 'Defender' 'Defender cmdlets not available'; return }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        if (-not $st.RealTimeProtectionEnabled) { Add-Finding -Category $cat -Level 3 -Item 'Real-time protection is OFF' -Details 'May also be caused by a third-party AV' -Mitre 'T1562.001' }
        if (-not $st.AntivirusEnabled) { Add-Finding -Category $cat -Level 2 -Item 'Defender antivirus disabled' -Details 'Verify whether another AV is installed' -Mitre 'T1562.001' }
        if ($st.IsTamperProtected -eq $false) { Add-Finding -Category $cat -Level 1 -Item 'Tamper protection off' -Mitre 'T1562.001' }
    } catch { Add-Note 'Defender' "Get-MpComputerStatus: $($_.Exception.Message)" }
    try {
        $mp = Get-MpPreference -ErrorAction Stop
        if ($mp.DisableRealtimeMonitoring) { Add-Finding -Category $cat -Level 3 -Item 'DisableRealtimeMonitoring = True' -Details 'Set-MpPreference (as in the Kaseya/REvil attack script)' -Mitre 'T1562.001' }
        if ($mp.DisableIOAVProtection)     { Add-Finding -Category $cat -Level 3 -Item 'DisableIOAVProtection = True' -Mitre 'T1562.001' }
        if ($mp.DisableScriptScanning)     { Add-Finding -Category $cat -Level 2 -Item 'DisableScriptScanning = True' -Mitre 'T1562.001' }
        foreach ($t in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
            foreach ($v in @($mp.$t)) {
                if (-not $v) { continue }
                if ($v -like 'N/A*') { Add-Note 'Defender' 'Exclusions hidden - run as administrator'; continue }
                $lvl = 2
                if ($v -match '(?i)^[a-z]:\\?$|\\users\\public|\\programdata\\?$|\\temp|\\perflogs|^\.?(exe|dll|ps1|bat)$') { $lvl = 3 }
                Add-Finding -Category $cat -Level $lvl -Item "Defender $t" -Details $v -Mitre 'T1562.001'
            }
        }
    } catch { Add-Note 'Defender' "Get-MpPreference: $($_.Exception.Message)" }
}

function Test-RecoveryInhibition {
    $cat = 'Impact: System recovery'
    try {
        $sc = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop)
        if ($sc.Count -eq 0) {
            Add-Finding -Category $cat -Level 1 -Item 'No volume shadow copies' -Details 'Deleted (vssadmin/wmic shadowcopy delete) or never enabled' -Mitre 'T1490'
        } else {
            $latest = ($sc | Sort-Object InstallDate -Descending | Select-Object -First 1).InstallDate
            Add-Finding -Category $cat -Level 0 -Item "$($sc.Count) shadow copies present" -Details "Newest: $(Format-Time $latest) - preserve them!" -Mitre 'T1490'
        }
    } catch { Add-Note 'Shadow copies' $_.Exception.Message }

    $vss = Get-CimInstance -ClassName Win32_Service -Filter "Name='VSS'" -ErrorAction SilentlyContinue
    if ($vss -and $vss.StartMode -eq 'Disabled') { Add-Finding -Category $cat -Level 2 -Item 'VSS service disabled' -Mitre 'T1490' }

    if ($script:IsAdmin) {
        try {
            $bcd = (& bcdedit.exe /enum '{current}' 2>$null) -join "`n"
            if ($bcd -match '(?im)^recoveryenabled\s+(No|Ne|Nein|Non)\s*$') {
                Add-Finding -Category $cat -Level 3 -Item 'Boot recovery disabled (recoveryenabled No)' -Details 'bcdedit /set {default} recoveryenabled No' -Mitre 'T1490'
            }
            if ($bcd -match '(?im)^bootstatuspolicy\s+IgnoreAllFailures') {
                Add-Finding -Category $cat -Level 3 -Item 'bootstatuspolicy IgnoreAllFailures' -Details 'bcdedit /set {default} bootstatuspolicy ignoreallfailures' -Mitre 'T1490'
            }
        } catch { Add-Note 'bcdedit' $_.Exception.Message }
    }
}

function Test-LocalAccounts {
    $cat = 'Persistence: Accounts'
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.Name) ($($_.PrincipalSource))" })
        Add-Finding -Category $cat -Level 0 -Item 'Local Administrators members' -Details ($admins -join ', ') -Mitre 'T1078'
    } catch {
        $raw = (& net.exe localgroup administrators 2>$null) -join '; '
        Add-Finding -Category $cat -Level 0 -Item 'Local Administrators members (net)' -Details $raw -Mitre 'T1078'
    }
    try {
        foreach ($u in Get-LocalUser -ErrorAction Stop) {
            if ($u.Enabled -and $u.SID.Value -match '-501$') {
                Add-Finding -Category $cat -Level 2 -Item "Guest account enabled ($($u.Name))" -Mitre 'T1078.001'
            }
            if ($u.Enabled -and $u.PasswordLastSet -and $u.PasswordLastSet -ge $script:Since) {
                Add-Finding -Category $cat -Level 1 -Item "Local user '$($u.Name)' password set within window" `
                    -Details "Possibly a newly created account (T1136). LastLogon: $(Format-Time $u.LastLogon)" -Mitre 'T1136.001' -Timestamp (Format-Time $u.PasswordLastSet)
            }
        }
    } catch { Add-Note 'Local users' $_.Exception.Message }
}

#endregion

#region ---------------------------------------------------------------- checks: event logs

function Test-EventLogs {
    $sev = 'Events'

    # Log clearing (T1070.001)
    foreach ($e in Get-EventsXPath 'Security' (Get-XPathWindow 1102) 200) {
        $d = Get-EventDataMap $e
        Add-Finding -Category "$($sev): Log cleared" -Level 3 -Item 'Security log cleared (1102)' -Details "By $($d['SubjectDomainName'])\$($d['SubjectUserName'])" `
            -Mitre 'T1070.001' -Timestamp (Format-Time $e.TimeCreated)
    }
    foreach ($e in Get-EventsXPath 'System' (Get-XPathWindow 104) 200) {
        $d = Get-EventDataMap $e
        Add-Finding -Category "$($sev): Log cleared" -Level 3 -Item "Event log cleared (104): $($d['Channel'])" -Details "By $($d['SubjectDomainName'])\$($d['SubjectUserName'])" `
            -Mitre 'T1070.001' -Timestamp (Format-Time $e.TimeCreated)
    }

    # New services (7045) - PsExec, Cobalt Strike, ransomware deployment
    foreach ($e in Get-EventsXPath 'System' (Get-XPathWindow 7045) 1000) {
        $d = Get-EventDataMap $e
        $a = Get-CommandAssessment -Command $d['ImagePath']
        $lvl = [Math]::Max($a.Level, 1)
        $reasons = @($a.Reasons)
        if ($d['ImagePath'] -match '(?i)(%comspec%|cmd(\.exe)?\s+/[bc]|powershell)') { $lvl = 3; $reasons += 'shell command as service' }
        if (($d['ServiceName'] -match '^(PSEXESVC|PAEXEC)') -or ($d['ImagePath'] -match '\\\\127\.0\.0\.1\\ADMIN\$')) {
            $lvl = [Math]::Max($lvl, 2); $reasons += 'remote execution service'
        }
        Add-Finding -Category "$($sev): Service installed (7045)" -Level $lvl -Item $d['ServiceName'] `
            -Details (Join-Details ("{0} (Account: {1}; Start: {2})" -f $d['ImagePath'], $d['AccountName'], $d['StartType']) $reasons) `
            -Mitre 'T1543.003 / T1569.002' -Timestamp (Format-Time $e.TimeCreated)
    }

    # Account creation / group membership
    foreach ($e in Get-EventsXPath 'Security' (Get-XPathWindow 4720, 4732, 4728, 4756) 500) {
        $d = Get-EventDataMap $e
        if ($e.Id -eq 4720) {
            Add-Finding -Category "$($sev): Accounts" -Level 2 -Item "Account created: $($d['TargetDomainName'])\$($d['TargetUserName'])" `
                -Details "By $($d['SubjectDomainName'])\$($d['SubjectUserName'])" -Mitre 'T1136' -Timestamp (Format-Time $e.TimeCreated)
        } else {
            $grp = $d['TargetUserName']
            $lvl = if ($grp -match '(?i)admin|Domain Admins|Enterprise|Schema|Remote Desktop') { 2 } else { 1 }
            Add-Finding -Category "$($sev): Accounts" -Level $lvl -Item "Member added to '$grp' ($($e.Id))" `
                -Details "Member: $($d['MemberName']) $($d['MemberSid']); by $($d['SubjectDomainName'])\$($d['SubjectUserName'])" `
                -Mitre 'T1098' -Timestamp (Format-Time $e.TimeCreated)
        }
    }

    # RDP brute force (4625) and RDP logons (4624 type 10, LSM 21/25)
    $ms = [long]$DaysBack * 86400000
    $fails = Get-EventsXPath 'Security' "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $ms]]]" 50000
    if ($fails.Count -gt 0) {
        $byIp = $fails | ForEach-Object { $d = Get-EventDataMap $_; [pscustomobject]@{ Ip = $d['IpAddress']; User = $d['TargetUserName']; Time = $_.TimeCreated } } |
            Group-Object Ip
        foreach ($g in $byIp) {
            if ($g.Count -lt [int]$script:Ioc.BruteForceThreshold) { continue }
            $lvl = if (Test-PrivateAddress $g.Name) { 2 } else { 3 }
            $users = ($g.Group | Group-Object User | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ', '
            $first = ($g.Group | Sort-Object Time | Select-Object -First 1).Time
            $last  = ($g.Group | Sort-Object Time | Select-Object -Last 1).Time
            Add-Finding -Category "$($sev): Brute force (4625)" -Level $lvl -Item "$($g.Count) failed logons from $($g.Name)" `
                -Details "Accounts: $users; $(Format-Time $first) - $(Format-Time $last)" -Mitre 'T1110 / T1133' -Timestamp (Format-Time $first)
        }
    }

    $rdp = @{}
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]] and EventData[Data[@Name='LogonType']='10']]"
    foreach ($e in Get-EventsXPath 'Security' $xp 5000) {
        $d = Get-EventDataMap $e
        $key = "$($d['IpAddress'])|$($d['TargetDomainName'])\$($d['TargetUserName'])"
        if (-not $rdp.ContainsKey($key)) { $rdp[$key] = [pscustomobject]@{ Ip = $d['IpAddress']; User = "$($d['TargetDomainName'])\$($d['TargetUserName'])"; Count = 0; First = $e.TimeCreated; Last = $e.TimeCreated; Src = '4624/10' } }
        $o = $rdp[$key]; $o.Count++; if ($e.TimeCreated -lt $o.First) { $o.First = $e.TimeCreated }; if ($e.TimeCreated -gt $o.Last) { $o.Last = $e.TimeCreated }
    }
    foreach ($e in Get-EventsXPath 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' (Get-XPathWindow 21, 25) 5000) {
        $d = Get-EventDataMap $e
        $key = "$($d['Address'])|$($d['User'])"
        if (-not $rdp.ContainsKey($key)) { $rdp[$key] = [pscustomobject]@{ Ip = $d['Address']; User = $d['User']; Count = 0; First = $e.TimeCreated; Last = $e.TimeCreated; Src = 'LSM 21/25' } }
        $o = $rdp[$key]; $o.Count++; if ($e.TimeCreated -lt $o.First) { $o.First = $e.TimeCreated }; if ($e.TimeCreated -gt $o.Last) { $o.Last = $e.TimeCreated }
    }
    foreach ($o in $rdp.Values) {
        if ($o.Ip -in @('LOCAL', '', $null)) { continue }
        $lvl = if (Test-PrivateAddress $o.Ip) { 0 } else { 3 }
        Add-Finding -Category "$($sev): RDP logons" -Level $lvl -Item "RDP $($o.User) from $($o.Ip)" `
            -Details "$($o.Count)x ($($o.Src)); first $(Format-Time $o.First), last $(Format-Time $o.Last)" -Mitre 'T1021.001 / T1133' -Timestamp (Format-Time $o.First)
    }

    # Defender detections and tampering
    $dlog = 'Microsoft-Windows-Windows Defender/Operational'
    $detections = [ordered]@{}
    foreach ($e in Get-EventsXPath $dlog (Get-XPathWindow 1006, 1116, 1117, 5001, 5007, 5010, 5012) 1000) {
        $d = Get-EventDataMap $e
        switch ($e.Id) {
            { $_ -in 1006, 1116, 1117 } {
                $key = "$($d['Threat Name'])|$(($d['Path'] -split ';')[0])"
                if (-not $detections.Contains($key)) {
                    $detections[$key] = [pscustomobject]@{ Threat = $d['Threat Name']; Path = $d['Path']; Actions = New-Object System.Collections.Generic.List[string]; User = $d['Detection User']; First = $e.TimeCreated; Count = 0 }
                }
                $o = $detections[$key]; $o.Count++
                if ($e.TimeCreated -lt $o.First) { $o.First = $e.TimeCreated }
                if ($d['Action Name'] -and -not $o.Actions.Contains($d['Action Name'])) { $o.Actions.Add($d['Action Name']) }
            }
            { $_ -in 5001, 5010, 5012 } {
                Add-Finding -Category "$($sev): Defender" -Level 3 -Item "Protection disabled ($($e.Id))" -Details ($e.Message -split "`n")[0] -Mitre 'T1562.001' -Timestamp (Format-Time $e.TimeCreated)
            }
            5007 {
                $msg = [string]$e.Message
                if ($msg -match '(?i)Exclusions|DisableRealtimeMonitoring|DisableAntiSpyware|DisableIOAV|DisableBehavior') {
                    $short = ($msg -replace '\s+', ' ')
                    if ($short.Length -gt 400) { $short = $short.Substring(0, 400) + '...' }
                    Add-Finding -Category "$($sev): Defender" -Level 2 -Item 'Defender configuration changed (5007)' -Details $short -Mitre 'T1562.001' -Timestamp (Format-Time $e.TimeCreated)
                }
            }
        }
    }

    foreach ($o in $detections.Values) {
        Add-Finding -Category "$($sev): Defender" -Level 3 -Item "Detection: $($o.Threat)" `
            -Details "$($o.Path) | actions: $($o.Actions -join ', ') | user: $($o.User) | events: $($o.Count)" -Mitre 'detection' -Timestamp (Format-Time $o.First)
    }

    # PowerShell
    $ownScript = $PSCommandPath
    $seenBlocks = @{}
    $moduleDirs = '(?i)^(' + [regex]::Escape("$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules") + '|' +
                  [regex]::Escape("$env:ProgramFiles\WindowsPowerShell\Modules") + ')\\'
    foreach ($e in Get-EventsXPath 'Microsoft-Windows-PowerShell/Operational' (Get-XPathWindow 4104) 5000) {
        $d = Get-EventDataMap $e
        $blockPath = [string]$d['Path']
        if ($ownScript -and $blockPath -eq $ownScript) { continue }
        if ($blockPath -match $moduleDirs) { continue }              # built-in / installed modules (e.g. Defender cmdlets)
        $text = [string]$d['ScriptBlockText']
        if ($text.Contains('Get-CommandAssessment')) { continue }    # this checker's own code
        $id = $d['ScriptBlockId']
        if ($id -and $seenBlocks.ContainsKey($id)) { continue }
        if ($id) { $seenBlocks[$id] = $true }
        $hits = Find-Keywords $text
        if ($hits.Count -eq 0) { continue }
        $short = ($text -replace '\s+', ' ')
        if ($short.Length -gt 500) { $short = $short.Substring(0, 500) + '...' }
        $where = if ($blockPath) { "[$blockPath] " } else { '' }
        Add-Finding -Category "$($sev): PowerShell 4104" -Level 3 -Item "Script block matched: $($hits -join ', ')" -Details ($where + $short) `
            -Mitre 'T1059.001' -Timestamp (Format-Time $e.TimeCreated)
    }
    # Windows PowerShell engine start (400) - one finding per unique host command line
    $hostApps = @{}
    foreach ($e in Get-EventsXPath 'Windows PowerShell' (Get-XPathWindow 400) 5000) {
        $m = [regex]::Match([string]$e.Message, '(?im)HostApplication=(.+)$')
        if (-not $m.Success) { continue }
        $hostApp = $m.Groups[1].Value.Trim()
        if ($ownScript -and $hostApp -like "*$ownScript*") { continue }
        if (-not $hostApps.ContainsKey($hostApp)) { $hostApps[$hostApp] = [pscustomobject]@{ First = $e.TimeCreated; Last = $e.TimeCreated; Count = 0 } }
        $o = $hostApps[$hostApp]; $o.Count++
        if ($e.TimeCreated -lt $o.First) { $o.First = $e.TimeCreated }
        if ($e.TimeCreated -gt $o.Last) { $o.Last = $e.TimeCreated }
    }
    foreach ($hostApp in $hostApps.Keys) {
        $hits = Find-Keywords $hostApp
        $a = Get-CommandAssessment -Command $hostApp
        if ($hits.Count -eq 0 -and $a.Behaviour -lt 2) { continue }
        $o = $hostApps[$hostApp]
        $short = if ($hostApp.Length -gt 600) { $hostApp.Substring(0, 600) + '...' } else { $hostApp }
        Add-Finding -Category "$($sev): PowerShell host (400)" -Level ([Math]::Max($a.Level, 2)) -Item "PowerShell started $($o.Count)x" `
            -Details (Join-Details ("{0}  (first {1}, last {2})" -f $short, (Format-Time $o.First), (Format-Time $o.Last)) (@($a.Reasons) + $hits)) `
            -Mitre 'T1059.001' -Timestamp (Format-Time $o.First)
    }

    # Scheduled task registration
    foreach ($e in Get-EventsXPath 'Microsoft-Windows-TaskScheduler/Operational' (Get-XPathWindow 106) 1000) {
        $d = Get-EventDataMap $e
        if ($d['TaskName'] -like '\Microsoft\*') { continue }
        Add-Finding -Category "$($sev): Task registered (106)" -Level 1 -Item $d['TaskName'] -Details "User: $($d['UserContext'])" `
            -Mitre 'T1053.005' -Timestamp (Format-Time $e.TimeCreated)
    }

    # Firewall rule changes (Remote Desktop enabled via netsh)
    foreach ($e in Get-EventsXPath 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' (Get-XPathWindow 2004, 2005, 2097, 2099) 2000) {
        $msg = [string]$e.Message
        if ($msg -notmatch '(?i)remote ?desktop|netsh\.exe|powershell') { continue }
        $d = Get-EventDataMap $e
        Add-Finding -Category "$($sev): Firewall rule change" -Level 2 -Item "$($d['RuleName']) ($($e.Id))" `
            -Details "Modifying app: $($d['ModifyingApplication']); user SID: $($d['ModifyingUser'])" -Mitre 'T1562.004 / T1021.001' -Timestamp (Format-Time $e.TimeCreated)
    }
}

#endregion

#region ---------------------------------------------------------------- checks: execution artifacts & files

function Test-Prefetch {
    $cat = 'Execution: Prefetch'
    $pf = Join-Path $env:SystemRoot 'Prefetch'
    $files = @(Get-ChildItem -LiteralPath $pf -Filter '*.pf' -ErrorAction Stop)
    foreach ($f in $files) {
        $exe = ($f.Name -replace '-[0-9A-F]{8}\.pf$', '').ToLowerInvariant()
        $hit = $null; $lvl = 0
        # names with an extension (ns.exe, sk.exe, 7za.exe) must match exactly; bare names (mimikatz, adfind) may be substrings
        $matchName = {
            param($exeName, $toolName)
            $t = ($toolName.ToLowerInvariant() -replace '\s', '')
            if ($t -match '\.(exe|dll)$') { return ($exeName -eq $t) }
            if ($t -match '\.') { return $false }
            return ($exeName -eq "$t.exe" -or ($t.Length -ge 5 -and $exeName.Contains($t)))
        }
        foreach ($n in $script:Ioc.AttackerTools) { if (& $matchName $exe $n) { $hit = $n; $lvl = 3; break } }
        if (-not $hit) { foreach ($n in (@($script:Ioc.DualUseTools) + @($script:Ioc.RemoteAccessTools))) { if (& $matchName $exe $n) { $hit = $n; $lvl = 2; break } } }
        if ($exe -match '^\.' ) { $hit = 'executable name starts with dot (Crylock .cr_hand.exe)'; $lvl = 3 }
        if (-not $hit -or $lvl -lt 1) { continue }
        Add-Finding -Category $cat -Level $lvl -Item $f.Name -Details "Executed (evidence of execution even if binary deleted) - matches '$hit'. Last run ~ $(Format-Time $f.LastWriteTime)" `
            -Mitre 'execution' -Timestamp (Format-Time $f.LastWriteTime)
    }
}

function Test-UserAssistAndBam {
    $cat = 'Execution: UserAssist / BAM'
    foreach ($h in Get-UserHives) {
        $ua = "$($h.Root)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        Get-ChildItem -LiteralPath $ua -ErrorAction SilentlyContinue | ForEach-Object {
            $k = Get-Item -LiteralPath (Join-Path $_.PSPath 'Count') -ErrorAction SilentlyContinue
            if (-not $k) { return }
            foreach ($vn in $k.GetValueNames()) {
                $name = ConvertFrom-Rot13 $vn
                $data = $k.GetValue($vn)
                $last = $null; $runs = ''
                if ($data -is [byte[]] -and $data.Length -ge 68) {
                    $runs = [BitConverter]::ToInt32($data, 4)
                    $ft = [BitConverter]::ToInt64($data, 60)
                    if ($ft -gt 0) { try { $last = [DateTime]::FromFileTime($ft) } catch { } }
                }
                $a = Get-CommandAssessment -Command $name
                $lvl = $a.Level
                if ($name -match '(?i)\\\.[^\\]+\.exe$') { $lvl = 3 }
                # location-only hits (e.g. installers run from Temp) are reported only inside the time window
                if ($a.Behaviour -lt 2 -and $lvl -lt 3 -and -not ($last -and $last -ge $script:Since)) { continue }
                if ($lvl -lt 2) { continue }
                Add-Finding -Category $cat -Level $lvl -Item "UserAssist ($($h.Name)): $name" -Details (Join-Details "run count: $runs" ($a.Reasons | Where-Object { $_ -notlike 'target missing*' })) `
                    -Mitre 'execution' -Timestamp (Format-Time $last)
            }
        }
    }

    foreach ($bam in @('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
                       'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
        Get-ChildItem -LiteralPath $bam -ErrorAction SilentlyContinue | ForEach-Object {
            $sidKey = $_
            $user = $sidKey.PSChildName
            try { $user = (New-Object Security.Principal.SecurityIdentifier $user).Translate([Security.Principal.NTAccount]).Value } catch { }
            foreach ($vn in $sidKey.GetValueNames()) {
                if ($vn -notmatch '^\\Device\\') { continue }
                $path = $vn -replace '^\\Device\\HarddiskVolume\d+', $env:SystemDrive
                $data = $sidKey.GetValue($vn)
                $last = $null
                if ($data -is [byte[]] -and $data.Length -ge 8) { try { $last = [DateTime]::FromFileTime([BitConverter]::ToInt64($data, 0)) } catch { } }
                $a = Get-CommandAssessment -Command "`"$path`""
                $lvl = $a.Level
                $reasons = @($a.Reasons | Where-Object { $_ -notlike 'target missing*' })
                $recent = $last -and $last -ge $script:Since
                if ($a.Level -ge 1 -and @($a.Reasons | Where-Object { $_ -like 'target missing*' }).Count -gt 0 -and $recent) {
                    $reasons += 'binary no longer present (deleted after use?)'; $lvl = [Math]::Max($lvl, 2)
                }
                if ($a.Behaviour -lt 2 -and -not $recent) { continue }
                if ($lvl -lt 2) { continue }
                Add-Finding -Category $cat -Level $lvl -Item "BAM ($user): $path" -Details (Join-Details 'last execution (volume mapped to system drive - verify)' $reasons) `
                    -Mitre 'execution' -Timestamp (Format-Time $last)
            }
        }
    }
}

function Test-PowerShellHistory {
    $cat = 'Execution: PSReadLine history'
    foreach ($u in Get-UserProfileDirs) {
        $hist = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (-not (Test-Path -LiteralPath $hist)) { continue }
        $n = 0
        $lineNo = 0
        foreach ($line in Get-Content -LiteralPath $hist -ErrorAction SilentlyContinue) {
            $lineNo++
            $hits = Find-Keywords $line
            $hit = Test-NameList $line.ToLowerInvariant() $script:Ioc.AttackerTools
            if ($hits.Count -eq 0 -and -not $hit) { continue }
            $n++
            if ($n -gt 50) { Add-Note 'PSReadLine' "More than 50 hits in $hist - review the file manually"; break }
            Add-Finding -Category $cat -Level 3 -Item "$($u.Name) line $lineNo" -Details (Join-Details $line (@($hits) + @($hit))) `
                -Mitre 'T1059.001' -Timestamp (Format-Time (Get-Item -LiteralPath $hist).LastWriteTime)
        }
    }
}

function Test-ExfilArtifacts {
    $cat = 'Exfiltration: tool artifacts'
    foreach ($u in Get-UserProfileDirs) {
        foreach ($rel in 'AppData\Roaming\rclone\rclone.conf', '.config\rclone\rclone.conf') {
            $f = Join-Path $u.FullName $rel
            if (Test-Path -LiteralPath $f) {
                $remotes = (Select-String -LiteralPath $f -Pattern '^\s*(\[.+\]|type\s*=.*|user\s*=.*)' -ErrorAction SilentlyContinue | ForEach-Object { $_.Line.Trim() }) -join ' '
                Add-Finding -Category $cat -Level 3 -Item $f -Details "Rclone configuration: $remotes" -Mitre 'T1567.002' -Timestamp (Format-Time (Get-Item -LiteralPath $f).LastWriteTime)
            }
        }
        $mega = Join-Path $u.FullName 'AppData\Local\Mega Limited\MEGAsync'
        if (Test-Path -LiteralPath $mega) {
            $log = Get-ChildItem -LiteralPath $mega -Recurse -Filter 'MEGAsync*.log' -ErrorAction SilentlyContinue | Select-Object -First 1
            $acc = ''
            if ($log) { $acc = (Select-String -LiteralPath $log.FullName -Pattern '"user":"([^"]+)"' -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object { $_.Matches[0].Groups[1].Value }) }
            Add-Finding -Category $cat -Level 2 -Item $mega -Details "MEGAsync data present (used by Nefilim affiliates). Account: $acc. Review logs for 'Adding file to upload queue'." -Mitre 'T1567.002'
        }
    }
}

function Test-GpoDeployment {
    $cat = 'Deployment: Group Policy (DC)'
    $sysvol = Join-Path $env:SystemRoot 'SYSVOL\domain'
    if (-not (Test-Path -LiteralPath $sysvol)) { Add-Note 'GPO' 'Not a domain controller (no SYSVOL) - skipped'; return }
    Get-ChildItem -LiteralPath (Join-Path $sysvol 'Policies') -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('ScheduledTasks.xml', 'Files.xml', 'Services.xml', 'Registry.pol', 'NetworkShares.xml', 'scripts.ini', 'psscripts.ini') -and $_.LastWriteTime -ge $script:Since } |
        ForEach-Object {
            $content = ''
            if ($_.Extension -ne '.pol') { try { $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop } catch { } }
            $hits = Find-Keywords $content
            $lvl = if ($_.Name -in @('ScheduledTasks.xml', 'Files.xml') -or $hits.Count -gt 0 -or $content -match '(?i)taskkill|\.exe') { 3 } else { 2 }
            Add-Finding -Category $cat -Level $lvl -Item $_.FullName -Details (Join-Details 'GPO component modified within window (LockBit GPO deployment)' $hits) `
                -Mitre 'T1484.001' -Timestamp (Format-Time $_.LastWriteTime)
        }
    Get-ChildItem -LiteralPath (Join-Path $sysvol 'scripts') -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '^\.(exe|dll|bat|cmd|ps1|vbs|js)$' } | ForEach-Object {
            $lvl = if ($_.Extension -in '.exe', '.dll') { 3 } else { 1 }
            if ($_.LastWriteTime -ge $script:Since) { $lvl = [Math]::Max($lvl, 2) }
            Add-Finding -Category $cat -Level $lvl -Item $_.FullName -Details "SHA256 $(Get-FileSha256 $_.FullName)" -Mitre 'T1484.001' -Timestamp (Format-Time $_.LastWriteTime)
        }
}

function Test-StagingFolders {
    $cat = 'Files: Staging folders & tools'
    $execExt = '^\.(exe|dll|scr|com|msi)$'
    $scriptExt = '^\.(bat|cmd|ps1|psm1|vbs|vbe|js|jse|hta|wsf)$'
    $skipNames = @('pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'dumpstack.log', 'dumpstack.log.tmp')
    $ownRoot = $script:Root.TrimEnd('\') + '\'
    # Mode: staging = classic attacker drop folders, temp = noisy temp folders, user = user content (names/scripts only)
    $targets = New-Object System.Collections.Generic.List[object]
    $targets.Add(@{ Path = $env:ProgramData;                Depth = 0; Mode = 'staging' })
    $targets.Add(@{ Path = "$env:SystemDrive\Users\Public"; Depth = 3; Mode = 'staging' })
    $targets.Add(@{ Path = "$env:SystemDrive\PerfLogs";     Depth = 3; Mode = 'staging' })
    $targets.Add(@{ Path = "$env:SystemRoot\Temp";          Depth = 1; Mode = 'temp' })
    $targets.Add(@{ Path = "$env:SystemDrive\";             Depth = 0; Mode = 'staging' })
    $targets.Add(@{ Path = $env:SystemRoot;                 Depth = 0; Mode = 'staging' })
    foreach ($u in Get-UserProfileDirs) {
        $targets.Add(@{ Path = (Join-Path $u.FullName 'AppData\Local\Temp'); Depth = 1; Mode = 'temp' })
        $targets.Add(@{ Path = (Join-Path $u.FullName 'AppData\Roaming');    Depth = 0; Mode = 'staging' })
        foreach ($sub in 'Desktop', 'Downloads', 'Documents', 'Pictures', 'Music', 'Videos') {
            $targets.Add(@{ Path = (Join-Path $u.FullName $sub); Depth = 3; Mode = 'user' })
        }
    }
    $allTools = @($script:Ioc.AttackerTools)
    $otherTools = @($script:Ioc.DualUseTools) + @($script:Ioc.RemoteAccessTools)

    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t.Path)) { continue }
        $files = Get-ChildItem -LiteralPath $t.Path -File -Force -Recurse -Depth $t.Depth -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            if ($f.FullName.StartsWith($ownRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $nameL = $f.Name.ToLowerInvariant()
            if ($skipNames -contains $nameL) { continue }
            $ext = $f.Extension.ToLowerInvariant()
            $isExec = $ext -match $execExt
            $isScript = $ext -match $scriptExt
            $lvl = 0
            $reasons = New-Object System.Collections.Generic.List[string]

            $hit = Test-NameList ('\' + $nameL) $allTools
            if ($hit) { $lvl = 3; $reasons.Add("attacker tool name '$hit'") }
            elseif ($isExec -or $isScript -or $ext -eq '.zip' -or $ext -eq '.7z' -or $ext -eq '.rar') {
                $hit2 = Test-NameList ('\' + $nameL) $otherTools
                if (-not $hit2) { foreach ($r in $script:Ioc.RemoteAccessTools) { if ($nameL.Contains($r.ToLowerInvariant())) { $hit2 = $r; break } } }
                if ($hit2) { $lvl = 2; $reasons.Add("dual-use / remote tool '$hit2'") }
            }
            if ($nameL -match '^\.[^.]+\.exe$') { $lvl = 3; $reasons.Add('dot-prefixed executable (Crylock pattern)') }
            if ($ext -in '.dmp', '.dit' -and $nameL -match 'lsass|ntds') { $lvl = 3; $reasons.Add('credential dump') }
            if ($nameL -in @('ad_users.txt', 'ad_computers.txt', 'ad_group.txt', 'trustdmp.txt', 'subnets.txt', 'ad_ous.txt', 'domainlist.txt', 'allwindows.csv', 'hashes.txt', 'ips.txt', 'comps.txt', 'list.txt')) {
                $lvl = [Math]::Max($lvl, 3); $reasons.Add('AdFind / recon / target-list output name')
            }

            if ($isScript -and $f.Length -lt 2MB) {
                $content = ''
                try { $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { }
                $kw = Find-Keywords $content
                if ($kw.Count -gt 0) {
                    # attacker-like commands in a drop folder are High; in user documents they may be admin scripts
                    $lvl = [Math]::Max($lvl, $(if ($t.Mode -eq 'user') { 2 } else { 3 }))
                    $reasons.Add('script content: ' + ($kw -join ', '))
                }
                elseif ($t.Mode -eq 'staging') { $lvl = [Math]::Max($lvl, 2); $reasons.Add('script in staging folder') }
            }
            if ($isExec -and $t.Mode -in 'staging', 'temp' -and $lvl -lt 2) {
                $sig = Get-SignatureInfo $f.FullName
                if (-not $sig.Valid) {
                    # unsigned DLLs in Temp are common (Java/JNA, installers) -> Low; elsewhere Medium
                    $minLvl = if ($t.Mode -eq 'temp' -and $ext -eq '.dll') { 1 } else { 2 }
                    $lvl = [Math]::Max($lvl, $minLvl); $reasons.Add('unsigned binary')
                } elseif ($f.CreationTime -ge $script:Since -and $t.Mode -eq 'staging') {
                    $lvl = [Math]::Max($lvl, 1); $reasons.Add("signed ($($sig.Signer)), created within window")
                }
            }
            if ($lvl -ge 1 -and $f.CreationTime -ge $script:Since) { $reasons.Add('created within window') }
            if ($lvl -lt 1) { continue }

            $hash = ''
            if ($lvl -ge 2 -and ($isExec -or $isScript)) { $hash = " SHA256 $(Get-FileSha256 $f.FullName)" }
            Add-Finding -Category $cat -Level $lvl -Item $f.FullName `
                -Details (Join-Details ("{0:N0} B; created {1}; modified {2};{3}" -f $f.Length, (Format-Time $f.CreationTime), (Format-Time $f.LastWriteTime), $hash) $reasons) `
                -Mitre 'T1105 / T1074' -Timestamp (Format-Time $f.CreationTime)
        }
    }
}

function Test-RansomNotes {
    $cat = 'Impact: Ransom notes'
    $roots = @(@{ Path = "$env:SystemDrive\"; Depth = 1 }, @{ Path = "$env:SystemDrive\Users"; Depth = 3 })
    $found = New-Object System.Collections.Generic.List[object]
    $ownRoot = $script:Root.TrimEnd('\') + '\'
    foreach ($r in $roots) {
        Get-ChildItem -LiteralPath $r.Path -File -Force -Recurse -Depth $r.Depth -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Extension -notmatch '^\.(txt|hta|html?|rtf|url)$') { return }
            if ($_.FullName.StartsWith($ownRoot, [StringComparison]::OrdinalIgnoreCase)) { return }
            $n = $_.Name
            foreach ($p in $script:Ioc.RansomNotePatterns) { if ($n -like $p) { $found.Add($_); break } }
        }
    }
    foreach ($g in ($found | Sort-Object FullName -Unique | Group-Object Name)) {
        $first = $g.Group | Sort-Object CreationTime | Select-Object -First 1
        $sample = ($g.Group | Select-Object -First 3 | ForEach-Object { $_.FullName }) -join ' | '
        $lvl = if ($g.Count -ge 3) { 3 } else { 2 }
        Add-Finding -Category $cat -Level $lvl -Item "$($g.Name) ($($g.Count)x)" `
            -Details "Earliest: $($first.FullName) @ $(Format-Time $first.CreationTime) - use as pivot point for the MFT timeline. Samples: $sample" `
            -Mitre 'T1486' -Timestamp (Format-Time $first.CreationTime)
    }
}

#endregion

#region ---------------------------------------------------------------- reporting

function Get-DocumentStyle {
    # Shared look of report.html and remediation.html (retro black & white, monospace)
    return @'
body{font-family:Consolas,'Courier New',monospace;margin:24px auto;max-width:1100px;padding:0 16px;background:#000;color:#c8c8c8;line-height:1.5;font-size:14px}
h1{color:#dedede;margin-bottom:4px;text-transform:uppercase;letter-spacing:2px}h2{color:#dedede;border-bottom:2px solid #c8c8c8;padding-bottom:4px;margin-top:30px;text-transform:uppercase;letter-spacing:1px}
h3{margin:0 0 8px;color:#dedede}.sub{color:#828282;margin-bottom:12px}
.note{border:1px dashed #c8c8c8;color:#dedede;padding:8px 12px;margin:14px 0}
li{margin:4px 0;font-size:13px}.cat{background:#000;border:1px solid #c8c8c8;padding:12px 16px;margin:12px 0}
.lbl{color:#828282;font-size:12px;text-transform:uppercase;margin:8px 0 2px}.cnt{color:#828282;font-weight:normal}
ul.items{list-style:none;padding-left:0}code{color:#dedede;word-break:break-all;font-family:inherit}
.badge{display:inline-block;padding:0 8px;font-size:11px;font-weight:700;border:1px solid #c8c8c8;text-transform:uppercase}
.High{color:#000;background:#cdcdcd;border-color:#cdcdcd}.Medium{color:#dedede;background:#4b4b4b;border-color:#dedede}.Low{color:#b4b4b4;background:#262626;border-color:#828282}.Info{color:#828282;background:#121212;border-color:#4b4b4b}
.footer{color:#828282;font-size:12px;margin-top:30px;border-top:1px dashed #4b4b4b;padding-top:8px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:14px 0}
.chip{cursor:pointer;padding:2px 12px;border:1px solid;font-size:13px;font-weight:700;user-select:none}
.chip.off{color:#4b4b4b;background:transparent;border-color:#4b4b4b;text-decoration:line-through}
#q{margin-left:auto;padding:5px 10px;width:300px;background:#000;color:#dedede;border:1px solid #c8c8c8;font-family:inherit}
details.f{border-top:1px dashed #464646;padding:6px 0}details.f:first-of-type{border-top:none}
details.f summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline}
details.f summary::-webkit-details-marker{display:none}
details.f summary::before{content:'+';color:#828282;width:10px}details.f[open] summary::before{content:'-'}
details.f summary code{flex:1}.time{color:#828282;font-size:12px;white-space:nowrap}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;margin:10px 0 6px 20px;padding-left:12px;border-left:2px solid #c8c8c8}
dt{color:#828282;font-size:12px;text-transform:uppercase;font-weight:700;padding-top:1px}
dd{margin:0;font-size:13px;word-break:break-all;white-space:pre-wrap}dd ul{margin:0;padding-left:18px}
table.host{border-collapse:collapse}table.host th{color:#828282;text-align:left;font-weight:700;padding:3px 16px 3px 0;font-size:12px;text-transform:uppercase}
table.host td{font-size:13px;padding:3px 0}
'@
}

function Split-FindingDetails {
    # Details from the checks look like "<text>  [reason1; reason2]<extra>"
    param([string]$Details)
    $o = [pscustomobject]@{ Main = [string]$Details; Reasons = @(); Extra = '' }
    if (-not $Details) { return $o }
    $open = $Details.LastIndexOf('  [')
    if ($open -ge 0) {
        $close = $Details.IndexOf(']', $open)
        if ($close -gt $open) {
            $o.Main = $Details.Substring(0, $open).Trim()
            $o.Reasons = @($Details.Substring($open + 3, $close - $open - 3) -split '; ' | Where-Object { $_.Trim() })
            $o.Extra = $Details.Substring($close + 1).Trim().TrimStart('|').Trim()
        }
    }
    return $o
}

function Export-HtmlReport {
    <#
        Writes report.html and report.md in the same format as the remediation plan:
        findings grouped by category in cards, each finding expandable (detail, flagged because, MITRE, time).
    #>
    param([string]$Path, $HostInfo, $Findings, $Notes)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $count = @{}
    foreach ($s in 'High', 'Medium', 'Low', 'Info') { $count[$s] = @($Findings | Where-Object Severity -eq $s).Count }
    $groups = @($Findings | Group-Object Category | Sort-Object @{ Expression = { ($_.Group | Measure-Object Rank -Maximum).Maximum }; Descending = $true }, Name)
    $title = "Ransomware check report - $($HostInfo.ComputerName)"
    $summary = "findings High $($count['High']), Medium $($count['Medium']), Low $($count['Low']), Info $($count['Info'])"

    $md = New-Object System.Text.StringBuilder
    $ht = New-Object System.Text.StringBuilder
    $mdLine = { param($t) [void]$md.AppendLine($t) }

    & $mdLine "# $title"; & $mdLine ''
    & $mdLine "Generated $($HostInfo.ReportTime) by $($HostInfo.Tool) | window $($HostInfo.WindowDays) days | $summary"
    & $mdLine ''
    & $mdLine '> RansomwareChecker is read-only triage. Every finding requires analyst validation; see the remediation plan for recommended steps.'
    & $mdLine ''
    & $mdLine '## Findings'; & $mdLine ''
    [void]$ht.AppendLine('<h2>Findings</h2>')
    if ($groups.Count -eq 0) {
        & $mdLine 'No findings.'
        [void]$ht.AppendLine('<p>No findings.</p>')
    }
    foreach ($g in $groups) {
        $sev = $script:SevNames[[int](($g.Group | Measure-Object Rank -Maximum).Maximum)]
        & $mdLine "### [$sev] $($g.Name) ($($g.Count))"; & $mdLine ''
        [void]$ht.AppendLine("<div class=""cat""><h3><span class=""badge $sev"">$sev</span> $(& $enc $g.Name) <span class=""cnt"">($($g.Count))</span></h3>")
        foreach ($f in ($g.Group | Sort-Object Rank -Descending)) {
            $p = Split-FindingDetails $f.Details
            $detail = $p.Main
            if ($p.Extra) { $detail = ($detail, $p.Extra | Where-Object { $_ }) -join ' | ' }
            $lines = @($detail -split ' \| ' | Where-Object { $_ })

            & $mdLine "- **[$($f.Severity)] $($f.Item)**"
            foreach ($l in $lines) { & $mdLine "  - Detail: $l" }
            foreach ($r in $p.Reasons) { & $mdLine "  - Flagged because: $r" }
            if ($f.Mitre) { & $mdLine "  - MITRE ATT&CK: $($f.Mitre)" }
            if ($f.Timestamp) { & $mdLine "  - Time: $($f.Timestamp)" }

            [void]$ht.Append("<details class=""f"" data-s=""$($f.Severity)""><summary><span class=""badge $($f.Severity)"">$($f.Severity)</span>")
            [void]$ht.Append("<code>$(& $enc $f.Item)</code><span class=""time"">$(& $enc $f.Timestamp)</span></summary><dl>")
            if ($lines.Count) { [void]$ht.Append("<dt>Detail</dt><dd>$((($lines | ForEach-Object { & $enc $_ }) -join "`n"))</dd>") }
            if ($p.Reasons.Count) { [void]$ht.Append("<dt>Flagged because</dt><dd><ul>$((($p.Reasons | ForEach-Object { '<li>' + (& $enc $_) + '</li>' }) -join ''))</ul></dd>") }
            if ($f.Mitre) { [void]$ht.Append("<dt>MITRE ATT&amp;CK</dt><dd>$(& $enc $f.Mitre)</dd>") }
            [void]$ht.Append("<dt>Category</dt><dd>$(& $enc $f.Category)</dd>")
            if ($f.Timestamp) { [void]$ht.Append("<dt>Time</dt><dd>$(& $enc $f.Timestamp)</dd>") }
            [void]$ht.AppendLine('</dl></details>')
        }
        [void]$ht.AppendLine('</div>')
        & $mdLine ''
    }

    & $mdLine '## Host'; & $mdLine ''
    [void]$ht.AppendLine('<h2>Host</h2><table class="host">')
    foreach ($prop in $HostInfo.PSObject.Properties) {
        & $mdLine "- $($prop.Name): $($prop.Value)"
        [void]$ht.AppendLine("<tr><th>$(& $enc $prop.Name)</th><td>$(& $enc $prop.Value)</td></tr>")
    }
    [void]$ht.AppendLine('</table>')
    & $mdLine ''
    & $mdLine '## Coverage notes'; & $mdLine ''
    [void]$ht.AppendLine('<h2>Coverage notes</h2><ul>')
    if (-not $Notes -or $Notes.Count -eq 0) { & $mdLine '- none'; [void]$ht.AppendLine('<li>none</li>') }
    foreach ($n in $Notes) {
        & $mdLine "- $($n.Check): $($n.Message)"
        [void]$ht.AppendLine("<li><b>$(& $enc $n.Check)</b>: $(& $enc $n.Message)</li>")
    }
    [void]$ht.AppendLine('</ul>')
    & $mdLine ''
    & $mdLine '---'
    & $mdLine "Generated by $($HostInfo.Tool). Timestamps are local time of the analysed host."
    [IO.File]::WriteAllText([IO.Path]::ChangeExtension($Path, '.md'), $md.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $page = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>__TITLE__</title>
<style>
__STYLE__
</style></head><body>
<h1>__TITLE__</h1>
<div class="sub">__SUB__</div>
<div class="note">RansomwareChecker is read-only triage. Every finding requires analyst validation; see the remediation plan for recommended steps. Click a finding for details.</div>
<div class="bar">
<span class="chip High" data-s="High">HIGH __H__</span>
<span class="chip Medium" data-s="Medium">MEDIUM __M__</span>
<span class="chip Low" data-s="Low">LOW __L__</span>
<span class="chip Info" data-s="Info">INFO __I__</span>
<input id="q" placeholder="Search..." oninput="apply()">
</div>
__BODY__
<div class="footer">Generated by __TOOL__. Timestamps are local time of the analysed host.</div>
<script>
var off={};
document.querySelectorAll('.chip').forEach(function(c){c.onclick=function(){var s=c.getAttribute('data-s');off[s]=!off[s];c.classList.toggle('off');apply();};});
function apply(){var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('details.f').forEach(function(d){var ok=!off[d.getAttribute('data-s')]&&(!q||d.textContent.toLowerCase().indexOf(q)>=0);d.style.display=ok?'':'none';});
document.querySelectorAll('.cat').forEach(function(c){var any=false;c.querySelectorAll('details.f').forEach(function(d){if(d.style.display!=='none')any=true;});c.style.display=any?'':'none';});}
</script></body></html>
'@
    $sub = "Generated $(& $enc $HostInfo.ReportTime) by $(& $enc $HostInfo.Tool) &middot; window $($HostInfo.WindowDays) days &middot; $summary"
    $page = $page.Replace('__STYLE__', (Get-DocumentStyle)).Replace('__TOOL__', (& $enc $HostInfo.Tool)).Replace('__TITLE__', (& $enc $title)).Replace('__SUB__', $sub)
    $page = $page.Replace('__H__', [string]$count['High']).Replace('__M__', [string]$count['Medium']).Replace('__L__', [string]$count['Low']).Replace('__I__', [string]$count['Info'])
    $page = $page.Replace('__BODY__', $ht.ToString())
    [IO.File]::WriteAllText($Path, $page, (New-Object System.Text.UTF8Encoding($true)))
}

function Export-Remediation {
    <#
        Writes the recommended remediation plan (Markdown + HTML) for the findings of this run.
        Order follows the incident response process: preserve evidence -> containment -> per-finding eradication -> recovery -> post-incident.
        Only Low/Medium/High findings get steps; Info findings are context only.
    #>
    param([string]$Dir, $HostInfo, $Findings)
    $cfgFile = Join-Path $script:Root 'config\remediation.json'
    if (-not (Test-Path -LiteralPath $cfgFile)) { Add-Note 'Remediation' "config\remediation.json not found - no remediation plan written"; return $null }
    $cfg = Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null

    $actionable = @($Findings | Where-Object Rank -ge 1)
    $h = @($actionable | Where-Object Rank -ge 3).Count
    $m = @($actionable | Where-Object Rank -eq 2).Count
    $l = @($actionable | Where-Object Rank -eq 1).Count
    $groups = @($actionable | Group-Object Category | Sort-Object @{ Expression = { ($_.Group | Measure-Object Rank -Maximum).Maximum }; Descending = $true }, Name)
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }

    $md = New-Object System.Text.StringBuilder
    $ht = New-Object System.Text.StringBuilder
    $mdLine = { param($t) [void]$md.AppendLine($t) }
    $section = {
        param($title, $steps, [switch]$Numbered)
        & $mdLine "## $title"; & $mdLine ''
        [void]$ht.AppendLine("<h2>$(& $enc $title)</h2>")
        [void]$ht.AppendLine($(if ($Numbered) { '<ol>' } else { '<ul>' }))
        $i = 0
        foreach ($s in $steps) {
            $i++
            & $mdLine $(if ($Numbered) { "$i. $s" } else { "- $s" })
            [void]$ht.AppendLine("<li>$(& $enc $s)</li>")
        }
        [void]$ht.AppendLine($(if ($Numbered) { '</ol>' } else { '</ul>' }))
        & $mdLine ''
    }

    $title = "Remediation plan - $($HostInfo.ComputerName)"
    & $mdLine "# $title"; & $mdLine ''
    & $mdLine "Generated $($HostInfo.ReportTime) by $($HostInfo.Tool) | window $($HostInfo.WindowDays) days | findings High $h, Medium $m, Low $l"
    & $mdLine ''
    & $mdLine '> RansomwareChecker is read-only. These are recommendations - validate every finding, preserve evidence first, and follow your incident response plan and change management. <item> in a step = the finding listed above it.'
    & $mdLine ''

    if ($actionable.Count -eq 0) {
        & $section 'Result' @('No Low, Medium or High findings - no remediation needed. Keep the post-incident recommendations below in mind.')
    } else {
        & $section '1. Preserve evidence' $cfg._General.Evidence -Numbered
        if ($h -gt 0) { & $section '2. Containment (High findings present)' $cfg._General.Containment -Numbered }
        else { & $section '2. Containment (only if an intrusion is confirmed)' $cfg._General.Containment -Numbered }

        & $mdLine '## 3. Eradication - per finding'; & $mdLine ''
        [void]$ht.AppendLine('<h2>3. Eradication - per finding</h2>')
        foreach ($g in $groups) {
            $max = ($g.Group | Measure-Object Rank -Maximum).Maximum
            $sev = $script:SevNames[[int]$max]
            & $mdLine "### [$sev] $($g.Name) ($($g.Count))"; & $mdLine ''
            [void]$ht.AppendLine("<div class=""cat""><h3><span class=""badge $sev"">$sev</span> $(& $enc $g.Name) <span class=""cnt"">($($g.Count))</span></h3>")
            & $mdLine 'Findings:'
            [void]$ht.AppendLine('<p class="lbl">Findings</p><ul class="items">')
            foreach ($f in ($g.Group | Sort-Object Rank -Descending)) {
                & $mdLine "- [$($f.Severity)] $($f.Item)"
                [void]$ht.AppendLine("<li><span class=""badge $($f.Severity)"">$($f.Severity)</span> <code>$(& $enc $f.Item)</code></li>")
            }
            [void]$ht.AppendLine('</ul>')
            & $mdLine ''
            $entry = $cfg.PSObject.Properties[$g.Name]
            $steps = if ($entry) { @($entry.Value.Steps) } else { @('No specific guidance in config\remediation.json - validate the finding manually.') }
            & $mdLine 'Recommended steps:'
            [void]$ht.AppendLine('<p class="lbl">Recommended steps</p><ol>')
            $i = 0
            foreach ($s in $steps) { $i++; & $mdLine "$i. $s"; [void]$ht.AppendLine("<li>$(& $enc $s)</li>") }
            [void]$ht.AppendLine('</ol></div>')
            & $mdLine ''
        }
        & $section '4. Recovery' $cfg._General.Recovery -Numbered
    }
    & $section '5. Post-incident - prevent it next time' $cfg._General.PostIncident
    & $mdLine '---'
    & $mdLine "Generated by $($HostInfo.Tool). Recommendations only - validate before acting."

    $mdPath = Join-Path $Dir 'remediation.md'
    [IO.File]::WriteAllText($mdPath, $md.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $page = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>__TITLE__</title>
<style>
__STYLE__
</style></head><body>
<h1>__TITLE__</h1>
<div class="sub">__SUB__</div>
<div class="note">RansomwareChecker is read-only. These are recommendations - validate every finding, preserve evidence first, and follow your incident response plan and change management. &lt;item&gt; in a step = the finding listed above it.</div>
__BODY__
<div class="footer">Generated by __TOOL__. Recommendations only - validate before acting.</div>
</body></html>
'@
    $sub = "Generated $($HostInfo.ReportTime) by $($HostInfo.Tool) &middot; window $($HostInfo.WindowDays) days &middot; findings High $h, Medium $m, Low $l"
    $page = $page.Replace('__STYLE__', (Get-DocumentStyle)).Replace('__TOOL__', (& $enc $HostInfo.Tool)).Replace('__TITLE__', (& $enc $title)).Replace('__SUB__', $sub).Replace('__BODY__', $ht.ToString())
    $htmlPath = Join-Path $Dir 'remediation.html'
    [IO.File]::WriteAllText($htmlPath, $page, (New-Object System.Text.UTF8Encoding($true)))
    return $htmlPath
}

#endregion

#region ---------------------------------------------------------------- main

function Invoke-Check {
    param([string]$Name, [scriptblock]$Script, [switch]$NeedsAdmin)
    $before = $script:Findings.Count
    Write-Host ('[*] {0,-42}' -f $Name) -NoNewline
    if ($NeedsAdmin -and -not $script:IsAdmin) { Add-Note $Name 'Not elevated - results may be incomplete' }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Script | Out-Null } catch { Add-Note $Name "error: $($_.Exception.Message)" }
    $new = $script:Findings.GetRange($before, $script:Findings.Count - $before)
    $hi = @($new | Where-Object Rank -ge 3).Count
    $me = @($new | Where-Object Rank -eq 2).Count
    $color = if ($hi) { 'Red' } elseif ($me) { 'Yellow' } else { 'Green' }
    Write-Host ('{0,3} findings (High {1}, Medium {2})  {3:N1}s' -f $new.Count, $hi, $me, $sw.Elapsed.TotalSeconds) -ForegroundColor $color
}

$start = Get-Date
Write-Host ''
Write-Host "RansomwareChecker $($script:Version)  -  read-only ransomware persistence & artifact triage" -ForegroundColor Cyan
Write-Host ("Host: {0}   Window: {1} days (since {2})   Elevated: {3}" -f $env:COMPUTERNAME, $DaysBack, (Format-Time $script:Since), $script:IsAdmin)
if (-not $script:IsAdmin) { Write-Host 'WARNING: not running as administrator - Security log, Prefetch, other users and services will be incomplete.' -ForegroundColor Yellow }
Write-Host ''

Invoke-Check 'Run / RunOnce keys'                { Test-RunKeys }
Invoke-Check 'Winlogon / IFEO / AppInit'         { Test-WinlogonAndIfeo }
Invoke-Check 'Startup folders'                   { Test-StartupFolders }
Invoke-Check 'Scheduled tasks'                   { Test-ScheduledTasks } -NeedsAdmin
Invoke-Check 'Services'                          { Test-Services }
Invoke-Check 'WMI event subscriptions'           { Test-WmiPersistence } -NeedsAdmin
Invoke-Check 'BITS jobs'                         { Test-BitsJobs } -NeedsAdmin
Invoke-Check 'Remote access / exfil software'    { Test-RemoteAccessSoftware }
Invoke-Check 'Running processes'                 { Test-RunningProcesses } -NeedsAdmin
Invoke-Check 'Security configuration'            { Test-SecurityConfiguration }
Invoke-Check 'Microsoft Defender'                { Test-Defender } -NeedsAdmin
Invoke-Check 'Shadow copies / boot recovery'     { Test-RecoveryInhibition } -NeedsAdmin
Invoke-Check 'Local accounts'                    { Test-LocalAccounts }
Invoke-Check 'Event logs'                        { Test-EventLogs } -NeedsAdmin
Invoke-Check 'Prefetch'                          { Test-Prefetch } -NeedsAdmin
Invoke-Check 'UserAssist / BAM'                  { Test-UserAssistAndBam } -NeedsAdmin
Invoke-Check 'PowerShell console history'        { Test-PowerShellHistory } -NeedsAdmin
Invoke-Check 'Exfiltration tool artifacts'       { Test-ExfilArtifacts } -NeedsAdmin
Invoke-Check 'GPO deployment (SYSVOL)'           { Test-GpoDeployment }
if (-not $Quick) {
    Invoke-Check 'Staging folders & tool files'  { Test-StagingFolders } -NeedsAdmin
    Invoke-Check 'Ransom notes'                  { Test-RansomNotes } -NeedsAdmin
} else {
    Add-Note 'File system' 'Skipped (-Quick)'
}

# ---- output
if (-not $OutputPath) { $OutputPath = Join-Path $script:Root 'Reports' }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Join-Path $OutputPath ("{0}_{1}" -f $env:COMPUTERNAME, $stamp)
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$sorted = @($script:Findings | Sort-Object @{ Expression = 'Rank'; Descending = $true }, Category, Item)
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$hostInfo = [pscustomobject][ordered]@{
    ComputerName = $env:COMPUTERNAME
    Domain       = $env:USERDOMAIN
    RunAs        = "$env:USERDOMAIN\$env:USERNAME"
    Elevated     = $script:IsAdmin
    OS           = if ($os) { "$($os.Caption) $($os.Version)" } else { '' }
    LastBoot     = if ($os) { Format-Time $os.LastBootUpTime } else { '' }
    TimeZone     = (Get-TimeZone).Id
    ReportTime   = Format-Time $start
    DurationSec  = [Math]::Round(((Get-Date) - $start).TotalSeconds, 1)
    WindowDays   = $DaysBack
    Quick        = [bool]$Quick
    Tool         = "RansomwareChecker $($script:Version)"
}

$sorted | Select-Object Severity, Category, Item, Details, Mitre, Timestamp |
    Export-Csv -LiteralPath (Join-Path $outDir 'findings.csv') -NoTypeInformation -Encoding UTF8
[pscustomobject]@{ Host = $hostInfo; Findings = @($sorted | Select-Object Severity, Category, Item, Details, Mitre, Timestamp); Notes = $script:Notes } |
    ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $outDir 'findings.json') -Encoding UTF8
$htmlPath = Join-Path $outDir 'report.html'
if (-not $NoHtml) { Export-HtmlReport -Path $htmlPath -HostInfo $hostInfo -Findings $sorted -Notes $script:Notes }

# Remediation plan next to the Reports folder: <parent of OutputPath>\Remediation\<same folder name as the report>
if (-not $RemediationPath) { $RemediationPath = Join-Path (Split-Path -Parent ([IO.Path]::GetFullPath($OutputPath))) 'Remediation' }
$remDir = Join-Path $RemediationPath (Split-Path -Leaf $outDir)
$remHtml = $null
try { $remHtml = Export-Remediation -Dir $remDir -HostInfo $hostInfo -Findings $sorted } catch { Add-Note 'Remediation' "failed: $($_.Exception.Message)" }

$h = @($sorted | Where-Object Rank -ge 3).Count
$m = @($sorted | Where-Object Rank -eq 2).Count
$l = @($sorted | Where-Object Rank -eq 1).Count
Write-Host ''
Write-Host ('Summary: High {0} | Medium {1} | Low {2} | Info {3}' -f $h, $m, $l, ($sorted.Count - $h - $m - $l)) -ForegroundColor Cyan
if ($script:Notes.Count) { Write-Host "Coverage notes: $($script:Notes.Count) (see report)" -ForegroundColor DarkYellow }
Write-Host "Report: $outDir"
if ($remHtml) { Write-Host "Remediation plan: $remDir" }
if ($OpenReport -and -not $NoHtml) { Start-Process $htmlPath }

if ($h -gt 0) { exit 2 } elseif ($m -gt 0) { exit 1 } else { exit 0 }

#endregion

# SIG # Begin signature block
# MIIdowYJKoZIhvcNAQcCoIIdlDCCHZACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgkJBxpdk8BG2y
# VseEpShaUyENiHxVoN/BKlegPRPBtaCCF2AwggQiMIICiqADAgECAhB1VkCOhmLH
# gU1PkVGYpUTbMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMMHlJhbnNvbXdhcmVD
# aGVja2VyIENvZGUgU2lnbmluZzAeFw0yNjEwMzExNzM3MThaFw0zMTEwMzExNzQ3
# MTZaMCkxJzAlBgNVBAMMHlJhbnNvbXdhcmVDaGVja2VyIENvZGUgU2lnbmluZzCC
# AaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALFyZgNZM9rgH+THY176Je58
# nBcJXWIo8AjEnqtuonGtSdl696bJMGgPEc6x0JQnkpwbdh9ZEtBCGtZE67P5LMgI
# nYd2ZDgj3q+M5AfTMTWXS53GWSa7WT1AzbioJcQX8S/p0lUVG3uZtbRyh8xI1vCG
# UyAxUzazQIwLavRWq2C8TpEiFyD07rrmLbd53qt8c75eoNM8Crw2o9bU5S9NTqaC
# FIK0acjv8e//Cx3D1ji2Jm2AGZ8+9Yz3sRM0IpgO2r4AnaTVlIesKzKq7EPneNvy
# mXH/jVykRUINZ/7DCHFBfct+ZEzyiOKSQvrWvaK9tAThztfmOwY6VlMbr7iaxWzr
# 8yGFhwjNnQuteqY9vKGV+0UUG9txImHeo1XlbZjXzjzAkvb3mgGuLV7g+O64LrXf
# 4dytOoHdYxp4SLFdhxrzsO1h5n1yE5FrYjdyZQ7qSkvrgZwCsIFOfusqUTzpO28L
# jAH0OksQgx975NMFHThswKrBdo8i8K3rvvCKYC/hBQIDAQABo0YwRDAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFD7uHE9xxItJ
# zoOrNGw6xA5t+z7kMA0GCSqGSIb3DQEBCwUAA4IBgQB8DqndQmimyS8zj2W9h/vq
# m61uWByEXz95pddWq2QdbVJKsL0Aczkfx9h2PnW11+E1OTDkMO/QV62NP/joC9pE
# eaAO9g6UP18QRDgWW1jSXmSrXk/598Ex/OUhKfolDbxGbjNTUC2ipJj3O64z6EQh
# 8K+cQfelZ+SPhJV3Qs0KyiO8m/w9aPo0CtmmjMYit+16E0ffHdzPbIdo34xe7mMS
# wfwcxckciE3oqenNcPJVTJUM+Cu/C/WQZZG8phXWF/34efFSjKPwwZvR72D0rUh0
# w4MmfBt0uydo27/k2xDjU34+i3mdMHEVjAK1J24O+IC1V06uaUfWQKRFnN4QtyXD
# lY9hZznO4OZCAIDce0to7oHC5rwtQrmZiC2rubKDn8fhyMIiMJ6/G7rwfA9tLO+r
# iKOyOVIsaHOXV3YwJJCrttofmRa8T3tPz3dAUrfqGrsCUwIE+8iobFf7lYqMXrxJ
# b1J/HewDNwgSUN3wIGHWVNvpAdPLk7aoe6cKyrFDDcUwggWNMIIEdaADAgECAhAO
# mxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# JDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEw
# MDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprN
# rnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVy
# r2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4
# IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13j
# rclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4Q
# kXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQn
# vKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu
# 5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/
# 8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQp
# JYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFf
# xCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGj
# ggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8B
# Af8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6
# oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEB
# AHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0a
# FPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNE
# m0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZq
# aVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCs
# WKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9Fc
# rBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmG
# MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5
# NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0
# eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+Ruw
# OnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4B
# t0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1U
# kxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTca
# arps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zb
# CclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnG
# pTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/
# AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v
# 5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoi
# wOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm
# 2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Q
# h8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3
# YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQ
# wr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/
# wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81
# hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00
# TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNj
# qFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0
# cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9
# sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0
# LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2
# tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG
# 9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1
# OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYD
# VQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVy
# IDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K
# +NSbTGWz/TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDf
# U3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZs
# DwO3BSkUxDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuiz
# VzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+
# SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3UR
# m26QZYMn/FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+
# bFRsIolvykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5d
# oH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu
# 1PT5prW83vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02G
# Dwy0ODjdzi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdw
# roczk9icflf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8E
# AjAAMB0GA1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAww
# CgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQw
# OTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0
# MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLy
# wSLaDXQIENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMe
# ApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4U
# NgAdZkfHhHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr
# 6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+Ui
# TfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2
# AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYc
# sQeSWmvKqzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5
# b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJB
# I+xZEbGRsMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7Qfie
# AIjWagkJNt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSj
# zSvdN8yWQPT9gzGCBZkwggWVAgEBMD0wKTEnMCUGA1UEAwweUmFuc29td2FyZUNo
# ZWNrZXIgQ29kZSBTaWduaW5nAhB1VkCOhmLHgU1PkVGYpUTbMA0GCWCGSAFlAwQC
# AQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwG
# CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZI
# hvcNAQkEMSIEIPwlOQTHdV8h0CUoOxbhxo1K4jvI22wsOyZjrhEc3vVrMA0GCSqG
# SIb3DQEBAQUABIIBgK49vLnqGLPb5SqIc9j+S0alMn6ovNcvGP2DmC7bcrLUJqO+
# +tfsOSB4O4s3L6t5aMV0sQ93XBQEWsKrFEL+X10fZvPeXSIysadxtW9G5Y2217HE
# 98BNbK31H0h3ykIYp12TAOWeMXxahbCnmYyxc/yFQGJ3b7+7Ej4fjH33MOh8nw/9
# DU1uFQZ8hs2gi7txy+XYiz+HSPhHpY+fHQzlV55EP/C8I9gXYqBhmF6IPe7fePEh
# ET+MfvN87Vh/G8xJqOnQd93c0hwhtQZRIoJoFNeCBv3sQdGE8zSPHRo5SjCGrYq4
# uPsEFSIHcwHDzQZJE7ICa+q7J12ZqiLT33P/sijm7wuk8c5w7opKMm0rCMmvOYID
# OjBAHlnUR0LuPl8XT//onRF6cIfOnCYcowUuZUVp2lbqgBmxpcYGBB7JGj/ew/JA
# MtbyBlLXz9tH6M/GrCejI3GMUggKIwIesSTg956eTsOHXHGyPMDfIk9rRmYHNWP7
# Je01z598eJeui06XGqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjEwMzExODM5
# MjBaMC8GCSqGSIb3DQEJBDEiBCCJp8S8nVOB88clUs6hB2js5blZF5lecuBbKIc6
# HpR6JjANBgkqhkiG9w0BAQEFAASCAgCiAnTQDHN7XHxA0cPJFX0VRRZa5g+LrxUY
# pf2Q3EfU7ulDjLBI6h3CYBE7wQWUqVqOHcPdKAefyIU88tOpYIH5oG250r99ROEL
# RKTpvS5mM5WoOijKHgj7n7Ts8GAv3/XmIbH9zNSPExq5IuRxuo3IwS/1YHIsGuao
# WtTDO1T9ZP6/PEWtqAJC0RtVO9mZ4pXAQvTWeokYpE797K5Z+clxnQ3vi4wQTJQE
# xJCFkzRK9EOZsKmUsvj8piYtssdc64GS/brS1NcUfn6XBsF0RVGkj03CzT0KtrxH
# Da6p3ODYjUf1bs0klNOAl/PvhwcJ/3gLHO4FP1TWQrJcuCsrFwgSMsZLTZy27+Nv
# DXUORzqaCHjLGuorg4poO32xZbjcARPdjVGFUkgBu61/Qrhc5rMpOo+3Vi8gxa4o
# opQxeGwQspm8PHePzPy0sidMVVCTolWVTNw6CcX6vudZ7m82VHAlDKKOgEqKVpU/
# n3TJg3i3yle4kMeJLgr/aIX0oXoVhe+NR2Bt6eaU0gDzjvXZyTCzTHkF6ccLYTE4
# S8n3KDxfTlTJnsbv0ChNe3E/96DtB5LhBn+Rgb6gxwpWHDHM+BYa8HPOuOGCgjBZ
# TBuEOrGNNwtZZ27pRfGNpDNLn0vBy++DTbCdNjkIDlosJOhCRKB3O+5Chhh/gmHQ
# m09/q50Fqw==
# SIG # End signature block
