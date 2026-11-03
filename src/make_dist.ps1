# Builds a clean distribution package dist\RansomwareChecker-<version>.zip from the built and signed files:
# app, script, config, launcher, README, licenses and the public certificate.
# Local data is left out on purpose: marks.json (analyst marks of this computer), RansomwareChecker.ini (local
# settings; the app creates defaults), Reports\, Remediation\, src\ and docs\.
# Run after src\build.cmd:  powershell -ExecutionPolicy Bypass -File src\make_dist.ps1
param([string]$OutDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

$m = Select-String -LiteralPath (Join-Path $root 'RansomwareChecker.ps1') -Pattern "^\`$script:Version\s*=\s*'([\d.]+)'" | Select-Object -First 1
if (-not $m) { throw 'Version not found in RansomwareChecker.ps1' }
$version = $m.Matches[0].Groups[1].Value
$exeVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $root 'RansomwareChecker.exe')).FileVersion
if ($exeVersion -ne "$version.0") { throw "RansomwareChecker.exe is $exeVersion, the script is $version - run src\build.cmd first" }
foreach ($f in 'RansomwareChecker.exe', 'RansomwareChecker.ps1') {
    $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $root $f)
    if ($sig.Status -ne 'Valid') { throw "$f signature is $($sig.Status) - run src\build.cmd first" }
}

$name = "RansomwareChecker-$version"
$stage = Join-Path $OutDir $name
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
foreach ($i in 'RansomwareChecker.exe', 'RansomwareChecker.ps1', 'Run-RansomwareChecker.bat', 'README.md', 'LICENSE', 'config', 'licenses', 'cert') {
    Copy-Item -LiteralPath (Join-Path $root $i) -Destination $stage -Recurse
}

# The copies must match the hashes pinned in the exe (src\Integrity.g.cs of the last build) - otherwise every user
# of the package would get the "modified" integrity warning
$pinned = [regex]::Matches([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Integrity.g.cs')), '\{\s*@"([^"]+)",\s*"([0-9A-F]{64})"\s*\}')
if ($pinned.Count -eq 0) { throw 'No pinned hashes found in src\Integrity.g.cs - run src\build.cmd first' }
foreach ($p in $pinned) {
    $f = $p.Groups[1].Value
    if ((Get-FileHash -LiteralPath (Join-Path $stage $f)).Hash -ne $p.Groups[2].Value) { throw "$f does not match the hash pinned in the exe - run src\build.cmd again" }
}

# Entry names with "/" (ZipFile.CreateFromDirectory in .NET Framework writes "\", which other unzip tools misread)
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::Open($zip, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($file in Get-ChildItem -LiteralPath $stage -Recurse -File) {
        $entry = $name + '/' + $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file.FullName, $entry, [IO.Compression.CompressionLevel]::Optimal)
    }
}
finally { $archive.Dispose() }
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
[IO.File]::WriteAllText("$zip.sha256", "$hash  $name.zip`r`n", (New-Object Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $stage -Recurse -Force

"Package: $zip"
"SHA-256: $hash"
