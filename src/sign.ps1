# Signs RansomwareChecker.exe and/or RansomwareChecker.ps1 with the code signing certificate from Cert:\CurrentUser\My.
# Called by build.cmd (script first, exe after compiling); skipped when the certificate is not present.
# After a change of the .ps1 run build.cmd again - the exe pins the hash of the signed script.
param(
    [string[]]$Files = @('RansomwareChecker.exe', 'RansomwareChecker.ps1'),
    [string]$Subject = 'CN=RansomwareChecker Code Signing',
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)
$root = Split-Path -Parent $PSScriptRoot
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { Write-Host "Signing skipped: no certificate '$Subject' in Cert:\CurrentUser\My"; exit 0 }
foreach ($f in $Files) {
    $path = Join-Path $root $f
    $r = $null
    # a freshly built exe can be locked for a moment by the antivirus scan
    for ($try = 0; $try -lt 5 -and -not ($r -and $r.SignerCertificate); $try++) {
        if ($try) { Start-Sleep -Seconds 2 }
        try { $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop } catch { $r = $null }
        if (-not $r -or -not $r.SignerCertificate) {
            # Offline: sign without timestamp (signature then expires with the certificate)
            try { $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop } catch { $r = $null }
        }
    }
    Write-Host ("Signed {0}: {1}" -f $f, $(if ($r) { $r.Status } else { 'FAILED' }))
}
