# Signs RansomwareChecker.exe and RansomwareChecker.ps1 with the code signing certificate from Cert:\CurrentUser\My.
# Called by build.cmd; skipped when the certificate is not present. Re-run after every change of the .ps1.
param([string]$Subject = 'CN=RansomwareChecker Code Signing', [string]$TimestampServer = 'http://timestamp.digicert.com')
$root = Split-Path -Parent $PSScriptRoot
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { Write-Host "Signing skipped: no certificate '$Subject' in Cert:\CurrentUser\My"; exit 0 }
foreach ($f in 'RansomwareChecker.exe', 'RansomwareChecker.ps1') {
    $path = Join-Path $root $f
    $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction SilentlyContinue
    if (-not $r -or -not $r.SignerCertificate) {
        # Offline: sign without timestamp (signature then expires with the certificate)
        $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256
    }
    Write-Host ("Signed {0}: {1}" -f $f, $r.Status)
}
