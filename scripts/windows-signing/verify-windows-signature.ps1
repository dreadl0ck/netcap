param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Serial)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$signature = Get-AuthenticodeSignature -LiteralPath $Path
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.SerialNumber -ne $Serial) {
    throw "Invalid signature or unexpected certificate: $Path"
}
if (-not $signature.TimeStamperCertificate) { throw "Missing timestamp: $Path" }
$tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($tool) { $signtool = $tool.Source } else {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $signtool = Get-ChildItem "$kits/*/x64/signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $signtool) { throw 'Windows SDK signtool.exe is required' }
& $signtool verify /pa /all /tw /v $Path
if ($LASTEXITCODE) { throw "signtool verification failed: $Path" }
