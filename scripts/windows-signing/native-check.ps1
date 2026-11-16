param([string]$Version, [string]$Source, [string]$Directory = 'bin/signed-windows')
$ErrorActionPreference = 'Stop'
$configPath = 'scripts/windows-signing.json'
$config = Get-Content $configPath -Raw | ConvertFrom-Json
$release = 'scripts/windows-signing/release.py'
python $release verify --config $configPath --out $Directory --version $Version --source $Source
if ($LASTEXITCODE) { throw 'Signed package verification failed' }
$install = Join-Path $env:RUNNER_TEMP 'estate-signature-qualification'
$setup = (Resolve-Path (Join-Path $Directory $config.setup.Replace('{version}', $Version))).Path
$process = Start-Process $setup -ArgumentList @('/S', "/D=$install") -Wait -PassThru
if ($process.ExitCode) { throw 'Signed installation failed' }
python $release verify --config $configPath --out $Directory --version $Version --source $Source --installed $install
if ($LASTEXITCODE) { throw 'Installed payload verification failed' }
$uninstaller = if ($config.PSObject.Properties.Name -contains 'uninstaller') { $config.uninstaller } else { 'uninstall.exe' }
$process = Start-Process (Join-Path $install $uninstaller) -ArgumentList '/S' -Wait -PassThru
if ($process.ExitCode) { throw 'Signed uninstall failed' }
$binary = $config.binaries[0]
for ($attempt = 0; $attempt -lt 30 -and (Test-Path (Join-Path $install $binary)); $attempt++) { Start-Sleep -Seconds 1 }
if (Test-Path (Join-Path $install $binary)) { throw 'Uninstall left application behind' }
