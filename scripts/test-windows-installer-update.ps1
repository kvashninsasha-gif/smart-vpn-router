# Disposable runner only: install the previous release, then use NSIS /UPDATE /P.
param([Parameter(Mandatory=$true)][string]$Installer,
      [Parameter(Mandatory=$true)][string]$ExpectedVersion)
$ErrorActionPreference = 'Stop'
if ($env:FOXVPN_TEST_ALLOW_INSTALLER -ne '1') { throw 'Explicit disposable-runner opt-in required' }
$taskRoot = Join-Path $env:TEMP ("foxvpn-install-test-" + [guid]::NewGuid())
$installRoot = Join-Path $taskRoot 'app'
$savedAppData = $env:APPDATA
New-Item -ItemType Directory -Path $taskRoot -Force | Out-Null
try {
    $env:APPDATA = Join-Path $taskRoot 'data'
    $profileRoot = Join-Path $env:APPDATA 'ru.smartvpn.router'
    New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
    $profile = Join-Path $profileRoot 'profile.enc'
    [IO.File]::WriteAllBytes($profile, [Text.Encoding]::UTF8.GetBytes('preserved-test-profile'))
    $profileHash = (Get-FileHash $profile -Algorithm SHA256).Hash
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/kvashninsasha-gif/foxVPN/releases/tags/v0.1.19'
    $asset = $release.assets | Where-Object name -eq 'foxVPN_0.1.19_x64-setup.exe'
    if (-not $asset -or -not $asset.digest.StartsWith('sha256:')) { throw 'Pinned old release missing' }
    $oldInstaller = Join-Path $taskRoot 'old.exe'
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $oldInstaller
    if (('sha256:' + (Get-FileHash $oldInstaller -Algorithm SHA256).Hash.ToLowerInvariant()) -ne $asset.digest) {
        throw 'Old installer SHA256 mismatch'
    }
    $first = Start-Process $oldInstaller -ArgumentList @('/S', "/D=$installRoot") -PassThru
    if (-not $first.WaitForExit(120000)) { $first.Kill(); throw 'Old installer timed out' }
    if ($first.ExitCode -notin @(0,3010)) { throw 'Old installation failed' }
    $exe = Join-Path $installRoot 'smart-vpn-desktop.exe'
    if (-not (Test-Path $exe)) { throw 'Initial app missing' }
    $next = Start-Process (Resolve-Path $Installer).Path -ArgumentList @('/UPDATE','/P',"/D=$installRoot") -PassThru
    if (-not $next.WaitForExit(120000)) { $next.Kill(); throw 'Update installer timed out' }
    if ($next.ExitCode -notin @(0,3010)) { throw 'Update installation failed' }
    if ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion -ne $ExpectedVersion) {
        throw 'Installed application version mismatch'
    }
    if ((Get-FileHash $profile -Algorithm SHA256).Hash -ne $profileHash) { throw 'Profile changed by update' }
    # Gate the exact core extracted by the real installer, not just the input
    # downloaded before bundling. A missing core/generator is a hard failure.
    $repoRoot = Split-Path $PSScriptRoot -Parent
    $generator = Join-Path $repoRoot 'target/release/examples/startup-fixtures.exe'
    $core = Join-Path $installRoot 'core/sing-box.exe'
    $report = Join-Path (Split-Path (Resolve-Path $Installer).Path -Parent) 'windows-core-startup.json'
    python (Join-Path $PSScriptRoot 'test-core-startup.py') --generator $generator --core $core --report $report
    if ($LASTEXITCODE -ne 0) { throw 'Installed core startup gate failed' }
    $proof = Get-Content $report -Raw | ConvertFrom-Json
    $proof | Add-Member -NotePropertyName installer_sha256 -NotePropertyValue (Get-FileHash $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
    $proof | Add-Member -NotePropertyName installer_version -NotePropertyValue $ExpectedVersion
    $proof | ConvertTo-Json -Depth 10 | Set-Content -Encoding utf8 $report
    $model = Join-Path $repoRoot 'target/ai-test/Qwen3-0.6B-Q8_0.gguf'
    $aiReport = Join-Path (Split-Path (Resolve-Path $Installer).Path -Parent) 'windows-local-ai.json'
    python (Join-Path $PSScriptRoot 'test-local-ai.py') $exe --model $model --report $aiReport --installer $Installer
    if ($LASTEXITCODE -ne 0) { throw 'Installed local AI worker gate failed' }
    if ((Get-FileHash $profile -Algorithm SHA256).Hash -ne $profileHash) { throw 'AI worker changed the profile' }
    Write-Output 'NSIS update mode and profile preservation verified'
} finally {
    $uninstaller = Join-Path $installRoot 'uninstall.exe'
    if (Test-Path $uninstaller) {
        $cleanup = Start-Process $uninstaller -ArgumentList '/S' -PassThru
        if (-not $cleanup.WaitForExit(60000)) { $cleanup.Kill() }
    }
    $env:APPDATA = $savedAppData
    Remove-Item -LiteralPath $taskRoot -Recurse -Force -ErrorAction SilentlyContinue
}
