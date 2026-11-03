# Installs the KaChat-NFC helper on Windows, for this user only, with no admin prompt.
#
#   irm https://github.com/KaspaSilver/KaChat-NFC/releases/latest/download/install-helper.ps1 | iex
#
# $env:KACHAT_NFC_ORIGIN adds a Quick Start panel that isn't on localhost.
# Run it again to update. uninstall-helper.ps1 removes everything this adds.
$ErrorActionPreference = 'Stop'

$base = 'https://github.com/KaspaSilver/KaChat-NFC/releases/latest/download'
$asset = 'kachat-nfc-windows-amd64.exe'
$taskName = 'KaChat-NFC Helper'
$installDir = Join-Path $env:LOCALAPPDATA 'KaChat-NFC'
$target = Join-Path $installDir 'kachat-nfc.exe'
$temp = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    Write-Host 'Downloading the KaChat-NFC helper...'
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $temp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $temp 'SHA256SUMS')

    Write-Host 'Checking its hash...'
    $line = Get-Content (Join-Path $temp 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[1] -eq $asset }
    if (-not $line) { throw "The published hashes don't list $asset, so nothing was installed." }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash (Join-Path $temp $asset) -Algorithm SHA256).Hash
    if ($expected -ne $actual.ToLower()) { throw "The download doesn't match the published hash, so nothing was installed." }

    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Copy-Item (Join-Path $temp $asset) $target -Force

    $arguments = "--headless `"$target`" serve"
    if ($env:KACHAT_NFC_ORIGIN) { $arguments += " --allow-origin $($env:KACHAT_NFC_ORIGIN)" }
    $action = New-ScheduledTaskAction -Execute 'conhost.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    foreach ($attempt in 1..10) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:18421/v1/status' -TimeoutSec 2 | Out-Null
            Write-Host 'The KaChat-NFC helper is running. Go back to the Quick Start panel.'
            return
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "The helper was installed but didn't answer. Check that nothing else is using port 18421."
} finally {
    Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
}
