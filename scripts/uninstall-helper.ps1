# Removes the KaChat-NFC helper from Windows. Cards keep their software and any backup.
$ErrorActionPreference = 'Stop'

$taskName = 'KaChat-NFC Helper'
Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Get-Process -Name 'kachat-nfc' -ErrorAction SilentlyContinue | Stop-Process -Force
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $env:LOCALAPPDATA 'KaChat-NFC') -ErrorAction SilentlyContinue
Write-Host 'The KaChat-NFC helper has been removed.'
