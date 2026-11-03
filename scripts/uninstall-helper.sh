#!/bin/sh
# Removes the KaChat-NFC helper from macOS. Cards keep their software and any backup.
set -eu

label="app.kachat.nfc.helper"
launchctl bootout "gui/$(id -u)/${label}" 2>/dev/null || true
rm -f "${HOME}/Library/LaunchAgents/${label}.plist"
rm -rf "${HOME}/Library/Application Support/KaChat-NFC"
echo "The KaChat-NFC helper has been removed."
