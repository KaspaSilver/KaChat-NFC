#!/bin/sh
# Installs the KaChat-NFC helper on macOS, for this user only, with no password.
#
#   curl -fsSL https://github.com/KaspaSilver/KaChat-NFC/releases/latest/download/install-helper.sh | sh
#
# KACHAT_NFC_ORIGIN adds a Quick Start panel that isn't on localhost, such as https://panel.example.com.
# Run it again to update. uninstall-helper.sh removes everything this adds.
set -eu

repo="KaspaSilver/KaChat-NFC"
base="https://github.com/${repo}/releases/latest/download"
label="app.kachat.nfc.helper"
install_dir="${HOME}/Library/Application Support/KaChat-NFC"
plist="${HOME}/Library/LaunchAgents/${label}.plist"

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This installer is for macOS. On Linux, Kaspa Quick Start reaches the reader through Docker." >&2
    exit 1
fi
case "$(uname -m)" in
    arm64) asset="kachat-nfc-darwin-arm64" ;;
    x86_64) asset="kachat-nfc-darwin-amd64" ;;
    *) echo "Unsupported Mac: $(uname -m)" >&2; exit 1 ;;
esac

temp="$(mktemp -d)"
trap 'rm -rf "$temp"' EXIT

echo "Downloading the KaChat-NFC helper..."
curl -fsSL -o "${temp}/${asset}" "${base}/${asset}"
curl -fsSL -o "${temp}/SHA256SUMS" "${base}/SHA256SUMS"

echo "Checking its hash..."
expected="$(awk -v name="$asset" '$2 == name { print $1 }' "${temp}/SHA256SUMS")"
actual="$(shasum -a 256 "${temp}/${asset}" | awk '{ print $1 }')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "The download doesn't match the published hash, so nothing was installed." >&2
    exit 1
fi

mkdir -p "$install_dir" "$(dirname "$plist")"
launchctl bootout "gui/$(id -u)/${label}" 2>/dev/null || true
install -m 755 "${temp}/${asset}" "${install_dir}/kachat-nfc"

origin_arguments=""
if [ -n "${KACHAT_NFC_ORIGIN:-}" ]; then
    origin_arguments="<string>--allow-origin</string><string>${KACHAT_NFC_ORIGIN}</string>"
fi

cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${install_dir}/kachat-nfc</string>
    <string>serve</string>
    ${origin_arguments}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF

launchctl bootstrap "gui/$(id -u)" "$plist"

attempt=0
while [ "$attempt" -lt 10 ]; do
    if curl -fsS -o /dev/null "http://127.0.0.1:18421/v1/status"; then
        echo "The KaChat-NFC helper is running. Go back to the Quick Start panel."
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done
echo "The helper was installed but didn't answer. Check that nothing else is using port 18421." >&2
exit 1
