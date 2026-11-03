# The helper for Linux machines, where a container can reach a USB reader. It's meant for a private
# Docker network behind Kaspa Quick Start's backend, with no published port.
#
#   docker build --build-arg VERSION=v0.1.0 -t kachat-nfc docker/
#   docker run --rm --network <private> --device /dev/bus/usb kachat-nfc
FROM debian:12-slim

ARG VERSION=latest

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends pcscd libccid curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The hash is checked before the binary is kept, the same as the Mac and Windows installers.
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    if [ "$VERSION" = "latest" ]; then base="https://github.com/KaspaSilver/KaChat-NFC/releases/latest/download"; \
    else base="https://github.com/KaspaSilver/KaChat-NFC/releases/download/$VERSION"; fi; \
    cd /tmp; \
    curl -fsSL -o "kachat-nfc-linux-$arch" "$base/kachat-nfc-linux-$arch"; \
    curl -fsSL -o SHA256SUMS "$base/SHA256SUMS"; \
    grep " kachat-nfc-linux-$arch\$" SHA256SUMS | sha256sum -c -; \
    install -m 755 "kachat-nfc-linux-$arch" /usr/local/bin/kachat-nfc; \
    rm -f "kachat-nfc-linux-$arch" SHA256SUMS

ENTRYPOINT ["sh", "-c", "pcscd --disable-polkit --foreground & exec kachat-nfc serve --listen 0.0.0.0:18421 --internal"]
