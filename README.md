# KaChat-NFC

Open source software for backing up a seed phrase you already have onto a Java Card, then restoring
it by tapping the card on your phone.

**This isn't cold storage.** The card never generates or uses keys. It holds an encrypted copy of
your existing seed behind a PIN, and your app does the encrypting. Keep your seed phrase on paper
too.

**Status: early and untested. Don't put a real seed on a card yet.**

## What's here

| Path | What it is |
|---|---|
| `applet/` | The Java Card applet that runs on the card |
| `cmd/`, `internal/` | `kachat-nfc`, the tool that writes the applet and runs the local helper |
| `docs/PROTOCOL.md` | The card's commands and the backup format, for any app to implement |
| `docs/HELPER-API.md` | The local API that Kaspa Quick Start's panel uses |
| `scripts/` | Helper installers for Mac and Windows, and the build's safety check |
| `docker/` | The helper for Linux, where a container can reach a USB reader |

## Loading a card

Most people will use the NFC Card page in [Kaspa Quick Start](https://github.com/KaspaSilver/Kaspa-Quick-Start).
It finds the reader and card, loads the software and replaces the card's public admin keys.

You can also use the command line:

```bash
kachat-nfc status
kachat-nfc load
kachat-nfc secure
```

`secure` prints a new admin key once. Save it: without it, the card keeps working, but its software
can never be updated or replaced.

## Supported hardware

- **Card:** J3R180 (NXP JCOP 4), the only chip tested so far. Other chips are refused.
- **Reader:** any PC/SC contact reader. Tested with the ACS ACR39U-UF.

## Trusting a build

GitHub Actions builds every release from this repo with pinned tools and publishes the hashes in
`SHA256SUMS`. The installers refuse a download that doesn't match. Each helper has one applet built
in and can't load anything else.

## Security

Report problems privately through this repo's Security tab. [docs/PROTOCOL.md](docs/PROTOCOL.md)
explains what protects what.

## License

[MIT](LICENSE)
