# Card protocol and backup format

Everything an app needs to use a KaChat-NFC card, over NFC or a contact reader.

## The rule this is built around

The card never generates, derives or uses a wallet key. It stores bytes an app has already
encrypted and returns them after the right PIN. The applet has no random number generator and no
key objects, and `scripts/check-applet-no-keygen.sh` fails the build if either is added.

## Identifiers

| | AID |
|---|---|
| Package | `F04B41434841544E4643` |
| Applet | `F04B41434841544E464301` |

`F0` marks a proprietary ID, followed by "KACHAT" and "NFC" in ASCII. An iOS app has to list the
applet AID under `com.apple.developer.nfc.readersession.iso7816.select-identifiers`.

## Commands

Commands use class `0x80`. Selecting the applet returns the same reply as `STATUS`.

| Command | INS | P1 P2 | Data | PIN verified? | Reply |
|---|---|---|---|---|---|
| `STATUS` | `A0` | 0 | none | No | See below |
| `VERIFY PIN` | `20` | 0 | PIN | No | None |
| `SET PIN` | `21` | 0 | The PIN, 6 to 16 bytes (KaChat sends 6 digits). Only while no PIN is set | No | None |
| `WRITE BEGIN` | `D0` | Total length | none | Yes | None |
| `WRITE CHUNK` | `D1` | Offset | Up to 247 bytes, in order | Yes | None |
| `WRITE COMMIT` | `D2` | 0 | SHA-256 of the whole backup | Yes | None |
| `READ` | `B0` | Offset | none, Le is the most to return | Yes | Backup bytes. Empty at the end |
| `WIPE` | `E0` | 0 | none | Yes | None |

P1 is the high byte of a length or offset, and P2 is the low byte.

The `STATUS` reply is 7 bytes:

| Byte | Meaning |
|---|---|
| 0 | Protocol version, currently 1 |
| 1, 2 | Applet version, major and minor |
| 3 | Flags: `01` PIN set, `02` has a backup, `04` PIN blocked, `08` PIN verified now |
| 4 | PIN tries remaining |
| 5, 6 | Largest backup in bytes, currently 2048 |

Status words beyond the usual ISO 7816 ones:

| SW | Meaning |
|---|---|
| `63Cx` | Wrong PIN, x tries remaining |
| `6983` | PIN blocked after 5 wrong tries |
| `6982` | Verify the PIN first |
| `6985` | Out of order, such as a chunk with no save started, no PIN set yet, or `SET PIN` once a PIN is set |
| `6A80` | The commit's hash doesn't match, or the PIN is the wrong length |
| `6A88` | There's no backup |

### Behaviour to rely on

- **Saving is all or nothing.** A save goes beside the current backup and replaces it only on a
  commit whose hash matches. Pulling the card away at any point leaves the old backup, and the save
  has to start again.
- **Verification ends with the session.** Deselecting the applet, removing the card or losing power
  clears it.
- **The PIN is set once.** `SET PIN` works only while no PIN is set, and a set PIN can't be changed,
  even after verifying it. Applet 1.0 allowed a change after verifying; 1.1 doesn't.
- **A blocked or forgotten PIN can't be recovered.** Reusing the card means reinstalling the applet
  with the admin key, which erases the backup and PIN. Kaspa Quick Start's NFC Card page does this
  with **Reset this card**.

## Backup format

The card doesn't read this. Apps must follow it so a card works across apps.

The bytes on the card are:

| Offset | Length | Content |
|---|---|---|
| 0 | 4 | Magic, ASCII `KNB1` |
| 4 | 4 | PBKDF2 iterations, big endian. At least 600,000 |
| 8 | 16 | Random salt |
| 24 | 12 | Random nonce |
| 36 | Rest | AES-256-GCM ciphertext, then its 16-byte tag |

- The key is PBKDF2-HMAC-SHA512 of the card's PIN as UTF-8, NFKD normalized, with that salt and
  count, 32 bytes long. The same PIN unlocks the card with `VERIFY PIN`; there's no separate
  password.
- Use the first 36 bytes as the GCM additional authenticated data.
- Generate the salt and nonce on the phone or computer, new for every save. Never ask the card.
- Read the backup back and decrypt it after every save, before telling the user it worked.

The plaintext is UTF-8 JSON:

```json
{
  "version": 2,
  "words": ["abandon", "..."],
  "family": "kaspaStandard",
  "chattingAddressIndex": 0,
  "chattingAddress": "kaspa:...",
  "alias": "My Account"
}
```

- **The BIP39 passphrase is never in the backup.** KaChat only offers a card backup for an account
  that has one, and a restore asks for the PIN and then for the passphrase, typed in.
- `chattingAddress` is the account's chatting address. A restore derives it again from the words,
  the typed passphrase, `family` and `chattingAddressIndex`, and a mismatch means the passphrase
  was mistyped.
- `family` is one of `kaspaStandard`, `kaspaLegacy972`, `chainge` or `oneKey`. An app should ignore
  keys it doesn't know.
- Version 1 carried an optional `passphrase` and no `chattingAddress`.

## What protects what

| Threat | Protection |
|---|---|
| Someone picks up the card | 5 PIN tries, then the PIN is blocked and the backup can't be read |
| Someone records the NFC traffic, including the PIN | Only the passphrase. The recording holds the PIN and the encrypted backup, so they get the seed words |
| Someone extracts the chip's memory | Only the passphrase. A 6-digit PIN can be guessed offline, so they get the seed words |
| Someone replaces the applet | Replace the public admin keys, which the Quick Start flow does |
| A forgotten PIN or passphrase, or a lost card | Nothing. A backup without its passphrase is useless. Keep the seed phrase and passphrase on paper too |

The seed words alone don't open the account, because the passphrase is part of the wallet. That's
why only accounts with a passphrase can back up to a card, and why the passphrase has to be strong:
anyone who gets the words can try passphrases offline.
