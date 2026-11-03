# Helper API

The helper lets Kaspa Quick Start's panel find a card and load it. It can't see a PIN, a password or
a seed, because no endpoint takes one.

- **Address:** `http://127.0.0.1:18421`
- **Who it answers:** a loopback origin on any port, plus any `--allow-origin` values. It rejects any
  other `Origin` and any non-loopback `Host`, so a website can't drive it.
- **No internet:** it never connects out. It can only write the applet built into it, so nothing
  that talks to it can supply different software.

## `GET /v1/status`

Safe to poll about every 2 seconds. It never starts an admin login.

```json
{
  "helperVersion": "v0.1.0",
  "appletVersion": "1.0",
  "appletSha256": "...",
  "readers": [
    {
      "name": "ACS ACR39U ICC Reader",
      "card": {
        "atr": "3BF81300008131FE454A434F5076323431B7",
        "chip": "NXP JCOP 4 P71 (J3R180 family)",
        "supported": true,
        "state": "blank",
        "applet": null,
        "appletVersion": "",
        "adminKeyVersion": 1,
        "adminKeysChanged": false,
        "freeMemoryBytes": 163544
      }
    }
  ]
}
```

- `readers` is empty when nothing is plugged in, and `card` is `null` when a reader is empty.
- `state` is `blank`, `loaded` or `unreadable`. `blank` means this applet isn't there. The card may
  still hold other software, and loading leaves that alone.
- `supported` is false for chips this project hasn't tested. `load` refuses those.
- `applet` is set when loaded: `version` fields, `pinSet`, `hasBackup`, `pinBlocked`,
  `triesRemaining` and `maxBackup`.
- `adminKeysChanged` is true once the public keys have been replaced.

## `POST /v1/card/load`

Writes the built-in applet and confirms it answers. Takes about 20 seconds. Send
`Content-Type: application/json`.

```json
{ "reader": "", "confirmErase": false, "adminKey": "" }
```

All fields are optional. `reader` is needed only with several cards in. `adminKey` is needed once a
card's keys have been replaced. `confirmErase` must be true to reload a card that has the applet.

```json
{ "reader": "...", "appletVersion": "1.0", "appletSha256": "...", "replaced": false }
```

## `POST /v1/card/secure`

Replaces the public admin keys with a new random key and proves the card accepts it.

```json
{ "reader": "", "adminKey": "" }
```

```json
{ "reader": "...", "adminKey": "32 HEX CHARACTERS", "adminKeyVersion": 2 }
```

**This response is the only copy of the key.** The helper doesn't store it. Without it, the applet
keeps working, but the card's software can never be updated or replaced.

## Errors

Failures return a non-2xx status and:

```json
{ "error": { "code": "wrong_admin_key", "message": "..." } }
```

| Code | Meaning | Card changed? |
|---|---|---|
| `no_reader`, `no_card`, `multiple_cards` | Plug in, or take out, what's named | No |
| `card_removed` | The card left mid-job. Load again | Possibly part-way. Loading again recovers it |
| `would_erase` | Reloading erases the PIN and backup. Ask, then send `confirmErase` | No |
| `unsupported_card` | Untested chip or unsupported login method | No |
| `wrong_admin_key`, `login_refused` | Keys don't match. Ask for the saved key | No |
| `too_many_attempts` | The helper has stopped trying this card until it restarts | No |
| `bad_admin_key` | The key isn't 32 hex characters | No |
| `secure_uncertain` | Key replacement didn't finish cleanly. `error.adminKey` holds the new key. Show it and tell the user to keep it | Possibly |
| `verify_failed`, `card_error` | Something else went wrong. `message` says what | Possibly |
| `forbidden`, `forbidden_origin`, `bad_request` | The request was refused | No |

A wrong key never sends a login: the card has to prove it holds the key first.
