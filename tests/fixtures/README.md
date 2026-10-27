# Test-Schlüssel

Reine Testschlüssel (aus dem Repository `simple-ssh-lib` übernommen), sie schützen nichts.

| Datei | Inhalt | Passphrase |
|---|---|---|
| `ed25519_plain` | ed25519, unverschlüsselt | – |
| `ed25519_aes256ctr` | ed25519, `aes256-ctr` + bcrypt | `correct horse` |
