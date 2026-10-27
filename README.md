# simple-ssh-cli

Kommandozeilenprogramm auf Basis von [simple-ssh-lib](https://github.com/Andie2302/simple-ssh-lib).
Es soll vor allem eines: die Bibliothek **gegen echte SSH-Server** ausprobieren und prüfen –
und nebenbei als schlanker SSH-Client taugen.

> Status: Meilenstein 1 von 7. Aktuell gibt es `hostkey` und `check`. `exec`, `shell`, `sftp`
> und ein eingebauter `selftest` folgen. Linux und macOS; Windows wird nicht unterstützt.

## Was die Bibliothek (und damit dieses Programm) kann – und was nicht

Genau ein Satz moderner Algorithmen, keine Verhandlung, keine Umwege:
`curve25519-sha256` (mit Strict KEX), Host-Key `ssh-ed25519`, `chacha20-poly1305@openssh.com`,
Anmeldung ausschließlich per **ed25519-Schlüssel** im OpenSSH-Format (auch mit Passphrase).
Kein Passwort-Login, kein Agent, kein Forwarding, kein SCP. Bietet ein Server etwas davon nicht,
gibt es eine klare Fehlermeldung statt eines stillen Fallbacks.

## Installation

```sh
cargo install --git https://github.com/Andie2302/simple-ssh-cli
```

## Benutzung

```sh
# Fingerprint des Servers anzeigen (wie `ssh-keygen -lf`), ohne ihm zu vertrauen
simple-ssh-cli hostkey anna@server.example:22

# Verbindung und Anmeldung prüfen
simple-ssh-cli check anna@server.example
```

Ziel ist `[benutzer@]host[:port]`; IPv6 in eckigen Klammern: `[::1]:22`. Ohne Benutzer wird
`$USER` genommen.

| Option | Bedeutung |
|---|---|
| `-i, --identity <datei>` | Schlüssel, Standard `~/.ssh/id_ed25519` |
| `--passphrase-file <datei>` | Passphrase aus der ersten Zeile dieser Datei |
| `--known-hosts <datei>` | eigene Host-Key-Datei, Standard `~/.config/simple-ssh-cli/known_hosts` |
| `--accept-new` | unbekannten Server nach erfolgreicher Anmeldung speichern |
| `--fingerprint SHA256:…` | erwarteter Fingerprint; hat Vorrang, die Datei bleibt unberührt |
| `--timeout <s>` | Frist für Verbindung, Handshake und Anmeldung (Standard 30) |
| `-v, --verbose` | ausführlichere Ausgabe auf stderr |

Die Optionen dürfen auch hinter dem Befehl stehen.

### Passphrase

Ist der Schlüssel geschützt, wird die Passphrase der Reihe nach aus `SSH_KEY_PASSPHRASE`, aus
`--passphrase-file` oder per Rückfrage im Terminal (ohne Echo, drei Versuche) geholt. Als
Argument kann sie nicht übergeben werden (sie stünde in der Prozessliste).

### Host-Key-Prüfung

* **Bekannt** (Eintrag in der `known_hosts`-Datei dieses Programms): weiter.
* **Unbekannt**: Abbruch mit Exit-Code 2 und Anzeige des Fingerprints. Prüfe ihn über einen
  zweiten Weg, z.B. `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` auf dem Server. Mit
  `--accept-new` wird der Server **nach erfolgreicher Anmeldung** gespeichert.
* **Geändert**: Abbruch mit Exit-Code 3, immer – auch mit `--accept-new`. Die Datei wird nie
  automatisch verändert; ist der Wechsel gewollt, entfernst du die alte Zeile von Hand.

Die Datei hat das Format `host SHA256:…` (bei anderem Port `[host]:port SHA256:…`), Rechte 0600.
Sie ist unabhängig von `~/.ssh/known_hosts`.

### Exit-Codes

| Code | Bedeutung |
|---|---|
| 0 | Erfolg |
| 1 | allgemeiner Fehler (Verbindung, Frist, Schlüsseldatei, falsche Passphrase, …) |
| 2 | Host-Key unbekannt |
| 3 | Host-Key geändert oder passt nicht zu `--fingerprint` |
| 4 | Anmeldung fehlgeschlagen |
| 64 | falsche Bedienung (Argumente) |

## Tests

```sh
sudo apt install openssh-server     # für die Integrationstests nötig
cargo test
```

Die Integrationstests starten einen eigenen `sshd` auf `127.0.0.1` und rufen das Programm auf.
Ohne `sshd` überspringen sie sich.

## Lizenz

Wahlweise unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).
