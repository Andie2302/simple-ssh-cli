# simple-ssh-cli

Kommandozeilenprogramm auf Basis von [simple-ssh-lib](https://github.com/Andie2302/simple-ssh-lib).
Es soll vor allem eines: die Bibliothek **gegen echte SSH-Server** ausprobieren und prüfen –
und nebenbei als schlanker SSH-Client taugen.

> Status: Meilenstein 3 von 7. Aktuell gibt es `hostkey`, `check`, `exec` und `shell`. `sftp`
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

# Befehl ausführen (Ausgabe kommt live, Exit-Code wird übernommen)
simple-ssh-cli exec anna@server.example uname -a
simple-ssh-cli exec anna@server.example 'tail -f /var/log/syslog'

# Interaktive Shell mit echtem Terminal (Beenden: `exit` oder `~.` am Zeilenanfang)
simple-ssh-cli shell anna@server.example

# Eingabe durchreichen
tar czf - ordner | simple-ssh-cli exec anna@server.example 'tar xzf - -C /tmp'
simple-ssh-cli exec anna@server.example 'cat /etc/hostname' | tr a-z A-Z
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

### `exec`

`simple-ssh-cli [OPTIONEN] exec <ziel> [--no-stdin] <befehl…>`

* Die Wörter des Befehls werden wie bei `ssh` mit Leerzeichen verbunden und von der Shell des
  Servers ausgewertet. Optionen des Programms gehören **vor** den Befehl; alles dahinter ist Teil
  des Befehls (`--` ist erlaubt).
* **Ausgabe live:** Remote-stdout geht an lokales stdout, Remote-stderr an lokales stderr, als
  rohe Bytes und sobald sie ankommen (also auch `tail -f`, Fortschrittsanzeigen, Binärdaten).
  Ein langsamer lokaler Leser bremst den Server; das Programm hält nie die ganze Ausgabe im Speicher.
* **Eingabe live:** Ist lokales stdin kein Terminal (Pipe, Datei), wird es an den Befehl
  weitergereicht; sein Ende ist EOF für den Befehl. Bei einem Terminal oder mit `--no-stdin` sieht
  der Befehl sofort EOF (interaktive Programme brauchen `shell`).
* **Host-Key zuerst:** Vor dem ersten Byte des Befehls wird der Host-Key geprüft. Bei unbekanntem
  oder geändertem Key läuft auf dem Server nichts.
* **Strg-C** schließt den Channel und beendet das Programm mit 130; ein vorzeitig geschlossenes
  lokales stdout (`… | head`) beendet es still mit 141. Ob der Remote-Befehl danach weiterläuft,
  entscheidet der Server (ohne Terminal meist: er endet beim nächsten Schreiben).
* `--keepalive <s>` erkennt eine tote Verbindung (3 verpasste Intervalle).

**Exit-Code wie bei ssh:** der Code des Remote-Befehls; endete er durch ein Signal, `128 +
Signalnummer` (z.B. 137 für KILL); 255, wenn die Verbindung verloren ging oder der Server keinen
Status meldet. Fehler vor dem Start des Befehls behalten die Codes unten. *Achtung:* liefert der
Remote-Befehl selbst 1, 2, 3, 4 oder 64, ist das vom Fehler des Programms nur an der Meldung auf
stderr zu unterscheiden (sie beginnt mit `simple-ssh-cli:`).

### `shell`

Interaktive Shell mit Pseudo-Terminal. Erst werden Host-Key geprüft, angemeldet und die Shell
geöffnet; erst danach schaltet das Programm das Terminal in den Raw-Mode und stellt es am Ende
(auch bei Fehlern, Panik, `~.` und SIGTERM/SIGHUP) wieder her. `$TERM` kommt aus der Umgebung
(Standard `xterm-256color`), die Fenstergröße wird beim Start gesendet und bei Änderungen
nachgeführt. Strg-C geht an den Server.

Escape-Folgen gelten wie bei OpenSSH nur am Zeilenanfang und nur bei interaktivem stdin:

| Eingabe | Wirkung |
|---|---|
| `~.` | Verbindung trennen (Exit-Code 255) |
| `~~` | ein einzelnes `~` senden |
| `~?` | Hilfe anzeigen |
| `~` + anderes Zeichen | beide Zeichen unverändert senden |

`--no-escape` schaltet das ab, `--escape-char <zeichen>` wählt ein anderes Zeichen. Ist stdin
kein Terminal (`befehle | simple-ssh-cli shell …`), bleibt das Terminal unberührt; am Ende der
Eingabe wird Strg-D gesendet, sobald die Shell ruhig ist. Exit-Code wie bei `exec`.

Manuell zu prüfen (nicht automatisiert): `vim`, `top`, `less`, `htop`, `tmux`, Strg-Z/`fg`,
Einfügen mit Bracketed Paste und die Fenstergröße in einem echten Terminalemulator.

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
| 0 | Erfolg (bei `exec`: Remote-Befehl lieferte 0) |
| 1 | allgemeiner Fehler (Verbindung, Frist, Schlüsseldatei, falsche Passphrase, …) |
| 2 | Host-Key unbekannt |
| 3 | Host-Key geändert oder passt nicht zu `--fingerprint` |
| 4 | Anmeldung fehlgeschlagen |
| 64 | falsche Bedienung (Argumente) |
| 130 | `exec` per Strg-C abgebrochen |
| 141 | `exec`: lokales stdout wurde geschlossen |
| 255 | `exec`/`shell`: Verbindung verloren, getrennt (`~.`) oder kein Exit-Status |

Bei `exec` und `shell` gilt zusätzlich der Code des Remote-Programms, siehe oben.

## Tests

```sh
sudo apt install openssh-server     # für die Integrationstests nötig
cargo test
```

Die Integrationstests starten einen eigenen `sshd` auf `127.0.0.1` und rufen das Programm auf.
Die Bibliothek ist auf einen festen Commit gepinnt (`Cargo.toml`).
Ohne `sshd` überspringen sie sich.

## Lizenz

Wahlweise unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).
