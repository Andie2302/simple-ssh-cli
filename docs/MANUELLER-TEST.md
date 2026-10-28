# Manuelle Prüfung

Das Automatisierte deckt Pipes und ein Pseudo-Terminal ab. Diese Punkte brauchen ein echtes
Terminal und/oder einen echten Server. Abhaken, Auffälligkeiten mit Server-Version notieren.

## 1. Selftest gegen einen echten Server

```sh
simple-ssh-cli --accept-new selftest benutzer@server --json > selftest.json
simple-ssh-cli selftest benutzer@server --destructive
```

Erwartet: kein `FAIL`. `SKIP` bei `sftp` ist nur in Ordnung, wenn der Server wirklich kein SFTP
anbietet. Die JSON-Datei zur Auswertung weitergeben.

## 2. `shell` im Terminalemulator

Jeweils in `simple-ssh-cli shell benutzer@server`:

- [ ] `vim`: Bildschirm sauber, Mauszeiger/Einfügen funktionieren, `:q` stellt den Bildschirm her
- [ ] `top` / `htop`: Darstellung korrekt; Fenstergröße während des Laufs ändern → passt sich an
- [ ] `less /etc/services`: Blättern, `q`
- [ ] `tmux`: starten, Fenster teilen, Fenstergröße ändern
- [ ] Strg-C bricht `sleep 100` ab; Strg-Z / `fg` funktionieren
- [ ] Einfügen mehrerer Zeilen (Bracketed Paste) in der Shell und in `vim`
- [ ] Umlaute und Emoji tippen und anzeigen
- [ ] `~.` am Zeilenanfang trennt; `~?` zeigt die Hilfe; Terminal danach normal (`echo` an, Zeilenmodus)
- [ ] `kill -9` auf das Programm von außen: Terminal ggf. mit `reset` retten (bekannte Ausnahme)
- [ ] Lange Ausgabe (`seq 1 1000000`) und `cat` einer großen Datei

## 3. `sftp`

- [ ] `get`/`put` einer großen Datei (> 1 GiB) mit Fortschrittsanzeige; Strg-C bricht ab,
      `.part`-Datei verschwindet
- [ ] Interaktiv: Pfeil hoch (Verlauf), Tab nach Befehlsnamen, Strg-C am Prompt, Strg-D
- [ ] Datei mit Leerzeichen und Umlauten im Namen

## 4. macOS

- [ ] Release-Binary startet, `check`, `exec`, `shell`, `sftp ls`, `selftest` laufen
