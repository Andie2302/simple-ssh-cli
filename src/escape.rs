//! Escape-Zeichen der Shell (wie bei OpenSSH): nur am Zeilenanfang wirksam.
//!
//! `~.` trennt die Verbindung, `~~` sendet ein einzelnes `~`, `~?` zeigt eine Hilfe, `~` mit einem
//! anderen Zeichen wird unverändert durchgereicht. Das `~` wird bis zum nächsten Zeichen
//! zurückgehalten.

/// Ereignis, das der Automat meldet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Verbindung trennen.
    Disconnect,
    /// Hilfe anzeigen.
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    LineStart,
    Normal,
    /// Escape-Zeichen am Zeilenanfang gesehen, noch nicht weitergegeben.
    Escape,
}

/// Zustandsautomat für die Eingabe.
#[derive(Debug)]
pub struct Escape {
    enabled: bool,
    ch: u8,
    state: State,
}

impl Escape {
    /// `enabled = false` reicht alles unverändert durch.
    pub fn new(enabled: bool, ch: u8) -> Self {
        Self {
            enabled,
            ch,
            state: State::LineStart,
        }
    }

    /// Verarbeitet ein Eingabestück. Was an den Server geht, wird an `out` angehängt. Nach
    /// `Disconnect` wird der Rest der Eingabe verworfen.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Vec<Event> {
        let mut events = Vec::new();
        if !self.enabled {
            out.extend_from_slice(input);
            return events;
        }
        for &b in input {
            match self.state {
                State::LineStart if b == self.ch => self.state = State::Escape,
                State::LineStart | State::Normal => {
                    out.push(b);
                    self.state = Self::after(b);
                }
                State::Escape => match b {
                    b'.' => {
                        events.push(Event::Disconnect);
                        return events;
                    }
                    b'?' => {
                        events.push(Event::Help);
                        self.state = State::LineStart;
                    }
                    _ if b == self.ch => {
                        out.push(b);
                        self.state = State::Normal;
                    }
                    _ => {
                        out.push(self.ch);
                        out.push(b);
                        self.state = Self::after(b);
                    }
                },
            }
        }
        events
    }

    fn after(b: u8) -> State {
        if b == b'\r' || b == b'\n' {
            State::LineStart
        } else {
            State::Normal
        }
    }
}

/// Hilfetext für `~?` (Zeilenenden für den Raw-Mode).
pub fn help(ch: u8) -> String {
    let c = char::from(ch);
    format!(
        "\r\nUnterstützte Escape-Folgen (nur am Zeilenanfang):\r\n  {c}.  Verbindung trennen\r\n  {c}{c}  ein einzelnes {c} senden\r\n  {c}?  diese Hilfe\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    type Case<'a> = (&'a [&'a [u8]], &'a [u8], &'a [Event]);

    /// Führt die Eingabestücke durch einen frischen Automaten.
    fn run(chunks: &[&[u8]]) -> (Vec<u8>, Vec<Event>) {
        let mut esc = Escape::new(true, b'~');
        let mut out = Vec::new();
        let mut events = Vec::new();
        for c in chunks {
            events.extend(esc.feed(c, &mut out));
        }
        (out, events)
    }

    #[test]
    fn table() {
        let cases: &[Case] = &[
            (&[b"abc"], b"abc", &[]),
            (&[b"~."], b"", &[Event::Disconnect]),
            (&[b"~~"], b"~", &[]),
            (&[b"~?"], b"", &[Event::Help]),
            (&[b"~x"], b"~x", &[]),
            (&[b"a~."], b"a~.", &[]),
            (&[b"a~b"], b"a~b", &[]),
            (&[b"ls\r~."], b"ls\r", &[Event::Disconnect]),
            (&[b"ls\n~."], b"ls\n", &[Event::Disconnect]),
            (&[b"ls\r~~"], b"ls\r~", &[]),
            (&[b"~"], b"", &[]),
            (&[b"~", b"."], b"", &[Event::Disconnect]),
            (&[b"~", b"x"], b"~x", &[]),
            (&[b"~", b"~", b"."], b"~.", &[]),
            (&[b"~\r~."], b"~\r", &[Event::Disconnect]),
            (&[b"~?~."], b"", &[Event::Help, Event::Disconnect]),
            (&[b"~.rest"], b"", &[Event::Disconnect]),
            (&[b"~~~."], b"~~.", &[]),
        ];
        for (chunks, out, events) in cases {
            let (o, e) = run(chunks);
            assert_eq!(&o, out, "Ausgabe für {chunks:?}");
            assert_eq!(&e, events, "Ereignisse für {chunks:?}");
        }
    }

    #[test]
    fn disabled_passes_everything_through() {
        let mut esc = Escape::new(false, b'~');
        let mut out = Vec::new();
        assert!(esc.feed(b"~.\r~?", &mut out).is_empty());
        assert_eq!(out, b"~.\r~?");
    }

    #[test]
    fn custom_escape_char() {
        let mut esc = Escape::new(true, b'#');
        let mut out = Vec::new();
        assert_eq!(esc.feed(b"~.\r#.", &mut out), vec![Event::Disconnect]);
        assert_eq!(out, b"~.\r");
    }
}
