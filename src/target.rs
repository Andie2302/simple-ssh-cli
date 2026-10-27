//! Verbindungsziel der Form `[benutzer@]host[:port]`.

use std::str::FromStr;

use crate::error::CliError;

/// Standardport von SSH.
pub const DEFAULT_PORT: u16 = 22;

/// Ein Ziel wie `anna@example.org:2222` oder `[::1]:22`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub user: Option<String>,
    pub host: String,
    pub port: u16,
}

impl Target {
    /// Schlüssel in der `known_hosts`-Datei, wie bei OpenSSH: `host` bei Port 22, sonst `[host]:port`.
    pub fn known_hosts_label(&self) -> String {
        if self.port == DEFAULT_PORT {
            self.host.clone()
        } else {
            format!("[{}]:{}", self.host, self.port)
        }
    }

    /// Anzeige `host:port` (IPv6 in eckigen Klammern).
    pub fn display_addr(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Benutzer aus dem Ziel, sonst `fallback` (üblicherweise aus der Umgebung).
    pub fn user_or(&self, fallback: Option<String>) -> Result<String, CliError> {
        self.user
            .clone()
            .or(fallback)
            .filter(|u| !u.is_empty())
            .ok_or_else(|| {
                CliError::usage(
                    "Kein Benutzername: gib ihn im Ziel an (benutzer@host) oder setze USER",
                )
            })
    }

    /// Benutzer aus dem Ziel, sonst aus `USER` bzw. `LOGNAME`.
    pub fn resolve_user(&self) -> Result<String, CliError> {
        self.user_or(
            std::env::var("USER")
                .ok()
                .or_else(|| std::env::var("LOGNAME").ok()),
        )
    }
}

fn valid_text(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl FromStr for Target {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (user, rest) = match input.rfind('@') {
            Some(at) => {
                let user = &input[..at];
                if !valid_text(user) {
                    return Err(format!("ungültiger Benutzername in `{input}`"));
                }
                (Some(user.to_string()), &input[at + 1..])
            }
            None => (None, input),
        };

        let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
            let close = inner
                .find(']')
                .ok_or_else(|| format!("`]` fehlt in `{input}`"))?;
            let host = &inner[..close];
            let after = &inner[close + 1..];
            let port = match after {
                "" => None,
                _ => Some(
                    after
                        .strip_prefix(':')
                        .ok_or_else(|| format!("nach `]` darf nur `:port` folgen (`{input}`)"))?,
                ),
            };
            (host, port)
        } else {
            match rest.matches(':').count() {
                0 => (rest, None),
                1 => {
                    let (h, p) = rest.split_once(':').unwrap_or((rest, ""));
                    (h, Some(p))
                }
                _ => {
                    return Err(format!(
                        "IPv6-Adressen müssen in eckigen Klammern stehen, z.B. [::1]:22 (`{input}`)"
                    ));
                }
            }
        };

        if !valid_text(host) || host.contains('/') {
            return Err(format!("ungültiger Host in `{input}`"));
        }
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return Err(format!("ungültiger Port `{p}` (erlaubt: 1-65535)")),
            },
        };
        Ok(Target {
            user,
            host: host.to_string(),
            port,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Target, String> {
        s.parse()
    }

    fn target(user: Option<&str>, host: &str, port: u16) -> Target {
        Target {
            user: user.map(str::to_string),
            host: host.into(),
            port,
        }
    }

    #[test]
    fn accepts_all_common_forms() {
        assert_eq!(parse("example.org"), Ok(target(None, "example.org", 22)));
        assert_eq!(
            parse("anna@example.org"),
            Ok(target(Some("anna"), "example.org", 22))
        );
        assert_eq!(
            parse("example.org:2222"),
            Ok(target(None, "example.org", 2222))
        );
        assert_eq!(
            parse("anna@example.org:2222"),
            Ok(target(Some("anna"), "example.org", 2222))
        );
        assert_eq!(
            parse("127.0.0.1:65535"),
            Ok(target(None, "127.0.0.1", 65535))
        );
    }

    #[test]
    fn handles_ipv6_in_brackets() {
        assert_eq!(parse("[::1]"), Ok(target(None, "::1", 22)));
        assert_eq!(parse("[::1]:2200"), Ok(target(None, "::1", 2200)));
        assert_eq!(
            parse("anna@[fe80::1]:22"),
            Ok(target(Some("anna"), "fe80::1", 22))
        );
        assert!(parse("::1").is_err(), "IPv6 ohne Klammern ist mehrdeutig");
        assert!(parse("[::1").is_err());
        assert!(parse("[::1]x").is_err());
        assert!(parse("[::1]:").is_err());
    }

    #[test]
    fn rejects_bad_ports_hosts_and_users() {
        for bad in [
            "host:0",
            "host:65536",
            "host:abc",
            "host:",
            "host:-1",
            "",
            "@host",
            "anna@",
            ":22",
            "a b",
            "anna @host",
            "host/x",
        ] {
            assert!(parse(bad).is_err(), "`{bad}` sollte abgelehnt werden");
        }
    }

    #[test]
    fn at_sign_in_user_uses_the_last_separator() {
        // Der Benutzername selbst darf kein `@` enthalten; der Parser trennt am letzten.
        assert_eq!(parse("a@b@host"), Ok(target(Some("a@b"), "host", 22)));
    }

    #[test]
    fn known_hosts_label_follows_openssh() {
        assert_eq!(
            target(None, "example.org", 22).known_hosts_label(),
            "example.org"
        );
        assert_eq!(
            target(None, "example.org", 2222).known_hosts_label(),
            "[example.org]:2222"
        );
        assert_eq!(target(None, "::1", 22).known_hosts_label(), "::1");
        assert_eq!(target(None, "::1", 2200).known_hosts_label(), "[::1]:2200");
    }

    #[test]
    fn display_addr_brackets_ipv6() {
        assert_eq!(
            target(None, "example.org", 22).display_addr(),
            "example.org:22"
        );
        assert_eq!(target(None, "::1", 22).display_addr(), "[::1]:22");
    }

    #[test]
    fn user_resolution_prefers_the_target() {
        let t = target(Some("anna"), "h", 22);
        assert_eq!(t.user_or(Some("root".into())).ok(), Some("anna".into()));
        let t = target(None, "h", 22);
        assert_eq!(t.user_or(Some("root".into())).ok(), Some("root".into()));
        assert!(t.user_or(None).is_err());
        assert!(t.user_or(Some(String::new())).is_err());
    }
}
