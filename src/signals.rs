//! Signalnamen (wie sie `exit-signal` liefert) auf Signalnummern abbilden (Linux-Nummerierung).

/// Nummer zum Namen (`KILL`, `SIGKILL`, `kill` …), `None` wenn unbekannt.
pub fn number(name: &str) -> Option<i32> {
    let upper = name.trim().to_ascii_uppercase();
    let short = upper.strip_prefix("SIG").unwrap_or(&upper);
    let n = match short {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" | "IOT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" | "POLL" => 29,
        "PWR" => 30,
        "SYS" => 31,
        _ => return None,
    };
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::number;

    #[test]
    fn known_names_with_and_without_prefix() {
        assert_eq!(number("KILL"), Some(9));
        assert_eq!(number("SIGKILL"), Some(9));
        assert_eq!(number("term"), Some(15));
        assert_eq!(number("SIGINT"), Some(2));
        assert_eq!(number("SEGV"), Some(11));
        assert_eq!(number("PIPE"), Some(13));
        assert_eq!(number("SYS"), Some(31));
    }

    #[test]
    fn unknown_names_are_none() {
        assert_eq!(number(""), None);
        assert_eq!(number("NOPE"), None);
        assert_eq!(number("SIG"), None);
        assert_eq!(number("RTMIN+3"), None);
    }
}
