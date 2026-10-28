//! Hilfe, Version und Bedienfehler (brauchen keinen Server).

use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"))
        .args(args)
        .output()
        .expect("Programm starten");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn version_and_top_level_help() {
    let (code, out, _) = run(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("simple-ssh-cli "), "{out}");

    let (code, out, _) = run(&["--help"]);
    assert_eq!(code, 0);
    for command in ["hostkey", "check", "exec", "shell", "sftp", "selftest"] {
        assert!(out.contains(command), "{command} fehlt:\n{out}");
    }
    assert!(out.contains("Exit-Codes:"), "{out}");
    assert!(out.contains("Beispiele:"), "{out}");
}

#[test]
fn every_command_has_help() {
    for (command, expected) in [
        ("hostkey", "Fingerprint"),
        ("check", "Anmeldung"),
        ("exec", "--no-stdin"),
        ("shell", "--escape-char"),
        ("sftp", "chmod"),
        ("selftest", "--destructive"),
    ] {
        let (code, out, err) = run(&[command, "--help"]);
        assert_eq!(code, 0, "{command}: {err}");
        assert!(out.contains(expected), "{command}:\n{out}");
        assert!(
            out.contains("--fingerprint"),
            "{command} ohne globale Optionen"
        );
    }
}

#[test]
fn usage_errors_exit_with_64_not_clap_default() {
    for args in [
        &[][..],
        &["frobnicate"][..],
        &["check"][..],
        &["exec", "host"][..],
        &["check", "host:99999"][..],
        &["--timeout", "0", "check", "host"][..],
        &["shell", "host", "--escape-char", "ab"][..],
    ] {
        let (code, _, err) = run(args);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(!err.is_empty(), "{args:?}: keine Meldung");
    }
}
