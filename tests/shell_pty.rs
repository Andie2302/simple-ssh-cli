//! `shell` unter einem Pseudo-Terminal (Raw-Mode, Strg-C, Größe, Escape-Folgen).

mod common;

use std::process::Command;
use std::time::Duration;

use common::{Scratch, TestSshd};
use expectrl::Expect;
use expectrl::process::unix::WaitStatus;
use expectrl::session::OsSession as Session;

struct Fixture {
    sshd: TestSshd,
    home: Scratch,
}

impl Fixture {
    fn new(name: &str) -> Option<Self> {
        Some(Self {
            sshd: TestSshd::start()?,
            home: Scratch::new(name),
        })
    }

    /// Die Kommandozeile `<cli> … shell <ziel>` als Text für `sh -c`.
    fn shell_line(&self, extra: &str) -> String {
        format!(
            "{} --fingerprint {} -i {} shell {} {}@127.0.0.1:{}",
            env!("CARGO_BIN_EXE_simple-ssh-cli"),
            self.sshd.fingerprint,
            self.sshd.key_plain_path().display(),
            extra,
            self.sshd.user,
            self.sshd.port,
        )
    }

    fn spawn(&self, script: &str) -> Session {
        let mut cmd = Command::new("sh");
        cmd.env_clear()
            .env("HOME", &self.home.dir)
            .env("XDG_CONFIG_HOME", self.home.dir.join("cfg"))
            .env("TERM", "xterm")
            .env("PATH", "/usr/bin:/bin")
            .arg("-c")
            .arg(script);
        let mut session = Session::spawn(cmd).expect("Prozess unter PTY starten");
        session.set_expect_timeout(Some(Duration::from_secs(20)));
        session
    }
}

/// Wartet auf einen Text, der garantiert erst durch die Shell entsteht (Marker aus Rechnung).
fn wait_for(s: &mut Session, text: &str) {
    s.expect(text)
        .unwrap_or_else(|e| panic!("`{text}` nicht gesehen: {e}"));
}

fn exit_status(s: &Session) -> i32 {
    let status = s.get_process().wait().expect("Prozessende abwarten");
    match status {
        WaitStatus::Exited(_, code) => code,
        other => panic!("unerwartet: {other:?}"),
    }
}

#[test]
fn interactive_input_output_and_exit_code() {
    let Some(f) = Fixture::new("pty-basic") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.send_line("echo r$((6*7))x").unwrap();
    wait_for(&mut s, "r42x");
    s.send_line("exit 3").unwrap();
    assert_eq!(exit_status(&s), 3);
}

#[test]
fn ctrl_c_reaches_the_server() {
    let Some(f) = Fixture::new("pty-ctrlc") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.send_line("sleep 100").unwrap();
    std::thread::sleep(Duration::from_millis(800));
    s.send(&[0x03u8][..]).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    s.send_line("echo after$((1+1))y").unwrap();
    wait_for(&mut s, "after2y");
    s.send_line("exit").unwrap();
    assert_eq!(exit_status(&s), 0);
}

#[test]
fn window_size_is_sent_at_start_and_on_change() {
    let Some(f) = Fixture::new("pty-size") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.get_process_mut().set_window_size(100, 30).unwrap();
    // SIGWINCH kommt beim Setzen; die Startgröße war die Standardgröße des PTY.
    std::thread::sleep(Duration::from_millis(800));
    s.send_line("echo S=$(stty size)=").unwrap();
    wait_for(&mut s, "S=30 100=");
    s.get_process_mut().set_window_size(132, 50).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    s.send_line("echo T=$(stty size)=").unwrap();
    wait_for(&mut s, "T=50 132=");
    s.send_line("exit").unwrap();
    assert_eq!(exit_status(&s), 0);
}

#[test]
fn tilde_dot_at_line_start_disconnects() {
    let Some(f) = Fixture::new("pty-escape") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.send_line("echo ready$((2+2))").unwrap();
    wait_for(&mut s, "ready4");
    s.send("~.").unwrap();
    wait_for(&mut s, "Verbindung getrennt");
    assert_eq!(exit_status(&s), 255);
}

#[test]
fn tilde_elsewhere_is_passed_through() {
    let Some(f) = Fixture::new("pty-tilde") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.send_line("echo a~b$((1+1))").unwrap();
    wait_for(&mut s, "a~b2");
    // `~x` am Zeilenanfang wird unverändert gesendet: `~x` ist für die Shell ein unbekannter Benutzer.
    s.send_line("echo ~~").unwrap();
    s.send_line("echo q$((3+4))q").unwrap();
    wait_for(&mut s, "q7q");
    s.send_line("exit").unwrap();
    assert_eq!(exit_status(&s), 0);
}

#[test]
fn utf8_passes_unchanged() {
    let Some(f) = Fixture::new("pty-utf8") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.send_line("echo äöü€$((1+1))").unwrap();
    wait_for(&mut s, "äöü€2");
    s.send_line("exit").unwrap();
    assert_eq!(exit_status(&s), 0);
}

#[test]
fn terminal_is_restored_after_normal_end_and_disconnect() {
    let Some(f) = Fixture::new("pty-restore") else {
        return;
    };
    for (name, keys) in [("exit", "exit\n"), ("escape", "~.")] {
        // Die Terminal-Einstellungen vor dem Start müssen danach wieder genau so vorliegen.
        let script = format!(
            "S=$(stty -g); {}; echo CODE=$?; if [ \"$(stty -g)\" = \"$S\" ]; then echo RESTORED; else echo BROKEN; fi",
            f.shell_line("")
        );
        let mut s = f.spawn(&script);
        s.send_line("echo go$((1+1))").unwrap();
        wait_for(&mut s, "go2");
        s.send(keys).unwrap();
        wait_for(&mut s, "CODE=");
        let found = s
            .expect(expectrl::Any(["RESTORED", "BROKEN"]))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(found.get(0).unwrap(), b"RESTORED", "{name}");
    }
}

#[test]
fn large_paste_and_large_output_do_not_deadlock() {
    let Some(f) = Fixture::new("pty-large") else {
        return;
    };
    let mut s = f.spawn(&f.shell_line(""));
    s.set_expect_timeout(Some(Duration::from_secs(60)));
    // Ohne Echo kommt während des Einfügens nichts zurück; das Testprogramm liest nicht mit.
    s.send_line("stty -echo; echo ok$((1+1))").unwrap();
    wait_for(&mut s, "ok2");
    s.send_line("echo cat$((1+1)); cat > /dev/null").unwrap();
    wait_for(&mut s, "cat2");
    std::thread::sleep(Duration::from_millis(300));
    let line = format!("{}\n", "x".repeat(79));
    for _ in 0..3750 {
        s.send(line.as_str()).unwrap();
    }
    s.send(&[0x04u8][..]).unwrap();
    s.send_line("seq 1 100000").unwrap();
    if let Err(e) = s.expect("100000") {
        let rest = s.expect(expectrl::Eof).map(|c| c.as_bytes().to_vec());
        let rest = rest.unwrap_or_default();
        let tail = &rest[rest.len().saturating_sub(600)..];
        panic!(
            "`100000` nicht gesehen: {e}; Rest: {:?}",
            String::from_utf8_lossy(tail)
        );
    }
    s.send_line("exit").unwrap();
    assert_eq!(exit_status(&s), 0);
}
