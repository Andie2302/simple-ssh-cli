//! Interaktive `sftp`-Sitzung unter einem Pseudo-Terminal.

mod common;

use std::process::Command;
use std::time::Duration;

use common::{Scratch, TestSshd};
use expectrl::Expect;
use expectrl::process::unix::WaitStatus;
use expectrl::session::OsSession as Session;

#[test]
fn prompt_completion_ctrl_c_and_ctrl_d() {
    let Some(sshd) = TestSshd::start() else {
        return;
    };
    let home = Scratch::new("sftp-pty-home");
    let remote = Scratch::new("sftp-pty-remote");
    std::fs::write(remote.dir.join("visible.txt"), b"x").unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_simple-ssh-cli"));
    cmd.env_clear()
        .env("HOME", &home.dir)
        .env("XDG_CONFIG_HOME", home.dir.join("cfg"))
        .env("TERM", "xterm")
        .args(["--fingerprint", &sshd.fingerprint, "-i"])
        .arg(sshd.key_plain_path())
        .arg("sftp")
        .arg(format!("{}@127.0.0.1:{}", sshd.user, sshd.port));
    let mut s = Session::spawn(cmd).expect("PTY-Start");
    s.set_expect_timeout(Some(Duration::from_secs(20)));

    s.expect("sftp> ").unwrap();
    // Tab vervollständigt den Befehl: `rmd` + Tab → `rmdir `.
    s.send("rmd\t").unwrap();
    std::thread::sleep(Duration::from_millis(300));
    s.send_line("").unwrap();
    // `rmdir ` ohne Pfad ergibt eine Fehlermeldung mit Usage; erst danach kommt der nächste Prompt.
    s.expect("Usage:").unwrap();
    s.expect("sftp> ").unwrap();

    s.send_line(format!("ls {}", remote.dir.display())).unwrap();
    if let Err(e) = s.expect("visible.txt") {
        let mut buf = [0u8; 4096];
        let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
        panic!("{e}; {:?}", String::from_utf8_lossy(&buf[..n]));
    }
    s.expect("sftp> ").unwrap();

    // Strg-C am Prompt beendet die Sitzung nicht.
    s.send(&[0x03u8][..]).unwrap();
    s.expect("sftp> ").unwrap();
    s.send_line("pwd").unwrap();
    s.expect("sftp> ").unwrap();

    // Strg-D beendet mit 0.
    s.send(&[0x04u8][..]).unwrap();
    let status = s.get_process().wait().unwrap();
    assert!(matches!(status, WaitStatus::Exited(_, 0)), "{status:?}");
}
