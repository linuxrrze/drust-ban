//! Test helpers.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Writes an executable shell script. The file is written by a child
/// process: a file this process held open for writing could be inherited
/// by a process another test thread is forking right then, and executing
/// the script would fail with ETXTBSY ("text file busy").
pub fn write_script(path: &Path, body: &str) {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$1\" && chmod 755 \"$1\"")
        .arg("sh")
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .expect("sh");
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .expect("write");
    assert!(child.wait().expect("sh").success());
}
