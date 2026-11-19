//! A firewall backend that runs a program (`firewall = "exec"`), for
//! anything without a built-in backend (a hardware firewall's API, a cloud
//! security group, a local tool).
//!
//! The program (absolute path, no shell, cleared environment except PATH,
//! 60 s timeout) is called with the operation as its last argument:
//!
//! - `setup`: once at start; the agent then re-applies its active bans
//! - `ban`: lines `PREFIX TIMEOUT` on stdin (seconds; 0 = permanent)
//! - `unban`: lines `PREFIX` on stdin
//! - `check`: health check (exit 0 = healthy, stderr says why not)
//! - `list`: print the banned prefixes, one per line; exit status 2 means
//!   "cannot list" (then the agent does not reconcile)
//!
//! Exit 0 is success; anything else is a failure (stderr is logged).

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use ipnet::IpNet;

use crate::{BanEntry, FirewallBackend};

const TIMEOUT: Duration = Duration::from_secs(60);
/// `list`: "this program cannot list".
const CANNOT_LIST: i32 = 2;

#[derive(Debug, Clone)]
pub struct Exec {
    command: Vec<String>,
    timeout: Duration,
}

/// Result of one run: exit code (None: signal) and output.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Exec {
    /// `command`: program (absolute path) and its leading arguments.
    pub fn new(command: Vec<String>) -> anyhow::Result<Self> {
        match command.first() {
            Some(p) if std::path::Path::new(p).is_absolute() => {}
            Some(_) => bail!("firewall_exec: the program must be an absolute path"),
            None => bail!("firewall_exec: no program given"),
        }
        Ok(Self {
            command,
            timeout: TIMEOUT,
        })
    }

    #[cfg(test)]
    fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    fn run(&self, op: &str, input: &str) -> anyhow::Result<Run> {
        let mut child = Command::new(&self.command[0])
            .args(&self.command[1..])
            .arg(op)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // its own process group: what it starts is killed with it
            .process_group(0)
            .spawn()
            .with_context(|| format!("starting {}", self.command[0]))?;
        let pgid = i32::try_from(child.id()).unwrap_or(0);
        let kill_group = || {
            if pgid > 0 {
                // SAFETY: plain syscall; a negative pid is the group
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
        };
        // feed stdin and drain stdout/stderr on threads: no pipe deadlock
        let mut stdin = child.stdin.take().expect("piped");
        let input = input.to_owned();
        let feeder = std::thread::spawn(move || {
            let _ = stdin.write_all(input.as_bytes());
        });
        let mut out_pipe = child.stdout.take().expect("piped");
        let err_pipe = child.stderr.take().expect("piped");
        let out_t = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out_pipe.read_to_string(&mut s);
            s
        });
        let err_t = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err_pipe.take(64 * 1024).read_to_string(&mut s);
            s
        });
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if start.elapsed() > self.timeout {
                kill_group();
                let _ = child.wait();
                bail!(
                    "{} {op}: timed out after {:?}",
                    self.command[0],
                    self.timeout
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        // something it started in the background may still hold the
        // pipes: wait a little, then kill the group so the readers end
        let done = || out_t.is_finished() && err_t.is_finished() && feeder.is_finished();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !done() {
            kill_group();
        }
        let _ = feeder.join();
        Ok(Run {
            code: status.code(),
            stdout: out_t.join().unwrap_or_default(),
            stderr: err_t.join().unwrap_or_default(),
        })
    }

    fn ok(&self, op: &str, input: &str) -> anyhow::Result<()> {
        let r = self.run(op, input)?;
        if r.code != Some(0) {
            bail!(
                "{} {op} failed ({}): {}",
                self.command[0],
                r.code.map_or("signal".to_owned(), |c| format!("exit {c}")),
                r.stderr.trim().chars().take(500).collect::<String>()
            );
        }
        Ok(())
    }
}

impl FirewallBackend for Exec {
    fn name(&self) -> &'static str {
        "exec"
    }

    fn ensure_setup(&self) -> anyhow::Result<()> {
        self.ok("setup", "")
    }

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let input: String = entries
            .iter()
            .map(|e| {
                format!(
                    "{} {}\n",
                    e.net.trunc(),
                    e.timeout.map_or(0, |t| t.as_secs().max(1))
                )
            })
            .collect();
        self.ok("ban", &input)
    }

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }
        let input: String = nets.iter().map(|n| format!("{}\n", n.trunc())).collect();
        self.ok("unban", &input)
    }

    fn check(&self) -> anyhow::Result<()> {
        self.ok("check", "")
    }

    fn list(&self) -> anyhow::Result<Option<Vec<IpNet>>> {
        let r = self.run("list", "")?;
        match r.code {
            Some(0) => {}
            Some(CANNOT_LIST) => return Ok(None),
            c => bail!(
                "{} list failed ({c:?}): {}",
                self.command[0],
                r.stderr.trim().chars().take(500).collect::<String>()
            ),
        }
        r.stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.parse::<IpNet>()
                    .or_else(|_| l.parse::<std::net::IpAddr>().map(IpNet::from))
                    .map(|n| n.trunc())
                    .with_context(|| format!("{} list: {l:?} is not a prefix", self.command[0]))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(tag: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("df2b-fwexec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("fw");
        crate::testutil::write_script(&p, body);
        (dir, p)
    }

    #[test]
    fn operations() {
        let (dir, p) = script(
            "ops",
            r#"log="$(dirname "$0")/log"
echo "$1 $2 HOME=${HOME:-none}" >> "$log"
case "$2" in
  ban|unban) cat >> "$log" ;;
  list) echo 192.0.2.7; echo 2001:db8::/64 ;;
  check) echo "table gone" >&2; exit 1 ;;
esac"#,
        );
        let b = Exec::new(vec![p.display().to_string(), "--table=df2b".into()]).unwrap();
        b.ensure_setup().unwrap();
        b.ban(&[
            BanEntry {
                net: "192.0.2.7/32".parse().unwrap(),
                timeout: Some(Duration::from_secs(60)),
            },
            BanEntry {
                net: "2001:db8::1/64".parse().unwrap(),
                timeout: None,
            },
        ])
        .unwrap();
        b.unban(&["192.0.2.7/32".parse().unwrap()]).unwrap();
        let e = b.check().unwrap_err().to_string();
        assert!(e.contains("exit 1") && e.contains("table gone"), "{e}");
        let listed: Vec<String> = b
            .list()
            .unwrap()
            .unwrap()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(listed, ["192.0.2.7/32", "2001:db8::/64"]);
        let log = std::fs::read_to_string(dir.join("log")).unwrap();
        assert_eq!(
            log,
            "--table=df2b setup HOME=none\n\
             --table=df2b ban HOME=none\n192.0.2.7/32 60\n2001:db8::/64 0\n\
             --table=df2b unban HOME=none\n192.0.2.7/32\n\
             --table=df2b check HOME=none\n\
             --table=df2b list HOME=none\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cannot_list_bad_output_and_timeout() {
        let (d1, p) = script("nolist", "exit 2");
        assert!(Exec::new(vec![p.display().to_string()])
            .unwrap()
            .list()
            .unwrap()
            .is_none());
        let (d2, p) = script("badlist", "echo 'not a prefix'");
        assert!(Exec::new(vec![p.display().to_string()])
            .unwrap()
            .list()
            .is_err());
        let (d3, p) = script("slow", "sleep 5");
        let b = Exec::new(vec![p.display().to_string()])
            .unwrap()
            .with_timeout(Duration::from_millis(200));
        let t = Instant::now();
        assert!(b.check().unwrap_err().to_string().contains("timed out"));
        assert!(t.elapsed() < Duration::from_secs(3));
        assert!(Exec::new(vec!["fw".into()]).is_err(), "relative path");
        assert!(Exec::new(vec![]).is_err());
        for d in [d1, d2, d3] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Regression (security review): a background process holding the
    /// program's output kept the agent waiting forever.
    #[test]
    fn background_children_do_not_hang_it() {
        let (dir, p) = script("bg", "sleep 30 &\nexit 0");
        let b = Exec::new(vec![p.display().to_string()]).unwrap();
        let t = Instant::now();
        b.check().unwrap();
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let _ = std::fs::remove_dir_all(dir);
    }
}
