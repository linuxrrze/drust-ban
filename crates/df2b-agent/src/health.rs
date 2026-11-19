//! What the agent reports about its own health in heartbeats: per-source
//! throughput, lag and errors, and whether the firewall backend works.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::{DateTime, Utc};
use df2b_firewall::{BanEntry, FirewallBackend};
use df2b_proto::v1;
use df2b_sources::{SourceBatch, SourceErrors};
use ipnet::IpNet;

#[derive(Debug, Default, Clone, Copy)]
struct Counters {
    lines: u64,
    /// Largest lag / backlog seen since the last report.
    lag_ms: u64,
    backlog: u64,
}

/// Per-source counters, read (and reset) once per heartbeat.
#[derive(Debug)]
pub struct SourceHealth {
    pub errors: Arc<SourceErrors>,
    inner: Mutex<(Instant, HashMap<String, Counters>)>,
}

impl Default for SourceHealth {
    fn default() -> Self {
        Self {
            errors: Arc::default(),
            inner: Mutex::new((Instant::now(), HashMap::new())),
        }
    }
}

impl SourceHealth {
    fn lock(&self) -> std::sync::MutexGuard<'_, (Instant, HashMap<String, Counters>)> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A source that is (re)started: listed even before its first line.
    pub fn start(&self, source: &str) {
        self.errors.clear(source);
        self.lock().1.entry(source.to_owned()).or_default();
    }

    /// A source that was stopped on purpose (central jail removed).
    pub fn stop(&self, source: &str) {
        self.errors.clear(source);
        self.lock().1.remove(source);
    }

    /// Records a processed batch. Lag: how old its newest line is (sources
    /// that know event times).
    pub fn record(&self, b: &SourceBatch, now: DateTime<Utc>) {
        let lag = b
            .lines
            .iter()
            .filter_map(|l| l.ts)
            .max()
            .map(|ts| u64::try_from((now - ts).num_milliseconds()).unwrap_or(0));
        let mut g = self.lock();
        let c = g.1.entry(b.source.to_string()).or_default();
        c.lines += b.lines.len() as u64;
        if let Some(lag) = lag {
            c.lag_ms = c.lag_ms.max(lag);
        }
        if let Some(backlog) = b.backlog {
            c.backlog = c.backlog.max(backlog);
        }
    }

    /// Status per source since the last call, sorted by name; resets the
    /// counters. A source without lines in the interval is caught up.
    pub fn report(&self) -> Vec<v1::SourceStatus> {
        self.build(true)
    }

    /// Like [`Self::report`] without resetting (local status queries).
    pub fn peek(&self) -> Vec<v1::SourceStatus> {
        self.build(false)
    }

    fn build(&self, reset: bool) -> Vec<v1::SourceStatus> {
        let mut g = self.lock();
        let secs = g.0.elapsed().as_secs_f64().max(0.001);
        if reset {
            g.0 = Instant::now();
        }
        let mut out: Vec<_> =
            g.1.iter_mut()
                .map(|(name, c)| {
                    let taken = if reset { std::mem::take(c) } else { *c };
                    v1::SourceStatus {
                        name: name.clone(),
                        lines_per_second: (taken.lines as f64 / secs).round() as u64,
                        lag_ms: taken.lag_ms,
                        backlog_bytes: taken.backlog,
                        error: self.errors.get(name).unwrap_or_default(),
                    }
                })
                .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// Last results of firewall operations and of the periodic check.
#[derive(Debug, Default)]
pub struct FirewallHealth {
    /// Failed ban/unban/setup, until one succeeds again.
    op_error: Mutex<Option<String>>,
    /// Failed [`FirewallBackend::check`], until one succeeds.
    check_error: Mutex<Option<String>>,
}

impl FirewallHealth {
    fn set(slot: &Mutex<Option<String>>, r: &anyhow::Result<()>) {
        *slot.lock().unwrap_or_else(|e| e.into_inner()) =
            r.as_ref().err().map(|e| format!("{e:#}"));
    }

    /// `None`: healthy.
    pub fn error(&self) -> Option<String> {
        let get = |m: &Mutex<Option<String>>| m.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match (get(&self.op_error), get(&self.check_error)) {
            (None, None) => None,
            (a, b) => Some(a.into_iter().chain(b).collect::<Vec<_>>().join("; ")),
        }
    }
}

/// A backend that records the outcome of every call in [`FirewallHealth`].
pub struct Monitored {
    pub inner: Arc<dyn FirewallBackend>,
    pub health: Arc<FirewallHealth>,
}

impl Monitored {
    fn op(&self, r: anyhow::Result<()>) -> anyhow::Result<()> {
        FirewallHealth::set(&self.health.op_error, &r);
        r
    }
}

impl FirewallBackend for Monitored {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn ensure_setup(&self) -> anyhow::Result<()> {
        self.op(self.inner.ensure_setup())
    }

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
        self.op(self.inner.ban(entries))
    }

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
        self.op(self.inner.unban(nets))
    }

    fn check(&self) -> anyhow::Result<()> {
        let r = self.inner.check();
        FirewallHealth::set(&self.health.check_error, &r);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use df2b_sources::LogLine;

    fn batch(
        source: &str,
        n: usize,
        ts: Option<DateTime<Utc>>,
        backlog: Option<u64>,
    ) -> SourceBatch {
        let line = LogLine {
            source: Arc::from(source),
            ts,
            line: "x".into(),
        };
        SourceBatch {
            source: Arc::from(source),
            lines: vec![line; n],
            position: None,
            backlog,
            gone: None,
        }
    }

    #[test]
    fn source_counters() {
        let h = SourceHealth::default();
        h.start("journal");
        h.start("files");
        h.start("idle");
        let now = Utc::now();
        h.record(
            &batch(
                "journal",
                10,
                Some(now - chrono::Duration::seconds(3)),
                None,
            ),
            now,
        );
        h.record(
            &batch("journal", 5, Some(now - chrono::Duration::seconds(1)), None),
            now,
        );
        h.record(&batch("files", 7, None, Some(4096)), now);
        h.errors.set("idle", "gone".into());
        let r = h.report();
        let names: Vec<_> = r.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["files", "idle", "journal"]);
        assert_eq!((r[0].backlog_bytes, r[0].lag_ms), (4096, 0));
        assert_eq!(r[1].error, "gone");
        assert!(r[2].lines_per_second >= 15, "elapsed well under a second");
        assert_eq!(r[2].lag_ms, 3000, "largest lag in the interval");
        // next interval: nothing new, counters reset
        let r = h.report();
        assert!(r
            .iter()
            .all(|s| s.lines_per_second == 0 && s.lag_ms == 0 && s.backlog_bytes == 0));
        h.stop("idle");
        h.start("files");
        assert_eq!(h.report().len(), 2);
        assert!(h.errors.get("idle").is_none());
    }

    struct Flaky(std::sync::atomic::AtomicBool);
    impl FirewallBackend for Flaky {
        fn name(&self) -> &'static str {
            "flaky"
        }
        fn ensure_setup(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn ban(&self, _: &[BanEntry]) -> anyhow::Result<()> {
            if self.0.load(std::sync::atomic::Ordering::Relaxed) {
                anyhow::bail!("nft failed")
            }
            Ok(())
        }
        fn unban(&self, _: &[IpNet]) -> anyhow::Result<()> {
            Ok(())
        }
        fn check(&self) -> anyhow::Result<()> {
            anyhow::bail!("table gone")
        }
    }

    #[test]
    fn firewall_health() {
        let inner = Arc::new(Flaky(true.into()));
        let m = Monitored {
            inner: inner.clone(),
            health: Arc::default(),
        };
        assert_eq!(m.health.error(), None);
        assert!(m.ban(&[]).is_err());
        assert_eq!(m.health.error().as_deref(), Some("nft failed"));
        let _ = m.check();
        assert_eq!(m.health.error().as_deref(), Some("nft failed; table gone"));
        inner.0.store(false, std::sync::atomic::Ordering::Relaxed);
        m.ban(&[]).unwrap();
        assert_eq!(m.health.error().as_deref(), Some("table gone"));
    }
}
