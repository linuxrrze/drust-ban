//! Reports waiting to be sent to the controller.
//!
//! The link task queues every observation here and sends the queue once per
//! second. Entries still unsent at that point (controller unreachable, or
//! the send failed) are written to `agent.redb` in one transaction, and
//! deleted there once sent, so a restart or crash while the controller is
//! unreachable loses at most about one second of reports. While connected,
//! the queue is normally empty after each send and nothing is written.
//!
//! At most [`MAX_PENDING`] reports are kept; when full, failure counts are
//! dropped before ban reports (those drive propagation and quorum rules),
//! oldest first.

use std::collections::VecDeque;

use df2b_proto::v1;
use prost::Message;
use tracing::{info, warn};

use crate::state::State;

pub const MAX_PENDING: usize = 10_000;

pub struct Entry {
    id: u64,
    pub obs: v1::Observation,
    /// Stored in `agent.redb`.
    saved: bool,
}

pub struct Outbox {
    queue: VecDeque<Entry>,
    next_id: u64,
    /// Saved entries that were sent or dropped since the last write.
    removed: Vec<u64>,
    dropped: u64,
    state: Option<State>,
    write_failing: bool,
}

impl Outbox {
    /// Loads reports left from an earlier run. Blocking (one read).
    pub fn open(state: Option<State>) -> Self {
        let mut this = Self {
            queue: VecDeque::new(),
            next_id: 1,
            removed: Vec::new(),
            dropped: 0,
            state,
            write_failing: false,
        };
        let Some(st) = &this.state else {
            return this;
        };
        let saved = match st.load_reports() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "cannot load unsent reports");
                return this;
            }
        };
        for (id, bytes) in saved {
            this.next_id = this.next_id.max(id + 1);
            match v1::Observation::decode(bytes.as_slice()) {
                Ok(obs) => this.insert(Entry {
                    id,
                    obs,
                    saved: true,
                }),
                Err(e) => {
                    warn!(id, error = %e, "dropping unreadable saved report");
                    this.removed.push(id);
                }
            }
        }
        if !this.queue.is_empty() {
            info!(
                count = this.queue.len(),
                "unsent reports from the previous run queued"
            );
        }
        this
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn push(&mut self, obs: v1::Observation) {
        let id = self.next_id;
        self.next_id += 1;
        self.insert(Entry {
            id,
            obs,
            saved: false,
        });
    }

    fn insert(&mut self, e: Entry) {
        if self.queue.len() >= MAX_PENDING {
            let i = self
                .queue
                .iter()
                .position(|p| !p.obs.locally_banned)
                .unwrap_or(0);
            if let Some(old) = self.queue.remove(i) {
                self.forget(old);
            }
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                warn!(
                    dropped = self.dropped,
                    "controller unreachable, dropping old reports"
                );
            }
        }
        self.queue.push_back(e);
    }

    fn forget(&mut self, e: Entry) {
        if e.saved {
            self.removed.push(e.id);
        }
    }

    /// Takes up to `n` reports from the front; hand them back with
    /// [`Outbox::sent`] or [`Outbox::unsent`].
    pub fn take(&mut self, n: usize) -> Vec<Entry> {
        let n = n.min(self.queue.len());
        self.queue.drain(..n).collect()
    }

    pub fn sent(&mut self, batch: Vec<Entry>) {
        for e in batch {
            self.forget(e);
        }
    }

    /// Puts a batch back at the front, in its order.
    pub fn unsent(&mut self, batch: Vec<Entry>) {
        for e in batch.into_iter().rev() {
            self.queue.push_front(e);
        }
    }

    /// Writes reports not yet stored and deletes those sent or dropped,
    /// in one transaction; nothing to do: no write. Failures are logged
    /// and retried on the next call.
    pub async fn persist(&mut self) {
        let Some(st) = self.state.clone() else {
            self.removed.clear();
            return;
        };
        let add: Vec<(u64, Vec<u8>)> = self
            .queue
            .iter()
            .filter(|e| !e.saved)
            .map(|e| (e.id, e.obs.encode_to_vec()))
            .collect();
        if add.is_empty() && self.removed.is_empty() {
            return;
        }
        let remove = std::mem::take(&mut self.removed);
        let result = tokio::task::spawn_blocking(move || {
            let r = st.save_reports(&add, &remove);
            (r, remove)
        })
        .await;
        match result {
            Ok((Ok(()), _)) => {
                // the queue did not change while writing (`&mut self`)
                for e in self.queue.iter_mut() {
                    e.saved = true;
                }
                if self.write_failing {
                    info!("saving unsent reports works again");
                    self.write_failing = false;
                }
            }
            Ok((Err(e), remove)) => {
                self.removed.extend(remove);
                if !self.write_failing {
                    warn!(error = %format!("{e:#}"), "saving unsent reports failed");
                    self.write_failing = true;
                }
            }
            Err(e) => warn!(error = %e, "saving unsent reports failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("df2b-outbox-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn obs(key: &str, banned: bool) -> v1::Observation {
        v1::Observation {
            key: key.into(),
            jail: "sshd".into(),
            count: 1,
            locally_banned: banned,
            ..Default::default()
        }
    }

    fn keys(o: &Outbox) -> Vec<String> {
        o.queue.iter().map(|e| e.obs.key.clone()).collect()
    }

    #[tokio::test]
    async fn survives_reopen_and_forgets_sent() {
        let dir = tmp("reopen");
        {
            let st = State::open(&dir).unwrap();
            let mut o = Outbox::open(Some(st));
            o.push(obs("192.0.2.1", true));
            o.push(obs("192.0.2.2", false));
            o.push(obs("192.0.2.3", true));
            o.persist().await;
            // first one delivered later, the others still pending
            let b = o.take(1);
            o.sent(b);
            let b = o.take(5);
            o.unsent(b);
            o.persist().await;
            assert_eq!(keys(&o), ["192.0.2.2", "192.0.2.3"]);
        }
        let st = State::open(&dir).unwrap();
        let mut o = Outbox::open(Some(st.clone()));
        assert_eq!(keys(&o), ["192.0.2.2", "192.0.2.3"]);
        assert!(!o.queue[1].obs.key.is_empty() && o.queue[1].obs.locally_banned);
        // new ids continue after the loaded ones
        o.push(obs("192.0.2.4", false));
        o.persist().await;
        let b = o.take(10);
        o.sent(b);
        o.persist().await;
        assert!(st.load_reports().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sent_before_persist_writes_nothing() {
        let dir = tmp("nowrite");
        let st = State::open(&dir).unwrap();
        let mut o = Outbox::open(Some(st.clone()));
        o.push(obs("192.0.2.1", true));
        let b = o.take(10);
        o.sent(b);
        assert!(o.removed.is_empty());
        o.persist().await;
        assert!(st.load_reports().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn full_queue_drops_failure_counts_first() {
        let dir = tmp("full");
        let st = State::open(&dir).unwrap();
        let mut o = Outbox::open(Some(st.clone()));
        o.push(obs("ban-0", true));
        o.push(obs("fail-0", false));
        for i in 2..MAX_PENDING {
            o.push(obs(&format!("ban-{i}"), true));
        }
        o.persist().await;
        o.push(obs("ban-new", true));
        assert_eq!(o.len(), MAX_PENDING);
        assert!(!keys(&o).iter().any(|k| k == "fail-0"));
        // only ban reports left: the oldest goes
        o.push(obs("ban-newer", true));
        assert_eq!(o.queue.front().unwrap().obs.key, "ban-2");
        o.persist().await;
        let on_disk = st.load_reports().unwrap();
        assert_eq!(on_disk.len(), MAX_PENDING);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn without_state_keeps_memory_queue() {
        let mut o = Outbox::open(None);
        o.push(obs("192.0.2.1", true));
        o.persist().await;
        assert_eq!(o.len(), 1);
        assert!(!o.is_empty());
    }
}
