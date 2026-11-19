//! Request rate limit for the REST API, per client (IPv6: per /64), as a
//! token bucket: `burst` requests at once, refilled at `rate` per second.
//! Over it: 429 with Retry-After. `/api/v1/health` is exempt (monitoring),
//! as are the web UI's static files. Failed logins have their own, much
//! stricter limit (session.rs).
//!
//! Memory is bounded: idle buckets (full again) are dropped by `prune`;
//! beyond [`MAX_CLIENTS`] clients new ones share a bucket per network
//! (IPv6 /48, IPv4 /16) - one attacker keeping the table full then only
//! throttles its own networks - and beyond that one last bucket.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, Request};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub const MAX_CLIENTS: usize = 50_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ApiLimit {
    /// Requests per second, sustained; 0 = no limit.
    pub rate: u32,
    /// Requests at once.
    pub burst: u32,
}

impl Default for ApiLimit {
    fn default() -> Self {
        Self {
            rate: 20,
            burst: 200,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Debug)]
pub struct Limiter {
    limit: ApiLimit,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Per network, for clients beyond MAX_CLIENTS.
    networks: Mutex<HashMap<IpAddr, Bucket>>,
    /// Shared by everybody beyond both tables.
    overflow: Mutex<Bucket>,
}

/// IPv6 clients usually control a whole /64; IPv4-mapped addresses count
/// as IPv4.
/// The network a client key belongs to: IPv6 /48, IPv4 /16.
fn network_key(key: IpAddr) -> IpAddr {
    match key {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4([o[0], o[1], 0, 0].into())
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6([s[0], s[1], s[2], 0, 0, 0, 0, 0].into())
        }
    }
}

fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6([s[0], s[1], s[2], s[3], 0, 0, 0, 0].into())
            }
        },
        v4 => v4,
    }
}

impl Limiter {
    pub fn new(limit: ApiLimit) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            limit,
            buckets: Mutex::new(HashMap::new()),
            networks: Mutex::new(HashMap::new()),
            overflow: Mutex::new(Bucket {
                tokens: limit.burst as f64,
                at: now,
            }),
        })
    }

    fn take(&self, b: &mut Bucket, now: Instant) -> Result<(), u64> {
        let rate = self.limit.rate as f64;
        let burst = self.limit.burst.max(1) as f64;
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * rate).min(burst);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            // seconds until one token is back
            Err(((1.0 - b.tokens) / rate).ceil().max(1.0) as u64)
        }
    }

    /// `Err(retry_after_secs)` if the client is over its rate.
    pub fn check(&self, ip: IpAddr, now: Instant) -> Result<(), u64> {
        if self.limit.rate == 0 {
            return Ok(());
        }
        let key = client_key(ip);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if !buckets.contains_key(&key) && buckets.len() >= MAX_CLIENTS {
            drop(buckets);
            let net = network_key(key);
            let mut nets = self.networks.lock().unwrap_or_else(|e| e.into_inner());
            if nets.contains_key(&net) || nets.len() < MAX_CLIENTS {
                let b = nets.entry(net).or_insert(Bucket {
                    tokens: self.limit.burst.max(1) as f64,
                    at: now,
                });
                return self.take(b, now);
            }
            drop(nets);
            let mut o = self.overflow.lock().unwrap_or_else(|e| e.into_inner());
            return self.take(&mut o, now);
        }
        let b = buckets.entry(key).or_insert(Bucket {
            tokens: self.limit.burst.max(1) as f64,
            at: now,
        });
        self.take(b, now)
    }

    /// Drops buckets that are full again (their clients are idle).
    pub fn prune(&self, now: Instant) {
        let (rate, burst) = (self.limit.rate as f64, self.limit.burst.max(1) as f64);
        for m in [&self.buckets, &self.networks] {
            m.lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|_, b| b.tokens + now.duration_since(b.at).as_secs_f64() * rate < burst);
        }
    }

    #[cfg(test)]
    pub fn clients(&self) -> usize {
        self.buckets.lock().map(|b| b.len()).unwrap_or(0)
    }
}

/// Middleware: applies the limit to `/api/` except the health check.
pub async fn layer(limiter: Arc<Limiter>, req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.starts_with("/api/") && path != "/api/v1/health" {
        if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
            if let Err(secs) = limiter.check(addr.ip(), Instant::now()) {
                let mut r = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "too many requests, slow down" })),
                )
                    .into_response();
                if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                    r.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return r;
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_per_client() {
        let l = Limiter::new(ApiLimit { rate: 2, burst: 3 });
        let t0 = Instant::now();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap(); // same /64
        let c: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..3 {
            assert!(l.check(a, t0).is_ok());
        }
        assert_eq!(l.check(b, t0), Err(1), "same /64, burst used up");
        assert!(l.check(c, t0).is_ok(), "other client");
        // 2 per second come back
        let t1 = t0 + Duration::from_millis(1000);
        assert!(l.check(a, t1).is_ok());
        assert!(l.check(a, t1).is_ok());
        assert!(l.check(a, t1).is_err());
        // idle clients are forgotten once their bucket is full again
        assert_eq!(l.clients(), 2);
        l.prune(t1 + Duration::from_secs(10));
        assert_eq!(l.clients(), 0);
        // off
        let off = Limiter::new(ApiLimit { rate: 0, burst: 0 });
        for _ in 0..1000 {
            assert!(off.check(a, t0).is_ok());
        }
    }

    #[test]
    fn overflow_bucket_is_shared() {
        let l = Limiter::new(ApiLimit { rate: 1, burst: 1 });
        let t0 = Instant::now();
        {
            let mut b = l.buckets.lock().unwrap();
            for i in 0..MAX_CLIENTS as u32 {
                b.insert(
                    IpAddr::V4((0x0a00_0000 + i).into()),
                    Bucket {
                        tokens: 0.0,
                        at: t0,
                    },
                );
            }
        }
        assert!(l.check("192.0.2.1".parse().unwrap(), t0).is_ok());
        assert!(
            l.check("192.0.2.2".parse().unwrap(), t0).is_err(),
            "same /16: shares a bucket"
        );
        // regression (security review): one network keeping the table full
        // no longer throttles everybody else
        assert!(
            l.check("198.51.100.1".parse().unwrap(), t0).is_ok(),
            "other network"
        );
    }
}
