//! ASN and country of addresses (DESIGN.md §9 "ASN/GeoIP").
//!
//! Optional MaxMind DB files (`--geoip`, repeatable): MaxMind GeoLite2/
//! GeoIP2 ASN, Country or City, DB-IP Lite (same layout), or ipinfo Lite
//! (ASN and country in one file, its own field names). Each lookup merges
//! the files in the given order (the first one with a field wins). Files
//! are read into memory and reloaded when they change on disk (e.g. after
//! `geoipupdate`); a broken update keeps the old data.
//!
//! Lookups only read the few fields used here (`decode_path`), so ranking
//! thousands of active bans stays cheap.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use anyhow::Context;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use maxminddb::{PathElement, Reader};
use serde::Serialize;

/// What the databases know about an address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GeoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_org: Option<String>,
    /// ISO 3166-1 alpha-2
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
}

impl GeoInfo {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Fields this one lacks are taken from `other`.
    /// (ASN and organization, country code and name go together.)
    fn fill(&mut self, other: GeoInfo) {
        if self.asn.is_none() && self.as_org.is_none() {
            self.asn = other.asn;
            self.as_org = other.as_org;
        }
        if self.country.is_none() {
            self.country = other.country;
            self.country_name = other.country_name;
        }
    }
}

/// A loaded database, for the status page.
#[derive(Debug, Clone, Serialize)]
pub struct DbInfo {
    pub path: PathBuf,
    pub database_type: String,
    pub build: Option<DateTime<Utc>>,
    /// the last reload failed (the previous data is still used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Db {
    path: PathBuf,
    modified: Option<SystemTime>,
    reader: Reader<Vec<u8>>,
    error: Option<String>,
}

#[derive(Default)]
pub struct Geo {
    dbs: RwLock<Vec<Db>>,
}

fn modified(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn open(p: &Path) -> anyhow::Result<Reader<Vec<u8>>> {
    let r = Reader::open_readfile(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(r)
}

impl Geo {
    /// Loads the files; an unreadable one is an error (startup).
    pub fn open(paths: &[PathBuf]) -> anyhow::Result<Self> {
        let mut dbs = Vec::new();
        for p in paths {
            let reader = open(p)?;
            tracing::info!(
                path = %p.display(),
                database_type = %reader.metadata().database_type,
                build = %build_time(&reader).map_or("?".into(), |b| b.to_rfc3339()),
                "GeoIP database loaded"
            );
            dbs.push(Db {
                path: p.clone(),
                modified: modified(p),
                reader,
                error: None,
            });
        }
        Ok(Self {
            dbs: RwLock::new(dbs),
        })
    }

    pub fn enabled(&self) -> bool {
        !self.read().is_empty()
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Db>> {
        self.dbs.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Reloads files that changed on disk (housekeeping; blocking). True
    /// if one was replaced.
    pub fn reload_changed(&self) -> bool {
        let mut replaced = false;
        let changed: Vec<(usize, PathBuf, Option<SystemTime>)> = self
            .read()
            .iter()
            .enumerate()
            .filter_map(|(i, d)| {
                let m = modified(&d.path);
                (m.is_some() && m != d.modified).then(|| (i, d.path.clone(), m))
            })
            .collect();
        for (i, path, m) in changed {
            // read outside the lock: lookups go on meanwhile
            let result = open(&path);
            let mut dbs = self.dbs.write().unwrap_or_else(|e| e.into_inner());
            let Some(d) = dbs.get_mut(i) else { continue };
            d.modified = m;
            match result {
                Ok(r) => {
                    tracing::info!(
                        path = %path.display(),
                        database_type = %r.metadata().database_type,
                        "GeoIP database reloaded"
                    );
                    d.reader = r;
                    d.error = None;
                    replaced = true;
                }
                Err(e) => {
                    let e = format!("{e:#}");
                    tracing::warn!(path = %path.display(), error = %e, "GeoIP reload failed, keeping the previous data");
                    d.error = Some(e);
                }
            }
        }
        replaced
    }

    pub fn databases(&self) -> Vec<DbInfo> {
        self.read()
            .iter()
            .map(|d| DbInfo {
                path: d.path.clone(),
                database_type: d.reader.metadata().database_type.clone(),
                build: build_time(&d.reader),
                error: d.error.clone(),
            })
            .collect()
    }

    /// None without databases or when none knows the address.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let dbs = self.read();
        let mut out = GeoInfo::default();
        for d in dbs.iter() {
            out.fill(lookup_one(&d.reader, ip));
        }
        (!out.is_empty()).then_some(out)
    }

    /// The networks of these autonomous systems in all loaded files (with
    /// several files: all of them). Blocking: walks every database.
    pub fn networks_of(&self, asns: &[u32]) -> std::collections::HashMap<u32, Vec<IpNet>> {
        let mut out: std::collections::HashMap<u32, Vec<IpNet>> =
            asns.iter().map(|a| (*a, Vec::new())).collect();
        if asns.is_empty() {
            return out;
        }
        for d in self.read().iter() {
            let Ok(iter) = d.reader.networks(maxminddb::WithinOptions::default()) else {
                continue;
            };
            for res in iter.flatten() {
                let Some(asn) = info_of(&res).asn else {
                    continue;
                };
                let Some(list) = out.get_mut(&asn) else {
                    continue;
                };
                if let Some(net) = res
                    .network()
                    .ok()
                    .and_then(|n| n.to_string().parse::<IpNet>().ok())
                {
                    list.push(net.trunc());
                }
            }
        }
        for list in out.values_mut() {
            list.sort();
            list.dedup();
        }
        out
    }

    /// A prefix is looked up by its first address.
    pub fn lookup_net(&self, net: &IpNet) -> Option<GeoInfo> {
        self.lookup(net.network())
    }
}

fn build_time(r: &Reader<Vec<u8>>) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::try_from(r.metadata().build_epoch).ok()?, 0)
}

fn lookup_one(r: &Reader<Vec<u8>>, ip: IpAddr) -> GeoInfo {
    // an IPv6 address in an IPv4-only database is an error: no data
    let Ok(res) = r.lookup(ip) else {
        return GeoInfo::default();
    };
    info_of(&res)
}

fn info_of(res: &maxminddb::LookupResult<'_, Vec<u8>>) -> GeoInfo {
    if !res.has_data() {
        return GeoInfo::default();
    }
    // a field with another type than expected counts as missing
    fn get<'a, T: serde::Deserialize<'a>>(
        res: &maxminddb::LookupResult<'a, Vec<u8>>,
        path: &[&str],
    ) -> Option<T> {
        let path: Vec<PathElement<'_>> = path.iter().map(|k| PathElement::Key(k)).collect();
        res.decode_path(&path).ok().flatten()
    }
    let s = |path: &[&str]| get::<String>(res, path).filter(|v| !v.is_empty());
    // MaxMind/DB-IP: autonomous_system_number; ipinfo: asn = "AS13335"
    let asn = get::<u32>(res, &["autonomous_system_number"]).or_else(|| {
        s(&["asn"]).and_then(|a| {
            a.strip_prefix("AS")
                .or(Some(a.as_str()))
                .and_then(|n| n.parse().ok())
        })
    });
    let as_org = s(&["autonomous_system_organization"]).or_else(|| s(&["as_name"]));
    // MaxMind: country (else registered_country) is a map; ipinfo:
    // country_code and country (the name)
    let (country, country_name) = if let Some(c) = s(&["country", "iso_code"]) {
        (Some(c), s(&["country", "names", "en"]))
    } else if let Some(c) = s(&["registered_country", "iso_code"]) {
        (Some(c), s(&["registered_country", "names", "en"]))
    } else if let Some(c) = s(&["country_code"]) {
        (Some(c), s(&["country"]))
    } else {
        (None, None)
    };
    GeoInfo {
        asn,
        as_org,
        country: country.map(|c| c.to_ascii_uppercase()),
        country_name,
    }
}

/// A minimal MaxMind DB writer for tests (IPv6 tree, IPv4 below ::/96,
/// 24-bit records; strings, uint32 and maps only).
#[cfg(test)]
pub(crate) mod testdb {
    use std::net::IpAddr;

    use ipnet::IpNet;

    pub enum V {
        S(&'static str),
        U32(u32),
        M(Vec<(&'static str, V)>),
    }

    /// Control byte, extended type byte, then sizes 29..=284 as one more
    /// byte (size - 29).
    fn ctrl(out: &mut Vec<u8>, ty: u8, size: usize) {
        assert!(size < 285);
        let small = size.min(29) as u8;
        if ty <= 7 {
            out.push((ty << 5) | small);
        } else {
            out.push(small);
            out.push(ty - 7);
        }
        if size >= 29 {
            out.push((size - 29) as u8);
        }
    }

    pub fn encode(v: &V, out: &mut Vec<u8>) {
        match v {
            V::S(s) => {
                ctrl(out, 2, s.len());
                out.extend_from_slice(s.as_bytes());
            }
            V::U32(n) => {
                let b = n.to_be_bytes();
                let skip = b.iter().take_while(|x| **x == 0).count();
                ctrl(out, 6, 4 - skip);
                out.extend_from_slice(&b[skip..]);
            }
            V::M(entries) => {
                ctrl(out, 7, entries.len());
                for (k, v) in entries {
                    encode(&V::S(k), out);
                    encode(v, out);
                }
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Rec {
        Empty,
        Node(usize),
        Data(usize),
    }

    /// Builds a database from (network, record) pairs.
    pub fn build(database_type: &'static str, entries: Vec<(&str, V)>) -> Vec<u8> {
        let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
        let mut data = Vec::new();
        for (net, v) in entries {
            let net: IpNet = net.parse().unwrap();
            let (bits, len): (u128, u8) = match net.network() {
                IpAddr::V4(a) => (u32::from(a) as u128, 96 + net.prefix_len()),
                IpAddr::V6(a) => (u128::from(a), net.prefix_len()),
            };
            let off = data.len();
            encode(&v, &mut data);
            let mut node = 0;
            for i in 0..len {
                let bit = ((bits >> (127 - i)) & 1) as usize;
                if i == len - 1 {
                    nodes[node][bit] = Rec::Data(off);
                } else {
                    node = match nodes[node][bit] {
                        Rec::Node(n) => n,
                        _ => {
                            nodes.push([Rec::Empty; 2]);
                            let n = nodes.len() - 1;
                            nodes[node][bit] = Rec::Node(n);
                            n
                        }
                    };
                }
            }
        }
        let count = nodes.len();
        let mut out = Vec::new();
        for n in &nodes {
            for r in n {
                let v = match *r {
                    Rec::Empty => count,
                    Rec::Node(i) => i,
                    Rec::Data(off) => count + 16 + off,
                };
                out.extend_from_slice(&(v as u32).to_be_bytes()[1..]);
            }
        }
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
        let mut meta = Vec::new();
        // uint16 is type 5, uint64 is extended type 9, array extended 11
        let u16 = |out: &mut Vec<u8>, n: u16| {
            ctrl(out, 5, 2);
            out.extend_from_slice(&n.to_be_bytes());
        };
        ctrl(&mut meta, 7, 9);
        encode(&V::S("node_count"), &mut meta);
        encode(&V::U32(count as u32), &mut meta);
        encode(&V::S("record_size"), &mut meta);
        u16(&mut meta, 24);
        encode(&V::S("ip_version"), &mut meta);
        u16(&mut meta, 6);
        encode(&V::S("database_type"), &mut meta);
        encode(&V::S(database_type), &mut meta);
        encode(&V::S("languages"), &mut meta);
        ctrl(&mut meta, 11, 1);
        encode(&V::S("en"), &mut meta);
        encode(&V::S("binary_format_major_version"), &mut meta);
        u16(&mut meta, 2);
        encode(&V::S("binary_format_minor_version"), &mut meta);
        u16(&mut meta, 0);
        encode(&V::S("build_epoch"), &mut meta);
        ctrl(&mut meta, 9, 8);
        meta.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        encode(&V::S("description"), &mut meta);
        encode(&V::M(vec![("en", V::S("test"))]), &mut meta);
        out.extend_from_slice(&meta);
        out
    }

    pub fn asn(asn: u32, org: &'static str) -> V {
        V::M(vec![
            ("autonomous_system_number", V::U32(asn)),
            ("autonomous_system_organization", V::S(org)),
        ])
    }

    pub fn country(iso: &'static str, name: &'static str) -> V {
        V::M(vec![(
            "country",
            V::M(vec![
                ("iso_code", V::S(iso)),
                ("names", V::M(vec![("en", V::S(name))])),
            ]),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::testdb::*;
    use super::*;

    fn write(dir: &Path, name: &str, bytes: Vec<u8>) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn maxmind_and_ipinfo_layouts_merge() {
        let dir = std::env::temp_dir().join(format!("df2b-geo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let asn_db = write(
            &dir,
            "asn.mmdb",
            build(
                "GeoLite2-ASN",
                vec![
                    ("203.0.113.0/24", asn(64500, "Example Hosting")),
                    ("2001:db8::/32", asn(64501, "Example v6")),
                ],
            ),
        );
        let country_db = write(
            &dir,
            "country.mmdb",
            build(
                "GeoLite2-Country",
                vec![
                    ("203.0.113.0/25", country("de", "Germany")),
                    ("2001:db8::/32", country("NL", "Netherlands")),
                ],
            ),
        );
        let g = Geo::open(&[asn_db.clone(), country_db]).unwrap();
        assert!(g.enabled());
        let get = |ip: &str| g.lookup(ip.parse().unwrap());
        assert_eq!(
            get("203.0.113.9"),
            Some(GeoInfo {
                asn: Some(64500),
                as_org: Some("Example Hosting".into()),
                country: Some("DE".into()),
                country_name: Some("Germany".into()),
            })
        );
        // only in the ASN database
        let half = get("203.0.113.200").unwrap();
        assert_eq!((half.asn, half.country), (Some(64500), None));
        assert_eq!(get("2001:db8::1").unwrap().country.as_deref(), Some("NL"));
        assert_eq!(get("198.51.100.1"), None);
        assert_eq!(
            g.lookup_net(&"203.0.113.0/24".parse().unwrap())
                .unwrap()
                .asn,
            Some(64500)
        );
        let info = g.databases();
        assert_eq!(info[0].database_type, "GeoLite2-ASN");
        assert_eq!(info[1].build.unwrap().timestamp(), 1_700_000_000);

        // ipinfo Lite: one file, other field names
        let ipinfo = write(
            &dir,
            "ipinfo.mmdb",
            build(
                "ipinfo lite",
                vec![(
                    "198.51.100.0/24",
                    V::M(vec![
                        ("asn", V::S("AS64502")),
                        ("as_name", V::S("Example ISP")),
                        ("country_code", V::S("FR")),
                        ("country", V::S("France")),
                    ]),
                )],
            ),
        );
        let g2 = Geo::open(&[ipinfo]).unwrap();
        assert_eq!(
            g2.lookup("198.51.100.7".parse().unwrap()),
            Some(GeoInfo {
                asn: Some(64502),
                as_org: Some("Example ISP".into()),
                country: Some("FR".into()),
                country_name: Some("France".into()),
            })
        );

        // a changed file is reloaded; a broken one keeps the old data
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            &asn_db,
            build(
                "GeoLite2-ASN",
                vec![("203.0.113.0/24", asn(64999, "Moved"))],
            ),
        )
        .unwrap();
        bump(&asn_db, 10);
        g.reload_changed();
        assert_eq!(get("203.0.113.9").unwrap().asn, Some(64999));
        std::fs::write(&asn_db, b"garbage").unwrap();
        bump(&asn_db, 20);
        g.reload_changed();
        assert_eq!(
            get("203.0.113.9").unwrap().asn,
            Some(64999),
            "old data kept"
        );
        assert!(g.databases()[0].error.is_some());

        assert!(Geo::open(&[dir.join("missing.mmdb")]).is_err());
        assert!(!Geo::default().enabled());
        assert_eq!(Geo::default().lookup("203.0.113.9".parse().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// File systems with coarse timestamps: set the mtime explicitly.
    fn bump(p: &Path, secs: u64) {
        let f = std::fs::File::options().write(true).open(p).unwrap();
        f.set_modified(SystemTime::now() + std::time::Duration::from_secs(secs))
            .unwrap();
    }

    #[test]
    fn networks_of_an_asn() {
        let dir = std::env::temp_dir().join(format!("df2b-geo-nets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = write(
            &dir,
            "asn.mmdb",
            build(
                "GeoLite2-ASN",
                vec![
                    ("203.0.113.0/25", asn(64500, "Example Hosting")),
                    ("198.51.100.0/24", asn(64500, "Example Hosting")),
                    ("203.0.113.128/25", asn(64501, "Other")),
                    ("2001:db8::/32", asn(64500, "Example Hosting")),
                ],
            ),
        );
        let g = Geo::open(&[db]).unwrap();
        let n = g.networks_of(&[64500, 64999]);
        let got: Vec<String> = n[&64500].iter().map(|n| n.to_string()).collect();
        assert_eq!(got, ["198.51.100.0/24", "203.0.113.0/25", "2001:db8::/32"]);
        assert!(n[&64999].is_empty());
        assert!(Geo::default().networks_of(&[64500])[&64500].is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
