//! REST client for the controller.
//!
//! Settings come from flags, environment, or `~/.config/df2b/df2bctl.toml`
//! (in that order of precedence):
//!
//! ```toml
//! controller = "https://ctl.example.org:7444"
//! token = "df2bapi1.…"            # or token_file = "/path/to/token"
//! ca_fingerprint = "c7a1…"        # pin the internal CA (printed by api-token create)
//! # ca_file = "/etc/df2b/ca.pem"  # or trust these CAs; neither: public roots
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use df2b_tls::pki::certs_from_pem;
use df2b_tls::transport::{https_client_config, Trust};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub controller: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub ca_fingerprint: Option<String>,
    pub ca_file: Option<PathBuf>,
}

/// Values given on the command line / in the environment.
#[derive(Debug, Default)]
pub struct Overrides {
    pub controller: Option<String>,
    pub token: Option<String>,
    pub ca_fingerprint: Option<String>,
    pub ca_file: Option<PathBuf>,
    pub config: Option<PathBuf>,
}

fn default_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("df2b/df2bctl.toml"))
}

fn load_file(path: &Path, explicit: bool) -> anyhow::Result<FileConfig> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
            return Ok(FileConfig::default())
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let cfg: FileConfig =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if cfg.token.is_some() {
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            eprintln!(
                "warning: {} contains an API token but is readable by others (chmod 600)",
                path.display()
            );
        }
    }
    Ok(cfg)
}

pub fn parse_fingerprint(s: &str) -> anyhow::Result<[u8; 32]> {
    let hex: String = s.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        bail!("CA fingerprint must be 64 hex digits (SHA-256)");
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b =
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).context("CA fingerprint must be hex")?;
    }
    Ok(out)
}

pub struct Client {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl Client {
    pub fn new(o: Overrides) -> anyhow::Result<Self> {
        let file = match (&o.config, default_config_path()) {
            (Some(p), _) => load_file(p, true)?,
            (None, Some(p)) => load_file(&p, false)?,
            (None, None) => FileConfig::default(),
        };
        let base = o
            .controller
            .or(file.controller)
            .context("no controller configured (--controller, DF2B_CONTROLLER or config file)")?;
        let base = base.trim_end_matches('/').to_owned();
        if !base.starts_with("https://") {
            bail!("controller URL must start with https://");
        }
        let token = match (o.token.or(file.token), file.token_file) {
            (Some(t), _) => t,
            (None, Some(p)) => std::fs::read_to_string(&p)
                .with_context(|| format!("reading {}", p.display()))?
                .trim()
                .to_owned(),
            (None, None) => {
                bail!("no API token configured (--token, DF2B_API_TOKEN or config file)")
            }
        };
        let trust = match (
            o.ca_fingerprint.or(file.ca_fingerprint),
            o.ca_file.or(file.ca_file),
        ) {
            (Some(fp), _) => Trust::PinnedCa(parse_fingerprint(&fp)?),
            (None, Some(p)) => {
                let pem = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading {}", p.display()))?;
                Trust::CaCerts(certs_from_pem(&pem)?)
            }
            (None, None) => Trust::SystemRoots,
        };
        let tls = https_client_config(trust)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(concat!("df2bctl/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { http, base, token })
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> anyhow::Result<Value> {
        let resp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.base))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            let msg = body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("no details");
            bail!("controller: {status}: {msg}");
        }
        Ok(body)
    }

    pub async fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.send(self.http.get(format!("{}{path}", self.base)))
            .await
    }

    pub async fn get_query(&self, path: &str, q: &[(&str, String)]) -> anyhow::Result<Value> {
        self.send(self.http.get(format!("{}{path}", self.base)).query(q))
            .await
    }

    pub async fn patch(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.send(self.http.patch(format!("{}{path}", self.base)).json(&body))
            .await
    }

    pub async fn delete(&self, path: &str, q: &[(&str, String)]) -> anyhow::Result<Value> {
        self.send(self.http.delete(format!("{}{path}", self.base)).query(q))
            .await
    }

    pub async fn post(&self, path: &str, body: Value) -> anyhow::Result<Value> {
        self.send(self.http.post(format!("{}{path}", self.base)).json(&body))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints() {
        let hex = "c7a1285b6288562224f4ebbb54b3fc8ee7874447b7f00a3a2c36bd700c49fb22";
        let fp = parse_fingerprint(hex).unwrap();
        assert_eq!(df2b_tls::hex(&fp), hex);
        let colons: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(parse_fingerprint(&colons.join(":")).unwrap(), fp);
        assert!(parse_fingerprint("abc").is_err());
        assert!(parse_fingerprint(&"zz".repeat(32)).is_err());
    }
}
