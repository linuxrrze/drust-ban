//! PKI and transport security for dist-f2b (DESIGN.md §4.4).
//!
//! rustls with the ring provider, TLS 1.3 only, no cipher configuration.

pub mod pki;
pub mod token;
pub mod transport;

pub use pki::{AgentKey, Ca, CertInfo};
pub use rustls::pki_types::CertificateDer;
pub use rustls::ClientConfig;
pub use token::{ApiToken, EnrollToken};

/// The name in the controller's server certificate that agents verify,
/// independent of the address they connect to.
pub const SERVER_NAME: &str = "df2b-controller";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    d.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system random number generator failed");
    b
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests;
