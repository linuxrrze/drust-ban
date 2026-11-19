//! Internal CA and certificates (rcgen, ECDSA P-256).
//!
//! - The **CA** lives on the controller (`ca.pem`, `ca.key`).
//! - The **controller server certificate** is issued at every start for
//!   [`SERVER_NAME`](crate::SERVER_NAME) plus configured names; its key never
//!   touches the disk.
//! - **Agent certificates** are issued from a CSR. The controller ignores the
//!   CSR's subject and extensions and sets them itself: CN = agent id,
//!   EKU = clientAuth only, so an agent certificate can never act as a
//!   controller.

use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, TimeZone, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateSigningRequestDer, PrivateKeyDer};

use crate::{random_bytes, sha256, SERVER_NAME};

const CA_LIFETIME: Duration = Duration::from_secs(10 * 365 * 86400);
const SERVER_CERT_LIFETIME: Duration = Duration::from_secs(365 * 86400);
/// Tolerated clock skew: certificates are valid from this long before issue.
pub const BACKDATE: Duration = Duration::from_secs(3600);

/// SHA-256 over a certificate's DER encoding.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    sha256(der)
}

fn validity(params: &mut CertificateParams, lifetime: Duration) {
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - BACKDATE;
    params.not_after = now + lifetime;
}

fn random_serial() -> SerialNumber {
    let mut b = random_bytes::<16>();
    b[0] &= 0x7f; // positive
    b[0] |= 0x01; // no leading zero byte
    SerialNumber::from_slice(&b)
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn
}

/// The controller's certificate authority.
pub struct Ca {
    /// The CA certificate exactly as stored (its fingerprint is pinned by
    /// enrollment tokens).
    der: CertificateDer<'static>,
    pem: String,
    /// Re-created issuer object for signing (same subject and key).
    issuer: Certificate,
    key: KeyPair,
}

impl Ca {
    pub fn generate(name: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(name);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.serial_number = Some(random_serial());
        validity(&mut params, CA_LIFETIME);
        let cert = params.self_signed(&key)?;
        Self::from_pem(&cert.pem(), &key.serialize_pem())
    }

    pub fn from_pem(cert_pem: &str, key_pem: &str) -> anyhow::Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parsing CA key")?;
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .context("parsing CA certificate")?;
        let params =
            CertificateParams::from_ca_cert_pem(cert_pem).context("parsing CA certificate")?;
        if !matches!(params.is_ca, IsCa::Ca(_)) {
            bail!("CA certificate is not a CA");
        }
        let issuer = params.self_signed(&key)?;
        Ok(Self {
            der,
            pem: cert_pem.to_owned(),
            issuer,
            key,
        })
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    pub fn cert_pem(&self) -> &str {
        &self.pem
    }

    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.der)
    }

    /// Issues a fresh controller server certificate; returns `(chain, key)`
    /// with the chain `[server, ca]` (the CA is included so enrolling agents
    /// can check it against the pinned fingerprint).
    pub fn issue_server(
        &self,
        extra_names: &[String],
    ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let key = KeyPair::generate()?;
        let mut names = vec![SERVER_NAME.to_owned()];
        names.extend(extra_names.iter().cloned());
        let mut params = CertificateParams::new(names)?;
        params.distinguished_name = dn(SERVER_NAME);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial());
        validity(&mut params, SERVER_CERT_LIFETIME);
        let cert = params.signed_by(&key, &self.issuer, &self.key)?;
        let key = PrivateKeyDer::try_from(key.serialize_der()).map_err(anyhow::Error::msg)?;
        Ok((vec![cert.der().clone(), self.der.clone()], key))
    }

    /// Signs an agent CSR. Only the CSR's public key (and its proof of
    /// possession) is used; subject, extensions and lifetime are ours.
    pub fn sign_agent_csr(
        &self,
        csr_der: &[u8],
        agent_id: &str,
        lifetime: Duration,
    ) -> anyhow::Result<CertificateDer<'static>> {
        let mut csr =
            CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der))
                .context("invalid CSR")?;
        let mut params = CertificateParams::default();
        params.distinguished_name = dn(agent_id);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(random_serial());
        validity(&mut params, lifetime);
        csr.params = params;
        Ok(csr.signed_by(&self.issuer, &self.key)?.der().clone())
    }
}

/// A freshly generated agent key with its CSR.
pub struct AgentKey {
    pub key_pem: String,
    pub csr_der: Vec<u8>,
}

impl AgentKey {
    pub fn generate(hostname: &str) -> anyhow::Result<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        // informational only; the controller sets the subject
        params.distinguished_name = dn(hostname);
        let csr = params.serialize_request(&key)?;
        Ok(Self {
            key_pem: key.serialize_pem(),
            csr_der: csr.der().to_vec(),
        })
    }
}

/// The parts of a certificate dist-f2b cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub common_name: String,
    /// Lower-case hex.
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl CertInfo {
    /// When to renew: after 2/3 of the lifetime (not counting the backdated
    /// part), i.e. with 1/3 left.
    pub fn renew_at(&self) -> DateTime<Utc> {
        let backdate = chrono::Duration::from_std(BACKDATE).expect("small");
        let issued = (self.not_before + backdate).min(self.not_after);
        self.not_after - (self.not_after - issued) / 3
    }

    pub fn parse(der: &[u8]) -> anyhow::Result<Self> {
        let (_, c) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| anyhow::anyhow!("invalid certificate: {e}"))?;
        let common_name = c
            .subject()
            .iter_common_name()
            .next()
            .and_then(|a| a.as_str().ok())
            .context("certificate has no common name")?
            .to_owned();
        let ts = |t: x509_parser::time::ASN1Time| {
            Utc.timestamp_opt(t.timestamp(), 0)
                .single()
                .context("certificate time out of range")
        };
        Ok(Self {
            common_name,
            serial: crate::hex(c.raw_serial()),
            not_before: ts(c.validity().not_before)?,
            not_after: ts(c.validity().not_after)?,
        })
    }
}

/// PEM helpers for files on disk.
pub fn cert_to_pem(der: &[u8]) -> String {
    pem_encode("CERTIFICATE", der)
}

fn pem_encode(tag: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {tag}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {tag}-----\n"));
    out
}

pub fn cert_from_pem(pem: &str) -> anyhow::Result<CertificateDer<'static>> {
    CertificateDer::from_pem_slice(pem.as_bytes()).context("parsing certificate PEM")
}

/// All certificates in a PEM file (a chain, leaf first).
pub fn certs_from_pem(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("parsing certificate PEM")
}

pub fn key_from_pem(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).context("parsing private key PEM")
}
