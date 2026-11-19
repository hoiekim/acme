//! Certificate keys, CSRs and the certificates that come back.

use anyhow::{Context, Result, anyhow, bail, ensure};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PublicKeyData};
use rustls_pki_types::PrivatePkcs8KeyDer;
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;

/// The key a lineage's certificates use, from its `key_type`,
/// `elliptic_curve` and `rsa_key_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySpec {
    P256,
    P384,
    Rsa(usize),
}

impl KeySpec {
    /// certbot's defaults. A renewal file without `key_type` is from before
    /// certbot 1.25 recorded its default, which was RSA.
    pub fn from_params(key_type: Option<&str>, curve: Option<&str>, rsa_bits: Option<&str>) -> Result<Self> {
        match key_type.unwrap_or("rsa").to_ascii_lowercase().as_str() {
            "rsa" => {
                let bits: usize = match rsa_bits {
                    Some(v) => v.parse().map_err(|_| anyhow!("rsa_key_size {v:?} is not a number"))?,
                    None => 2048,
                };
                ensure!(
                    matches!(bits, 2048 | 3072 | 4096),
                    "rsa_key_size {bits} is not 2048, 3072 or 4096"
                );
                Ok(KeySpec::Rsa(bits))
            }
            "ecdsa" => match curve.unwrap_or("secp256r1").to_ascii_lowercase().as_str() {
                "secp256r1" | "prime256v1" | "p-256" => Ok(KeySpec::P256),
                "secp384r1" | "p-384" => Ok(KeySpec::P384),
                other => bail!("elliptic_curve {other} is not supported: use secp256r1 or secp384r1"),
            },
            other => bail!("key_type {other} is not supported: use rsa or ecdsa"),
        }
    }

    pub fn generate(self) -> Result<KeyPair> {
        Ok(match self {
            KeySpec::P256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            KeySpec::P384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
            KeySpec::Rsa(bits) => {
                use rsa::pkcs8::EncodePrivateKey;
                let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits).context("generating an RSA key")?;
                let der = key.to_pkcs8_der().context("encoding the RSA key")?;
                KeyPair::from_pkcs8_der_and_sign_algo(
                    &PrivatePkcs8KeyDer::from(der.as_bytes()),
                    &rcgen::PKCS_RSA_SHA256,
                )?
            }
        })
    }

    /// The renewal-file parameters that name this key.
    pub fn params(self) -> Vec<(&'static str, String)> {
        match self {
            KeySpec::P256 => vec![("key_type", "ecdsa".into()), ("elliptic_curve", "secp256r1".into())],
            KeySpec::P384 => vec![("key_type", "ecdsa".into()), ("elliptic_curve", "secp384r1".into())],
            KeySpec::Rsa(bits) => vec![("key_type", "rsa".into()), ("rsa_key_size", bits.to_string())],
        }
    }
}

impl std::fmt::Display for KeySpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySpec::P256 => f.write_str("ecdsa secp256r1"),
            KeySpec::P384 => f.write_str("ecdsa secp384r1"),
            KeySpec::Rsa(bits) => write!(f, "rsa {bits}"),
        }
    }
}

/// A CSR for `domains`, with an empty subject as the CA takes the names from
/// the subject alternative names.
pub fn csr(key: &KeyPair, domains: &[String]) -> Result<Vec<u8>> {
    let mut params = CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = DistinguishedName::new();
    Ok(params.serialize_request(key)?.der().to_vec())
}

pub struct CertInfo {
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub dns_names: Vec<String>,
    pub other_names: usize,
    pub spki: Vec<u8>,
}

impl CertInfo {
    pub fn parse(der: Vec<u8>) -> Result<Self> {
        let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow!("parsing a certificate: {e}"))?;
        let validity = cert.validity();
        let (not_before, not_after) = (validity.not_before.timestamp(), validity.not_after.timestamp());
        let mut dns_names = Vec::new();
        let mut other_names = 0;
        if let Some(san) = cert
            .subject_alternative_name()
            .map_err(|e| anyhow!("reading the subject alternative names: {e}"))?
        {
            for name in &san.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => dns_names.push(dns.to_string()),
                    _ => other_names += 1,
                }
            }
        }
        let spki = cert.tbs_certificate.subject_pki.raw.to_vec();
        Ok(CertInfo {
            der,
            not_before,
            not_after,
            dns_names,
            other_names,
            spki,
        })
    }

    /// The first certificate in a PEM file.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let der = pem_certificates(pem)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no certificate in the file"))?;
        Self::parse(der)
    }
}

fn pem_certificates(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for block in Pem::iter_from_buffer(pem) {
        let block = block.map_err(|e| anyhow!("reading PEM: {e}"))?;
        if block.label == "CERTIFICATE" {
            out.push(block.contents);
        }
    }
    Ok(out)
}

/// What the CA sent back, split the way certbot stores it.
pub struct Issued {
    pub cert: String,
    pub chain: String,
    pub info: CertInfo,
}

impl Issued {
    /// Splits the PEM chain into the certificate and the rest, and checks the
    /// certificate is for `key` and covers `domains`, so a wrong answer never
    /// reaches the disk.
    pub fn check(chain_pem: &str, key: &KeyPair, domains: &[String]) -> Result<Self> {
        const END: &str = "-----END CERTIFICATE-----";
        let mut blocks = Vec::new();
        let mut rest = chain_pem;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let end = rest[start..]
                .find(END)
                .ok_or_else(|| anyhow!("unterminated certificate in the chain"))?
                + start
                + END.len();
            blocks.push(format!("{}\n", &rest[start..end]));
            rest = &rest[end..];
        }
        ensure!(
            blocks.len() >= 2,
            "the CA sent {} certificate(s), expected the certificate and its chain",
            blocks.len()
        );
        let info = CertInfo::from_pem(blocks[0].as_bytes())?;
        ensure!(
            info.spki == key.subject_public_key_info(),
            "the certificate is not for the key that was sent"
        );
        for domain in domains {
            ensure!(
                info.dns_names.iter().any(|n| n.eq_ignore_ascii_case(domain)),
                "the certificate does not cover {domain}"
            );
        }
        let cert = blocks.remove(0);
        Ok(Issued {
            cert,
            chain: blocks.concat(),
            info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_spec_follows_certbot_defaults() {
        assert_eq!(KeySpec::from_params(None, None, None).unwrap(), KeySpec::Rsa(2048));
        assert_eq!(
            KeySpec::from_params(Some("rsa"), None, Some("4096")).unwrap(),
            KeySpec::Rsa(4096)
        );
        assert_eq!(KeySpec::from_params(Some("ecdsa"), None, None).unwrap(), KeySpec::P256);
        assert_eq!(
            KeySpec::from_params(Some("ecdsa"), Some("secp384r1"), None).unwrap(),
            KeySpec::P384
        );
        assert!(KeySpec::from_params(Some("ecdsa"), Some("secp521r1"), None).is_err());
        assert!(KeySpec::from_params(Some("rsa"), None, Some("1024")).is_err());
        assert!(KeySpec::from_params(Some("ed25519"), None, None).is_err());
    }

    /// A self-signed certificate stands in for the CA's answer.
    fn answer(key: &KeyPair, names: &[&str]) -> String {
        let params = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let cert = params.self_signed(key).unwrap().pem();
        let issuer = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let chain = CertificateParams::new(vec!["issuer.test".to_string()])
            .unwrap()
            .self_signed(&issuer)
            .unwrap()
            .pem();
        format!("{cert}{chain}")
    }

    #[test]
    fn issued_chain_is_split_and_checked() {
        for spec in [KeySpec::P256, KeySpec::P384, KeySpec::Rsa(2048)] {
            let key = spec.generate().unwrap();
            let domains = vec!["a.example.com".to_string(), "b.example.com".to_string()];
            assert!(!csr(&key, &domains).unwrap().is_empty());
            let issued = Issued::check(&answer(&key, &["a.example.com", "b.example.com"]), &key, &domains).unwrap();
            assert_eq!(issued.cert.matches("BEGIN CERTIFICATE").count(), 1);
            assert_eq!(issued.chain.matches("BEGIN CERTIFICATE").count(), 1);
            assert_eq!(issued.info.dns_names, domains);

            let other = spec.generate().unwrap();
            assert!(Issued::check(&answer(&other, &["a.example.com", "b.example.com"]), &key, &domains).is_err());
            assert!(Issued::check(&answer(&key, &["a.example.com"]), &key, &domains).is_err());
        }
    }
}
