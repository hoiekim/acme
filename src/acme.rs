//! The ACME side: the HTTPS client, this tool's accounts, orders answered
//! over HTTP-01 from a webroot, and ACME Renewal Information.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use bytes::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, CertificateIdentifier, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::lineage::write_atomic;
use crate::log::info;

type Http = HyperClient<HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .backoff(1.5)
    .timeout(Duration::from_secs(120));

/// HTTPS with Mozilla's roots compiled in, so the image needs no CA files,
/// plus any roots in `extra_roots`.
fn http_client(extra_roots: Option<&Path>) -> Result<Http> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(path) = extra_roots {
        let certs = CertificateDer::pem_file_iter(path).with_context(|| format!("reading {}", path.display()))?;
        for cert in certs {
            roots.add(cert.with_context(|| format!("reading {}", path.display()))?)?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http);
    Ok(HyperClient::builder(TokioExecutor::new()).build(https))
}

/// This tool's ACME accounts, one per ACME server, kept in
/// `<config>/acme/accounts/`. certbot's own accounts have RSA keys, which
/// instant-acme can't sign with, so this tool registers its own and leaves
/// certbot's untouched.
pub struct Acme {
    http: Http,
    store: PathBuf,
    accounts: HashMap<String, Account>,
    unreachable: HashSet<String>,
}

impl Acme {
    pub fn new(config_dir: &Path, extra_roots: Option<&Path>) -> Result<Self> {
        Ok(Acme {
            http: http_client(extra_roots)?,
            store: config_dir.join("acme").join("accounts"),
            accounts: HashMap::new(),
            unreachable: HashSet::new(),
        })
    }

    fn account_file(&self, directory: &str) -> PathBuf {
        let name: String = directory
            .trim_start_matches("https://")
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.store.join(format!("{name}.json"))
    }

    /// The stored account for `directory`, if there is one. Doesn't register.
    pub async fn existing(&mut self, directory: &str) -> Result<Option<Account>> {
        if let Some(account) = self.accounts.get(directory) {
            return Ok(Some(account.clone()));
        }
        if self.unreachable.contains(directory) {
            bail!("{directory} was unreachable earlier in this run");
        }
        let path = self.account_file(directory);
        let json = match fs::read(&path) {
            Ok(json) => json,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let credentials: AccountCredentials =
            serde_json::from_slice(&json).with_context(|| format!("reading {}", path.display()))?;
        let account = match Account::builder_with_http(Box::new(self.http.clone()))
            .from_credentials(credentials)
            .await
        {
            Ok(account) => account,
            Err(e) => {
                self.unreachable.insert(directory.to_owned());
                return Err(e).with_context(|| format!("reaching {directory}"));
            }
        };
        self.accounts.insert(directory.to_owned(), account.clone());
        Ok(Some(account))
    }

    /// The stored account for `directory`, registering one the first time.
    pub async fn account(&mut self, directory: &str) -> Result<Account> {
        if let Some(account) = self.existing(directory).await? {
            return Ok(account);
        }
        let new = NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let (account, credentials) = Account::builder_with_http(Box::new(self.http.clone()))
            .create(&new, directory.to_owned(), None)
            .await
            .with_context(|| format!("registering an account at {directory}"))?;
        fs::create_dir_all(&self.store)?;
        write_atomic(
            &self.account_file(directory),
            &serde_json::to_vec_pretty(&credentials)?,
            0o600,
            None,
        )?;
        info!("registered ACME account {} at {directory}", account.id());
        self.accounts.insert(directory.to_owned(), account.clone());
        Ok(account)
    }
}

/// The time ACME Renewal Information suggests renewing `cert_der`: a random
/// point in the server's window, as certbot picks.
pub async fn ari_renewal_time(account: &Account, cert_der: &[u8]) -> Result<i64> {
    let cert = CertificateDer::from(cert_der);
    let id = CertificateIdentifier::try_from(&cert).map_err(|e| anyhow!(e))?;
    let (info, _) = account.renewal_info(&id).await?;
    let (start, end) = (
        info.suggested_window.start.unix_timestamp(),
        info.suggested_window.end.unix_timestamp(),
    );
    ensure!(end >= start, "the suggested window ends before it starts");
    let spread = (end - start) as u64;
    let offset = if spread == 0 {
        0
    } else {
        rsa::rand_core::RngCore::next_u64(&mut rsa::rand_core::OsRng) % (spread + 1)
    };
    Ok(start + offset as i64)
}

/// Removes the challenge files when dropped, which includes a renewal that
/// times out part way.
struct ChallengeFiles(Vec<PathBuf>);

impl Drop for ChallengeFiles {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Orders a certificate for `domains`, answers each HTTP-01 challenge from
/// the domain's webroot, and returns the PEM chain.
pub async fn obtain(
    account: &Account,
    domains: &[String],
    webroots: &HashMap<String, PathBuf>,
    csr_der: &[u8],
    profile: Option<&str>,
) -> Result<String> {
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut new_order = NewOrder::new(&identifiers);
    if let Some(profile) = profile {
        new_order = new_order.profile(profile);
    }
    let mut order = account.new_order(&new_order).await.context("creating the order")?;
    let mut files = ChallengeFiles(Vec::new());

    let mut authorizations = order.authorizations();
    while let Some(authz) = authorizations.next().await {
        let mut authz = authz.context("fetching an authorization")?;
        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => bail!("the authorization for {} is {status:?}", authz.identifier()),
        }
        let domain = authz.identifier().to_string();
        let webroot = webroots
            .get(&domain)
            .ok_or_else(|| anyhow!("no webroot for {domain}"))?
            .clone();
        let mut challenge = authz
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| anyhow!("the server offered no http-01 challenge for {domain}"))?;
        let token = challenge.token.clone();
        ensure!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "the server sent a challenge token that isn't base64url"
        );
        let dir = webroot.join(".well-known").join("acme-challenge");
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(&token);
        fs::write(&path, challenge.key_authorization().as_str())
            .with_context(|| format!("writing {}", path.display()))?;
        files.0.push(path);
        challenge
            .set_ready()
            .await
            .with_context(|| format!("answering the challenge for {domain}"))?;
    }

    let status = order.poll_ready(&POLL).await.context("waiting for validation")?;
    if status != OrderStatus::Ready {
        let mut reasons = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(Ok(mut authz)) = authorizations.next().await {
            if authz.refresh().await.is_ok() {
                for challenge in &authz.challenges {
                    if let Some(problem) = &challenge.error {
                        reasons.push(format!("{}: {problem}", authz.identifier()));
                    }
                }
            }
        }
        if let Some(problem) = &order.state().error {
            reasons.push(problem.to_string());
        }
        bail!(
            "the order is {status:?}{}",
            if reasons.is_empty() {
                String::new()
            } else {
                format!(": {}", reasons.join("; "))
            }
        );
    }
    drop(files);

    order.finalize_csr(csr_der).await.context("finalizing the order")?;
    order
        .poll_certificate(&POLL)
        .await
        .context("downloading the certificate")
}

/// The ids of certbot's accounts for `directory`, in certbot's layout:
/// `accounts/<host[:port]><path>/<id>/`.
pub fn certbot_account_ids(config_dir: &Path, directory: &str) -> Vec<String> {
    let Some(rest) = directory.strip_prefix("https://") else {
        return Vec::new();
    };
    let dir = config_dir.join("accounts").join(rest.trim_end_matches('/'));
    let mut ids: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().join("private_key.json").is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}
