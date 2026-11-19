//! A renewal pass over every lineage, and issuing a new one.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::acme::{self, Acme};
use crate::conf::{self, NewLineage};
use crate::keys::{CertInfo, Issued, KeySpec};
use crate::lineage::{self, KINDS, Lineage, write_atomic};
use crate::log::{error, info, utc, warning};

/// How long one certificate may take, end to end, before it counts as failed.
#[cfg(not(test))]
const LINEAGE_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a pass or an issue waits for another acme process to release
/// the lock. An issue holds it for at most `LINEAGE_TIMEOUT`.
#[cfg(not(test))]
const LOCK_WAIT: Duration = Duration::from_secs(600);
// Short in tests, which stall on purpose.
#[cfg(test)]
const LINEAGE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The `cli.ini` keys acme accepts. They only change logging, registration
/// and prompts, never what a renewal asks for or writes; any other key fails
/// every certificate (`config_dir_refusals`).
const CLI_INI_ACCEPTED: &[&str] = &[
    "agree-tos",
    "directory-hooks",
    "eff-email",
    "email",
    "logs-dir",
    "max-log-backups",
    "no-directory-hooks",
    "no-eff-email",
    "no-random-sleep-on-renew",
    "non-interactive",
    "noninteractive",
    "quiet",
    "register-unsafely-without-email",
    "text",
    "user-agent",
    "verbose",
    "work-dir",
];

/// What in `config_dir`, beyond the renewal files, certbot would act on and
/// acme can't: each `cli.ini` key outside `CLI_INI_ACCEPTED`, and each
/// executable certbot would run from `renewal-hooks/{pre,deploy,post}/`
/// (every executable file not ending in `~`, unless `cli.ini` turns
/// directory hooks off).
fn config_dir_refusals(config_dir: &Path) -> Result<Vec<String>> {
    let mut refusals = Vec::new();
    let mut directory_hooks = true;
    let cli_ini = config_dir.join("cli.ini");
    match fs::read_to_string(&cli_ini) {
        Ok(text) => {
            for line in text.lines().map(str::trim) {
                if line.is_empty() || line.starts_with(['#', ';', '[']) {
                    continue;
                }
                let (key, value) = match line.find(|c: char| c == '=' || c == ':' || c.is_ascii_whitespace()) {
                    Some(at) => (&line[..at], line[at + 1..].trim_start_matches(['=', ':']).trim()),
                    None => (line, ""),
                };
                let key = key
                    .trim()
                    .trim_start_matches("--")
                    .to_ascii_lowercase()
                    .replace('_', "-");
                let on = !matches!(value.to_ascii_lowercase().as_str(), "false" | "no" | "off" | "0");
                match key.as_str() {
                    "no-directory-hooks" if on => directory_hooks = false,
                    "directory-hooks" if !on => directory_hooks = false,
                    accepted if CLI_INI_ACCEPTED.contains(&accepted) => {}
                    other => refusals.push(format!("cli.ini sets {other}")),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", cli_ini.display())),
    }
    if directory_hooks {
        for stage in ["pre", "deploy", "post"] {
            let dir = config_dir.join("renewal-hooks").join(stage);
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
            };
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let executable =
                    fs::metadata(entry.path()).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
                if executable && !name.ends_with('~') {
                    refusals.push(format!("renewal-hooks/{stage}/{name} is a hook certbot would run"));
                }
            }
        }
    }
    refusals.sort();
    Ok(refusals)
}

/// The error for a certificate while `config_dir_refusals` found something.
fn refused(refusals: &[String]) -> anyhow::Error {
    anyhow!(
        "{}; acme runs no hooks and honours no other cli.ini setting, so it renews nothing until they are gone",
        refusals.join("; ")
    )
}

pub struct Settings {
    pub config_dir: PathBuf,
    pub ca_cert: Option<PathBuf>,
}

/// Whether a certificate is due, by the rules certbot 5 uses: renew once the
/// ACME Renewal Information time has passed; otherwise, with
/// `renew_before_expiry` set, once that much time is left; otherwise, without
/// ARI, once two thirds of its lifetime have passed (half, for certificates
/// that live under ten days). For a 90-day certificate that's 30 days left.
pub fn due(now: i64, not_before: i64, not_after: i64, renew_before_expiry: Option<i64>, ari_time: Option<i64>) -> bool {
    if ari_time.is_some_and(|t| now > t) {
        return true;
    }
    if let Some(before) = renew_before_expiry {
        return not_after < now.saturating_add(before);
    }
    if ari_time.is_none() {
        let lifetime = not_after - not_before;
        let at = if lifetime < 10 * 86_400 {
            not_before + lifetime / 2
        } else {
            not_before + lifetime * 2 / 3
        };
        return now > at;
    }
    false
}

/// What a renewal file asks for, checked before anything is due so a setting
/// this tool can't honour fails every pass rather than on the day it matters.
struct Plan {
    server: String,
    key: KeySpec,
    webroots: HashMap<String, PathBuf>,
    profile: Option<String>,
    required_profile: bool,
    autorenew: bool,
    renew_before_expiry: Option<i64>,
}

impl Plan {
    fn new(lineage: &Lineage, domains: &[String]) -> Result<Self> {
        let conf = &lineage.conf;
        let authenticator = conf.param("authenticator").unwrap_or("none");
        ensure!(
            authenticator == "webroot",
            "authenticator {authenticator} is not supported, only webroot is"
        );
        if let Some(installer) = conf.param("installer") {
            bail!("installer {installer} is not supported");
        }
        for key in ["pre_hook", "post_hook", "renew_hook", "deploy_hook"] {
            ensure!(
                conf.param(key).is_none(),
                "{key} is set, and this tool doesn't run hooks"
            );
        }
        ensure!(
            conf::boolean(conf.param("reuse_key"))? != Some(true),
            "reuse_key is not supported"
        );
        ensure!(
            conf::boolean(conf.param("must_staple"))? != Some(true),
            "must_staple is not supported"
        );
        if let Some(challenges) = conf.param("pref_challs") {
            ensure!(
                conf::list(challenges).iter().any(|c| c.eq_ignore_ascii_case("http-01")),
                "pref_challs {challenges} leaves out http-01"
            );
        }
        if conf.param("preferred_chain").is_some() {
            warning!(
                "{}: ignoring preferred_chain, the CA's default chain is used",
                lineage.name
            );
        }
        let key = KeySpec::from_params(
            conf.param("key_type"),
            conf.param("elliptic_curve"),
            conf.param("rsa_key_size"),
        )?;
        let mut webroots = HashMap::new();
        for domain in domains {
            let webroot = conf
                .webroot_for(domain)
                .ok_or_else(|| anyhow!("no webroot_path or webroot_map entry for {domain}"))?;
            webroots.insert(domain.clone(), PathBuf::from(webroot));
        }
        let (profile, required_profile) = match (conf.param("required_profile"), conf.param("preferred_profile")) {
            (Some(p), _) => (Some(p.to_owned()), true),
            (None, Some(p)) => (Some(p.to_owned()), false),
            (None, None) => (None, false),
        };
        Ok(Plan {
            server: conf.param("server").unwrap_or(crate::LETS_ENCRYPT).to_owned(),
            key,
            webroots,
            profile,
            required_profile,
            autorenew: conf::boolean(conf.param("autorenew"))?.unwrap_or(true),
            renew_before_expiry: conf
                .get("renew_before_expiry")
                .map(conf::interval_seconds)
                .transpose()?,
        })
    }

    /// The profile to ask for: a required one always, a preferred one only
    /// when the server offers it.
    fn profile_for(&self, account: &instant_acme::Account) -> Result<Option<String>> {
        let Some(profile) = &self.profile else { return Ok(None) };
        if self.required_profile || account.profiles().any(|p| p.name == profile) {
            return Ok(Some(profile.clone()));
        }
        Ok(None)
    }
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// One pass over `renewal/*.conf`. Returns whether every renewal that was
/// due succeeded.
pub async fn renew_all(settings: &Settings, force: bool, only: &[String]) -> Result<bool> {
    let _lock = lineage::lock(&settings.config_dir, LOCK_WAIT).await?;
    let refusals = config_dir_refusals(&settings.config_dir)?;
    let mut acme = Acme::new(&settings.config_dir, settings.ca_cert.as_deref())?;
    let mut confs = lineage::renewal_confs(&settings.config_dir)?;
    if !only.is_empty() {
        for name in only {
            ensure!(
                confs.iter().any(|c| c.file_stem().is_some_and(|s| s == name.as_str())),
                "there is no renewal/{name}.conf"
            );
        }
        confs.retain(|c| c.file_stem().is_some_and(|s| only.iter().any(|n| s == n.as_str())));
    }
    if confs.is_empty() {
        info!("no certificates in {}", settings.config_dir.join("renewal").display());
        return Ok(true);
    }
    let (mut renewed, mut not_due, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    for path in &confs {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let outcome = if refusals.is_empty() {
            tokio::time::timeout(LINEAGE_TIMEOUT, renew_one(&mut acme, path, force)).await
        } else {
            Ok(Err(refused(&refusals)))
        };
        match outcome {
            Ok(Ok(true)) => renewed.push(name),
            Ok(Ok(false)) => not_due.push(name),
            Ok(Err(e)) => {
                error!("{name}: renewal failed: {e:#}");
                failed.push(name);
            }
            Err(_) => {
                error!("{name}: renewal failed: no result after {}s", LINEAGE_TIMEOUT.as_secs());
                failed.push(name);
            }
        }
    }
    info!(
        "renewed {} [{}], not due {}, failed {} [{}]",
        renewed.len(),
        renewed.join(" "),
        not_due.len(),
        failed.len(),
        failed.join(" ")
    );
    Ok(failed.is_empty())
}

async fn renew_one(acme: &mut Acme, conf_path: &Path, force: bool) -> Result<bool> {
    let lineage = Lineage::load(conf_path)?;
    let name = lineage.name.clone();
    let current = lineage.current_version()?;
    lineage.clean_up(current)?;
    let cert = CertInfo::from_pem(&lineage.read_current("cert")?).context("reading the current certificate")?;
    ensure!(
        cert.other_names == 0,
        "the certificate has names other than DNS names, which webroot can't validate"
    );
    ensure!(!cert.dns_names.is_empty(), "the certificate names no domains");
    ensure!(
        !cert.dns_names.iter().any(|d| d.starts_with("*.")),
        "wildcard names need DNS validation, not webroot"
    );
    let plan = Plan::new(&lineage, &cert.dns_names)?;

    if !force {
        if !plan.autorenew {
            info!("{name}: autorenew is off, skipping");
            return Ok(false);
        }
        let ari = match acme.existing(&plan.server).await {
            Ok(Some(account)) => match acme::ari_renewal_time(&account, &cert.der).await {
                Ok(time) => Some(time),
                Err(e) => {
                    warning!(
                        "{name}: no renewal information from the server ({e:#}), using the certificate's lifetime"
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warning!("{name}: no renewal information ({e:#}), using the certificate's lifetime");
                None
            }
        };
        if !due(now(), cert.not_before, cert.not_after, plan.renew_before_expiry, ari) {
            info!("{name}: not due, expires {}", utc(cert.not_after));
            return Ok(false);
        }
    }

    info!(
        "{name}: renewing {} ({}), expires {}",
        cert.dns_names.join(" "),
        plan.key,
        utc(cert.not_after)
    );
    let account = acme.account(&plan.server).await?;
    let profile = plan.profile_for(&account)?;
    let key = plan.key.generate()?;
    let csr = crate::keys::csr(&key, &cert.dns_names)?;
    let chain = acme::obtain(&account, &cert.dns_names, &plan.webroots, &csr, profile.as_deref()).await?;
    let issued = Issued::check(&chain, &key, &cert.dns_names)?;
    let version = lineage.save(&issued.cert, &issued.chain, &key.serialize_pem(), Some(current))?;
    lineage.activate(version)?;
    lineage.truncate(version);
    info!(
        "{name}: renewed, version {version}, expires {}",
        utc(issued.info.not_after)
    );
    Ok(true)
}

pub struct IssueRequest {
    pub cert_name: String,
    pub domains: Vec<String>,
    pub webroot: PathBuf,
    pub server: String,
    pub key: KeySpec,
}

/// Issues a certificate into a new lineage, in the layout and renewal file
/// certbot would have written, so `renew` (or certbot) keeps it renewed.
pub async fn issue(settings: &Settings, request: &IssueRequest) -> Result<()> {
    let name = &request.cert_name;
    ensure!(
        !name.is_empty() && !name.starts_with('.') && !name.contains('/') && name != "..",
        "{name:?} can't be a certificate name"
    );
    ensure!(!request.domains.is_empty(), "name at least one domain");
    for domain in &request.domains {
        ensure!(
            !domain.starts_with("*."),
            "{domain}: wildcard names need DNS validation, not webroot"
        );
    }
    let _lock = lineage::lock(&settings.config_dir, LOCK_WAIT).await?;
    let refusals = config_dir_refusals(&settings.config_dir)?;
    if !refusals.is_empty() {
        return Err(refused(&refusals));
    }
    let live_dir = settings.config_dir.join("live").join(name);
    ensure!(
        fs::symlink_metadata(&live_dir).is_err(),
        "{} already exists",
        live_dir.display()
    );
    tokio::time::timeout(LINEAGE_TIMEOUT, issue_locked(settings, request, &live_dir))
        .await
        .map_err(|_| anyhow!("{name}: no result after {}s", LINEAGE_TIMEOUT.as_secs()))?
}

/// The part of `issue` that runs under the lock and the timeout. Every write
/// comes after the last network wait, so the timeout can't cut one short.
async fn issue_locked(settings: &Settings, request: &IssueRequest, live_dir: &Path) -> Result<()> {
    let name = &request.cert_name;
    let config = &settings.config_dir;
    let mut acme = Acme::new(config, settings.ca_cert.as_deref())?;
    let account = acme.account(&request.server).await?;
    let key = request.key.generate()?;
    let csr = crate::keys::csr(&key, &request.domains)?;
    let webroots = request
        .domains
        .iter()
        .map(|d| (d.clone(), request.webroot.clone()))
        .collect();
    let chain = acme::obtain(&account, &request.domains, &webroots, &csr, None).await?;
    let issued = Issued::check(&chain, &key, &request.domains)?;

    // The renewal file goes first: if what follows is cut short, renew fails
    // loudly on the missing links rather than the certificate going unrenewed.
    for dir in ["renewal", "archive", "live"] {
        let path = config.join(dir);
        if !path.exists() {
            fs::create_dir_all(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
    }
    let archive_dir = config.join("archive").join(name);
    let archive = archive_dir.to_string_lossy();
    let links = KINDS.map(|kind| {
        (
            kind,
            live_dir.join(format!("{kind}.pem")).to_string_lossy().into_owned(),
        )
    });
    let webroot = request.webroot.to_string_lossy().into_owned();
    let mut params = Vec::new();
    match acme::certbot_account_ids(config, &request.server).as_slice() {
        [id] => params.push(("account", id.clone())),
        _ => warning!(
            "{name}: no single certbot account for {}, so the renewal file names none",
            request.server
        ),
    }
    params.push(("authenticator", "webroot".to_owned()));
    params.push(("webroot_path", format!("{webroot},")));
    params.push(("server", request.server.clone()));
    params.extend(request.key.params());
    let text = NewLineage {
        archive_dir: &archive,
        links,
        params,
        webroot_map: request.domains.iter().map(|d| (d.clone(), webroot.clone())).collect(),
    }
    .render();
    let conf_path = config.join("renewal").join(format!("{name}.conf"));
    write_atomic(&conf_path, text.as_bytes(), 0o644, None)?;

    let lineage = Lineage::load(&conf_path)?;
    let version = lineage.save(&issued.cert, &issued.chain, &key.serialize_pem(), None)?;
    lineage.activate(version)?;
    info!(
        "{name}: issued for {}, expires {}",
        request.domains.join(" "),
        utc(issued.info.not_after)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const DAY: i64 = 86_400;

    /// A renewal file in the shape certbot 5.9.0 writes, for a lineage named
    /// `example` under `ROOT`. Its server is a closed local port, so a test
    /// that gets further than it should fails without reaching a real CA.
    const CERTBOT_RENEWAL_FILE: &str = "\
# renew_before_expiry = 30 days
version = 5.9.0
archive_dir = ROOT/archive/example
cert = ROOT/live/example/cert.pem
privkey = ROOT/live/example/privkey.pem
chain = ROOT/live/example/chain.pem
fullchain = ROOT/live/example/fullchain.pem

# Options used in the renewal process
[renewalparams]
account = 0123456789abcdef0123456789abcdef
authenticator = webroot
webroot_path = /data/letsencrypt-acme-challenge,
server = https://127.0.0.1:1/directory
key_type = ecdsa
[[webroot_map]]
example.test = /data/letsencrypt-acme-challenge
";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("acme-renew-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes renewal/example.conf from the certbot fixture with `edit`
    /// applied, and returns its path.
    fn renewal_file(root: &Path, edit: impl Fn(&str) -> String) -> PathBuf {
        fs::create_dir_all(root.join("renewal")).unwrap();
        let path = root.join("renewal/example.conf");
        let text = CERTBOT_RENEWAL_FILE.replace("ROOT", &root.to_string_lossy());
        fs::write(&path, edit(&text)).unwrap();
        path
    }

    /// A lineage at version 1 whose certificate names `names` and has 89
    /// days left of 90, so it isn't due. Returns its renewal file.
    fn lineage_on_disk(root: &Path, names: &[&str]) -> PathBuf {
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(89);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap().pem();
        let archive = root.join("archive/example");
        let live = root.join("live/example");
        fs::create_dir_all(&archive).unwrap();
        fs::create_dir_all(&live).unwrap();
        for (kind, contents) in [
            ("cert", cert.clone()),
            ("chain", cert.clone()),
            ("fullchain", format!("{cert}{cert}")),
            ("privkey", key.serialize_pem()),
        ] {
            fs::write(archive.join(format!("{kind}1.pem")), contents).unwrap();
            symlink(
                format!("../../archive/example/{kind}1.pem"),
                live.join(format!("{kind}.pem")),
            )
            .unwrap();
        }
        renewal_file(root, |text| text.to_owned())
    }

    fn settings(root: &Path) -> Settings {
        Settings {
            config_dir: root.to_path_buf(),
            ca_cert: None,
        }
    }

    fn block_on<T>(work: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(work)
    }

    /// Runs `work` on its own thread and gives up waiting after `limit`, so a
    /// call that never returns fails the test instead of hanging it.
    fn returns_within<T: Send + 'static>(limit: Duration, work: impl FnOnce() -> T + Send + 'static) -> T {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(work());
        });
        receive.recv_timeout(limit).expect("it never returned")
    }

    fn executable(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_pass_with_nothing_due_and_nothing_refused_succeeds() {
        let root = temp_dir("clean-pass");
        lineage_on_disk(&root, &["example.test"]);
        assert!(block_on(renew_all(&settings(&root), false, &[])).unwrap());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_executable_in_certbots_hook_directories_fails_every_pass() {
        for stage in ["pre", "deploy", "post"] {
            let root = temp_dir(&format!("hook-{stage}"));
            lineage_on_disk(&root, &["example.test"]);
            executable(&root.join(format!("renewal-hooks/{stage}/reload")));
            assert!(
                !block_on(renew_all(&settings(&root), false, &[])).unwrap(),
                "{stage} hook"
            );
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn hook_files_certbot_would_not_run_are_ignored() {
        let root = temp_dir("not-hooks");
        lineage_on_disk(&root, &["example.test"]);
        executable(&root.join("renewal-hooks/deploy/reload~"));
        fs::write(root.join("renewal-hooks/deploy/notes.txt"), "not executable\n").unwrap();
        fs::create_dir_all(root.join("renewal-hooks/pre")).unwrap();
        assert!(block_on(renew_all(&settings(&root), false, &[])).unwrap());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_cli_ini_setting_acme_cannot_honour_fails_every_pass() {
        for line in [
            "deploy-hook = systemctl reload nginx",
            "key-type = rsa",
            "rsa_key_size: 4096",
            "must-staple",
        ] {
            let root = temp_dir("cli-ini");
            lineage_on_disk(&root, &["example.test"]);
            fs::write(root.join("cli.ini"), format!("# certbot settings\n{line}\n")).unwrap();
            assert!(!block_on(renew_all(&settings(&root), false, &[])).unwrap(), "{line}");
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn cli_ini_settings_that_change_nothing_are_accepted() {
        let root = temp_dir("cli-ini-ok");
        lineage_on_disk(&root, &["example.test"]);
        fs::write(
            root.join("cli.ini"),
            "email = someone@example.com\nagree-tos = true\nnon-interactive\nmax-log-backups = 10\n",
        )
        .unwrap();
        assert!(block_on(renew_all(&settings(&root), false, &[])).unwrap());
        fs::write(root.join("cli.ini"), "no-directory-hooks = true\n").unwrap();
        executable(&root.join("renewal-hooks/deploy/reload"));
        assert!(
            block_on(renew_all(&settings(&root), false, &[])).unwrap(),
            "hooks certbot is told not to run"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_stuck_lock_holder_fails_the_pass() {
        use std::os::fd::AsRawFd;
        let root = temp_dir("stuck-lock");
        lineage_on_disk(&root, &["example.test"]);
        fs::create_dir_all(root.join("acme")).unwrap();
        let held = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.join("acme/lock"))
            .unwrap();
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
        let settings = settings(&root);
        let result = returns_within(Duration::from_secs(20), move || {
            block_on(renew_all(&settings, false, &[]))
        });
        let err = result.expect_err("a pass that can't take the lock fails");
        assert!(err.to_string().contains("acme/lock"), "{err:#}");
        drop(held);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_issue_whose_server_never_answers_gives_up() {
        let root = temp_dir("stalled-issue");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = format!("https://127.0.0.1:{}/dir", listener.local_addr().unwrap().port());
        let settings = settings(&root);
        let request = IssueRequest {
            cert_name: "stalled".to_owned(),
            domains: vec!["example.test".to_owned()],
            webroot: root.join("webroot"),
            server,
            key: KeySpec::P256,
        };
        let result = returns_within(Duration::from_secs(20), move || block_on(issue(&settings, &request)));
        let err = result.expect_err("a stalled issue fails");
        assert!(err.to_string().contains("no result after"), "{err:#}");
        assert!(!root.join("renewal/stalled.conf").exists());
        drop(listener);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn plan_refuses_each_setting_acme_cannot_honour() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "authenticator = webroot",
                "authenticator = nginx",
                "authenticator nginx",
            ),
            (
                "key_type = ecdsa",
                "key_type = ecdsa\ninstaller = nginx",
                "installer nginx",
            ),
            ("key_type = ecdsa", "key_type = ecdsa\npre_hook = true", "pre_hook"),
            ("key_type = ecdsa", "key_type = ecdsa\npost_hook = true", "post_hook"),
            ("key_type = ecdsa", "key_type = ecdsa\nrenew_hook = true", "renew_hook"),
            (
                "key_type = ecdsa",
                "key_type = ecdsa\ndeploy_hook = true",
                "deploy_hook",
            ),
            ("key_type = ecdsa", "key_type = ecdsa\nreuse_key = True", "reuse_key"),
            (
                "key_type = ecdsa",
                "key_type = ecdsa\nmust_staple = True",
                "must_staple",
            ),
            (
                "key_type = ecdsa",
                "key_type = ecdsa\npref_challs = dns-01,",
                "pref_challs",
            ),
            ("key_type = ecdsa", "key_type = ed25519", "key_type ed25519"),
        ];
        let domains = vec!["example.test".to_owned()];
        let root = temp_dir("plan");
        let unchanged = Lineage::load(&renewal_file(&root, |text| text.to_owned())).unwrap();
        assert!(Plan::new(&unchanged, &domains).is_ok());
        for (from, to, refusal) in cases {
            let conf = renewal_file(&root, |text| {
                assert_eq!(text.matches(from).count(), 1, "{from}");
                text.replace(from, to)
            });
            let err = Plan::new(&Lineage::load(&conf).unwrap(), &domains)
                .err()
                .expect(refusal)
                .to_string();
            assert!(err.contains(refusal), "{refusal}: {err}");
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn names_webroot_cannot_validate_fail_the_certificate() {
        for (names, refusal) in [
            (&["*.example.test"][..], "wildcard"),
            (&["example.test", "192.0.2.1"][..], "other than DNS names"),
        ] {
            let root = temp_dir("names");
            let conf = lineage_on_disk(&root, names);
            let mut acme = Acme::new(&root, None).unwrap();
            let err = block_on(renew_one(&mut acme, &conf, true))
                .expect_err(refusal)
                .to_string();
            assert!(err.contains(refusal), "{refusal}: {err}");
            assert!(!root.join("archive/example/cert2.pem").exists());
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn ninety_day_certificates_renew_with_thirty_days_left() {
        let (nb, na) = (0, 90 * DAY);
        assert!(!due(59 * DAY, nb, na, None, None));
        assert!(due(60 * DAY + 1, nb, na, None, None));
    }

    #[test]
    fn short_certificates_renew_at_half_life() {
        assert!(!due(2 * DAY, 0, 6 * DAY, None, None));
        assert!(due(3 * DAY + 1, 0, 6 * DAY, None, None));
    }

    #[test]
    fn renew_before_expiry_wins_over_the_lifetime() {
        assert!(due(10 * DAY, 0, 90 * DAY, Some(85 * DAY), None));
        assert!(!due(70 * DAY, 0, 90 * DAY, Some(10 * DAY), None));
    }

    #[test]
    fn a_huge_renew_before_expiry_means_due_rather_than_overflow() {
        assert!(due(70 * DAY, 0, 90 * DAY, Some(i64::MAX - DAY), None));
    }

    #[test]
    fn ari_decides_when_it_answers() {
        assert!(due(10 * DAY, 0, 90 * DAY, None, Some(5 * DAY)));
        assert!(!due(70 * DAY, 0, 90 * DAY, None, Some(80 * DAY)));
        assert!(due(70 * DAY, 0, 90 * DAY, Some(30 * DAY), Some(80 * DAY)));
    }
}
