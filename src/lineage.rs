//! certbot's storage layout. Each certificate is a lineage named `<name>`:
//!
//! - `archive/<name>/{cert,privkey,chain,fullchain}N.pem`, every version kept
//! - `live/<name>/{cert,privkey,chain,fullchain}.pem`, symlinks to the current version
//! - `renewal/<name>.conf`, how to renew it
//!
//! A renewal writes version N+1 into the archive, then replaces `live/<name>`
//! with a directory whose links point at N+1 in one `rename`, so a reader
//! never finds a missing link or links into two different versions.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::ops::Bound;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::conf::Conf;
use crate::log::{info, warning};

pub const KINDS: [&str; 4] = ["cert", "privkey", "chain", "fullchain"];

/// certbot's `BASE_PRIVKEY_MODE`.
const KEY_MODE: u32 = 0o600;
/// The group and other bits a renewed key keeps from the key it replaces, as
/// certbot's `compute_private_key_mode` does.
const KEY_MODE_KEPT: u32 = 0o074;
/// Prior versions kept in the archive, as certbot's `truncate` does.
const PRIOR_VERSIONS_KEPT: u32 = 5;

pub struct Lineage {
    pub name: String,
    pub conf: Conf,
    pub archive_dir: PathBuf,
    pub live_dir: PathBuf,
    links: [PathBuf; 4],
    link_files: [OsString; 4],
}

impl Lineage {
    pub fn load(conf_path: &Path) -> Result<Self> {
        let name = lineage_name(conf_path)?;
        let text = fs::read_to_string(conf_path).with_context(|| format!("reading {}", conf_path.display()))?;
        let conf = Conf::parse(&text).with_context(|| format!("parsing {}", conf_path.display()))?;
        let archive_dir = PathBuf::from(
            conf.get("archive_dir")
                .ok_or_else(|| anyhow!("archive_dir is missing"))?,
        );
        let links = KINDS.map(|kind| conf.get(kind).map(PathBuf::from));
        let links = match links {
            [Some(a), Some(b), Some(c), Some(d)] => [a, b, c, d],
            _ => bail!("the renewal file needs all of cert, privkey, chain and fullchain"),
        };
        let link_files = match links.each_ref().map(|l| l.file_name().map(OsStr::to_os_string)) {
            [Some(a), Some(b), Some(c), Some(d)] => [a, b, c, d],
            _ => bail!("cert, privkey, chain and fullchain must each name a file"),
        };
        let live_dir = links[0]
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| anyhow!("cert has no directory"))?;
        ensure!(
            links.iter().all(|l| l.parent() == Some(live_dir.as_path())),
            "cert, privkey, chain and fullchain are not in one directory"
        );
        ensure!(
            live_dir.is_absolute() && archive_dir.is_absolute(),
            "archive_dir and the live paths must be absolute"
        );
        ensure!(
            live_dir.parent().is_some() && live_dir.file_name().is_some(),
            "{} can't be replaced",
            live_dir.display()
        );
        Ok(Lineage {
            name,
            conf,
            archive_dir,
            live_dir,
            links,
            link_files,
        })
    }

    fn link(&self, kind: &str) -> &Path {
        &self.links[kind_index(kind)]
    }

    /// The link's file name, such as `fullchain.pem`.
    fn link_file(&self, kind: &str) -> &OsStr {
        &self.link_files[kind_index(kind)]
    }

    /// The version `live/` points at. All four links must agree.
    pub fn current_version(&self) -> Result<u32> {
        let mut versions = KINDS.iter().map(|kind| {
            let link = self.link(kind);
            let target = fs::read_link(link).with_context(|| format!("{} is not a symlink", link.display()))?;
            let file = target.file_name().and_then(|f| f.to_str()).unwrap_or_default();
            version_of(kind, file)
                .ok_or_else(|| anyhow!("{} points at {}, not {kind}N.pem", link.display(), target.display()))
        });
        let first = versions.next().expect("four kinds")?;
        for v in versions {
            ensure!(
                v? == first,
                "the links in {} point at different versions",
                self.live_dir.display()
            );
        }
        Ok(first)
    }

    pub fn read_current(&self, kind: &str) -> Result<Vec<u8>> {
        let link = self.link(kind);
        fs::read(link).with_context(|| format!("reading {}", link.display()))
    }

    fn archive_versions(&self) -> Result<BTreeMap<u32, Vec<PathBuf>>> {
        let mut versions: BTreeMap<u32, Vec<PathBuf>> = BTreeMap::new();
        let entries = match fs::read_dir(&self.archive_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(versions),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.archive_dir.display())),
        };
        for entry in entries {
            let entry = entry?;
            let file = entry.file_name();
            let Some(file) = file.to_str() else { continue };
            if let Some(v) = KINDS.iter().find_map(|kind| version_of(kind, file)) {
                versions.entry(v).or_default().push(entry.path());
            }
        }
        Ok(versions)
    }

    /// Removes what an interrupted run left: a half-built live directory, temp
    /// files, and archive versions newer than the one `live/` points at. certbot
    /// decides whether to renew from the newest version in the archive, so an
    /// unlinked newer one would stop it renewing after a rollback.
    pub fn clean_up(&self, current: u32) -> Result<()> {
        let staging = self.staging_dir();
        if fs::symlink_metadata(&staging).is_ok() {
            warning!(
                "{}: removing {} left by an interrupted run",
                self.name,
                staging.display()
            );
            remove_dir_tree(&staging)?;
        }
        if let Ok(entries) = fs::read_dir(&self.archive_dir) {
            for entry in entries.flatten() {
                let file = entry.file_name();
                if file.to_str().is_some_and(|f| f.starts_with('.') && f.ends_with(".tmp")) {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        for (version, files) in self
            .archive_versions()?
            .range((Bound::Excluded(current), Bound::Unbounded))
        {
            warning!(
                "{}: removing version {version}, which an interrupted run wrote but never linked",
                self.name
            );
            for file in files {
                fs::remove_file(file)?;
            }
        }
        Ok(())
    }

    /// Writes a new version into the archive and returns its number. If any
    /// file fails, the ones written are removed again.
    pub fn save(&self, cert: &str, chain: &str, key: &str, prior: Option<u32>) -> Result<u32> {
        fs::create_dir_all(&self.archive_dir)?;
        let version = match self.archive_versions()?.keys().next_back() {
            None => 1,
            Some(&last) => last
                .checked_add(1)
                .ok_or_else(|| anyhow!("version {last} in the archive is the last a version number can hold"))?,
        };
        let (key_mode, key_gid) = match prior {
            Some(prior) => {
                let old = fs::metadata(self.archive_dir.join(format!("privkey{prior}.pem")))
                    .context("reading the current private key's mode")?;
                use std::os::unix::fs::MetadataExt;
                (KEY_MODE | (old.permissions().mode() & KEY_MODE_KEPT), Some(old.gid()))
            }
            None => (KEY_MODE, None),
        };
        let files = [
            ("privkey", key.to_owned(), key_mode),
            ("cert", cert.to_owned(), 0o644),
            ("chain", chain.to_owned(), 0o644),
            ("fullchain", format!("{cert}{chain}"), 0o644),
        ];
        let mut written = Vec::new();
        let result = (|| -> Result<()> {
            for (kind, contents, mode) in &files {
                let path = self.archive_dir.join(format!("{kind}{version}.pem"));
                write_new(
                    &path,
                    contents.as_bytes(),
                    *mode,
                    if *kind == "privkey" { key_gid } else { None },
                )?;
                written.push(path);
            }
            sync_dir(&self.archive_dir)
        })();
        if let Err(e) = result {
            for path in written {
                let _ = fs::remove_file(path);
            }
            return Err(e);
        }
        Ok(version)
    }

    fn staging_dir(&self) -> PathBuf {
        let name = self.live_dir.file_name().expect("checked in load").to_string_lossy();
        self.live_dir.with_file_name(format!(".{name}.next"))
    }

    /// Points `live/<name>` at `version`. The new links are built in a
    /// sibling directory, which then swaps places with the old one in a
    /// single rename. Where the filesystem can't swap, each link is replaced
    /// by its own rename instead, so no link is ever missing.
    pub fn activate(&self, version: u32) -> Result<()> {
        let staging = self.staging_dir();
        let parent = self.live_dir.parent().expect("checked in load");
        fs::create_dir_all(parent)?;
        if fs::symlink_metadata(&staging).is_ok() {
            remove_dir_tree(&staging)?;
        }
        let existing = fs::metadata(&self.live_dir).ok();
        fs::create_dir(&staging)?;
        fs::set_permissions(
            &staging,
            fs::Permissions::from_mode(existing.as_ref().map_or(0o755, |m| m.permissions().mode() & 0o7777)),
        )?;
        let fallback_dir = relative_path(&self.live_dir, &self.archive_dir);
        for kind in KINDS {
            let link = self.link(kind);
            // Keep the form of the target the old link had, as certbot does.
            let dir = fs::read_link(link)
                .ok()
                .and_then(|t| t.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| fallback_dir.clone());
            symlink(
                dir.join(format!("{kind}{version}.pem")),
                staging.join(self.link_file(kind)),
            )?;
        }
        let readme = self.live_dir.join("README");
        if readme.is_file() {
            fs::copy(&readme, staging.join("README"))?;
        } else if existing.is_none() {
            fs::write(staging.join("README"), LIVE_README)?;
        }
        sync_dir(&staging)?;

        if existing.is_none() {
            fs::rename(&staging, &self.live_dir)?;
        } else {
            match exchange(&staging, &self.live_dir) {
                Ok(()) => remove_dir_tree(&staging)?,
                Err(e)
                    if e.raw_os_error() == Some(libc::EINVAL)
                        || e.raw_os_error() == Some(libc::ENOSYS)
                        || e.kind() == std::io::ErrorKind::Unsupported =>
                {
                    warning!(
                        "{}: this filesystem can't swap directories ({e}), replacing each link on its own",
                        self.name
                    );
                    for kind in KINDS {
                        let file = self.link_file(kind);
                        fs::rename(staging.join(file), self.live_dir.join(file))?;
                    }
                    remove_dir_tree(&staging)?;
                }
                Err(e) => return Err(e).with_context(|| format!("swapping {} into place", self.live_dir.display())),
            }
        }
        sync_dir(parent)?;
        Ok(())
    }

    /// Deletes archive versions older than the five before `current`.
    pub fn truncate(&self, current: u32) {
        let Ok(versions) = self.archive_versions() else { return };
        for (version, files) in versions.range(..current.saturating_sub(PRIOR_VERSIONS_KEPT)) {
            for file in files {
                if let Err(e) = fs::remove_file(file) {
                    warning!(
                        "{}: couldn't remove version {version}'s {}: {e}",
                        self.name,
                        file.display()
                    );
                }
            }
        }
    }
}

const LIVE_README: &str = "This directory contains your keys and certificates.

`privkey.pem`  : the private key for your certificate.
`fullchain.pem`: the certificate file used in most server software.
`chain.pem`    : used for OCSP stapling in Nginx >=1.3.7.
`cert.pem`     : will break many server configurations, and should not be used
                 without reading further documentation (see link below).

WARNING: DO NOT MOVE OR RENAME THESE FILES!
         Certbot expects these files to remain in this location in order
         to function properly!

We recommend not moving these files. For more information, see the Certbot
User Guide at https://certbot.eff.org/docs/using.html#where-are-my-certificates.
";

fn lineage_name(conf_path: &Path) -> Result<String> {
    let file = conf_path.file_name().and_then(|f| f.to_str()).unwrap_or_default();
    file.strip_suffix(".conf")
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{} is not a .conf file", conf_path.display()))
}

fn kind_index(kind: &str) -> usize {
    KINDS.iter().position(|k| *k == kind).expect("one of KINDS")
}

/// `cert12.pem` is version 12 of `cert`.
fn version_of(kind: &str, file: &str) -> Option<u32> {
    let digits = file.strip_prefix(kind)?.strip_suffix(".pem")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The `renewal/*.conf` files, by name.
pub fn renewal_confs(config_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = config_dir.join("renewal");
    let mut confs = Vec::new();
    match fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "conf") && path.is_file() {
                    confs.push(path);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    }
    confs.sort();
    Ok(confs)
}

/// Creates `path` with `contents` through a temp file and a rename, so it
/// appears whole or not at all. Fails if `path` exists.
pub fn write_new(path: &Path, contents: &[u8], mode: u32, gid: Option<u32>) -> Result<()> {
    ensure!(fs::symlink_metadata(path).is_err(), "{} already exists", path.display());
    write_atomic(path, contents, mode, gid)
}

/// Writes `path` through a temp file and a rename, replacing what's there.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32, gid: Option<u32>) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no directory", path.display()))?;
    let file = path
        .file_name()
        .ok_or_else(|| anyhow!("{} has no file name", path.display()))?
        .to_string_lossy();
    let tmp = dir.join(format!(".{file}.tmp"));
    let _ = fs::remove_file(&tmp);
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        if let Some(gid) = gid {
            std::os::unix::fs::fchown(&f, None, Some(gid))?;
        }
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.write_all(contents)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.with_context(|| format!("writing {}", path.display()))
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)?
        .sync_all()
        .with_context(|| format!("syncing {}", dir.display()))
}

/// Removes a directory of plain files and symlinks without following the links.
fn remove_dir_tree(dir: &Path) -> Result<()> {
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        fs::remove_file(dir)?;
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_dir_tree(&entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    fs::remove_dir(dir).with_context(|| format!("removing {}", dir.display()))
}

/// Swaps two paths in one step (Linux `renameat2` with `RENAME_EXCHANGE`).
#[cfg(target_os = "linux")]
fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    const RENAME_EXCHANGE: libc::c_uint = 2;
    let a = CString::new(a.as_os_str().as_bytes())?;
    let b = CString::new(b.as_os_str().as_bytes())?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn exchange(_: &Path, _: &Path) -> std::io::Result<()> {
    Err(std::io::ErrorKind::Unsupported.into())
}

/// The path to `to` from the directory `from`, both absolute.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<Component> = from.components().collect();
    let to: Vec<Component> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for part in &to[common..] {
        out.push(part.as_os_str());
    }
    out
}

/// Holds `<config>/acme/lock` until dropped, so a renewal and an issue never
/// write at the same time.
pub struct Lock(#[allow(dead_code)] File);

/// Takes `<config>/acme/lock`, waiting up to `wait` for another acme process
/// to let go of it, and fails after that, so a stuck holder can't stall the
/// caller with no error.
pub async fn lock(config_dir: &Path, wait: Duration) -> Result<Lock> {
    use std::os::fd::AsRawFd;
    let dir = config_dir.join("acme");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join("lock"))?;
    let deadline = Instant::now() + wait;
    let mut waiting = false;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(Lock(file));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(err).context("locking acme/lock");
        }
        ensure!(
            Instant::now() < deadline,
            "another acme process has held acme/lock for {}s",
            wait.as_secs()
        );
        if !waiting {
            info!("waiting up to {}s for another acme process to finish", wait.as_secs());
            waiting = true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(path).unwrap().ino()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("acme-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A lineage at version 1, laid out the way certbot lays it out.
    fn certbot_lineage(root: &Path, name: &str) -> Lineage {
        let archive = root.join("archive").join(name);
        let live = root.join("live").join(name);
        fs::create_dir_all(&archive).unwrap();
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(root.join("renewal")).unwrap();
        for kind in KINDS {
            fs::write(archive.join(format!("{kind}1.pem")), format!("{kind} one\n")).unwrap();
            symlink(
                format!("../../archive/{name}/{kind}1.pem"),
                live.join(format!("{kind}.pem")),
            )
            .unwrap();
        }
        fs::set_permissions(archive.join("privkey1.pem"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::write(live.join("README"), "readme\n").unwrap();
        let conf = root.join("renewal").join(format!("{name}.conf"));
        let mut text = format!("archive_dir = {}\n", archive.display());
        for kind in KINDS {
            text.push_str(&format!("{kind} = {}\n", live.join(format!("{kind}.pem")).display()));
        }
        text.push_str("[renewalparams]\nauthenticator = webroot\n");
        fs::write(&conf, text).unwrap();
        Lineage::load(&conf).unwrap()
    }

    #[test]
    fn renewal_writes_the_next_version_and_relinks() {
        let root = temp_dir("renew");
        let lineage = certbot_lineage(&root, "example");
        assert_eq!(lineage.current_version().unwrap(), 1);
        let version = lineage.save("cert two\n", "chain two\n", "key two\n", Some(1)).unwrap();
        assert_eq!(version, 2);
        let before = inode(&root.join("live/example"));
        lineage.activate(version).unwrap();
        if cfg!(target_os = "linux") {
            assert_ne!(
                inode(&root.join("live/example")),
                before,
                "live/example is replaced by a whole new directory"
            );
        }
        assert_eq!(lineage.current_version().unwrap(), 2);
        assert_eq!(
            fs::read_to_string(root.join("live/example/fullchain.pem")).unwrap(),
            "cert two\nchain two\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("live/example/privkey.pem")).unwrap(),
            "key two\n"
        );
        assert_eq!(
            fs::read_link(root.join("live/example/cert.pem")).unwrap(),
            PathBuf::from("../../archive/example/cert2.pem")
        );
        assert_eq!(
            fs::read_to_string(root.join("live/example/README")).unwrap(),
            "readme\n"
        );
        let mode = fs::metadata(root.join("archive/example/privkey2.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "the new key keeps the old key's group read bit");
        assert!(fs::symlink_metadata(root.join("live/.example.next")).is_err());
        assert!(fs::symlink_metadata(root.join("live/example")).unwrap().is_dir());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn interrupted_runs_are_cleaned_up() {
        let root = temp_dir("cleanup");
        let lineage = certbot_lineage(&root, "c");
        lineage.save("x\n", "y\n", "z\n", Some(1)).unwrap();
        fs::create_dir(root.join("live/.c.next")).unwrap();
        fs::write(root.join("archive/c/.cert3.pem.tmp"), "half").unwrap();
        lineage.clean_up(1).unwrap();
        let mut left: Vec<_> = fs::read_dir(root.join("archive/c"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["cert1.pem", "chain1.pem", "fullchain1.pem", "privkey1.pem"]);
        assert!(fs::symlink_metadata(root.join("live/.c.next")).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn truncate_keeps_five_prior_versions() {
        let root = temp_dir("truncate");
        let lineage = certbot_lineage(&root, "t");
        let mut version = 1;
        for _ in 0..7 {
            version = lineage.save("c\n", "ch\n", "k\n", Some(version)).unwrap();
            lineage.activate(version).unwrap();
            lineage.truncate(version);
        }
        let versions: Vec<u32> = lineage.archive_versions().unwrap().keys().copied().collect();
        assert_eq!(versions, vec![3, 4, 5, 6, 7, 8]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_new_lineage_gets_certbots_relative_links() {
        let root = temp_dir("new");
        let conf = root.join("renewal/n.conf");
        fs::create_dir_all(conf.parent().unwrap()).unwrap();
        let mut text = format!("archive_dir = {}\n", root.join("archive/n").display());
        for kind in KINDS {
            text.push_str(&format!(
                "{kind} = {}\n",
                root.join(format!("live/n/{kind}.pem")).display()
            ));
        }
        fs::write(&conf, text).unwrap();
        let lineage = Lineage::load(&conf).unwrap();
        let version = lineage.save("c\n", "ch\n", "k\n", None).unwrap();
        lineage.activate(version).unwrap();
        assert_eq!(
            fs::read_link(root.join("live/n/privkey.pem")).unwrap(),
            PathBuf::from("../../archive/n/privkey1.pem")
        );
        assert!(root.join("live/n/README").is_file());
        assert_eq!(
            fs::metadata(root.join("archive/n/privkey1.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(&root).unwrap();
    }

    /// Points every live link of lineage `name` at `version`, with archive files for it.
    fn relink(root: &Path, name: &str, version: u32) {
        for kind in KINDS {
            fs::write(
                root.join(format!("archive/{name}/{kind}{version}.pem")),
                format!("{kind} {version}\n"),
            )
            .unwrap();
            let link = root.join(format!("live/{name}/{kind}.pem"));
            fs::remove_file(&link).unwrap();
            symlink(format!("../../archive/{name}/{kind}{version}.pem"), &link).unwrap();
        }
    }

    #[test]
    fn the_last_version_number_neither_wraps_nor_cleans_up_the_archive() {
        let root = temp_dir("last-version");
        let lineage = certbot_lineage(&root, "last");
        relink(&root, "last", u32::MAX);
        assert_eq!(lineage.current_version().unwrap(), u32::MAX);
        lineage.clean_up(u32::MAX).unwrap();
        assert!(
            root.join("archive/last/cert1.pem").exists(),
            "clean-up removed an older version"
        );
        assert!(root.join(format!("archive/last/cert{}.pem", u32::MAX)).exists());
        let err = lineage
            .save("c\n", "ch\n", "k\n", Some(u32::MAX))
            .unwrap_err()
            .to_string();
        assert!(err.contains("the last a version number can hold"), "{err}");
        assert!(
            !root.join("archive/last/cert0.pem").exists(),
            "save wrapped to version 0"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn links_at_different_versions_are_refused() {
        let root = temp_dir("mixed-versions");
        let lineage = certbot_lineage(&root, "mixed");
        fs::write(root.join("archive/mixed/cert2.pem"), "cert 2\n").unwrap();
        fs::remove_file(root.join("live/mixed/cert.pem")).unwrap();
        symlink("../../archive/mixed/cert2.pem", root.join("live/mixed/cert.pem")).unwrap();
        let err = lineage.current_version().unwrap_err().to_string();
        assert!(err.contains("different versions"), "{err}");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_link_path_that_names_no_file_is_refused_on_load() {
        let root = temp_dir("no-file");
        fs::create_dir_all(root.join("renewal")).unwrap();
        let conf = root.join("renewal/bad.conf");
        let mut text = format!("archive_dir = {}\n", root.join("archive/bad").display());
        for kind in KINDS {
            text.push_str(&format!("{kind} = {}\n", root.join("live/bad/..").display()));
        }
        fs::write(&conf, text).unwrap();
        let err = Lineage::load(&conf).err().expect("load refuses it").to_string();
        assert!(err.contains("must each name a file"), "{err}");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn versions_and_paths() {
        assert_eq!(version_of("cert", "cert12.pem"), Some(12));
        assert_eq!(version_of("cert", "fullchain1.pem"), None);
        assert_eq!(version_of("chain", "chain.pem"), None);
        assert_eq!(
            relative_path(Path::new("/etc/le/live/a"), Path::new("/etc/le/archive/a")),
            PathBuf::from("../../archive/a")
        );
    }
}
