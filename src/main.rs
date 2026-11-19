mod acme;
mod conf;
mod keys;
mod lineage;
mod log;
mod renew;

use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::keys::KeySpec;
use crate::log::{error, info};
use crate::renew::{IssueRequest, Settings};

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Renews the certificates in a certbot configuration directory in place.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// certbot's configuration directory, holding renewal/, archive/ and live/.
    #[arg(long, global = true, env = "ACME_CONFIG_DIR", default_value = "/etc/letsencrypt")]
    config_dir: PathBuf,
    /// A PEM file of root certificates to trust beside the built-in Mozilla
    /// roots, for an ACME server with a private CA such as a test server.
    #[arg(long, global = true, env = "ACME_CA_CERT", value_name = "PEM")]
    ca_cert: Option<PathBuf>,
    /// Also append the log to this file.
    #[arg(long, global = true, env = "ACME_LOG_FILE", value_name = "PATH")]
    log_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Renew each certificate that is due, once. Exits 1 if any renewal failed.
    Renew(RenewArgs),
    /// Run `renew` every --interval. After a pass with a failure, wait one
    /// more interval and exit 1.
    Run {
        #[command(flatten)]
        renew: RenewArgs,
        /// Time between passes: a positive number followed by s, m, h or d.
        #[arg(long, default_value = "12h", value_parser = parse_interval)]
        interval: Duration,
    },
    /// Issue a certificate into a new lineage, answering HTTP-01 from a webroot.
    Issue(IssueArgs),
    /// Print the name of each certificate under live/, one per line.
    List,
}

#[derive(Args)]
struct RenewArgs {
    /// Renew whether or not the certificate is due.
    #[arg(long)]
    force: bool,
    /// Only this certificate. Repeat for more than one.
    #[arg(long = "cert-name", value_name = "NAME")]
    cert_names: Vec<String>,
}

#[derive(Args)]
struct IssueArgs {
    /// The lineage's name: the directory under live/.
    #[arg(long, value_name = "NAME")]
    cert_name: String,
    /// A domain the certificate covers. Repeat for more than one.
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN", required = true)]
    domains: Vec<String>,
    /// The directory the web server serves /.well-known/acme-challenge/ from.
    #[arg(short = 'w', long, value_name = "DIR")]
    webroot: PathBuf,
    /// The ACME directory URL.
    #[arg(long, default_value = LETS_ENCRYPT, value_name = "URL")]
    server: String,
    /// rsa or ecdsa.
    #[arg(long, default_value = "ecdsa")]
    key_type: String,
    /// secp256r1 or secp384r1, for ecdsa.
    #[arg(long, default_value = "secp256r1")]
    elliptic_curve: String,
    /// 2048, 3072 or 4096, for rsa.
    #[arg(long, default_value = "2048")]
    rsa_key_size: String,
}

fn parse_interval(value: &str) -> Result<Duration, String> {
    let (number, unit) = match value.char_indices().next_back() {
        Some((at, _)) => value.split_at(at),
        None => return Err("an empty interval".to_owned()),
    };
    let number: u64 = number
        .parse()
        .map_err(|_| format!("{value:?} is not like 30s, 10m, 12h or 1d"))?;
    let unit: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("{value:?} is not like 30s, 10m, 12h or 1d")),
    };
    match number.checked_mul(unit) {
        Some(0) => Err(format!("{value:?} would run the passes back to back: use 1s or more")),
        Some(seconds) => Ok(Duration::from_secs(seconds)),
        None => Err(format!("{value:?} is too long an interval")),
    }
}

fn main() -> ExitCode {
    let Cli {
        config_dir,
        ca_cert,
        log_file,
        command,
    } = Cli::parse();
    exit_on_signals();
    if let Err(e) = log::init(log_file.as_deref()) {
        eprintln!("can't open the log file: {e}");
        return ExitCode::FAILURE;
    }
    let settings = Settings { config_dir, ca_cert };
    match command {
        Command::Run { renew, interval } => run(&settings, log_file.as_deref(), &renew, interval),
        Command::Renew(args) => block_on(renew::renew_all(&settings, args.force, &args.cert_names)),
        Command::Issue(args) => {
            let key = match KeySpec::from_params(
                Some(&args.key_type),
                Some(&args.elliptic_curve),
                Some(&args.rsa_key_size),
            ) {
                Ok(key) => key,
                Err(e) => {
                    error!("{e:#}");
                    return ExitCode::FAILURE;
                }
            };
            let request = IssueRequest {
                cert_name: args.cert_name,
                domains: args.domains,
                webroot: args.webroot,
                server: args.server,
                key,
            };
            block_on(async { renew::issue(&settings, &request).await.map(|()| true) })
        }
        Command::List => list(&settings.config_dir),
    }
}

fn block_on(work: impl Future<Output = anyhow::Result<bool>>) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("starting the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(work) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The container's long-running mode. Each pass runs as a child process, so
/// between passes only this loop is resident: the memory a pass used goes
/// back with the child. A failed pass ends the loop one interval later with
/// exit 1, so a restart policy retries no sooner and a monitor sees the exit.
fn run(settings: &Settings, log_file: Option<&Path>, renew: &RenewArgs, interval: Duration) -> ExitCode {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            error!("finding this program's path: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut args: Vec<OsString> = vec!["--config-dir".into(), settings.config_dir.clone().into()];
    if let Some(ca_cert) = &settings.ca_cert {
        args.extend(["--ca-cert".into(), ca_cert.clone().into()]);
    }
    if let Some(log_file) = log_file {
        args.extend(["--log-file".into(), log_file.into()]);
    }
    args.push("renew".into());
    if renew.force {
        args.push("--force".into());
    }
    for name in &renew.cert_names {
        args.extend(["--cert-name".into(), name.into()]);
    }
    let every = humanize(interval);
    loop {
        let ok = match std::process::Command::new(&exe).args(&args).status() {
            Ok(status) => status.success(),
            Err(e) => {
                error!("starting a renewal pass: {e}");
                false
            }
        };
        if !ok {
            error!("a renewal failed; exiting with 1 in {every}");
            std::thread::sleep(interval);
            return ExitCode::FAILURE;
        }
        info!("next pass in {every}");
        std::thread::sleep(interval);
    }
}

fn humanize(d: Duration) -> String {
    match d.as_secs() {
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// As PID 1 in a container a process gets no default action for SIGTERM, so
/// `docker stop` would wait out its timeout. Exit straight away instead, with
/// the shell's 128+signal status. Every write is a rename of a complete file,
/// so stopping part way leaves nothing half-written.
fn exit_on_signals() {
    extern "C" fn exit_now(signal: libc::c_int) {
        unsafe { libc::_exit(128 + signal) }
    }
    unsafe {
        libc::signal(libc::SIGTERM, exit_now as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, exit_now as *const () as libc::sighandler_t);
    }
}

fn list(config_dir: &Path) -> ExitCode {
    let live = config_dir.join("live");
    let entries = match fs::read_dir(&live) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ExitCode::SUCCESS,
        Err(e) => {
            error!("reading {}: {e}", live.display());
            return ExitCode::FAILURE;
        }
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort();
    for name in names {
        println!("{name}");
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals() {
        assert_eq!(parse_interval("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_interval("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_interval("1d").unwrap(), Duration::from_secs(86_400));
        assert!(parse_interval("12").is_err());
        assert!(parse_interval("h").is_err());
    }

    #[test]
    fn an_interval_ending_in_a_multibyte_character_is_a_usage_error() {
        for value in ["12é", "é", "1日"] {
            assert!(parse_interval(value).is_err(), "{value}");
        }
    }

    #[test]
    fn intervals_that_would_loop_without_waiting_are_refused() {
        for value in ["0s", "0h"] {
            assert!(parse_interval(value).unwrap_err().contains("back to back"));
        }
        for value in ["18446744073709551615h", "213503982334602d"] {
            assert!(parse_interval(value).unwrap_err().contains("too long"));
        }
        assert_eq!(
            parse_interval("213503982334601d").unwrap(),
            Duration::from_secs(213_503_982_334_601 * 86_400)
        );
        assert_eq!(humanize(Duration::from_secs(43_200)), "12h");
    }
}
