use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

static FILE: OnceLock<Mutex<File>> = OnceLock::new();

/// Sends the log to stderr and, when `path` is given, appends it there too.
pub fn init(path: Option<&Path>) -> std::io::Result<()> {
    if let Some(path) = path {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let _ = FILE.set(Mutex::new(file));
    }
    Ok(())
}

pub fn write(level: &str, message: std::fmt::Arguments) {
    let line = format!(
        "{} {level} {message}\n",
        utc(time::OffsetDateTime::now_utc().unix_timestamp())
    );
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Some(Ok(mut file)) = FILE.get().map(Mutex::lock) {
        let _ = file.write_all(line.as_bytes());
    }
}

/// `2026-01-31T12:00:00Z`
pub fn utc(unix: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            t.month() as u8,
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => format!("@{unix}"),
    }
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write("info", format_args!($($arg)*)) };
}
macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::write("warn", format_args!($($arg)*)) };
}
macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write("error", format_args!($($arg)*)) };
}
pub(crate) use {error, info, warning};
