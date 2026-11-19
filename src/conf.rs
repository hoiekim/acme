//! certbot's `renewal/<name>.conf`: the part of the configobj format those
//! files use, which is `key = value` lines, `[section]` and `[[subsection]]`
//! headers, `#` comments, and comma-separated lists.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};

#[derive(Debug, Default)]
pub struct Conf {
    top: BTreeMap<String, String>,
    params: BTreeMap<String, String>,
    webroot_map: BTreeMap<String, String>,
}

impl Conf {
    pub fn parse(text: &str) -> Result<Self> {
        let mut conf = Conf::default();
        let mut section: Vec<String> = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                let depth = line.chars().take_while(|&c| c == '[').count();
                let closing = line.chars().rev().take_while(|&c| c == ']').count();
                let name = line[depth..line.len() - closing].trim();
                if closing != depth || name.is_empty() || depth > section.len() + 1 {
                    bail!("line {}: malformed section header {line:?}", index + 1);
                }
                section.truncate(depth - 1);
                section.push(unquote(name).to_owned());
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| anyhow!("line {}: expected `key = value`, found {line:?}", index + 1))?;
            let key = unquote(key.trim()).to_owned();
            let value = value_of(value.trim());
            let target = match section.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                [] => &mut conf.top,
                ["renewalparams"] => &mut conf.params,
                ["renewalparams", "webroot_map"] => &mut conf.webroot_map,
                // Other sections, such as certbot's [acme_renewal_info], don't
                // change how a certificate renews.
                _ => continue,
            };
            target.insert(key, value);
        }
        Ok(conf)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.top.get(key).map(String::as_str)
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty() && *v != "None")
    }

    /// The webroot certbot would answer `domain`'s HTTP-01 challenge from: its
    /// `webroot_map` entry, else the last `webroot_path`.
    pub fn webroot_for(&self, domain: &str) -> Option<String> {
        if let Some(path) = self.webroot_map.get(domain) {
            return Some(path.clone());
        }
        self.param("webroot_path").and_then(|v| list(v).pop())
    }
}

/// A configobj value with any quotes or trailing comment taken off.
fn value_of(raw: &str) -> String {
    let mut chars = raw.chars();
    match chars.next() {
        Some(q @ ('"' | '\'')) => match raw[1..].find(q) {
            Some(end) if !raw[end + 2..].trim_start().starts_with(',') => raw[1..end + 1].to_owned(),
            _ => raw.to_owned(),
        },
        _ => match raw.find(" #") {
            Some(at) => raw[..at].trim_end().to_owned(),
            None => raw.to_owned(),
        },
    }
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// A configobj list: `a, b,` or `a,` are both lists.
pub fn list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|item| unquote(item).to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

/// configobj's boolean spellings.
pub fn boolean(value: Option<&str>) -> Result<Option<bool>> {
    let Some(value) = value else { return Ok(None) };
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(Some(true)),
        "false" | "no" | "off" | "0" => Ok(Some(false)),
        _ => bail!("{value:?} is not a boolean"),
    }
}

/// certbot's `renew_before_expiry`, such as `30 days` or a bare `30`, in seconds.
pub fn interval_seconds(value: &str) -> Result<i64> {
    let value = value.trim();
    let (number, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => (&value[..at], value[at..].trim()),
        None => (value, "days"),
    };
    let number: i64 = number
        .parse()
        .map_err(|_| anyhow!("{value:?} is not an interval such as \"30 days\""))?;
    let unit = match unit.trim_end_matches('s') {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        "day" => 86_400,
        "week" => 7 * 86_400,
        _ => bail!("{value:?} is not an interval such as \"30 days\""),
    };
    number
        .checked_mul(unit)
        .ok_or_else(|| anyhow!("{value:?} is too long an interval"))
}

/// A new lineage's renewal file, in the shape certbot writes.
pub struct NewLineage<'a> {
    pub archive_dir: &'a str,
    pub links: [(&'a str, String); 4],
    pub params: Vec<(&'a str, String)>,
    pub webroot_map: Vec<(String, String)>,
}

impl NewLineage<'_> {
    pub fn render(&self) -> String {
        let mut out = format!(
            "# Written by acme {}, in the format certbot reads.\narchive_dir = {}\n",
            env!("CARGO_PKG_VERSION"),
            self.archive_dir
        );
        for (kind, path) in &self.links {
            out.push_str(&format!("{kind} = {path}\n"));
        }
        out.push_str("\n# Options used in the renewal process\n[renewalparams]\n");
        for (key, value) in &self.params {
            out.push_str(&format!("{key} = {value}\n"));
        }
        if !self.webroot_map.is_empty() {
            out.push_str("[[webroot_map]]\n");
            for (domain, path) in &self.webroot_map {
                out.push_str(&format!("{domain} = {path}\n"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERTBOT: &str = "\
# renew_before_expiry = 30 days
version = 5.9.0
archive_dir = /etc/letsencrypt/archive/example
cert = /etc/letsencrypt/live/example/cert.pem
privkey = /etc/letsencrypt/live/example/privkey.pem
chain = /etc/letsencrypt/live/example/chain.pem
fullchain = /etc/letsencrypt/live/example/fullchain.pem

# Options used in the renewal process
[renewalparams]
account = 0123456789abcdef0123456789abcdef
authenticator = webroot
webroot_path = /data/letsencrypt-acme-challenge,
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
installer = None
[[webroot_map]]
a.example.com = /data/letsencrypt-acme-challenge
www.a.example.com = /srv/other
[acme_renewal_info]
ari_retry_after = 2026-11-19T06:00:00
";

    #[test]
    fn reads_a_certbot_renewal_file() {
        let conf = Conf::parse(CERTBOT).unwrap();
        assert_eq!(conf.get("archive_dir"), Some("/etc/letsencrypt/archive/example"));
        assert_eq!(
            conf.get("fullchain"),
            Some("/etc/letsencrypt/live/example/fullchain.pem")
        );
        assert_eq!(conf.get("renew_before_expiry"), None);
        assert_eq!(
            conf.param("server"),
            Some("https://acme-v02.api.letsencrypt.org/directory")
        );
        assert_eq!(conf.param("installer"), None);
        assert_eq!(conf.param("ari_retry_after"), None);
        assert_eq!(
            conf.webroot_for("a.example.com").as_deref(),
            Some("/data/letsencrypt-acme-challenge")
        );
        assert_eq!(conf.webroot_for("www.a.example.com").as_deref(), Some("/srv/other"));
        assert_eq!(
            conf.webroot_for("b.example.com").as_deref(),
            Some("/data/letsencrypt-acme-challenge")
        );
    }

    #[test]
    fn values_lose_quotes_and_comments() {
        let conf = Conf::parse("a = \"x # y\"\nb = plain # note\nc = 'single'\n").unwrap();
        assert_eq!(conf.get("a"), Some("x # y"));
        assert_eq!(conf.get("b"), Some("plain"));
        assert_eq!(conf.get("c"), Some("single"));
        assert_eq!(list("/a, /b,"), vec!["/a", "/b"]);
        assert_eq!(list("/a,"), vec!["/a"]);
    }

    #[test]
    fn rejects_broken_lines() {
        assert!(Conf::parse("no equals sign\n").is_err());
        assert!(Conf::parse("[[skipped level]]\n").is_err());
        assert!(Conf::parse("[open\n").is_err());
    }

    #[test]
    fn intervals() {
        assert_eq!(interval_seconds("30 days").unwrap(), 30 * 86_400);
        assert_eq!(interval_seconds("30").unwrap(), 30 * 86_400);
        assert_eq!(interval_seconds("2 weeks").unwrap(), 14 * 86_400);
        assert_eq!(interval_seconds("1 day").unwrap(), 86_400);
        assert!(interval_seconds("soon").is_err());
        assert_eq!(boolean(Some("True")).unwrap(), Some(true));
        assert_eq!(boolean(Some("False")).unwrap(), Some(false));
        assert!(boolean(Some("maybe")).is_err());
    }

    #[test]
    fn an_interval_too_long_to_count_is_refused() {
        for value in ["9223372036854775807 days", "106751991167301 days"] {
            let err = interval_seconds(value).unwrap_err().to_string();
            assert!(err.contains("too long"), "{err}");
        }
        assert_eq!(
            interval_seconds("106751991167300 days").unwrap(),
            106_751_991_167_300 * 86_400
        );
    }

    #[test]
    fn renders_what_it_parses() {
        let text = NewLineage {
            archive_dir: "/etc/letsencrypt/archive/n",
            links: [
                ("cert", "/etc/letsencrypt/live/n/cert.pem".into()),
                ("privkey", "/etc/letsencrypt/live/n/privkey.pem".into()),
                ("chain", "/etc/letsencrypt/live/n/chain.pem".into()),
                ("fullchain", "/etc/letsencrypt/live/n/fullchain.pem".into()),
            ],
            params: vec![("authenticator", "webroot".into()), ("webroot_path", "/w,".into())],
            webroot_map: vec![("a.example.com".into(), "/w".into())],
        }
        .render();
        let conf = Conf::parse(&text).unwrap();
        assert_eq!(conf.get("privkey"), Some("/etc/letsencrypt/live/n/privkey.pem"));
        assert_eq!(conf.param("authenticator"), Some("webroot"));
        assert_eq!(conf.webroot_for("a.example.com").as_deref(), Some("/w"));
    }
}
