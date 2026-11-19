# acme

A small ACME client that renews the certificates certbot manages, in place,
in certbot's own layout under `/etc/letsencrypt`. It replaces a container
that runs `certbot renew` in a loop: same volume, same files, the same paths
for the web server to read, and a fraction of the memory.

certbot is Python, and a renewal pass imports certbot, its ACME library and
`cryptography` before it does anything, which takes it past 30 MiB. acme is
one static binary in a `FROM scratch` image, built on
[instant-acme](https://crates.io/crates/instant-acme), rustls and
[rcgen](https://crates.io/crates/rcgen), with Mozilla's root certificates
compiled in.

## Commands

- **`run`**, the image's default: a renewal pass every 12 hours (`--interval`).
  Each pass runs as a child process, so between passes only the loop is in
  memory. When any renewal in a pass fails, it waits one more interval and
  exits 1: a restart policy retries no sooner than the next pass would have,
  and a monitor watching the container sees the exit.
- **`renew`**: one pass. Exits 1 if any renewal failed. `--force` renews
  whether or not a certificate is due; `--cert-name NAME` limits the pass.
- **`issue --cert-name NAME -d DOMAIN [-d DOMAIN...] -w WEBROOT`**: a new
  certificate in a new lineage, with the renewal file certbot would have
  written. `--server` (Let's Encrypt by default), `--key-type`
  (`ecdsa` or `rsa`), `--elliptic-curve` and `--rsa-key-size` as in certbot.
- **`list`**: the certificate names under `live/`, one per line.

Each renewal, and each `issue`, gives up after 5 minutes. A pass or an
`issue` waits at most 10 minutes for another acme process to release
`acme/lock`, then fails.

Every command takes `--config-dir` (`/etc/letsencrypt`), `--ca-cert` (a PEM
file of extra roots to trust, for a test ACME server) and `--log-file`, or
the environment variables `ACME_CONFIG_DIR`, `ACME_CA_CERT` and
`ACME_LOG_FILE`.

## How it reads certbot's layout

Each `renewal/<name>.conf` is a certificate to keep renewed. From it, acme
takes:

- the ACME server (`server`);
- how to answer the challenge: `authenticator = webroot`, with each domain's
  directory from `[[webroot_map]]`, else `webroot_path`;
- the key: `key_type`, `rsa_key_size` and `elliptic_curve`. A file without
  `key_type` predates certbot 1.25 and means RSA, as certbot reads it;
- `renew_before_expiry`, `autorenew`, and `preferred_profile` or
  `required_profile`.

The domains come from the current certificate, as certbot takes them.

A setting acme can't honour fails that certificate on every pass, so it shows
up long before the certificate expires: an authenticator other than webroot,
an installer, a pre, post, renew or deploy hook, `reuse_key` and
`must_staple`. `preferred_chain` is ignored, and the CA's default chain is
used.

certbot also acts on two things beside the renewal files, and while either
is there every certificate fails on every pass:

- an executable in `renewal-hooks/pre/`, `deploy/` or `post/`, other than
  one whose name ends in `~`, which certbot would run around a renewal;
- a `cli.ini` setting other than those that only change logging,
  registration or prompts: `agree-tos`, `email`, `eff-email`,
  `no-eff-email`, `register-unsafely-without-email`, `non-interactive` (or
  `noninteractive`), `text`, `quiet`, `verbose`, `max-log-backups`,
  `logs-dir`, `work-dir`, `no-random-sleep-on-renew` and `user-agent`.
  `directory-hooks` and `no-directory-hooks` are accepted too: turning
  directory hooks off turns the hook check off, as it turns the hooks off
  for certbot.

## When it renews

By the rules certbot 5 follows. When the ACME server publishes renewal
information (ARI) for the certificate, acme renews once a random point in the
suggested window has passed. Otherwise, with `renew_before_expiry` set, it
renews once that much time is left. Otherwise it renews once two thirds of
the certificate's lifetime have passed: with 30 days left of a 90-day
certificate. If the server can't be reached, a certificate that isn't due
doesn't fail the pass.

## How it writes

A renewal writes version N+1 into `archive/<name>/` next to the old ones:
each file through a temp file, `fsync` and `rename`. The private key gets
mode 0600, plus the group bits and group of the key it replaces, as certbot
does. acme checks that the certificate is for that key and covers every
domain before it writes anything.

Then the new links go into `live/.<name>.next/` and that directory swaps
places with `live/<name>/` in one `rename` (`RENAME_EXCHANGE`). Anything that
opens `live/<name>/fullchain.pem` finds the old version or the new one,
never a missing link and never a mix. A program that opens `fullchain.pem`
and `privkey.pem` separately can still read one before the swap and the
other after it, as with certbot; nginx then fails that reload and keeps
serving what it had. On a filesystem without `RENAME_EXCHANGE`,
each link is replaced by its own `rename`.

The links keep certbot's relative form (`../../archive/<name>/cert3.pem`),
and the archive keeps the current version and the five before it, as
certbot's does.

If a renewal fails, nothing is written. If a run is stopped part way, the
next pass removes what it left: temp files, the half-built directory, and
any version written but never linked.

## The ACME account

certbot's accounts have RSA keys, and instant-acme signs only with ECDSA
P-256. So acme registers its own account with each ACME server the first time
it needs one, keeps it in `acme/accounts/` in the configuration directory
with mode 0600, and leaves certbot's accounts as they are. certbot can
renew the same certificates with its own account.

## Going back to certbot

The layout stays certbot's, so certbot reads it and renews from it. A
lineage acme issued names certbot's account in its renewal file when there
is exactly one for that server. Don't run the two against one volume at
the same time: acme's lock, `acme/lock`, keeps its own runs apart, but
certbot doesn't take it.

## Memory

One renewal pass over seven certificates, against Pebble, with each tool's
container run the way the example below runs it, measured from the host
through the container's cgroup. The peak is the kernel's `memory.peak`,
which counts page cache too; anon (heap and stacks) is sampled every 50 ms.

| | limit | renewed | pass peak | pass anon | after the pass |
|---|---|---|---|---|---|
| acme | 16 MiB | 7 of 7 | 1.5 MiB | 0.5 MiB | 0.9 MiB |
| acme | 32 MiB | 7 of 7 | 1.5 MiB | 0.5 MiB | 0.9 MiB |
| certbot 5.9.0 | 16 MiB | none, OOM-killed | 16.0 MiB | 12.6 MiB | 0.6 MiB |
| certbot 5.9.0 | 32 MiB | none, OOM-killed | 32.0 MiB | 27.0 MiB | 1.2 MiB |
| certbot 5.9.0 | 64 MiB | 7 of 7 | 41.2 MiB | 34.8 MiB | 6.8 MiB |

certbot ran with `--no-random-sleep-on-renew`. Without it, certbot first
waits up to eight minutes, at its full size, before renewing. The image is
1.8 MiB, against certbot's 75.3 MiB.

## Deploying

```yaml
services:
  acme:
    image: hoie/acme:latest
    restart: unless-stopped
    mem_limit: 16m
    volumes:
      - ./letsencrypt:/etc/letsencrypt
      - ./acme-challenge:/data/letsencrypt-acme-challenge
```

The web server serves `/.well-known/acme-challenge/` from the second volume
and reads the certificates from the first, read-only. It has to reload to
pick up a renewal.

To add a certificate:

```sh
docker compose run --rm acme issue --cert-name example -d example.com -d www.example.com \
  -w /data/letsencrypt-acme-challenge
```

## Development

```sh
cargo test
docker build -t acme:dev .
IMAGE=acme:dev ci/e2e.sh   # Docker and sudo; issues and renews against Pebble
```

`ci/e2e.sh` is what CI runs on every pull request: certbot issues
certificates against [Pebble](https://github.com/letsencrypt/pebble), acme
renews them under a 16 MiB limit, nginx serves the result, certbot reads and
renews it again, and an unreachable server and a failed challenge both exit
1 and leave the files as they were.

## License

Apache 2.0. See [LICENSE](LICENSE).
