# shellcheck shell=bash
# Sourced by the end-to-end checks. Runs Pebble, Let's Encrypt's ACME test
# server, and nginx answering HTTP-01 from a webroot on one Docker network,
# and defines helpers that run the image under test and certbot against them
# with one shared /etc/letsencrypt, as a deployment that uses certbot does.

IMAGE=${IMAGE:?set IMAGE to the acme image to test}
CERTBOT_IMAGE=certbot/certbot:v5.9.0
NGINX_IMAGE=nginx:1.30.6-alpine
PEBBLE_IMAGE=ghcr.io/letsencrypt/pebble:2.10.3
SERVER=https://pebble:14000/dir
NET=acme-e2e
WORK=${WORK:-$(mktemp -d)}
LE=$WORK/letsencrypt
WEBROOT=$WORK/webroot
HTTPS_PORT=8443
# The memory limit the image under test runs with.
ACME_MEMORY=${ACME_MEMORY:-16m}
# Every name a test certificate uses. nginx answers for each, through
# Docker's DNS, which is also how Pebble finds it.
NAMES="a.example.test www.a.example.test b.example.test c.example.test d.example.test
  e.example.test f.example.test g.example.test h.example.test i.example.test"

start_env() {
  mkdir -p "$LE" "$WEBROOT" "$WORK/nginx/snippets"
  docker network create "$NET" >/dev/null

  # Validates HTTP-01 on port 80, as a public CA does, and issues 90-day
  # certificates, as Let's Encrypt does.
  cat >"$WORK/pebble.json" <<'JSON'
{"pebble": {
  "listenAddress": "0.0.0.0:14000",
  "managementListenAddress": "0.0.0.0:15000",
  "certificate": "/test/certs/localhost/cert.pem",
  "privateKey": "/test/certs/localhost/key.pem",
  "httpPort": 80,
  "tlsPort": 5001,
  "ocspResponderURL": "",
  "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 3, "order": 5},
  "keyAlgorithm": "ecdsa",
  "profiles": {"default": {"description": "90 days", "validityPeriod": 7776000}}
}}
JSON
  # Every order validates afresh: with authorizations reused, a broken
  # webroot could pass unnoticed. Pebble also rejects 5% of nonces by
  # default, which certbot doesn't retry, so that is off too.
  docker run -d --name pebble --network "$NET" \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_AUTHZREUSE=0 -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$WORK/pebble.json:/pebble.json:ro" "$PEBBLE_IMAGE" -config /pebble.json >/dev/null
  docker cp pebble:/test/certs/pebble.minica.pem "$WORK/pebble.minica.pem" >/dev/null

  cat >"$WORK/nginx/snippets/acme.inc" <<'NGINX'
location ^~ /.well-known/acme-challenge/ {
  default_type text/plain;
  root /data/letsencrypt-acme-challenge;
}
NGINX
  cat >"$WORK/nginx/00-default.conf" <<'NGINX'
server {
  listen 80 default_server;
  include conf.d/snippets/acme.inc;
  location / {
    return 404;
  }
}
NGINX
  local aliases=()
  for name in $NAMES; do aliases+=(--network-alias "$name"); done
  docker run -d --name nginx --network "$NET" "${aliases[@]}" -p "127.0.0.1:$HTTPS_PORT:443" \
    -v "$WORK/nginx:/etc/nginx/conf.d:ro" \
    -v "$WEBROOT:/data/letsencrypt-acme-challenge:ro" \
    -v "$LE:/etc/letsencrypt:ro" \
    "$NGINX_IMAGE" >/dev/null

  for _ in $(seq 60); do
    docker logs pebble 2>&1 | grep 'Listening on' >/dev/null && return 0
    sleep 1
  done
  docker logs pebble
  fail "Pebble didn't start"
}

stop_env() {
  local status=$?
  if [ "$status" != 0 ]; then
    echo "--- pebble"; docker logs pebble 2>&1 | tail -n 40 || true
    echo "--- nginx"; docker logs nginx 2>&1 | tail -n 20 || true
    echo "--- /etc/letsencrypt"; sudo find "$LE" -not -path '*/logs/*' -printf '%p %y %m %l\n' | sort || true
  fi
  docker rm -f pebble nginx >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  return "$status"
}

fail() {
  echo "::error::$*"
  exit 1
}

pass() {
  echo "ok - $*"
}

# The image under test, with the volumes and limits a deployment gives it.
acme() {
  docker run --rm --network "$NET" --memory "$ACME_MEMORY" --memory-swap "$ACME_MEMORY" \
    -v "$LE:/etc/letsencrypt" -v "$WEBROOT:/data/letsencrypt-acme-challenge" \
    -v "$WORK/pebble.minica.pem:/pebble.minica.pem:ro" -e ACME_CA_CERT=/pebble.minica.pem \
    "$IMAGE" "$@"
}

certbot() {
  docker run --rm --network "$NET" \
    -v "$LE:/etc/letsencrypt" -v "$WEBROOT:/data/letsencrypt-acme-challenge" \
    -v "$WORK/pebble.minica.pem:/pebble.minica.pem:ro" -e REQUESTS_CA_BUNDLE=/pebble.minica.pem \
    "$CERTBOT_IMAGE" "$@"
}

# certbot_issue <name> [certbot flags] -d <domain>...
certbot_issue() {
  local name=$1
  shift
  certbot certonly --server "$SERVER" --webroot -w /data/letsencrypt-acme-challenge --cert-name "$name" \
    --non-interactive --agree-tos --register-unsafely-without-email "$@" >"$WORK/certbot-$name.log" 2>&1 ||
    { cat "$WORK/certbot-$name.log"; fail "certbot couldn't issue $name"; }
}

# add_site <name> <host>: an HTTPS server for <host> with lineage <name>'s certificate.
add_site() {
  printf '%s\n' \
    "server {" \
    "  listen 443 ssl;" \
    "  server_name $2;" \
    "  ssl_certificate /etc/letsencrypt/live/$1/fullchain.pem;" \
    "  ssl_certificate_key /etc/letsencrypt/live/$1/privkey.pem;" \
    "  include conf.d/snippets/acme.inc;" \
    "  location / {" \
    "    return 200 ok;" \
    "  }" \
    "}" >"$WORK/nginx/$1.conf"
}

reload_nginx() {
  docker exec nginx nginx -t 2>&1 | tail -n 1
  docker exec nginx nginx -s reload 2>/dev/null
  sleep 1
}

# The version live/<name> points at.
live_version() {
  sudo readlink "$LE/live/$1/cert.pem" | sed -E 's/.*cert([0-9]+)\.pem$/\1/'
}

key_matches() {
  cmp -s <(sudo openssl x509 -noout -pubkey -in "$LE/live/$1/fullchain.pem") \
    <(sudo openssl pkey -pubout -in "$LE/live/$1/privkey.pem")
}

key_kind() {
  sudo openssl pkey -in "$LE/live/$1/privkey.pem" -noout -text | grep -E 'Private-Key|ASN1 OID' | tr '\n' ' '
}

names_of() {
  sudo openssl x509 -noout -ext subjectAltName -in "$LE/live/$1/cert.pem" | tail -n +2 | tr -d ' ' | tr ',' '\n' | sort | tr '\n' ' '
}

on_disk() {
  sudo openssl x509 -noout -fingerprint -sha256 -in "$LE/live/$1/cert.pem"
}

# The certificate nginx serves for <host>.
served() {
  openssl s_client -connect "127.0.0.1:$HTTPS_PORT" -servername "$1" </dev/null 2>/dev/null |
    openssl x509 -noout -fingerprint -sha256
}

# Every path, type, mode, owner, link target and content hash under the
# volume, for checking that a failed run changed nothing.
state() {
  (cd "$LE" && sudo find . -not -path './logs*' -not -path './acme/lock' -printf '%p %y %m %u:%g %l\n' | sort)
  (cd "$LE" && sudo find . -type f -not -path './logs*' -not -path './acme/lock' -exec sha256sum {} + | sort)
  (cd "$WEBROOT" && find . | sort)
}

# Files nothing should leave behind: challenge responses, temp files and
# half-built live directories.
leftovers() {
  { sudo find "$WEBROOT" -type f; sudo find "$LE" -name '*.tmp' -o -name '.*.next'; } | sort
}
