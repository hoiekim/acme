#!/usr/bin/env bash
# End to end, against Pebble: certbot issues certificates the way a
# deployment does, then the image renews them in place under a 16 MiB memory
# limit, nginx serves what it wrote, certbot can still read and renew the
# result, and the failures leave everything as it was.
#
# usage: IMAGE=acme:ci ci/e2e.sh
set -euo pipefail
# shellcheck source=env.sh
source "$(dirname "$0")/env.sh"
trap stop_env EXIT
start_env

echo "== certbot issues the starting certificates"
certbot_issue ecdsa -d a.example.test -d www.a.example.test
certbot_issue rsa --key-type rsa -d b.example.test
certbot_issue p384 --key-type ecdsa --elliptic-curve secp384r1 -d c.example.test
certbot_issue early -d d.example.test
# A setting certbot honours, which makes this one due 90 days early.
sudo sed -i '1i renew_before_expiry = 100 days' "$LE/renewal/early.conf"
LINEAGES="ecdsa:a.example.test rsa:b.example.test p384:c.example.test early:d.example.test"
for pair in $LINEAGES; do add_site "${pair%%:*}" "${pair#*:}"; done
reload_nginx
account_kty=$(sudo sh -c "cat '$LE'/accounts/*/*/*/private_key.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["kty"])')
echo "certbot's account key: $account_kty"
certbot_accounts=$(cd "$LE" && sudo find accounts -type f -exec sha256sum {} + | sort)

echo "== a pass with nothing due renews only what renew_before_expiry makes due"
acme renew
for pair in $LINEAGES; do
  name=${pair%%:*}
  want=1
  [ "$name" = early ] && want=2
  [ "$(live_version "$name")" = "$want" ] || fail "$name is at version $(live_version "$name"), expected $want"
done
pass "early renewed, the rest not due"
sudo test -f "$LE/acme/accounts/pebble_14000_dir.json" || fail "acme kept no account"
pass "acme registered its own account"

echo "== a forced pass renews every certificate in place"
declare -A version kind names fingerprint
for pair in $LINEAGES; do
  name=${pair%%:*}
  version[$name]=$(live_version "$name")
  kind[$name]=$(key_kind "$name")
  names[$name]=$(names_of "$name")
  fingerprint[$name]=$(on_disk "$name")
done
# A key nginx's group may read keeps that mode and group when renewed.
ecdsa_key=$(sudo readlink -f "$LE/live/ecdsa/privkey.pem")
sudo chgrp 101 "$ecdsa_key"
sudo chmod 0640 "$ecdsa_key"
acme renew --force
for pair in $LINEAGES; do
  name=${pair%%:*}
  [ "$(live_version "$name")" = "$((${version[$name]} + 1))" ] || fail "$name wasn't renewed"
  [ "$(sudo readlink "$LE/live/$name/fullchain.pem")" = "../../archive/$name/fullchain$((${version[$name]} + 1)).pem" ] ||
    fail "$name's links aren't certbot's relative form"
  key_matches "$name" || fail "$name's key doesn't match its certificate"
  [ "$(key_kind "$name")" = "${kind[$name]}" ] || fail "$name's key changed type: ${kind[$name]} -> $(key_kind "$name")"
  [ "$(names_of "$name")" = "${names[$name]}" ] || fail "$name's names changed"
  [ "$(on_disk "$name")" != "${fingerprint[$name]}" ] || fail "$name's certificate is the old one"
  sudo test -d "$LE/live/$name" -a ! -L "$LE/live/$name" || fail "live/$name is no longer a plain directory"
  pass "$name renewed: version $(live_version "$name"), ${kind[$name]}, key matches"
done
[ "$(sudo stat -c '%a %g' "$(sudo readlink -f "$LE/live/ecdsa/privkey.pem")")" = "640 101" ] ||
  fail "the renewed key lost its mode or group"
pass "the renewed key kept mode 640 and its group"
[ -z "$(leftovers)" ] || fail "left behind: $(leftovers)"
pass "no challenge files, temp files or staging directories left"
[ "$(cd "$LE" && sudo find accounts -type f -exec sha256sum {} + | sort)" = "$certbot_accounts" ] ||
  fail "certbot's account changed"
pass "certbot's account untouched"

reload_nginx
for pair in $LINEAGES; do
  name=${pair%%:*}
  [ "$(served "${pair#*:}")" = "$(on_disk "$name")" ] || fail "nginx doesn't serve $name's new certificate"
done
pass "nginx -t passes and nginx serves every renewed certificate after a reload"

echo "== certbot still reads, and renews, what acme wrote"
certbot certificates >"$WORK/certificates.txt" 2>&1 || { cat "$WORK/certificates.txt"; fail "certbot certificates failed"; }
for pair in $LINEAGES; do
  grep -q "Certificate Name: ${pair%%:*}$" "$WORK/certificates.txt" || fail "certbot doesn't list ${pair%%:*}"
done
! grep -q INVALID "$WORK/certificates.txt" || { cat "$WORK/certificates.txt"; fail "certbot finds a lineage invalid"; }
pass "certbot certificates lists every lineage as valid"
before=$(live_version ecdsa)
certbot renew --force-renewal --no-random-sleep-on-renew --cert-name ecdsa >"$WORK/certbot-renew.log" 2>&1 ||
  { cat "$WORK/certbot-renew.log"; fail "certbot couldn't renew after acme"; }
[ "$(live_version ecdsa)" = "$((before + 1))" ] || fail "certbot didn't renew after acme"
key_matches ecdsa || fail "certbot's renewal after acme has a mismatched key"
pass "certbot renews a lineage acme renewed"
acme renew --force --cert-name ecdsa
[ "$(live_version ecdsa)" = "$((before + 2))" ] || fail "acme didn't renew after certbot"
key_matches ecdsa || fail "acme's renewal after certbot has a mismatched key"
pass "acme renews it again after certbot rewrote its renewal file"

echo "== acme issues a new certificate that certbot can renew"
acme issue --server "$SERVER" --cert-name new -d e.example.test -d f.example.test -w /data/letsencrypt-acme-challenge
acme list | grep -x new >/dev/null || fail "acme list doesn't show the new certificate"
[ "$(acme list)" = "$(sudo ls "$LE/live" | grep -v README)" ] || fail "acme list differs from ls live/"
key_matches new || fail "the new key doesn't match"
add_site new e.example.test
reload_nginx
[ "$(served e.example.test)" = "$(on_disk new)" ] || fail "nginx doesn't serve the new certificate"
certbot certificates 2>&1 | grep 'Certificate Name: new$' >/dev/null || fail "certbot doesn't list the new certificate"
certbot renew --force-renewal --no-random-sleep-on-renew --cert-name new >"$WORK/certbot-new.log" 2>&1 ||
  { cat "$WORK/certbot-new.log"; fail "certbot couldn't renew acme's new certificate"; }
[ "$(live_version new)" = 2 ] || fail "certbot didn't renew the new certificate"
key_matches new || fail "certbot's renewal of the new certificate has a mismatched key"
acme renew --force --cert-name new
[ "$(live_version new)" = 3 ] || fail "acme didn't renew the new certificate"
key_matches new || fail "acme's renewal of the new certificate has a mismatched key"
pass "issued, served, listed and renewed by certbot and by acme"

echo "== failure: the ACME server is unreachable"
docker network disconnect "$NET" pebble
before=$(state)
if acme renew --force; then fail "renew succeeded without a server"; fi
[ "$(state)" = "$before" ] || { diff <(echo "$before") <(state) || true; fail "a failed renewal changed files"; }
pass "renew exits 1 and changes nothing"
# Nothing is due for ecdsa, so its renewal information can't be fetched and
# the pass decides from the certificate's lifetime instead.
code=0
acme renew --cert-name ecdsa || code=$?
[ "$code" = 0 ] || fail "a pass with nothing due exited $code without a server"
[ "$(state)" = "$before" ] || fail "a pass with nothing due changed files"
pass "a pass with nothing due exits 0 and changes nothing"
start=$(date +%s)
code=0
acme run --force --interval 5s >"$WORK/run.log" 2>&1 || code=$?
took=$(($(date +%s) - start))
[ "$code" = 1 ] && [ "$took" -ge 5 ] || { cat "$WORK/run.log"; fail "run exited $code after ${took}s, expected 1 after the 5s interval"; }
[ "$(state)" = "$before" ] || fail "a failed run changed files"
pass "run waits out the interval, then exits 1"
docker network connect "$NET" pebble

echo "== failure: a challenge fails, and the other certificates still renew"
sudo cp "$LE/renewal/rsa.conf" "$WORK/rsa.conf"
sudo sed -i 's#/data/letsencrypt-acme-challenge#/data/not-served#g' "$LE/renewal/rsa.conf"
rsa_before=$(cd "$LE" && sudo find live/rsa archive/rsa -printf '%p %l\n' | sort)
p384_before=$(live_version p384)
if acme renew --force >"$WORK/challenge.log" 2>&1; then cat "$WORK/challenge.log"; fail "renew succeeded with a failing challenge"; fi
cat "$WORK/challenge.log"
grep -q 'rsa: renewal failed' "$WORK/challenge.log" || fail "the failure isn't reported"
[ "$(cd "$LE" && sudo find live/rsa archive/rsa -printf '%p %l\n' | sort)" = "$rsa_before" ] || fail "the failed lineage changed"
[ "$(live_version p384)" = "$((p384_before + 1))" ] || fail "a failure stopped the other renewals"
[ -z "$(leftovers)" ] || fail "left behind: $(leftovers)"
pass "the failed one is untouched, the others renewed, and the pass exits 1"
sudo cp "$WORK/rsa.conf" "$LE/renewal/rsa.conf"

echo "== certbot's hook directories and cli.ini fail every pass, and change nothing"
sudo mkdir -p "$LE/renewal-hooks/deploy"
printf '#!/bin/sh\nexit 0\n' | sudo tee "$LE/renewal-hooks/deploy/reload" >/dev/null
sudo chmod 0755 "$LE/renewal-hooks/deploy/reload"
before=$(state)
for args in "renew --force" "renew"; do
  code=0
  # shellcheck disable=SC2086
  acme $args >"$WORK/hook.log" 2>&1 || code=$?
  [ "$code" = 1 ] || { cat "$WORK/hook.log"; fail "acme $args exited $code with a deploy hook in place"; }
  grep 'renewal-hooks/deploy/reload is a hook certbot would run' "$WORK/hook.log" >/dev/null ||
    { cat "$WORK/hook.log"; fail "acme $args didn't name the hook"; }
  [ "$(state)" = "$before" ] || fail "acme $args changed files with a deploy hook in place"
done
sudo rm "$LE/renewal-hooks/deploy/reload"
pass "a deploy hook fails forced and unforced passes, which change nothing"
printf 'deploy-hook = nginx -s reload\n' | sudo tee "$LE/cli.ini" >/dev/null
before=$(state)
code=0
acme renew >"$WORK/cli-ini.log" 2>&1 || code=$?
[ "$code" = 1 ] || { cat "$WORK/cli-ini.log"; fail "renew exited $code with a deploy-hook in cli.ini"; }
grep 'cli.ini sets deploy-hook' "$WORK/cli-ini.log" >/dev/null ||
  { cat "$WORK/cli-ini.log"; fail "renew didn't name the cli.ini setting"; }
[ "$(state)" = "$before" ] || fail "renew changed files with a deploy-hook in cli.ini"
sudo rm "$LE/cli.ini"
pass "a cli.ini deploy-hook fails the pass, which changes nothing"

echo "== docker stop ends a run straight away"
docker run -d --name acme-run --network "$NET" --memory "$ACME_MEMORY" --memory-swap "$ACME_MEMORY" \
  -v "$LE:/etc/letsencrypt" -v "$WEBROOT:/data/letsencrypt-acme-challenge" \
  -v "$WORK/pebble.minica.pem:/pebble.minica.pem:ro" -e ACME_CA_CERT=/pebble.minica.pem "$IMAGE" >/dev/null
for _ in $(seq 60); do docker logs acme-run 2>&1 | grep 'next pass in 12h' >/dev/null && break; sleep 1; done
docker logs acme-run 2>&1 | grep 'next pass in 12h' >/dev/null || { docker logs acme-run; fail "the run's first pass didn't finish"; }
start=$(date +%s)
docker stop --timeout 10 acme-run >/dev/null
took=$(($(date +%s) - start))
code=$(docker inspect acme-run --format '{{.State.ExitCode}} {{.State.OOMKilled}}')
docker rm acme-run >/dev/null
[ "$code" = "143 false" ] && [ "$took" -lt 5 ] || fail "docker stop took ${took}s and the run exited '$code'"
pass "stopped in ${took}s with 143"

echo "all checks passed (certbot's account key type: $account_kty)"
