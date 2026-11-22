#!/usr/bin/env bash
# Podman end to end (docs/dev/design/podman.md, phase 4): a real participant install on rootful
# Podman, then the isolation checks, a reboot, and a negative check.
#
#   scripts/e2e/podman.sh [debian]
#
# Runs on a machine with Docker (a GitHub runner, or a developer machine; never a live node). It
# builds scripts/e2e/podman/Dockerfile.debian (Debian 13, Podman 5.4, systemd as PID 1), starts it
# as a privileged container, copies this checkout into it, and inside:
#   1. ./scripts/install.sh --participant --yes --version <newest release tag> as a normal user
#      (it opens the Podman socket to itself, installs the host firewall and the boot unit, and
#      starts the stack through suckerpot-stack.service), with the signed release images;
#   2. ./scripts/status.sh and `egress-check.sh --isolation`: every check must PASS;
#   3. a reboot of the container: the firewall, then the stack, then the checks again;
#   4. the firewall tables removed by hand: the isolation checks must FAIL (sensors reach the
#      internet and each other); then reloaded: PASS again.
# The hub is never contacted: the copy points NETWORK_HUB_URL at https://example.com, so the
# enrolment fails harmlessly. Image pulls, signature checks and that request are the only traffic.
#
# Environment: PODMAN_E2E_KEEP=1 keeps the container; SELFHOSTR_FREE_DISK_KB is passed to the
# installer (a developer machine with less than 15 GiB free).
set -euo pipefail

cd "$(dirname "$0")/../.."
distro=${1:-debian}
case $distro in debian) ;; *) echo "podman-e2e: unknown distribution: $distro" >&2; exit 2 ;; esac
image=sp-podman-e2e-$distro
node=sp-podman-e2e-$$
volume=$node-storage
work=$(mktemp -d)

say() { printf '\n== %s\n' "$*"; }
in_node() { docker exec "$node" bash -c "$1"; }
as_user() { docker exec -u node -w /home/node/suckerpot "${user_env[@]}" "$node" bash -c "$1"; }

dump() {
  say "logs (failure)"
  printf '\n-- install.log (last 80 lines)\n'
  in_node 'tail -n 80 /home/node/suckerpot/install.log 2>/dev/null' || true
  printf '\n-- units and containers\n'
  in_node ' journalctl --no-pager -n 80 -u suckerpot-firewall.service -u suckerpot-stack.service -u podman.socket 2>/dev/null; podman ps -a 2>/dev/null' || true
}
cleanup() {
  rc=$?
  [ "$rc" = 0 ] || dump
  if [ "${PODMAN_E2E_KEEP:-0}" != 1 ]; then
    docker rm -f "$node" > /dev/null 2>&1 || true
    docker volume rm "$volume" > /dev/null 2>&1 || true
  fi
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT

fail() {
  echo "podman-e2e: FAILED: $*" >&2
  exit 1
}

version=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2> /dev/null || true)
[ -n "$version" ] || fail "no release tag in this checkout (fetch with tags: fetch-depth 0)"

say "building the $distro Podman machine"
docker build -q -t "$image" -f "scripts/e2e/podman/Dockerfile.$distro" scripts/e2e/podman > /dev/null

say "starting it (systemd as PID 1)"
docker run -d --name "$node" --hostname podnode --privileged --cgroupns=private \
  -v "$volume:/var/lib/containers" --tmpfs /run --tmpfs /run/lock "$image" > /dev/null
for _ in $(seq 1 30); do
  state=$(in_node 'systemctl is-system-running 2>/dev/null' || true)
  case $state in running | degraded) break ;; esac
  sleep 2
done
in_node 'podman --version; docker-compose version --short; nft --version'

head=$(git rev-parse --short HEAD)
say "copying this checkout (scripts and compose files of HEAD $head; images of release $version), hub pointed at example.com"
# A clone (tags included; works from a linked worktree too), then the working tree on top of it,
# so uncommitted changes are tested as well.
git clone -q --no-local --no-hardlinks . "$work/repo"
git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -x -C "$work/repo"
tar -C "$work/repo" -cf "$work/checkout.tar" .
# Not /tmp: systemd mounts a fresh tmpfs there.
docker cp "$work/checkout.tar" "$node:/root/checkout.tar"
in_node "set -e
mkdir -p /home/node/suckerpot
tar -x -C /home/node/suckerpot -f /root/checkout.tar
cd /home/node/suckerpot
sed -i 's|^NETWORK_HUB_URL=.*|NETWORK_HUB_URL=https://example.com|' config/network-defaults.env
printf '\nNETWORK_HUB_URL=https://example.com\n' >> .env.example
chown -R node:node /home/node/suckerpot
sudo -u node git -c safe.directory='*' -c user.name=e2e -c user.email=e2e@example.invalid commit -qam 'e2e: hub stub' --no-verify
grep -q example.com config/network-defaults.env"
# The scripts under test are this checkout's, never the release tag's: the tag only names the images.
want=$(sha256sum scripts/install.sh | cut -d" " -f1)
have=$(in_node 'sha256sum /home/node/suckerpot/scripts/install.sh' | cut -d" " -f1)
[ "$want" = "$have" ] || fail "the copy does not hold this checkout's install.sh"

user_env=(-e SUCKERPOT_ENROL_WAIT=20)
[ -z "${SELFHOSTR_FREE_DISK_KB:-}" ] || user_env+=(-e "SELFHOSTR_FREE_DISK_KB=$SELFHOSTR_FREE_DISK_KB")

say "fresh participant install on Podman (only engine, socket closed)"
in_node 'systemctl is-active podman.socket || true; command -v docker || echo "no docker command"'
out=$(as_user "set -o pipefail; ./scripts/install.sh --participant --yes --version $version 2> >(tee /tmp/install.err >&2)" 2>&1) || {
  printf '\n-- installer output (last 60 lines)\n'
  printf '%s\n' "$out" | tail -n 60
  printf '\n-- installer stderr\n'
  in_node 'cat /tmp/install.err 2>/dev/null' || true
  fail "the install did not finish"
}
printf '%s\n' "$out" | grep -E '^\[[0-9]+/10\]|result:|warning|Podman' || true
grep -q "result: ok type=participant version=$version engine=podman" <<< "$out" || fail "no 'result: ok ... engine=podman' line"
in_node 'systemctl is-active --quiet suckerpot-firewall.service' || fail "the firewall unit is not active"
in_node 'systemctl is-active --quiet suckerpot-stack.service' || fail "the stack did not start through the boot unit"

say "status"
st=$(as_user './scripts/status.sh' 2>&1 || true)
printf '%s\n' "$st" | head -n 4
grep -q "Engine: Podman .* boot unit active" <<< "$st" || fail "status shows no Podman engine line with an active boot unit"

isolation() { in_node 'cd /home/node/suckerpot && bash scripts/egress-check.sh --isolation'; }

say "isolation checks (all must PASS)"
isolation || fail "isolation checks failed after the install"

say "reboot: the firewall, then the stack"
docker restart "$node" > /dev/null
for _ in $(seq 1 90); do
  s=$(in_node 'systemctl is-active suckerpot-stack.service 2>/dev/null' || true)
  [ "$s" = activating ] || [ -z "$s" ] || break
  sleep 5
done
[ "$s" = active ] || fail "the stack is '$s' after the reboot"
in_node "journalctl -b 0 -o short-monotonic --no-pager -u suckerpot-firewall.service -u suckerpot-stack.service | grep -E 'systemd\[1\]: (Starting|Finished)'"
isolation || fail "isolation checks failed after the reboot"

say "negative check: without the firewall tables, the isolation checks must FAIL"
in_node 'nft delete table inet suckerpot_host; nft delete table bridge suckerpot_bridge'
if neg=$(isolation 2>&1); then
  printf '%s\n' "$neg"
  fail "the isolation checks passed without the firewall: they do not test it"
fi
printf '%s\n' "$neg" | grep -E '^FAIL' || true
grep -q '^FAIL  host firewall loaded' <<< "$neg" || fail "no FAIL for the missing tables"
grep -q '^FAIL  sensor-.*: cannot reach another sensor' <<< "$neg" || fail "no FAIL for sensor-to-sensor traffic without the bridge table"
grep -q '^FAIL  sensor-.*: no connection to the internet' <<< "$neg" || fail "no FAIL for a sensor reaching the internet without the firewall"

say "firewall reloaded: PASS again"
in_node 'systemctl reload suckerpot-firewall.service'
isolation || fail "isolation checks failed after the reload"

say "podman e2e: all checks passed"
