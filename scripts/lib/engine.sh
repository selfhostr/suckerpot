#!/usr/bin/env bash
# Container engine abstraction of the host scripts (docs/dev/design/podman.md, section 8).
# Source this file from the root of the checkout. It defines functions and variables and runs no
# engine command. scripts/lib/env.sh sources it, so every script that sources env.sh has it.
#
#   dc ARGS...    compose:        docker compose ARGS...
#                                 (Podman: DOCKER_HOST=unix:///run/podman/podman.sock docker-compose ARGS...)
#   ctr ARGS...   everything else: docker ARGS...
#                                 (Podman: podman --url unix:///run/podman/podman.sock ARGS...)
#
# On Podman both talk to the root Podman service through its socket, never to the caller's own
# rootless Podman: a non-root user reaches that socket through a group (design D3), the way a
# Docker user does through the docker group. Without --url, `podman` run by a normal user would
# create rootless networks and volumes that the stack never uses and the host firewall never sees.
#
# ENGINE_DC and ENGINE_CTR hold the same commands as arrays, for the places where a shell function
# cannot run: exec, timeout, xargs. DOCKER_HOST is set for the compose call only, never exported to
# the whole script, so a stray docker call cannot reach the wrong engine.
#
# The engine is SUCKERPOT_ENGINE from .env (${ENV_FILE:-.env}), else from the environment (a fresh
# install), else docker: an install without the key is a Docker install. The functions use
# ENGINE_ID, because env_drop_loaded may unset SUCKERPOT_ENGINE. On Podman, the scripts that
# install, update or start the stack first check the host (engine_ready, engine_check_podman).

ENGINE_PODMAN_SOCKET=unix:///run/podman/podman.sock

# Shown by a script that refuses to run on Podman; engine_ready replaces it with the reason.
# shellcheck disable=SC2034 # used by the scripts that source this file
ENGINE_UNREADY_MSG="Podman support is not ready yet. SuckerPot runs on Docker Engine only for now: on Podman the sensor networks would not be isolated well enough. Install Docker Engine (see docs/install.md), or wait for a release that supports Podman."

# engine_use NAME: switches dc, ctr and the arrays to NAME (docker or podman).
engine_use() {
  case $1 in
    docker)
      ENGINE_DC=(docker compose)
      ENGINE_CTR=(docker)
      ;;
    podman)
      ENGINE_DC=(env "DOCKER_HOST=$ENGINE_PODMAN_SOCKET" docker-compose)
      ENGINE_CTR=(podman --url "$ENGINE_PODMAN_SOCKET")
      ;;
    *)
      echo "unknown container engine '$1': SUCKERPOT_ENGINE must be docker or podman" >&2
      return 1
      ;;
  esac
  ENGINE_ID=$1
  SUCKERPOT_ENGINE=$1
}

# engine_detect: prints the engine this host offers, by looking at PATH only (no engine call).
# Docker wins when both are there. A `docker` command that is really Podman (the podman-docker
# package) is caught later by the installer's version check.
engine_detect() {
  if command -v docker > /dev/null 2>&1; then
    echo docker
  elif command -v podman > /dev/null 2>&1; then
    echo podman
  else
    echo docker
  fi
}

# engine_ready: succeeds when the scripts may install, update or start the stack on this engine.
# Docker: always (no engine call). Podman: only when engine_check_podman finds nothing and .env
# lists the Podman overlay in COMPOSE_FILE (without it compose would make networks without
# isolation). On failure ENGINE_UNREADY_MSG says why.
engine_ready() {
  local problems
  [ "$ENGINE_ID" = podman ] || return 0
  if ! engine_overlay_listed; then
    ENGINE_UNREADY_MSG="Podman: COMPOSE_FILE in .env does not list docker-compose.podman.yml, so the sensor networks would not be isolated. Run the installer again (./scripts/install.sh --repair), or see docs/install.md (Podman)."
    return 1
  fi
  if ! problems=$(engine_check_podman); then
    # shellcheck disable=SC2034 # read by the scripts that source this file
    ENGINE_UNREADY_MSG="Podman: this host does not meet the requirements (docs/install.md, Podman): $(printf '%s' "$problems" | tr '\n' ';' | sed 's/;$//; s/;/; /g')"
    return 1
  fi
}

# engine_overlay_listed: COMPOSE_FILE (environment, else .env) lists the Podman overlay.
engine_overlay_listed() {
  local cf=${COMPOSE_FILE:-}
  [ -n "$cf" ] || cf=$(sed -n 's/^COMPOSE_FILE=//p' "${ENV_FILE:-.env}" 2> /dev/null | tail -n 1 | tr -d "\"'\r")
  case ":$cf:" in *:docker-compose.podman.yml:*) return 0 ;; esac
  return 1
}

# _engine_version_ge A B: version A >= version B (numeric, dotted).
_engine_version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]
}

# engine_check_podman: the requirements of docs/dev/design/podman.md section 6, checked through the
# root Podman socket. Prints one line per problem; succeeds when there is none.
#   Podman 5.4 or newer, rootful, netavark with the nftables driver, cgroup v2,
#   docker-compose 2.26 or newer, systemd, and Docker not active on the same host.
engine_check_podman() {
  local _engine_problems=() info v backend cgroup rootless cv drv
  if ! info=$("${ENGINE_CTR[@]}" info --format '{{.Version.Version}} {{.Host.NetworkBackend}} {{.Host.CgroupsVersion}} {{.Host.Security.Rootless}}' 2> /dev/null); then
    _engine_problems+=("the root Podman socket ($ENGINE_PODMAN_SOCKET) does not answer: sudo systemctl enable --now podman.socket, and add this user to its group")
  else
    read -r v backend cgroup rootless <<< "$info"
    _engine_version_ge "${v:-0}" 5.4 || _engine_problems+=("Podman ${v:-unknown} is too old: 5.4 or newer is needed")
    [ "$backend" = netavark ] || _engine_problems+=("the network backend is ${backend:-unknown}, not netavark")
    [ "$cgroup" = v2 ] || _engine_problems+=("cgroup ${cgroup:-unknown}: cgroup v2 is needed")
    [ "$rootless" = false ] || _engine_problems+=("the Podman service is rootless: SuckerPot needs rootful Podman")
  fi
  # The firewall driver is not in `podman info`. An explicit setting other than nftables is
  # refused; unset means netavark's default, nftables on every supported distribution.
  local c=${SUCKERPOT_CONF_ROOT:-} # tests only
  drv=$(cat "$c/usr/share/containers/containers.conf" "$c/etc/containers/containers.conf" "$c"/etc/containers/containers.conf.d/*.conf 2> /dev/null |
    sed -n 's/^[[:space:]]*firewall_driver[[:space:]]*=[[:space:]]*"\{0,1\}\([a-z]*\)"\{0,1\}.*/\1/p' | tail -n 1 || true)
  [ -z "$drv" ] || [ "$drv" = nftables ] || _engine_problems+=("netavark uses the $drv firewall driver: set firewall_driver = \"nftables\" in /etc/containers/containers.conf")
  if ! cv=$(docker-compose version --short 2> /dev/null); then
    _engine_problems+=("docker-compose is not installed (2.26 or newer)")
  else
    cv=${cv#v}
    _engine_version_ge "${cv%%-*}" 2.26 || _engine_problems+=("docker-compose $cv is too old: 2.26 or newer is needed")
  fi
  if ! command -v systemctl > /dev/null 2>&1; then
    _engine_problems+=("systemd is needed (healthchecks and the boot unit)")
  elif systemctl is-active --quiet docker.service 2> /dev/null || systemctl is-active --quiet docker.socket 2> /dev/null; then
    _engine_problems+=("Docker is active on this host too: use one engine only (sudo systemctl disable --now docker.service docker.socket)")
  fi
  [ "${#_engine_problems[@]}" -eq 0 ] && return 0
  printf '%s\n' "${_engine_problems[@]}"
  return 1
}

# engine_stack_unit_installed: the Podman boot unit is there (readable without root).
engine_stack_unit_installed() {
  [ -f "${SUCKERPOT_UNIT_ROOT:-}/etc/systemd/system/suckerpot-stack.service" ]
}

# _engine_systemctl ARGS: systemctl as root, through polkit without a prompt, or through sudo -n.
_engine_systemctl() {
  if [ "$(id -u)" = 0 ]; then
    systemctl "$@"
  else
    systemctl --no-ask-password "$@" 2> /dev/null || { command -v sudo > /dev/null 2>&1 && sudo -n systemctl "$@"; }
  fi
}

# engine_stack_up ARGS: starts or updates the stack with `dc up ARGS`. Docker: just that. Podman:
# the networks and the firewall check first (engine_prepare_networks; its exit code is returned on
# failure), then, when the boot unit is installed and not active, `systemctl start
# suckerpot-stack` (as root, through polkit or sudo -n), so the running stack is bound to the host
# firewall. The firewall unit's drop-in stops the containers in any case when it stops.
engine_stack_up() {
  if [ "$ENGINE_ID" = podman ]; then
    # The networks and the host firewall check (scripts/ensure-networks.sh) come first, always.
    engine_prepare_networks || return $?
  fi
  if [ "$ENGINE_ID" = podman ] && engine_stack_unit_installed &&
    ! systemctl is-active --quiet suckerpot-stack.service 2> /dev/null; then
    if ! _engine_systemctl start suckerpot-stack.service; then
      echo "note: could not start suckerpot-stack.service (needs root); starting with docker-compose. The firewall unit still stops these containers when it stops." >&2
    fi
  fi
  dc up "$@"
}

# engine_name: the engine's name for messages.
engine_name() {
  case $ENGINE_ID in
    podman) echo Podman ;;
    *) echo Docker ;;
  esac
}

# engine_data_root: the folder that holds the engine's images and volumes.
engine_data_root() {
  case $ENGINE_ID in
    podman) ctr info --format '{{.Store.GraphRoot}}' ;;
    *) ctr info --format '{{.DockerRootDir}}' ;;
  esac
}

# engine_prepare_networks: creates or fixes the SuckerPot networks before the stack starts. Docker:
# nothing (compose creates them). Podman: scripts/ensure-networks.sh, whose exit code it returns
# (3: a network in use must be recreated; stop the stack and call it again). Run from the root of
# the checkout. The installer calls it before its first `dc up` (Podman phase 3).
engine_prepare_networks() {
  [ "$ENGINE_ID" = podman ] || return 0
  bash scripts/ensure-networks.sh
}

# engine_install_boot_unit [--no-firewall]: Docker: nothing (the daemon restarts the containers).
# Podman: installs and enables suckerpot-stack.service for this user and checkout, which starts
# the stack at boot after the host firewall (scripts/host/install-stack-unit.sh; needs sudo).
# --no-firewall when the owner opted out of the firewall (the unit then does not require it). Run
# from the root of the checkout. The installer calls it after the firewall step (Podman phase 3).
engine_install_boot_unit() {
  [ "$ENGINE_ID" = podman ] || return 0
  local args=()
  [ "${1:-}" != --no-firewall ] || args+=(--no-firewall)
  bash scripts/host/install-stack-unit.sh "${args[@]}" "$(id -un)" "$(pwd -P)"
}

# engine_remove_boot_unit: Podman: stops and removes suckerpot-stack.service (needs sudo); the
# stack stops with it. Docker: nothing.
engine_remove_boot_unit() {
  [ "$ENGINE_ID" = podman ] || return 0
  bash scripts/host/install-stack-unit.sh --uninstall
}

# engine_socket_group: the group that may use the root Podman socket (design D3).
# shellcheck disable=SC2034 # used by the scripts that source this file
ENGINE_SOCKET_GROUP=suckerpot-podman

# engine_setup_socket_access: Podman: lets this user reach the root Podman socket through
# ENGINE_SOCKET_GROUP (scripts/host/podman-socket.sh; needs sudo). Succeeds at once when the socket
# already answers. The new group only counts in a new login session: the caller says so. Docker:
# nothing. The installer calls it before its first engine call (Podman phase 3).
engine_setup_socket_access() {
  [ "$ENGINE_ID" = podman ] || return 0
  "${ENGINE_CTR[@]}" version > /dev/null 2>&1 && return 0
  bash scripts/host/podman-socket.sh "$(id -un)"
}

# engine_compose_overlay: the compose file the engine adds to COMPOSE_FILE (Podman: the overlay
# that makes every network external, docs/dev/design/podman.md 5.2). Prints nothing on Docker.
engine_compose_overlay() {
  [ "$ENGINE_ID" != podman ] || echo docker-compose.podman.yml
}

# engine_tmpfs_owner UID GID: the tmpfs options that give a tmpfs to UID:GID. Docker: ",uid=UID,gid=GID".
# Podman refuses uid= and gid=; its own option U gives the mount to the container's user, which
# every caller sets to the same UID:GID with --user.
engine_tmpfs_owner() {
  if [ "$ENGINE_ID" = podman ]; then echo ",U"; else echo ",uid=$1,gid=$2"; fi
}

# engine_image REF: the image reference to give ctr. Docker: REF as it is. Podman: a short Docker Hub
# name gets its registry (timescale/x -> docker.io/timescale/x, alpine -> docker.io/library/alpine):
# the podman command resolves short names through registries.conf, which may list no registry or
# several (design 5.9). Same image and digest.
engine_image() {
  local ref=$1 first
  if [ "$ENGINE_ID" != podman ] || [ -z "$ref" ]; then
    printf '%s\n' "$ref"
    return 0
  fi
  first=${ref%%/*}
  if [ "$first" = "$ref" ]; then
    ref=docker.io/library/$ref
  elif [[ $first != *.* && $first != *:* && $first != localhost ]]; then
    ref=docker.io/$ref
  fi
  printf '%s\n' "$ref"
}

dc() { "${ENGINE_DC[@]}" "$@"; }
ctr() { "${ENGINE_CTR[@]}" "$@"; }

# Where the engine came from: file (.env), env (the environment) or default.
_engine=$(sed -n 's/^SUCKERPOT_ENGINE=//p' "${ENV_FILE:-.env}" 2> /dev/null | tail -n 1 | sed 's/[[:space:]]#.*//' | tr -d "\"' \r" || true)
# shellcheck disable=SC2034 # ENGINE_FROM is read by install.sh
if [ -n "$_engine" ]; then
  ENGINE_FROM="file"
elif [ -n "${SUCKERPOT_ENGINE:-}" ]; then
  ENGINE_FROM="env"
  _engine=$SUCKERPOT_ENGINE
else
  ENGINE_FROM="default"
  _engine=docker
fi
# A value that is neither docker nor podman stops the script. Read-only scripts (status.sh,
# auto-update.sh, render-firewall.sh) set ENGINE_LENIENT=1 before sourcing: they warn and use docker.
if ! engine_use "$_engine"; then
  [ "${ENGINE_LENIENT:-0}" = 1 ] || return 1
  echo "warning: using docker for this read-only command" >&2
  engine_use docker
fi
unset _engine
