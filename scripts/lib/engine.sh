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
# ENGINE_ID, because env_drop_loaded may unset SUCKERPOT_ENGINE. Podman support is not finished:
# until then the scripts that install, update or start the stack refuse it (engine_ready).

ENGINE_PODMAN_SOCKET=unix:///run/podman/podman.sock

# Shown by every script that refuses to run on Podman.
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
# Only Docker until the Podman isolation work (networks, mandatory firewall, boot unit) is merged.
engine_ready() { [ "$ENGINE_ID" = docker ]; }

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

# engine_compose_overlay: the compose file the engine adds to COMPOSE_FILE (Podman: the overlay
# that makes every network external, docs/dev/design/podman.md 5.2). Prints nothing on Docker.
engine_compose_overlay() {
  [ "$ENGINE_ID" != podman ] || echo docker-compose.podman.yml
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
