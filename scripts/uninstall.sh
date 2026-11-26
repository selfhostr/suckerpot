#!/usr/bin/env bash
# Remove SuckerPot from this machine, step by step, and say what stays.
#
#   scripts/uninstall.sh [--yes] [--remove-firewall] [--delete-data]
#
# What it does: a participant node leaves the network first; then the automatic update schedule
# and (Podman) the boot unit are removed, and the containers are stopped and removed
# (scripts/participant.sh uninstall for a participant node, the same steps for a full install).
#
# What stays unless you say otherwise: the data volumes (the database, captured files, keys), .env
# (it holds the database password, which lives inside the data: never delete one without the
# other), install.log, this checkout and the host firewall.
#   --remove-firewall  also remove the host firewall (sudo)
#   --delete-data      also delete the data volumes, for good; .env is then renamed to
#                      .env.removed-<date>, so this folder can install again. On a terminal you
#                      are asked to type DELETE; without one it needs --yes as well.
# Without --yes, the plan is shown and you are asked first.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/lib/env.sh
. scripts/lib/env.sh
sudo_drop scripts/uninstall.sh "$@"
# shellcheck source=scripts/lib/ask.sh
. scripts/lib/ask.sh

die() { echo "uninstall: $*" >&2; exit 1; }
# say TEXT: a line, wrapped at the width of a terminal (as given without one).
say() { printf '%s\n' "$*" | text_out 1; }

yes=0 rm_fw=0 rm_data=0
while [ $# -gt 0 ]; do
  case $1 in
    --yes | -y) yes=1 ;;
    --remove-firewall) rm_fw=1 ;;
    --delete-data) rm_data=1 ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

[ -f .env ] || die "nothing is installed in this folder (no .env)"
env_drop_loaded
need_project
stack=$(env_get SUCKERPOT_STACK_MODE full)
prefix=$(env_get SUCKERPOT_VOLUME_PREFIX)
[ -n "$prefix" ] || die "SUCKERPOT_VOLUME_PREFIX is not set in .env"
[ "$yes" = 1 ] || ask_open
ASK_IND="  "
volumes=$(ctr volume ls -q --filter "name=^${prefix}_" 2> /dev/null || true)
nvol=$(printf '%s' "$volumes" | grep -c . || true)
# shellcheck source=scripts/lib/fwcheck.sh
. scripts/lib/fwcheck.sh
fw=0
fw_installed && fw=1

say ""
say "Remove SuckerPot from this machine ($stack install, project $(env_get COMPOSE_PROJECT_NAME))"
say ""
say "  This will:"
[ "$stack" != participant ] || [ "$(env_get NETWORK_ENABLED false)" != true ] || say "    - leave the network (the hub deletes this node and what it sent)"
say "    - remove the automatic update schedule"
[ "$ENGINE_ID" != podman ] || say "    - remove the boot unit suckerpot-stack.service"
say "    - stop and remove the containers"
[ "$rm_fw" = 0 ] || say "    - remove the host firewall (sudo)"
[ "$rm_data" = 0 ] || say "    - DELETE the $nvol data volumes ${prefix}_* (cannot be undone) and rename .env"
say ""
say "  This keeps:"
if [ "$nvol" = 0 ]; then
  say "    - (no data volume named ${prefix}_* was found)"
elif [ "$rm_data" = 0 ]; then
  say "    - the $nvol data volumes ${prefix}_* (database, captured files, node key)"
fi
[ "$rm_data" = 1 ] || say "    - .env (the database password lives in the data: keep both or neither)"
say "    - install.log and this folder ($PWD)"
[ "$rm_fw" = 1 ] || [ "$fw" = 0 ] || say "    - the host firewall (remove it: ./scripts/participant.sh firewall uninstall)"
say ""

if [ "$yes" = 0 ]; then
  [ "$ASK_TTY" = 1 ] || die "no terminal to ask on; use --yes"
  ask_yn "Go ahead?" n || die "nothing was changed"
fi

if [ "$stack" = participant ]; then
  bash scripts/participant.sh uninstall --yes
else
  # shellcheck source=scripts/lib/schedule.sh
  . scripts/lib/schedule.sh
  schedule_remove || echo "uninstall: warning: could not remove the update schedule" >&2
  if [ "$ENGINE_ID" = podman ] && engine_stack_unit_installed; then
    engine_remove_boot_unit || echo "uninstall: warning: could not remove suckerpot-stack.service" >&2
  fi
  dc --profile '*' down
  say "uninstall: stopped. The containers are removed; the schedule is removed."
fi

if [ "$fw" = 1 ] && [ "$rm_fw" = 0 ] && [ "$yes" = 0 ]; then
  say ""
  if ask_yn "Also remove the host firewall (sudo)?" n; then rm_fw=1; fi
fi
if [ "$rm_fw" = 1 ] && [ "$fw" = 1 ]; then
  bash scripts/host/install-firewall.sh --uninstall || echo "uninstall: warning: the host firewall was not removed (sudo ./scripts/host/install-firewall.sh --uninstall)" >&2
fi

if [ "$rm_data" = 0 ] && [ "$yes" = 0 ] && [ "$nvol" -gt 0 ]; then
  say ""
  say "  The data volumes stay, so you can install again and keep your history."
  if ask_yn "Delete the data volumes too? This cannot be undone." n; then rm_data=1; fi
fi
if [ "$rm_data" = 1 ] && [ "$nvol" -gt 0 ]; then
  if [ "$yes" = 0 ]; then
    a=""
    ask_text a "Type DELETE to delete $nvol volumes for good" "" || a=""
    [ "$a" = DELETE ] || { echo "uninstall: the data volumes are kept."; rm_data=0; }
  fi
fi
if [ "$rm_data" = 1 ]; then
  if [ "$nvol" -gt 0 ]; then
    # shellcheck disable=SC2086 # one name per line, names are [a-z0-9_-]
    ctr volume rm $volumes > /dev/null || die "some volumes could not be removed (a container may still use them): ${ENGINE_CTR[*]} volume ls"
  fi
  moved=".env.removed-$(date -u +%Y%m%d%H%M%S)"
  mv .env "$moved"
  chmod 600 "$moved"
  say "uninstall: the data volumes are deleted. .env is now $moved (delete it when you are sure)."
  say "uninstall: this folder can install again: ./suckerpot install"
else
  say ""
  say "Kept: the data volumes ${prefix}_* and .env. Install again with your data: ./scripts/install.sh --repair"
  say "Delete them later: ./scripts/uninstall.sh --delete-data"
fi
