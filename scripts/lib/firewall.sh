# shellcheck shell=bash
# The host firewall step (scripts/host/): render the rules for this install, then offer to load
# them. Sourced by install.sh and participant.sh; needs scripts/lib/env.sh (env_get).
#
# Nothing here is ever fatal: a missing sudo, a refused file or a "no" only prints the two commands
# to run later. The rendered file holds the admin SSH port, so it stays in the untracked state
# folder (.suckerpot-state/, listed in .gitignore) with mode 0600.

FW_STATE_DIR=.suckerpot-state
FW_FILE=$FW_STATE_DIR/host-firewall.nft

# fw_admin_port: prints "PORT SOURCE". ADMIN_SSH_PORT from .env first, then what sshd is
# configured to listen on (readable without root), then 22.
# A wrong port is low risk: the rules never touch the LAN interface, and the port only matters for
# the Docker bridges (a container must not reach the admin SSH of the host).
fw_admin_port() {
  local p
  p=$(env_get ADMIN_SSH_PORT)
  if [[ $p =~ ^[1-9][0-9]{0,4}$ ]] && [ "$p" -le 65535 ]; then
    echo "$p ADMIN_SSH_PORT in .env"
    return 0
  fi
  # systemd socket activation (Ubuntu 22.10+): the port is the socket's, not sshd_config's. Only
  # when the socket is the one in use.
  if systemctl is-active --quiet ssh.socket 2> /dev/null; then
    p=$(systemctl show ssh.socket -p Listen --value 2> /dev/null | sed -n 's/^.*:\([0-9]\{1,5\}\) (Stream).*$/\1/p' | head -n 1 || true)
    if [[ $p =~ ^[1-9][0-9]{0,4}$ ]] && [ "$p" -le 65535 ]; then
      echo "$p ssh.socket"
      return 0
    fi
  fi
  # The effective configuration, when sshd -T works without root (it usually does not).
  p=$(sshd -T 2> /dev/null | sed -n 's/^port \([0-9]\{1,5\}\)$/\1/p' | head -n 1 || true)
  if [[ $p =~ ^[1-9][0-9]{0,4}$ ]] && [ "$p" -le 65535 ]; then
    echo "$p sshd -T"
    return 0
  fi
  p=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2> /dev/null | sed -n 's/^[[:space:]]*Port[[:space:]]\{1,\}\([0-9]\{1,5\}\)[[:space:]]*$/\1/p' | head -n 1 || true)
  if [[ $p =~ ^[1-9][0-9]{0,4}$ ]] && [ "$p" -le 65535 ]; then
    echo "$p sshd_config"
    return 0
  fi
  echo "22 default"
}

# fw_render_args MODE PORT: the arguments of render-firewall.sh, one per line.
fw_render_args() {
  local mode=$1 port=$2 ep_ip ep_port
  if [ "$mode" = participant ]; then
    printf '%s\n' --participant --admin-ssh-port "$port"
  else
    printf '%s\n' --full --admin-ssh-port "$port" --dashboard-port "$(env_get DASHBOARD_PORT 8443)"
  fi
  ep_ip=$(env_get VPN_WG_ENDPOINT_IP)
  ep_port=$(env_get VPN_WG_ENDPOINT_PORT)
  if [ -n "$ep_ip" ] && [ -n "$ep_port" ]; then printf '%s\n' --vpn-endpoint "$ep_ip:$ep_port"; fi
}

# fw_print_commands MODE PORT: what to run later, and why.
fw_print_commands() {
  local mode=$1 port=$2 args
  args=$(fw_render_args "$mode" "$port" | tr '\n' ' ')
  echo "  The host firewall stops a compromised sensor from reaching this machine or the internet."
  echo "  To install it later (the second command needs sudo):"
  echo "    scripts/host/render-firewall.sh ${args}--out $FW_FILE"
  echo "    scripts/host/install-firewall.sh $FW_FILE"
  echo "  Or: ./scripts/participant.sh firewall"
}

# fw_render MODE: renders into $FW_FILE and says which admin port it used. Returns the renderer's
# exit code. Sets FW_PORT.
fw_render() {
  local mode=$1 port src args=() line rc=0
  read -r port src <<< "$(fw_admin_port)"
  FW_PORT=$port
  echo "  Admin SSH port used: $port ($src). If that is wrong, set ADMIN_SSH_PORT in .env and run again."
  while IFS= read -r line; do args+=("$line"); done < <(fw_render_args "$mode" "$port")
  mkdir -p "$FW_STATE_DIR"
  chmod 700 "$FW_STATE_DIR" 2> /dev/null || true
  bash scripts/host/render-firewall.sh "${args[@]}" --out "$FW_FILE" || rc=$?
  return "$rc"
}

# fw_can_sudo: true when root rights are available without a password prompt (already root, or
# `sudo -n` works). Used by the unattended install (--yes): it never waits for a password.
fw_can_sudo() {
  [ "$(id -u)" = 0 ] && return 0
  command -v sudo > /dev/null 2>&1 && sudo -n true > /dev/null 2>&1
}

# fw_step MODE [ASK_FD|auto]: render and, when a terminal answers yes, install. ASK_FD is a file
# descriptor to read the answer from. With "auto" (--yes) nothing is asked: it installs when sudo
# works without a password, and otherwise prints the one command to run. With nothing, it only
# prints the commands (no terminal).
fw_step() {
  local mode=$1 fd=${2:-} rc=0 ans="" auto=0
  if [ "$fd" = auto ]; then auto=1; fd=""; fi
  echo
  echo "Host firewall"
  FW_PORT=22
  fw_render "$mode" || rc=$?
  if [ "$rc" != 0 ]; then
    echo "  The firewall rules could not be rendered (exit $rc). The stack is not affected."
    fw_print_commands "$mode" "$FW_PORT"
    return 0
  fi
  if [ "$auto" = 1 ]; then
    if ! fw_can_sudo; then
      echo "  The host firewall needs sudo, which asks for a password here. To install it now, run:"
      echo "    ./scripts/participant.sh firewall"
      return 0
    fi
  elif [ -z "$fd" ]; then
    fw_print_commands "$mode" "$FW_PORT"
    return 0
  fi
  if [ "$auto" = 0 ]; then
    printf '  Install the host firewall now? It stops a compromised sensor from reaching this machine or the internet. Needs sudo. [Y/n] ' >&2
    IFS= read -r ans <&"$fd" || ans=n
    case $ans in
      "" | y | Y | yes | YES | Yes) ;;
      *)
        fw_print_commands "$mode" "$FW_PORT"
        return 0
        ;;
    esac
  fi
  rc=0
  bash scripts/host/install-firewall.sh "$FW_FILE" || rc=$?
  if [ "$rc" = 0 ]; then
    echo "  The host firewall is loaded and starts at every boot. Remove it with: scripts/host/install-firewall.sh --uninstall"
  else
    echo "  The host firewall was not installed (exit $rc). The stack keeps running."
    fw_print_commands "$mode" "$FW_PORT"
  fi
  return 0
}
