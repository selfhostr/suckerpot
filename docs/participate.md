# Join the network in three commands

This page is for people who want to help the SuckerPot network and nothing else. You do not need a dashboard, an admin account, an API key or a VPN. You run sensors on a machine, and the machine shares what they see with the network.

If you want the full product (the dashboard, reports, blocklists), read [Install SuckerPot](install.md) instead. You can switch to it later and keep your data.

```{warning}
**Experimental preview.** The SuckerPot network has very few nodes today. Its shared feed may be empty, and a participant gets nothing back yet. Thresholds and the protocol may change without notice. Known limits: identity is free, so the consensus does not yet resist a determined attacker who creates several nodes, and the hub run by the project maintainers is the single root of trust. See [The SuckerPot network](network.md).
```

```{warning}
SuckerPot is built to be attacked. Use a dedicated machine that holds nothing else you care about. Choosing participant mode is your consent to join the network, as described below.
```

## What you need

| Item | Needed |
| --- | --- |
| Machine | A Linux VM or small server, `x86_64` or `aarch64`, with 2 GiB of memory (a plan sold as "2 GB", about 1.9 GiB, is fine: add swap) and 15 GiB of free disk. A 1 GiB VPS or Raspberry Pi works with `--lite` |
| Software | Docker Engine 24+ with the Compose plugin, `git`, `curl`, Bash 4+. Your user must run `docker` without `sudo`. Without Docker, the installer offers to install it from Docker's own package repository |
| Or | Podman 5.4+ (rootful) with `docker-compose` 2.26+, experimental: supported on Debian 13 and Ubuntu 26.04 (`sudo apt install podman docker-compose nftables`), experimental on Fedora and the RHEL 10 family. The installer sets up the rest; the host firewall is required. See [Podman (experimental)](install.md#podman-experimental). |
| Router | You can forward ports to this machine (not needed on a VPS) |
| VPN | Not needed |

No spare machine, or no access to your router? Use a cheap VPS or a Raspberry Pi: see [Join from a cheap VPS or a Raspberry Pi](vps.md).

The full list of checks is in [Install SuckerPot](install.md#requirements).

## The three commands

```bash
git clone https://github.com/selfhostr/suckerpot.git && cd suckerpot
git switch --detach "$(git describe --tags --abbrev=0)"
./suckerpot
```

`./suckerpot` opens a menu; choose **Install a participant node** with the arrow keys and Enter (or press `1`). `./scripts/install.sh --participant` does the same without the menu. The installer asks everything first, then runs by itself:

1. It prints what it will share and asks `Join the SuckerPot network as described? [y/N]`.
2. **Node name**: the name the network shows for your node (the protocol calls it the pseudonym). A random name such as `amber-falcon-42` is the default; you can also take this machine's host name (it may identify you, the installer says so), type your own, or have none. Do not use a name you use anywhere else.
3. **Show a country for this node?** No by default. If yes, you type its two-letter code, and the installer compares it with a GeoIP database on this machine; it never asks an outside service where the machine is, and it never fills the country in for you. See [the country check](network.md#the-country-check).

With `--yes` it asks nothing: `--yes` counts as your consent, and the name is random unless `--node-name NAME` or `--no-node-name` says otherwise (`--country CC --show-country` for a country). `--non-interactive` never reads the terminal. (Without `--participant` and without the menu, it first asks what to install: answer `1`, the participant node.)

It then creates every secret on this machine and starts the sensors, the database, the ingest service and the network node. The screen shows the list of steps, a progress bar with the percentage, and the result of each step; everything else goes to `install.log`. If a step fails, the screen names it, shows the last lines of the log and the fix. At the end it says whether the hub accepted the node, offers to wait longer while the hub has not decided yet, and shows the node's status. Memory use is about 2 GiB.

A machine sold as "2 GB" reports about 1.9 GiB and runs the default setup with the low-memory limits: add swap (the installer warns when there is less than 512 MiB). If the machine reports less than 1.75 GiB, the installer says so and takes the lite setup by itself, with a note. That is the same as passing `--lite` yourself, which stays the explicit way: `./scripts/install.sh --participant --lite`.

Near the end it installs the **host firewall**, without a question. It is a small nftables table that stops a compromised sensor from reaching this machine or the internet. It is part of the installer, so the three commands stay three commands. `sudo` asks for your password on the terminal. With `--yes` it installs the firewall by itself when `sudo` works without a password, and otherwise prints the one command to run (`./scripts/participant.sh firewall`). If you filter the containers elsewhere, pass `--no-firewall`. On Podman the firewall is required: the install stops without it, and `--no-firewall` only skips it with a warning. You can also run `./scripts/participant.sh firewall` at any time (`uninstall` removes it, `status` shows whether it is loaded). It never touches your LAN interface, and the installer says which admin SSH port it used (from `ADMIN_SSH_PORT` in `.env`, or detected from sshd, or 22).

After that, your only job is to open the printed ports.

## Open the ports

The installer ends with a table like this (example):

| Router port | This machine | Protocol | Sensor |
| --- | --- | --- | --- |
| 22 | 22 | TCP | ssh |
| 23 | 23 | TCP | telnet |
| 80 | 80 | TCP | web |
| 443 | 443 | TCP | web |

The first column is the port on your router. The second is the port on this machine. They are the same unless port 22 is busy on the machine: then the SSH sensor uses port 2222 and the table shows `22` and `2222`. Forward each router port to this machine on your router or firewall. Never forward your own admin SSH port. The installer never edits your `sshd_config`; to move your own SSH off port 22 run `sudo ./scripts/move-admin-ssh.sh` (see [VPS](vps.md#move-your-admin-ssh-off-port-22-first)).

Use port forwards, not your router's DMZ. A DMZ sends every port of this machine to the internet: the real `sshd` on port 22 and anything else that listens. It also cannot do the "router 22 to machine 2222" mapping above. A DMZ is acceptable only if this machine runs nothing else and its admin SSH port is not 22. The [host firewall](deployment.md#host-firewall) only stops containers; it does not filter internet traffic to the machine's own services. Under a DMZ your admin SSH faces the internet, so allow key-only SSH and add a rule on the router or on this machine for the admin port. More on ports: [Install SuckerPot](install.md#ports-to-forward).

### Check that the ports are open

Forwarding a port on a router is the one step the installer cannot do for you, so it checks the result. At the end of the installation it looks, once, for connections from the internet (for up to 90 seconds). If none has arrived yet, it says so and prints the command to run once you opened the ports. It does not ask anything.

You can run the check at any time (it also works on a full install):

```bash
./scripts/participant.sh ports-check              # waits up to 3 minutes
./scripts/participant.sh ports-check --wait 600   # wait up to 10 minutes
./scripts/participant.sh ports-check --since-install
```

It prints one row per port with `reached from the internet (N)` or `no traffic yet`. Exit code 0 means the internet reaches this machine, 3 means nothing arrived yet (your router probably does not forward the ports, or a DMZ is not active). Rarely scanned services such as SIP or MSSQL can stay quiet for hours, so one sensor with traffic is enough to prove the forwarding works.

The check makes no connection of its own: no port-check website, no address lookup, no request to the hub, no test of your public address. It counts sessions already recorded by your sensors from public addresses, because bots find an open port within minutes. It reads the local database only, never prints an address (only counts per sensor), and ignores private, loopback, link-local, carrier-grade NAT and documentation addresses. The counts are per sensor, so a sensor with two ports (web: 80 and 443) shows the same count on both rows.

## What you agree to share

In plain words, the node sends the hub:

- the addresses that attacked your sensors, with the service they used, what they did and rounded counts. This happens once a day, a few hours late;
- download links attackers tried, as hashes. The clear link goes to the hub only when two or more sensors saw the same link, so that a [verifier](#verifier-nodes) can check it;
- malware hashes and command-and-control addresses, but only if you have a VPN and the collector is on;
- takedown checks for addresses the network reported (not active yet).

It never shares passwords, commands, your ports, your own address or any name of yours in a payload. The full picture, with the threat model, is in [The SuckerPot network](network.md).

## Privacy without a VPN

The hub is reached through a Cloudflare tunnel. Without a VPN, Cloudflare and the hub's reverse proxy see your own public address when your machine connects. The hub application does not store it, but the address is not hidden. With a VPN, they see the VPN's exit address instead.

In this mode the stack has no VPN to keep it from using your home connection, so the only thing that holds the services back is the network layout and the host firewall. `hubproxy` is the one service meant to have a route out. It forwards connections to the hub host and nothing else. The ingest service, which parses attacker data, is not meant to have one, and your sensors never download anything. This is only enforced if the host firewall is loaded; without it, a compromised container on a host with Docker older than 28 could reach the internet on its own. Load the host firewall.

A VPN can be added at any time:

```bash
./scripts/participant.sh vpn /path/to/wireguard.conf
```

Everything then goes through the VPN, and the collector and enrichment can run. To go back to the direct path: `./scripts/participant.sh vpn --remove`.

## Check what it does

```bash
./suckerpot status          # or ./scripts/status.sh
./suckerpot status --wait   # first wait for the hub's answer to a join in progress
./suckerpot status --brief  # five lines: stack, sensors, network, what to fix
```

It shows the sensors and their ports, your standing in the network, the last contact with the hub, what was sent each day, and the update schedule. Exit code 0 is OK, 1 is a warning, 2 is an error. `--json` prints the same data for monitoring tools. `--last-batch` prints the exact data of the last submission.

Right after the install, the network section may say `Joining as <your pseudonym>: not accepted by the hub yet`, with the last problem (for example a closed path to the hub). Your agreement is already recorded: SuckerPot keeps trying by itself, and a problem makes the exit code 1 until the hub accepts the node.

The installer and `./scripts/participant.sh join` wait a few minutes for the hub's answer. If the hub refuses the pseudonym because another node already uses it, they say so and suggest a free variant, for example `./scripts/participant.sh join --pseudonym amber-falcon-42-17` (or `./scripts/participant.sh set-name amber-falcon-42-17`). The other node can be your own earlier install: the hub frees the name of a node that never sent a batch and made no request for two days on which the hub was working. A node that ever sent a batch keeps its name for good.

A refused join also heals by itself, with no command. If you set another name in `.env` (`NETWORK_PSEUDONYM`), the node tries it on its next cycle. If the refused name was generated by the installer, the node picks a new generated name by itself. A name you chose is kept and tried again once a day, in case the hub freed it. This works while your agreement in `.env` is at most 7 days old, and never after you left the network.

If the hub refused the join, the network section says `Not a member: ...` with the reason and the fix, and the exit code is 2. For a member, the last network error shows as `Last network error: <code> (<age>)`, with a plain explanation and the fix when one is known. Two cases go to **Needs attention**: a member with no contact with the hub 2 hours after joining, and the same error for more than 6 hours.

If something needs your action, the report ends with a **Needs attention** block. Each item comes with the one command that fixes it. Besides the network cases above, it lists three things: automatic updates are off (`./scripts/participant.sh auto-update on`), the host firewall is not installed (`./scripts/participant.sh firewall`), and the node runs a release at least three days older than the newest one it knows (`just update`). Any of them makes the exit code 1. The "newest release it knows" comes from the tags this checkout already has; the update job fetches new ones. An empty block means nothing to do.

By default, your sensor counts toward confirmations after 14 days of regular batches. Until then its standing is `new`.

A node that enrolled more than 7 days ago and never sent a batch, or that sent no batch for 30 days, is **dormant**. The hub keeps it, but leaves it out of the member list and of the member counts (network summary, public figures). It counts again from the next weekly snapshot after its next batch.

## Automatic updates

Signed releases install themselves: the node checks every 6 hours, from a random time between 03:00 and 06:00 local time. Details are in [Updates and rollback](updates.md#automatic-updates). In short:

- A release is installed only if its signature is valid and it is at least 48 hours old.
- Only releases of the same major version are installed.
- A database dump is taken first. If the update fails, the previous version is restored and that release is not tried again.

There is a risk to know about. If the release channel of the project were ever compromised, every auto-updating participant would be affected. The signature and the 48-hour delay reduce that risk. They do not remove it. To turn updates off:

```bash
./scripts/participant.sh auto-update off
```

You can also install with `--no-auto-update`. You then update by hand with `just update`. A participant install turns automatic updates on by default. They stay off only with `--no-auto-update`, with `--source` (a source build has no signed images to update to), or when no crontab or systemd user session could hold the schedule. In that last case the installer prints the command to run, and `./scripts/install.sh --repair` tries the schedule again.

## Verifier nodes

Most participants never download malware. When at least two nodes report the same download link, the hub asks a **verifier node** to fetch it through its VPN and send back a description (hash, size, file type, family). A verified malware-like link can then be reported to URLhaus, after a person reviews it.

A verifier is opt-in on two sides:

1. You ask for it: `./scripts/install.sh --participant --wg-conf FILE --verifier`. It needs a VPN file, and it turns the collector on.
2. The hub operator grants the role. Until then your node works as a normal participant.

At first, only the operator's own node is a verifier.

## Manage your membership

`./suckerpot` gathers all of this in one menu: status, **Edit the node** (name, country, sensors, VPN, automatic updates, host firewall; each change applies at once), update, ports check, logs, repair, leave or join, and remove. `./suckerpot edit name`, `./suckerpot edit country` and the others ask their question without the menu; `./suckerpot help` lists every command.

| Command | What it does |
| --- | --- |
| `./scripts/participant.sh status` | Same as `./scripts/status.sh` |
| `./scripts/participant.sh set-name NAME` (`--none`) | Change the node name. A member sends it to the hub at once and the command waits for the answer: a name another node uses is refused, and everything is put back. The hub allows one change per 7 days |
| `./scripts/participant.sh set-country CC` (`--hide`, `--none`) | Show a country (`--hide`: send it, do not show it; `--none`: no country). The code is compared with a GeoIP database on this machine only; a mismatch is a warning |
| `./scripts/participant.sh leave` | Leave the network. The sensors keep running |
| `./scripts/participant.sh join [--pseudonym NAME]` | Show the consent again and join. After a refused join, or for a new pseudonym, run it with `--pseudonym` |
| `./scripts/participant.sh vpn FILE` | Send everything through your VPN |
| `./scripts/participant.sh auto-update on\|off` | Turn the automatic update schedule on or off |
| `./scripts/participant.sh uninstall` | Leave, stop the stack and remove the schedule. It prints the command that removes the data volumes and never runs it |
| `./suckerpot remove` | The same, step by step: it shows what it keeps, and only on your explicit answer removes the host firewall and deletes the data (see [Remove SuckerPot](install.md#remove-suckerpot)) |

If a newer release widens what is shared, the node waits until you run `join` again. It never agrees for you.

## Switch to full mode

```bash
./scripts/install.sh --full
```

The installer takes a backup, starts the dashboard and the VPN service, and keeps your data and your membership. Without a VPN file, the node waits until you upload one in Settings. A full install needs a VPN for the network node, because every call to the hub goes through it. A full install cannot be switched back to participant mode.

## Useful flags

| Flag | Meaning |
| --- | --- |
| `--yes` | No prompt. This is your consent to join |
| `--node-name NAME` / `--no-node-name` | Choose the node name, or have none (the same as `--pseudonym NAME` / `--no-pseudonym`) |
| `--country CC --show-country` | Show a country (checked against a GeoIP database on this machine only) |
| `--non-interactive` | Never read the terminal, as in CI (the consent then needs `--yes`) |
| `--sensors LIST` | `recommended` (default), `all`, or a list such as `ssh,telnet` |
| `--feeds` | Also fetch the public blocklist feed |
| `--self-address ADDR` | Tell the node your own public address so it is never recorded |
| `--no-auto-update` | Do not schedule updates |
| `--repair` | Run the volume, start and schedule steps again without changing settings |

Run `./scripts/install.sh --help` for the full list.

## Next steps

- [The SuckerPot network](network.md)
- [Updates and rollback](updates.md)
- [Install SuckerPot](install.md)
