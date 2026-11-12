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
| Software | Docker Engine 24+ with the Compose plugin, `git`, `curl`, Bash 4+. Your user must run `docker` without `sudo` |
| Router | You can forward ports to this machine (not needed on a VPS) |
| VPN | Not needed |

No spare machine, or no access to your router? Use a cheap VPS or a Raspberry Pi: see [Join from a cheap VPS or a Raspberry Pi](vps.md).

The full list of checks is in [Install SuckerPot](install.md#requirements).

## The three commands

```bash
git clone --depth 1 --branch v0.11.3 https://github.com/selfhostr/suckerpot.git
cd suckerpot
./scripts/install.sh --participant
```

The installer prints what it will share and asks one question: `Join the SuckerPot network as described? [y/N]`. With `--yes` it does not ask, and `--yes` counts as your consent.

It then creates every secret on this machine, starts the sensors, the database, the ingest service and the network node, and picks a random pseudonym such as `amber-falcon-42`. Memory use is about 2 GiB.

A machine sold as "2 GB" reports about 1.9 GiB and runs the default setup with the low-memory limits: add swap (the installer warns and asks when there is less than 512 MiB). If the machine reports less than 1.75 GiB, the installer says so and offers the lite setup in one question (default yes; `--yes` takes it and prints a note). Accepting it is the same as passing `--lite` yourself, which stays the explicit way: `./scripts/install.sh --participant --lite`.

Near the end it offers the **host firewall**: `Install the host firewall now? ... Needs sudo. [Y/n]`. It is a small nftables table that stops a compromised sensor from reaching this machine or the internet. It is part of the installer, so the three commands stay three commands. It asks for your `sudo` password on the terminal. If you say no, or run with `--yes`, it prints the two commands to run later; you can also run `./scripts/participant.sh firewall` at any time (`uninstall` removes it, `status` shows whether it is loaded). It never touches your LAN interface, and the installer says which admin SSH port it used (from `ADMIN_SSH_PORT` in `.env`, or detected from sshd, or 22).

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

Forwarding a port on a router is the one step the installer cannot do for you, so it checks the result. At the end of the installation it looks, once, for connections from the internet. If none has arrived yet, it asks:

```text
Ports not reachable yet. [r]echeck now (after you opened them), or [c]ontinue and open them later? [c]
```

Answer `r` after you opened the ports: it looks again for up to a minute and repeats until a connection arrives or you answer `c`. With `--yes`, or without a terminal, it never asks: it prints the warning and the command to run later.

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
./scripts/status.sh
```

It shows the sensors and their ports, your standing in the network, the last contact with the hub, what was sent each day, and the update schedule. Exit code 0 is OK, 1 is a warning, 2 is an error. `--json` prints the same data for monitoring tools. `--last-batch` prints the exact data of the last submission.

Right after the install, the network section may say `Joining as <your pseudonym>: not accepted by the hub yet`, with the last problem (for example a closed path to the hub). Your agreement is already recorded: SuckerPot keeps trying by itself, and a problem makes the exit code 1 until the hub accepts the node.

By default, your sensor counts toward confirmations after 14 days of regular batches. Until then its standing is `new`.

## Automatic updates

Signed releases install themselves once a day, at a random time between 03:00 and 06:00 local time. Details are in [Updates and rollback](updates.md#automatic-updates). In short:

- A release is installed only if its signature is valid and it is at least 48 hours old.
- Only releases of the same major version are installed.
- A database dump is taken first. If the update fails, the previous version is restored and that release is not tried again.

There is a risk to know about. If the release channel of the project were ever compromised, every auto-updating participant would be affected. The signature and the 48-hour delay reduce that risk. They do not remove it. To turn updates off:

```bash
./scripts/participant.sh auto-update off
```

You can also install with `--no-auto-update`. You then update by hand with `just update`.

## Verifier nodes

Most participants never download malware. When at least two nodes report the same download link, the hub asks a **verifier node** to fetch it through its VPN and send back a description (hash, size, file type, family). A verified malware-like link can then be reported to URLhaus, after a person reviews it.

A verifier is opt-in on two sides:

1. You ask for it: `./scripts/install.sh --participant --wg-conf FILE --verifier`. It needs a VPN file, and it turns the collector on.
2. The hub operator grants the role. Until then your node works as a normal participant.

At first, only the operator's own node is a verifier.

## Manage your membership

| Command | What it does |
| --- | --- |
| `./scripts/participant.sh status` | Same as `./scripts/status.sh` |
| `./scripts/participant.sh leave` | Leave the network. The sensors keep running |
| `./scripts/participant.sh join` | Show the consent again and join |
| `./scripts/participant.sh vpn FILE` | Send everything through your VPN |
| `./scripts/participant.sh auto-update on\|off` | Turn the daily update schedule on or off |
| `./scripts/participant.sh uninstall` | Leave, stop the stack and remove the schedule. It prints the command that removes the data volumes and never runs it |

If a newer release widens what is shared, the node waits until you run `join` again. It never agrees for you.

## Switch to full mode

```bash
./scripts/install.sh --full
```

The installer asks the dashboard questions, takes a backup, starts the dashboard and the VPN service, and keeps your data and your membership. Without a VPN file, the node waits until you upload one in Settings. A full install needs a VPN for the network node, because every call to the hub goes through it. A full install cannot be switched back to participant mode.

## Useful flags

| Flag | Meaning |
| --- | --- |
| `--yes` | No prompt. This is your consent to join |
| `--pseudonym NAME` / `--no-pseudonym` | Choose your pseudonym, or have none |
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
