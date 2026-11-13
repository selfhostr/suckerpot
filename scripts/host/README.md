# Host firewall

SuckerPot publishes honeypot ports on the host and runs untrusted traffic through
Docker containers. Docker's network settings already remove the containers' route to
the internet, but they do not stop a compromised container from opening connections to
the **host itself** (for example its admin SSH port) or to other machines on your LAN.
This nftables table closes that gap.

There are two templates. Neither contains an address from any real network.

| File | For | Values to set |
| --- | --- | --- |
| `firewall-participant.nft` | A participant node: sensors, database, ingest and `hubproxy`, no dashboard, no VPN | The admin SSH port only |
| `firewall.nft` | A full install: dashboard, optional VPN (`egress` profile) | Admin SSH port, dashboard port, WireGuard endpoint |

Both define the same table, `inet suckerpot_host`, and are loaded the same way.

## Quick start

```
scripts/host/render-firewall.sh --participant --admin-ssh-port 2200 --out ~/suckerpot-firewall.nft
scripts/host/install-firewall.sh ~/suckerpot-firewall.nft
```

For a full install, use `--full` and add `--dashboard-port <DASHBOARD_PORT>` and, with the
`egress` profile, `--vpn-endpoint <VPN_WG_ENDPOINT_IP>:<VPN_WG_ENDPOINT_PORT>`.

- `render-firewall.sh` needs no root and changes nothing. It fills in the values, reads the
  resolvers hubproxy's DNS goes to (see [DNS](#dns-from-sp-hubgate)), writes the file with
  mode 0600 and checks it with `nft -c` when it may (root only; otherwise it says it skipped
  the check). It also refuses (exit 2) when a host bridge that is not Docker's matches the
  rules' `br-*` or `sp-*` wildcard, see [Bridges](#bridges-that-are-not-dockers). Exit codes:
  0 rendered, 1 `nft -c` refused the result, 2 bad arguments or a foreign bridge.
- `install-firewall.sh FILE` re-runs itself with `sudo`. It first copies FILE to a root-owned
  0600 temporary file next to `/etc/suckerpot-firewall.nft`, and checks only that copy: it
  refuses one that still holds a placeholder or that `nft -c` refuses, then renames the copy
  into place (atomic), installs and enables `suckerpot-firewall.service`, loads the table and
  checks it is there. A change to FILE after the check is never what gets installed.
  `install-firewall.sh --uninstall` removes all of it. Exit codes: 0 done, 2 bad arguments,
  3 `nft` or `systemctl` missing, 4 file refused (nothing changed), 5 loading failed.

Keep the rendered file out of the repository: it holds your admin port.

## What it blocks

Participant (`firewall-participant.nft`):

| Rule | Effect |
| --- | --- |
| input, from `sp-*` | A container on a SuckerPot network can send the host nothing but replies: new, invalid and untracked packets are dropped. The one exception: a new UDP 53 query from `sp-hubgate` to a listed resolver, if that resolver is the host itself. |
| input, from `docker0` and `br-*` to the admin SSH port | Containers of other Docker networks cannot reach the admin SSH port. |
| forward, from `sp-ingress` (and `sp-dashboard`) | Everything that is not a reply is dropped (new, invalid, untracked): no outbound traffic, no LAN scan, not even a one-way SYN or UDP packet with a container source address. Replies to inbound connections still go out. |
| forward, from `sp-hubgate` | `hubproxy` may open TCP 443 to public unicast addresses, and UDP 53 to the resolvers in `HUBGATE_DNS`. Private, shared (CGNAT), loopback, link-local, multicast and documentation ranges are dropped, and so is everything else, whatever its connection state. |
| forward, IPv6 from `sp-*` | Dropped. The networks have no IPv6. |
| forward, from `sp-vpn` | Nothing but replies (a direct participant has no VPN). With `--vpn-endpoint`, new UDP to that endpoint only. |
| forward, internal bridges (`sp-s-*`, `sp-backend`, `sp-hubproxy`) | No rule (except the IPv6 drop): their members (a sensor and Redis, ingest and the database, ingest and hubproxy) talk to each other across the bridge, and Docker keeps the networks internal. |

Full (`firewall.nft`):

| Rule | Effect |
| --- | --- |
| input, from `sp-ingress` and `sp-dashboard` | Containers of the sensor network and the dashboard network can send the host nothing but replies. |
| input, from `sp-s-*`, `sp-backend` and `sp-tools` | Nor can the internal networks. On Docker Engine 28 or later the host has no address on these bridges at all (isolated gateway); this rule covers older engines. |
| input, from `docker0`, `br-*` and `sp-*` to `protected_ports` | No container of any Docker network can reach the admin SSH port or the dashboard port of the host. |
| forward, from `sp-ingress` and `sp-dashboard` | Everything that is not a reply is dropped: no LAN scanning, no outbound traffic, no traffic between sensors. Replies to inbound connections still go out. |
| input, from `sp-egress`, `sp-samples` and `sp-hubproxy` | The proxy networks and the sample network can send the host nothing but replies. Without this, `CONNECT <bridge gateway>:<published port>` through a proxy would reach the host's published ports. |
| input, from `sp-vpn` | The `vpn` container (anonymous egress) can send the host nothing but replies. |
| forward, from `sp-vpn` | The only new connection allowed is UDP to the WireGuard endpoint, and nothing that is not a reply passes otherwise (`VPN_ENDPOINT_IP`, `VPN_ENDPOINT_PORT`). Everything else is dropped, so the kill switch holds even if the container's own firewall fails. |
| forward, from `sp-hubgate` | As for a participant: TCP 443 to public addresses and UDP 53 to `HUBGATE_DNS` only. Only matters with the `direct` profile. |
| forward, IPv6 from `sp-*` | Dropped. |

In both files, every input rule that names an `sp-*` bridge, and the last forward rule of each
uplink (`sp-ingress`, `sp-dashboard`, `sp-vpn`, `sp-hubgate`), drops whatever is not a reply,
not only new connections: an invalid or untracked packet never passes.

Nothing here affects traffic from the internet to the published sensor ports, or your own
admin SSH from the LAN: every rule names a Docker bridge.

## Bridges that are not Docker's

nftables only has trailing wildcards, so the rules match Docker's bridges as `br-*` and `sp-*`
(Docker's own pattern, `br-` plus 12 hex digits, cannot be written exactly). A bridge of yours
with such a name, for example a VM or LAN bridge called `br-lan`, would get the same drops, and
if your admin SSH reaches the host through it you would lock yourself out.

`render-firewall.sh` therefore lists the host's bridges (`ip -o link show type bridge`, or
`/sys/class/net`, no root needed) and the ones Docker owns (`docker network ls` and
`docker network inspect`), and refuses with exit 2 when a bridge matching `br-*` or `sp-*` is not
Docker's. When Docker cannot be asked, a bridge counts as Docker's only if it is named
`br-<12 hex digits>` or is one of SuckerPot's fixed `sp-*` names. Rename such a bridge, or, if you
are sure nothing you need reaches this host through it, pass `--allow-bridge NAME` for each one.

## DNS from sp-hubgate

`hubproxy` resolves the hub through Docker's embedded resolver (127.0.0.11 inside the
container). That resolver forwards each query **from the container's own network
namespace** (moby `libnetwork/resolver.go`, `forwardExtDNS`), so the packet leaves through
`sp-hubgate` with the container's address, to the upstream servers Docker read from the host:

- `/etc/resolv.conf`, or `/run/systemd/resolve/resolv.conf` when `/etc/resolv.conf` only lists
  the systemd-resolved stub `127.0.0.53` (Ubuntu's default);
- the `dns` list of `/etc/docker/daemon.json`, if you set one (pass it with `--dns`).

The one exception is a loopback upstream (for example a local `unbound` on `127.0.0.1`): Docker
queries it from the host's namespace, so it never crosses `sp-hubgate` and needs no rule.

So DNS through `sp-hubgate` is needed, but only UDP 53 to those servers. `render-firewall.sh`
lists them in `HUBGATE_DNS` (IPv4, loopback skipped; repeat `--dns IP` to override). When there
are none, it writes `{ 127.0.0.1 }`, which no forwarded packet can match. TCP 53 is not opened:
the answers hubproxy needs (the address of one or two names) fit in UDP. If your resolvers change (new router,
new DHCP lease), render and install the file again. A wrong list fails safe: hubproxy cannot
resolve the hub and the node stays idle, nothing else opens.

## Before you apply it by hand

The renderer does all of this. By hand:

1. Copy the template and set `ADMIN_SSH_PORT` to the port of your host's admin SSH daemon. The
   files ship with `CHANGE_ME` on purpose: they will not load until you change it.
2. Participant: set `HUBGATE_DNS` to your upstream resolvers (see above).
3. Full: check that `DASHBOARD_PORT` matches your `.env`. With the `egress` profile, set
   `VPN_ENDPOINT_IP` and `VPN_ENDPOINT_PORT` to the values of `VPN_WG_ENDPOINT_IP` and
   `VPN_WG_ENDPOINT_PORT`. Without the profile, use `127.0.0.1` and `51820`: the rule then
   never matches anything.
4. Nothing to adjust for Docker address pools: rules match network interfaces, not addresses.
5. Keep a second way into the machine (hypervisor console) the first time.

## Important: load it before exposing the host

Without this table, a compromised sensor can reach the host's admin SSH port. Load it
**before** you forward any traffic to the machine, and check it after every reboot:

```
sudo nft list table inet suckerpot_host
```

If that prints an error, the firewall is not active.

The internal networks also use Docker's isolated gateway mode
(`com.docker.network.bridge.gateway_mode_ipv4: isolated`), which needs **Docker Engine 28 or
later**. On an older engine that isolation does not apply (the host keeps an address on each
internal bridge), and only this table stops a container from reaching the host. Upgrade Docker.

## Apply

```
sudo nft -c -f FILE    # syntax check, changes nothing
sudo nft -f FILE       # apply (safe to run again)
sudo nft list table inet suckerpot_host    # see the rules and counters
```

The rules live in memory only until you persist them.

## Persist across reboots

`install-firewall.sh` does this for you. Do **not** use the stock `nftables` service: on
Debian and Ubuntu, `/etc/nftables.conf` starts with `flush ruleset`, and starting that service
on a running host wipes Docker's own rules (NAT and published ports) until Docker restarts.

Use the dedicated unit shipped next to this file instead. It only loads the
`suckerpot_host` table, after Docker has started. By hand:

```
sudo install -m 0600 FILE /etc/suckerpot-firewall.nft
sudo nft -c -f /etc/suckerpot-firewall.nft     # syntax check, changes nothing
sudo install -m 0644 scripts/host/suckerpot-firewall.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now suckerpot-firewall.service
```

Edit the installed copy, never the tracked file: your admin port must not end up in git.

The table does not clash with Docker: it has its own name, and Docker does not delete
tables it did not create. The rules match interface names as text, so they work even
if the Docker networks are created later.

## Verify

Egress: with the `egress` profile up, run `just egress-check`, then
`sudo nft list table inet suckerpot_host`. The `sp-vpn` accept rule counts the tunnel
handshake packets; the `sp-vpn` drop counters stay at 0 unless something inside `vpn`
tried to leave outside the tunnel.

Participant: the `sp-hubgate` UDP 53 and TCP 443 accept counters go up when the node talks to
the hub; the `sp-hubgate` drop counters stay at 0.

1. Start the stack, then from the host run `sudo nft list table inet suckerpot_host`.
   Counters on the `drop` rules stay at 0 in normal operation.
2. From inside a sensor, a new connection to the host must fail. For example (replace
   `<sensor-container>` and `<gateway>`; the gateway is the `.1` address of the `sp-ingress` subnet):

   ```
   docker run --rm --network container:<sensor-container> busybox nc -w2 -zv <gateway> <admin-ssh-port>
   ```

   It should time out, and the `input` drop counter should go up.
3. From the internet (or another machine), the sensor ports must still answer.
4. Check that the host listens on the sensor port for IPv4 only: `ss -tlnp | grep ':22 '`
   should show `0.0.0.0:22` and no `[::]:22`.
5. The internal bridges have no host address: `ip -4 addr show sp-backend` prints no `inet`
   line (Docker Engine 28 or later).

## Roll back

```
sudo scripts/host/install-firewall.sh --uninstall   # or, for this boot only: sudo nft delete table inet suckerpot_host
```

By hand: `sudo systemctl disable --now suckerpot-firewall.service`, then
`sudo rm /etc/systemd/system/suckerpot-firewall.service /etc/suckerpot-firewall.nft && sudo systemctl daemon-reload`.

## Proxmox firewall

The nftables table above runs inside the VM. If the VM runs on Proxmox VE, add the hypervisor
layer too: `proxmox-firewall.sh` writes the VM's own firewall file, `/etc/pve/firewall/<vmid>.fw`.
It stops the VM from reaching your LAN (even if the VM is fully compromised, because the
filter sits outside it), and it keeps the admin SSH port and the dashboard port private. Run it
as root **on the Proxmox node**, not in the VM. Nothing here is specific to your network: you
pass every address.

```
# 1. Dry run (the default): prints the file and its difference, changes nothing.
scripts/host/proxmox-firewall.sh --vmid 102 --gateway 192.0.2.1 \
  --admin-port <the port you chose with scripts/move-admin-ssh.sh> --admin-from 198.51.100.0/24 \
  --private-port 8443 --private-from 192.0.2.10

# 2. The same command with --apply added writes it (a backup first, a check after, rollback on failure).
scripts/host/proxmox-firewall.sh <the same arguments> --apply

# Undo: put the most recent backup back.
scripts/host/proxmox-firewall.sh --undo --vmid 102
```

Here `192.0.2.1` is the LAN gateway (it must also be the VM's DNS, or add the DNS server with
`--allow-out`), `198.51.100.0/24` is the network you SSH from, and `192.0.2.10` is the host of
your reverse tunnel (for example a cloudflared VM) that reaches the dashboard on `8443`.

### What it writes

Proxmox evaluates the rules top to bottom and the first match wins, so the order matters.
Every rule it writes ends with a `# SuckerPot: ...` comment.

| Section | Rule | Why |
| --- | --- | --- |
| `[OPTIONS]` | `enable: 1`, `policy_in: ACCEPT`, `policy_out: ACCEPT`, `macfilter: 1` | The sensors must accept the internet on many ports, so the input policy stays open; the rules below close what must be closed. `macfilter` stops the VM from sending with another MAC address. |
| `[RULES]` 1 | `OUT ACCEPT -dest <gateway>`, then one per `--allow-out` | The LAN gateway and DNS the VM needs, and any other LAN host you list (a local DNS server). |
| `[RULES]` 2 | `OUT DROP` to the private ranges | The VM may not start a connection to your LAN: the three RFC 1918 ranges (10/8, 172.16/12, 192.168/16), `100.64.0.0/10` (CGNAT), `169.254.0.0/16` (link-local) and, for IPv6, `fc00::/7` (unique local). `fe80::/10` stays open, because IPv6 neighbour discovery needs it. Replies to connections that came in (a sensor answering a scanner, the tunnel host reading the dashboard) are not new connections and still pass. |
| `[RULES]` 3 | `IN ACCEPT -source <admin CIDR> -p tcp -dport <admin port>`, then `IN DROP -p tcp -dport <admin port>` | The admin SSH answers your management network only. |
| `[RULES]` 4 | for each `--private-port`: `IN ACCEPT -source <tunnel host>` (one per `--private-from`, plus the admin network with `--private-from-admin`), then `IN DROP` on that port | The dashboard, or a hub port, answers the tunnel host only. |

The generated file for the example above, with the three RFC 1918 drops left out for brevity:

```
[OPTIONS]

enable: 1
policy_in: ACCEPT
policy_out: ACCEPT
macfilter: 1

[RULES]

OUT ACCEPT -dest 192.0.2.1 # SuckerPot: LAN gateway and DNS
OUT DROP -dest 100.64.0.0/10 # SuckerPot: no traffic to shared address space (CGNAT)
OUT DROP -dest 169.254.0.0/16 # SuckerPot: no traffic to link-local addresses
OUT DROP -dest fc00::/7 # SuckerPot: no traffic to IPv6 unique local addresses
IN ACCEPT -source 198.51.100.0/24 -p tcp -dport <admin port> # SuckerPot: admin SSH from the management network
IN DROP -p tcp -dport <admin port> # SuckerPot: admin SSH from nowhere else
IN ACCEPT -source 192.0.2.10 -p tcp -dport 8443 # SuckerPot: port 8443 from the tunnel host
IN DROP -p tcp -dport 8443 # SuckerPot: port 8443 from nowhere else
```

`ipfilter` is not set on purpose. For a VM, an empty `ipfilter` set drops all of the VM's IPv4
traffic, and the script cannot know which addresses the VM uses: it would cut the VM off.

### Required arguments

| Argument | Meaning |
| --- | --- |
| `--vmid N` | The VM. |
| `--gateway ADDR` | The LAN gateway and DNS the VM needs (IPv4 or IPv6). |
| `--admin-port N` | The port of the VM's admin SSH: the port you chose with `scripts/move-admin-ssh.sh`. There is no default. |
| `--admin-from CIDR` | Who may reach the admin port: an address or a CIDR, never `/0`. It must be the address the VM sees, so check it if your SSH goes through a router that rewrites it. |

Optional: `--allow-out ADDR` (repeat it), `--private-port N` (repeat it), `--private-from ADDR`
(repeat it), `--private-from-admin`, `--apply`, `--replace`, `--set-nic-firewall`, `--undo`.
Every value is checked before anything else happens (whole numbers for ports, real IPv4 and
IPv6 addresses and CIDRs). A private port may not be the admin port, nor one of the sensors'
default host ports, and a private port needs someone allowed to reach it.

### Safety

- The default is a dry run. It prints the generated file and a unified diff against the current
  `<vmid>.fw`, and changes nothing. It runs as any user, anywhere (it only warns that it could
  not check Proxmox).
- `--apply` needs root, the `pve-firewall`, `qm` and `pvesh` commands and a mounted `/etc/pve`.
  It copies the current file to `/root/suckerpot-firewall-backups/<vmid>-<UTC timestamp>.fw`
  (mode 0600; when there was no file yet, an empty `.absent` marker takes its place), writes the
  new file next to it and renames it into place, then runs `pve-firewall compile`. If that
  fails (or names the file in a warning), the backup is put back and the exit code is 5.
- If the current file holds a rule, an option or a section the script did not generate, the diff
  lists it and `--apply` refuses (exit 4). `--replace` goes ahead and **drops** them; the backup
  keeps them. A rule the script wrote itself (its comment starts with `# SuckerPot:`) is
  replaced without `--replace`, so you can run it again with other arguments.
- It never touches the datacenter firewall (`cluster.fw`) or the node's firewall. It only
  checks them and warns:
  - **Datacenter firewall disabled**: the VM's rules do nothing until it is enabled (web UI:
    Datacenter > Firewall > Options, or `pvesh set /cluster/firewall/options --enable 1`).
    Read the warning first: enabling it applies the datacenter `policy_in`, `DROP` by default,
    to the node itself, and without a rule that allows the web UI (8006/tcp) and SSH from your
    management network you can lose access to the node. Proxmox adds rules for the local
    network, but check that they cover your admin machine, and keep the console at hand.
  - **VM NIC without `firewall=1`**: the VM's rules do nothing until its NIC has it. The script
    prints the exact command, for example `qm set 102 --net0 <the NIC's current value>,firewall=1`.
    It only runs it with `--apply --set-nic-firewall`. A running VM's NIC reconnects briefly.
- `--undo --vmid N` puts the most recent backup of that VM back, with the same check and the same
  rollback. The file it replaces is kept as `<vmid>-<timestamp>-before-undo.fw`. Undoing the
  first `--apply` removes the file again.

Keep the Proxmox console open the first time. A wrong `--admin-from` cuts your SSH to the VM;
`--undo`, run on the node, brings it back.

Exit codes: 0 done, or the dry run worked; 2 bad arguments; 3 not a Proxmox node, or a tool is
missing; 4 refused (not root, VM not found, foreign rules without `--replace`, nothing to undo);
5 the change failed (a failed check is rolled back; a failed `qm set` leaves the written file in
place).

### What it does not cover

- **The router or ISP box.** Forward only the sensor ports there. This script does not replace
  that.
- **The nftables table inside the VM.** Keep it. The Proxmox firewall filters what leaves and
  enters the VM's network card; it cannot see a container reaching the VM's own admin SSH port,
  or one container reaching another. The table above stops those. The two layers cover
  different paths: install both.
- **A LAN that is reachable over global IPv6.** Proxmox can only match an address range, and
  this script cannot know which global prefix your LAN uses, so it drops `fc00::/7` only. If
  your LAN hosts have global IPv6 addresses, the VM can still open connections to them. Turn
  IPv6 off on the VM's network (or filter it at the router), or add a `OUT DROP` rule for your
  prefix by hand after running the script. The next run lists that rule as one it did not
  generate and refuses without `--replace`, which drops it: add it again afterwards.
- **Other networks on the same bridge.** Only the private ranges above are blocked. A public
  address that happens to sit on your LAN bridge is not.

### Verify

1. On the node: `pve-firewall status` says `enabled/running`, and the VM file is the one you
   expect (`cat /etc/pve/firewall/<vmid>.fw`).
2. From inside the VM, a new connection to another LAN machine must time out, for example
   `nc -zv -w3 <lan-machine> 22`, while DNS through the gateway and the internet still work.
3. From another LAN machine: the admin SSH answers from the `--admin-from` network and not from
   anywhere else, the dashboard port answers from the tunnel host only, and a sensor port still
   answers (`nc -zv -w3 <vm> <sensor port>`).
4. From the internet (or your phone on mobile data), the sensor ports still answer.

The `SUCKERPOT_PVE_ROOT` environment variable exists for the tests only (it moves `/etc/pve`
and `/root` to a scratch folder). Never set it.

## Also recommended

- Filter the dashboard port upstream (hypervisor or router firewall) so that only your
  reverse tunnel can reach it. Published Docker ports bypass ordinary host input rules. On
  Proxmox, [`proxmox-firewall.sh`](#proxmox-firewall) does it with `--private-port`.
- Keep the host's admin SSH on a port that is not a sensor port, and restrict it to your
  management network.

## Daily database backup

`scripts/backup-db.sh` dumps the database (custom format, TimescaleDB included) to
`./backups` (override with `BACKUP_DIR`), keeps the newest `BACKUP_KEEP` dumps (default 7) and
refuses to run when the disk has less than twice the last dump's size free. Dumps contain
captured attack data: keep them private and never commit them.

Restore with `just restore backups/FILE.dump` (it asks for confirmation, stops ingest and
the API, restores, runs the migrations and starts them again).

### systemd timer

`/etc/systemd/system/suckerpot-backup.service` (adjust the paths and the user, who must be able to run Docker):

```
[Unit]
Description=SuckerPot database backup

[Service]
Type=oneshot
User=CHANGE_ME
WorkingDirectory=/path/to/suckerpot
Environment=BACKUP_DIR=/path/to/backups
ExecStart=/path/to/suckerpot/scripts/backup-db.sh
```

`/etc/systemd/system/suckerpot-backup.timer`:

```
[Unit]
Description=Daily SuckerPot database backup

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it with `sudo systemctl enable --now suckerpot-backup.timer` and check it with
`systemctl list-timers suckerpot-backup.timer`.

### cron alternative

```
30 3 * * * cd /path/to/suckerpot && BACKUP_DIR=/path/to/backups scripts/backup-db.sh >> /path/to/backups/backup.log 2>&1
```

Copy the dumps off the machine (they are the only copy of your history), and test a
restore from time to time.
