# Deploy SuckerPot to the internet

This page is the checklist for putting SuckerPot on the internet. Follow the steps in order. Do not skip the firewall, the snapshot or the verification.

Read [Getting started](getting-started.md) first, and the [Security](SECURITY.md) page for the threat model.

```{admonition} Build status
:class: note

All twelve sensors are in `docker-compose.yml`: the SSH, Telnet, ADB, web, Docker API, Redis, MySQL, MSSQL, RDP, SMB, SIP and Synology sensors. The web and Synology sensors are still under security review. The seven M9 sensors and the Synology sensor (M20) are new: check them before you forward their ports. The dashboard has a login (M8). Keep it behind the tunnel and the upstream filter described below anyway: login is one layer, not the only one.
```

## Principles

- **Only the sensor ports face the internet.** Every other port stays private.
- **The dashboard is reached through a reverse tunnel.** The tunnel (for example cloudflared) connects from a machine you control to the dashboard port. The dashboard port is never open to everyone.
- **The host's own admin SSH runs on a port that no sensor uses.** It is never exposed to the internet.
- **Filters work upstream of the host.** Docker publishes ports in its own firewall rules, so a host `INPUT` rule does not protect a published port. Filter at the router or hypervisor, or in the `DOCKER-USER` chain.
- **Containers must not reach the host or the LAN.** The host firewall below enforces that.
- **A broken setup must fail closed.** Test the rules before you open the router.

## Go-live checklist

Do these in order. Tick each item only after you have checked it.

1. [ ] The host is a dedicated VM or machine (see the warning in [Getting started](getting-started.md)), with Docker and the Compose plugin up to date.
2. [ ] Generate fresh secrets (see [Secrets](#secrets)), the dashboard `SESSION_SECRET` and the [admin password hash](#dashboard-login) included. No `change-me` is left in `.env`.
3. [ ] Log out of any AI coding assistant, IDE sync and cloud CLI on the host. Revoke or rotate any git or API token that was used on the host. Check that no key sits in a file that other users can read.
4. [ ] Move the host's admin SSH to a port that no sensor or dashboard uses. Allow it only from your management network.
5. [ ] Run the [port guard](#port-guard) (`just ports`).
6. [ ] Install and verify the [host firewall](#host-firewall). If you use the VPN, set up [anonymous egress](#anonymous-egress-vpn) and run `just egress-check`.
7. [ ] Set [`DASHBOARD_BIND`](#dashboard-bind-and-upstream-filtering) and filter the dashboard port upstream.
8. [ ] Set [`API_ALLOWED_ORIGINS`](#behind-a-tls-terminating-tunnel) if the tunnel terminates TLS.
9. [ ] If you will turn on `FEEDS_ENABLED`, set `AUTH_TRUSTED_PROXIES` to the tunnel's address first. Without it every feed client looks like the tunnel, so the rate limits and the failure lockout are shared by everyone (see [Defend](defend.md)).
9. [ ] Set [`INDICATORS_IGNORE`](configuration.md) to your public IP (or CIDR block) and the host names you answer to, so your own addresses are never recorded as attack infrastructure. `API_ALLOWED_HOSTS` and `API_ALLOWED_ORIGINS` are added automatically.
10. [ ] Keep `API_ENABLE_DOCS=false`.
11. [ ] Start the stack and check it: `just up`, then `docker compose ps`. Run `just ssh-test`.
12. [ ] Take a [snapshot](#snapshot).
13. [ ] [Forward the ports](#forward-the-ports).
14. [ ] [Verify from outside](#verify-from-outside).

## Secrets

Every secret must be at least 24 characters long, and no two may be equal. The stack refuses to start otherwise, and names the variable (never its value).

Generate each one separately:

```bash
openssl rand -base64 32
```

| Secret | Purpose |
| --- | --- |
| `POSTGRES_PASSWORD` | Database owner. Schema changes only. |
| `POSTGRES_INGEST_PASSWORD` | Role `suckerpot_ingest` |
| `POSTGRES_API_PASSWORD` | Role `suckerpot_api` (read-only) |
| `REDIS_PASSWORD` | Redis `admin` user (operators only) |
| `REDIS_HEALTH_PASSWORD` | Redis `health` user |
| `REDIS_INGEST_PASSWORD` | Redis `ingest` user |
| `REDIS_SENSOR_SSH_PASSWORD` | Redis `sensor-ssh` user |
| `REDIS_SENSOR_RDP_PASSWORD` | Redis `sensor-rdp` user |
| `REDIS_SENSOR_TELNET_PASSWORD` | Redis `sensor-telnet` user |
| `REDIS_SENSOR_WEB_PASSWORD` | Redis `sensor-web` user |
| `REDIS_SENSOR_REDIS_PASSWORD` | Redis `sensor-redis` user |
| `REDIS_SENSOR_DOCKER_PASSWORD` | Redis `sensor-docker` user |
| `REDIS_SENSOR_MYSQL_PASSWORD` | Redis `sensor-mysql` user |
| `REDIS_SENSOR_MSSQL_PASSWORD` | Redis `sensor-mssql` user |
| `REDIS_SENSOR_ADB_PASSWORD` | Redis `sensor-adb` user |
| `REDIS_SENSOR_SMB_PASSWORD` | Redis `sensor-smb` user |
| `REDIS_SENSOR_SIP_PASSWORD` | Redis `sensor-sip` user |
| `REDIS_SENSOR_SYNOLOGY_PASSWORD` | Redis `sensor-synology` user |
| `REDIS_DEMO_PASSWORD` | Redis `demo` user |

Keep `.env` readable by the owner only (`chmod 600 .env`). Never commit it. `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` turns the checks off. It exists for CI only. Never set it on a real host.

### Rotating secrets

Rotate every secret before the first exposure, after any suspected leak, and from time to time. Passwords are read at container start, so each change needs a restart. Take a [snapshot](#snapshot) or a database dump first.

**Redis passwords** (`REDIS_*`):

1. Edit the values in `.env`.
2. Recreate everything that talks to Redis. Redis rewrites its ACL file on every start.

   ```bash
   docker compose up -d --force-recreate redis ingest sensor-ssh sensor-telnet sensor-adb sensor-web sensor-docker sensor-redis sensor-mysql sensor-mssql sensor-rdp sensor-smb sensor-sip sensor-synology
   ```

   Leave out any sensor you do not run. Events published while Redis restarts are dropped and counted, never buffered without limit.

**Ingest and API database passwords** (`POSTGRES_INGEST_PASSWORD`, `POSTGRES_API_PASSWORD`):

1. Edit the values in `.env`.
2. Run the migration step. It sets both role passwords on every run, from the environment, as SCRAM verifiers, so the clear text never reaches the database logs.

   ```bash
   docker compose run --rm migrate
   ```

3. Recreate the services that use the roles:

   ```bash
   docker compose up -d --force-recreate ingest api
   ```

**Database owner password** (`POSTGRES_PASSWORD`). This one is different: the database container only reads the variable when it first creates the data directory, so editing `.env` does not change the password inside the database. Change it in the database first, then in `.env`:

1. Open a `psql` shell as the owner and set the new password. `\password` hashes it on the client, so it is not written to the logs or to the shell history.

   ```bash
   just psql
   ```

   ```text
   suckerpot=# \password suckerpot
   ```

   Use the owner name from `POSTGRES_USER` if you changed it.
2. Put the same value in `.env` as `POSTGRES_PASSWORD`.
3. Check that the migration step still works: `docker compose run --rm migrate`.

If you edit `.env` first, `migrate` cannot log in and the stack will not start. Fix it by running `\password` with the old value in place.

## Dashboard login

The dashboard has one admin account. Set it up before the first start:

1. Make the password hash. It prompts twice without echo:

   ```bash
   docker compose run --rm api python -m api.hashpw
   ```

2. Put the result in `.env` in **single quotes**, because it contains `$`: `ADMIN_PASSWORD_HASH='$argon2id$...'`. Set `ADMIN_USERNAME` if you do not want `admin`.
3. Set `SESSION_SECRET` to at least 32 random bytes: `openssl rand -base64 48`.
4. Start the stack. `just up` (and `docker compose up`) refuse to start at all while `ADMIN_PASSWORD_HASH` or `SESSION_SECRET` is missing from `.env`, and the API refuses a weak hash or secret.

To change the password, make a new hash and put it in `.env`, then run `docker compose up -d api`. Changing the hash signs every session out. Rotating `SESSION_SECRET` does the same, and so does every restart of the API: the signing key includes a random value created at each start, so you sign in again after each restart. The login is limited to 5 attempts per address and 30 in total per minute, and only one password check runs at a time. The API must run as a single worker (the default).

Set `API_ALLOWED_HOSTS` (or `API_ALLOWED_ORIGINS`) to the host name you publish. With both empty the API accepts any `Host` header and logs a warning.

`API_AUTH_DISABLED=true` turns authentication off, but only together with `SUCKERPOT_DEMO=1`, and only the test overlay `docker-compose.ci.yml` (`just up-test`) sets both. The normal `docker-compose.yml` does not. Never run the test overlay on a host that other people can reach.

See [API](api.md#authentication) for the cookie and CSRF details.

## Port guard

`scripts/check-ports.sh` (`just ports`) refuses a port layout that would expose the wrong thing. It runs automatically before `just up` and `just config`, and in CI. It fails when:

- `DASHBOARD_PORT` is 22, 23, 80, 443 or 3389;
- two of `DASHBOARD_PORT` and the `*_HOST_PORT` variables are equal;
- one of them equals `ADMIN_SSH_PORT`, the optional variable in `.env` that holds the port of the host's own admin SSH daemon;
- a value is not a number between 1 and 65535.

The dashboard port must never be a sensor port. The script refuses the five classic service ports listed above. It also compares the dashboard port with every `*_HOST_PORT`, defaults included, and fails on a clash. Keep the dashboard on a port that no sensor uses. The default, 8443, is safe.

Set `ADMIN_SSH_PORT` in `.env`. It is used only by this script. If you start the stack with plain `docker compose up`, run `just ports` yourself first.

## Host firewall

Docker's network settings remove the containers' route to the internet, but they do not stop a compromised container from opening connections to the host itself (for example its admin SSH port) or to other machines on your LAN. The nftables table `inet suckerpot_host` closes that gap. The full reference, with every rule, is `scripts/host/README.md`.

There are two templates, with no address from any real network. They match Docker networks by interface name, not by address, so they do not depend on the address pools Docker picks.

| Template | For | Values to set |
| --- | --- | --- |
| `scripts/host/firewall.nft` | A full install (dashboard, optional VPN) | Admin SSH port, dashboard port, WireGuard endpoint |
| `scripts/host/firewall-participant.nft` | A participant node (no dashboard, no VPN) | Admin SSH port only |

### Render and install it

```bash
# Full install (add --vpn-endpoint <VPN_WG_ENDPOINT_IP>:<VPN_WG_ENDPOINT_PORT> with the egress profile):
scripts/host/render-firewall.sh --full --admin-ssh-port <port> --dashboard-port <DASHBOARD_PORT> --out ~/suckerpot-firewall.nft
# Participant node:
scripts/host/render-firewall.sh --participant --admin-ssh-port <port> --out ~/suckerpot-firewall.nft

scripts/host/install-firewall.sh ~/suckerpot-firewall.nft
```

`render-firewall.sh` needs no root and changes nothing: it fills in the values, reads the resolvers hubproxy's DNS goes to, and writes the file with mode 0600. It refuses (exit 2) when a host bridge that is not Docker's matches the rules' `br-*` or `sp-*` wildcard (a VM or LAN bridge called `br-lan`, say): the drops would hit it, and an admin SSH that arrives through it would be locked out. Rename the bridge, or pass `--allow-bridge NAME` when you are sure. `install-firewall.sh` runs itself through `sudo`, copies the file to a root-owned temporary file next to `/etc/suckerpot-firewall.nft`, refuses the copy if it holds a placeholder or `nft -c` refuses it, renames it into place, installs the dedicated `suckerpot-firewall.service` unit, loads it and checks that the table is there. Keep the rendered file out of git: it holds your admin port.

```{warning}
Do **not** use the stock `nftables` service for this. On Debian and Ubuntu, `/etc/nftables.conf` starts with `flush ruleset`. Starting that service on a running host wipes Docker's own rules (NAT and published ports) until Docker restarts. The dedicated unit only touches its own table, so it never does that.
```

### What each rule does

| Rule | Effect |
| --- | --- |
| `input`, from `sp-ingress` and `sp-dashboard` | Containers on the sensor network and the dashboard network can send the host nothing but replies (new, invalid and untracked packets are dropped). |
| `input`, from the internal networks (`sp-s-*`, `sp-backend`, `sp-tools`, `sp-egress`, `sp-samples`, `sp-hubproxy`) | Nor can these. On Docker Engine 28 or later the host has no address on these bridges at all (see below); the rule covers older engines. |
| `input`, from `docker0`, `br-*` and `sp-*`, to the admin SSH port (and, in full mode, the dashboard port) | No container on any Docker network can reach them. |
| `forward`, from `sp-ingress` and `sp-dashboard` | Everything that is not a reply is dropped: no LAN scanning, no outbound traffic, not even a one-way SYN or UDP packet, no traffic between sensors. Replies to inbound connections still go out. |
| `input`, from `sp-vpn` | The `vpn` container can send the host nothing but replies. |
| `forward`, from `sp-vpn` | The only new connection allowed is UDP to the WireGuard endpoint. Everything else is dropped, so the kill switch holds even if the container's own firewall fails. A participant without a VPN allows nothing but replies. |
| `forward`, from `sp-hubgate` (participant mode) | `hubproxy` may open TCP 443 to public unicast addresses and UDP 53 to the host's upstream resolvers (`HUBGATE_DNS`), nothing else: private, CGNAT, loopback, link-local, multicast and documentation ranges are dropped, and so is anything else whatever its connection state. |
| `forward`, IPv6 from `sp-*` | Dropped. The networks have no IPv6. |
| `forward`, internal bridges (`sp-s-*`, `sp-backend`, `sp-hubproxy`, ...) | No rule but the IPv6 drop: a sensor and Redis, ingest and the database, ingest and hubproxy talk across these bridges, and Docker keeps them internal. |

Nothing here affects traffic from the internet to the published sensor ports, or your own admin SSH from the LAN. Loopback and established connections are always accepted. Docker's own rules are left alone: the table only adds drops, at a priority ahead of Docker's chains.

**Why DNS from `sp-hubgate` is allowed, and only that far.** Docker's embedded resolver forwards each query of `hubproxy` from the container's own network namespace, so the query crosses `sp-hubgate` towards the upstream servers Docker read from the host (`/etc/resolv.conf`, or `/run/systemd/resolve/resolv.conf` behind the systemd-resolved stub `127.0.0.53`). A loopback upstream is queried from the host's namespace instead and needs no rule. The renderer lists exactly those upstream servers; pass `--dns IP` if `/etc/docker/daemon.json` sets its own. Render and install again when your resolvers change: a stale list fails safe (the node cannot resolve the hub and stays idle).

**Isolated gateways need Docker Engine 28 or later.** Every internal network sets `com.docker.network.bridge.gateway_mode_ipv4: isolated`, so the host keeps no address on the bridge and a compromised container there has no host address to connect to. On an older engine this isolation does not apply, and only the host firewall protects the host. Upgrade Docker.

**Existing installs.** The networks' bridge names and options changed, and Docker cannot change them on a network that already exists. Run `docker compose down`, then `just up`: the networks are created again, and the data volumes (external) are kept.

### Verify

1. After starting the stack, list the table. Counters on the `drop` rules stay at 0 in normal operation.

   ```bash
   sudo nft list table inet suckerpot_host
   ```

   An error means the firewall is not active. Check this after every reboot.
2. From inside a sensor, a new connection to the host must fail. Replace the placeholders: the gateway is the `.1` address of the `sp-ingress` subnet.

   ```bash
   docker run --rm --network container:<sensor-container> busybox nc -w2 -zv <gateway> <admin-ssh-port>
   ```

   It must time out, and the `input` drop counter must go up.
3. From the internet, or from another machine, the sensor ports must still answer.
4. The host listens on each sensor port for IPv4 only. `ss -tlnp | grep ':22 '` shows `0.0.0.0:22` and no `[::]:22`.
5. The internal bridges have no host address: `ip -4 addr show sp-backend` prints no `inet` line.

### Roll back

```bash
scripts/host/install-firewall.sh --uninstall
```

or, for the running session only, `sudo nft delete table inet suckerpot_host`.

Without the table, a compromised sensor can reach the host's admin SSH port. Do not forward ports while it is off.

## Anonymous egress (VPN)

The stack's own outbound traffic (GeoIP downloads, reputation and intel lookups, CVE feeds, alerts and the payload collector) leaves through a WireGuard tunnel in the `vpn` service, never from your own address. Sensors and the dashboard keep their current paths, and the host itself is unchanged. Without the `egress` profile these features stay idle. Settings shows "no egress".

You need a WireGuard configuration from any provider that gives you one: an interface private key, interface addresses, the server's public key, and the server address and UDP port.

### 1. Set the variables

Copy the values into `.env` (never into a tracked file). Split the server address in two:

```bash
COMPOSE_PROFILES=egress
VPN_WG_PRIVATE_KEY=<interface private key>
VPN_WG_PEER_PUBLIC_KEY=<server public key>
VPN_WG_ADDRESSES=<interface address, a /32 from the provider>
VPN_WG_DNS=<provider DNS address>
VPN_WG_ENDPOINT_IP=<server IPv4 address, e.g. 203.0.113.10>
VPN_WG_ENDPOINT_PORT=<server UDP port, e.g. 51820>
EGRESS_PROXY_PASSWORD=<at least 24 random characters>
POSTGRES_COLLECTOR_PASSWORD=<at least 24 random characters>
POSTGRES_ANALYZER_PASSWORD=<at least 24 random characters>
```

Generate the three passwords like the others (`openssl rand -hex 24`), all different. `just up` and `just config` run `scripts/check-vpn-env.sh`, which names any missing or invalid variable and never prints a value.

The exit address of the tunnel must be inside the expected network. By default that is the /24 of the server address. If your provider exits elsewhere, the gate stays closed with `ip_not_allowed`. Read the observed exit address in Settings (one click reveals it) and set `EGRESS_ALLOWED_CIDRS`.

### 2. Apply the host firewall rules

The kill switch has two layers. The second one is on the host. Render the table again with the WireGuard endpoint (see [Host firewall](#host-firewall)), then install it:

```bash
scripts/host/render-firewall.sh --full --admin-ssh-port <port> --dashboard-port <DASHBOARD_PORT> \
  --vpn-endpoint <VPN_WG_ENDPOINT_IP>:<VPN_WG_ENDPOINT_PORT> --out ~/suckerpot-firewall.nft
scripts/host/install-firewall.sh ~/suckerpot-firewall.nft
sudo nft list table inet suckerpot_host         # look for the sp-vpn, sp-egress and sp-samples rules
```

### 3. Start it and check it

```bash
just up                  # waits for healthy; vpn, collector and analyzer start with the profile
just guardrails          # static test of the compose layout (no stack needed)
just egress-check        # live proof, see below
```

`just egress-check` prints PASS or FAIL per line and exits non-zero on any FAIL. It checks that `ingest`, `collector` and `analyzer` cannot reach a public address directly or resolve external names, that the gate is open, that the proxy refuses the bridge gateway and loopback names, and then takes the tunnel down to prove that nothing leaves. It briefly stops `vpn`, so run it when a pause of outbound lookups does not matter. For read-only checks that leave the tunnel alone, run `scripts/egress-check.sh --quick`. It never prints the exit address.

After it, `sudo nft list table inet suckerpot_host` should show the `sp-vpn` accept rule counting the handshake packets and the drop counters at 0.

### 4. Turn the collector on

Set `COLLECTOR_ENABLED=true` and restart. The collector then fetches captured download URLs through the tunnel into the `quarantine` volume, and the analyzer examines them. Files are never executed. Settings has an Egress card with the gate state, the collector quota and the quarantine use. See [Security](SECURITY.md#anonymous-egress-m21) for the guarantees.

### If the tunnel is down

Nothing leaves. Lookups wait with a reason in Settings, events are still stored, and ingest stays healthy. The tunnel restarts itself. Check `docker compose logs vpn`.

## Anonymous reporting

The stack prepares abuse reports and CERT exports. By default it sends nothing: you read each report and send it yourself, from your own anonymous mailbox, behind your VPN (the To send queue helps). Optional SMTP sending can be set up in Settings > Reporting > Sending; it is off by default and only ever leaves through the VPN. It needs the [anonymous egress](#anonymous-egress-vpn) (RDAP lookups go through the tunnel).

### 1. Turn the worker on

Set `ABUSE_REPORTS_ENABLED=true` in `.env` and restart `ingest`. Tuning variables are in [Configuration](configuration.md#anonymous-reporting-m22). Reports stay locked (`no_self_address`) until the stack knows which address it is guarding.

### 2. Fill Settings > Reporting (admin)

Add a reply contact (an alias that is not on one of your own domains): it is the only required setting. Until it is set, rendering answers `settings_incomplete`, and a report cannot be marked reviewed. The introduction, closing text, note, signature, subject template and X-ARF user agent are optional. The project ships no wording, because shipped text lives in a public repo and could be searched. Leave them empty to send only the facts: an empty part is left out, an empty subject becomes `Abuse report for <address>` and an empty X-ARF user agent becomes `Mozilla/5.0`. If you write your own, make it yours.

### 3. Confirm the self terms

The worker learns the address and names of the monitored system from traffic (an address is stored only when two or more distinct /24 or /48 networks used it, and counts only while seen in the last 72 hours). Learned terms start inactive. Open the "Never in a report" list in Settings > Reporting, check each one and confirm it. If your address just changed, add it by hand: manual terms are active at once.

### 4. Check it

```bash
just abuse-guard-check
```

It renders every open report in every format and the last 7 days of STIX and MISP, and prints PASS or FAIL per format with reason codes only. A non-zero exit means something would leak, or no address is confirmed yet. Run it after changing settings or self terms, and before the first real report.

### 5. Send by hand

Open a report at Defend > Abuse reports, check the identity card, copy To, Subject and Body (or download `report.txt` and `evidence.csv` to attach), send it from your alias, then use "Mark sent". Sample bundles are uploaded by hand to the repository you choose. You can also let the dashboard send the mail for you, as described in [Sending reports](#sending-reports).

### Sending reports

By default you send each report yourself. The dashboard can also send it through your VPN, once you save an SMTP profile. Both paths need the [anonymous egress](#anonymous-egress-vpn) to be up.

**The To send queue.** Open Defend > Abuse reports and choose To send. It walks through the ready reports, oldest first, one at a time. For each report it shows the recipient, the subject and the body, with copy buttons. "Open in mail app" opens a `mailto:` link with the recipient and the subject. The full plain-text body is copied to the clipboard on every click, so a long report is one paste away. "Sent, next" marks the report as sent and opens the next one. Check the sender address in your mail app before you send, and connect that mailbox through your VPN.

**The three modes.** Pick the mode in Settings > Reporting > Sending:

| Mode | What happens |
| --- | --- |
| `off` (default) | Nothing is sent. Use the To send queue. |
| `click` | A "Send now" button sends a ready report, after a confirmation. |
| `auto` | Ready reports are sent after a hold time (default 60 minutes, 10 to 1440). While a report waits, the page shows the time it will go, with a Cancel button. At most `daily_cap` reports are sent per UTC day (default 20, 1 to 200). |

Demo reports are never sent. A report that fails the identity guard, or that has no reply contact, is never sent in any mode. "Send a test" sends a short neutral message to the sender address itself, so you can check the profile first.

**Setting up SMTP.** You need an SMTP server that accepts your login with STARTTLS (usually port 587) or with SMTPS (usually port 465). Enter the server's DNS name, not an IP address, with the port, the security, the login name, the sender address and the password. Saving the profile asks for your dashboard password again. The SMTP password is stored encrypted. The dashboard never shows it again. The API reference is in [Sending abuse reports](api.md#sending-abuse-reports-m25).

**Free Proton has no SMTP.** Proton gives SMTP access only with a paid plan. You also need a custom domain on that plan, and an SMTP token from Proton's settings. The token is the SMTP password. Free Proton addresses have no SMTP access at all, so keep the mode at `off` and use the To send queue with them. The Proton preset in Settings fills in the server and the port for you.

**Mail only leaves through the VPN.** The API has no route out and never connects to a mail server. Ingest sends the mail through the VPN proxy, with the certificate always checked. Before each send, ingest rebuilds the complete message, headers included, and runs the identity guard on it again. While the VPN gate is closed, nothing is sent: a send waits, and a test fails after two minutes.

## Host safeguards

Two optional or recommended host settings protect the host from floods. The repository never applies them for you. Run them yourself, as the host owner.

### Connection tracking (recommended)

The kernel keeps a table of open connections. Scans and floods (many short TCP connections, spoofed UDP to SIP) can fill it. When it is full, the kernel drops **new** connections for every service on the host, including your admin SSH port. The file `scripts/host/sysctl-suckerpot.conf` raises the table size and shortens the timeouts of half-open and UDP entries. Install it with:

```bash
sudo install -m 0644 <repo>/scripts/host/sysctl-suckerpot.conf /etc/sysctl.d/90-suckerpot.conf
sudo sysctl --system
sysctl net.netfilter.nf_conntrack_max      # verify
```

Replace `<repo>` with the path of your clone, for example the folder where you ran `git clone`. The `sysctl --system` command reloads all sysctl files, so it applies the other files in `/etc/sysctl.d/` too.

### Aggregate cap for the sensors (optional)

Each container already has its own limits in `docker-compose.yml`. The optional file `scripts/host/suckerpot-sensors.slice` caps their **sum**, so that a flood on every sensor at once cannot starve Redis, the database, ingest or the API. It sets a memory ceiling of 1536 MB, no swap and a CPU quota of 120 %. Nothing uses it by default.

1. Check the Docker cgroup driver. The slice only works with the `systemd` driver: `docker info | grep -i 'cgroup driver'`. If the driver is `cgroupfs`, skip this section.
2. Install the slice unit and reload systemd:

   ```bash
   sudo install -m 0644 <repo>/scripts/host/suckerpot-sensors.slice /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. In `docker-compose.yml`, add `cgroup_parent: suckerpot-sensors.slice` to each `sensor-*` service, then recreate the sensors. Only the host owner should make this change.

### Optional SIP rate limit in the firewall

The firewall template has a commented-out rule that rate-limits new SIP flows on UDP 5060 before they reach the sensor. Read the comment in `scripts/host/firewall.nft` before you enable it. Keep it off until you have measured your normal SIP traffic.

## Dashboard bind and upstream filtering

`DASHBOARD_BIND` is the host address the dashboard port binds to.

| Setup | `DASHBOARD_BIND` | Filter |
| --- | --- | --- |
| The tunnel runs on the same host | `127.0.0.1` (default) | None needed. The port is reachable from the host only. |
| The tunnel runs on another machine | The host's LAN address | Filter the port **upstream**: accept it only from the tunnel's address, drop everything else. |

A host `INPUT` rule is not enough, because Docker publishes the port in its own rules. Filter at the router or hypervisor firewall, or in the `DOCKER-USER` chain. Example rules, with documentation addresses only:

| Rule | Source | Port | Action |
| --- | --- | --- | --- |
| 1 | `198.51.100.10` (tunnel machine) | 8443/tcp | Accept |
| 2 | any | 8443/tcp | Drop |

Test from a machine that is not the tunnel machine: the dashboard port must not answer.

This matters most if you forward **all** ports to the host (a DMZ). A DMZ also forwards the dashboard port. Put the upstream filter in place first.

## Behind a TLS-terminating tunnel

A tunnel such as cloudflared usually terminates TLS and forwards plain HTTP to the dashboard port. The browser then loads the page from `https://dash.example.com` while the API sees a plain-HTTP request with another `Host`. The live WebSocket checks the `Origin` header against the request's host, so it would be refused (close code `1008`), and the dashboard would fall back to polling.

Fix it by listing the public origin in `.env`:

```text
API_ALLOWED_ORIGINS=https://dash.example.com
```

Use full origins (scheme and host, no path), comma-separated. Then restart the API: `docker compose up -d api`. Same-host origins are always accepted, so local use keeps working.

Also set the tunnel's own access policy (for example Cloudflare Access) in front of the dashboard, as a second layer in front of the dashboard login. If you give a colleague an account (Settings > Users), **add their email address to the Cloudflare Access policy as well**, or they never reach the sign-in page.

Keep `COOKIE_SECURE=true` (the default). The browser talks HTTPS to the tunnel, so the `__Host-` cookies work, even though the tunnel talks plain HTTP to the API. Production must be served over HTTPS. `COOKIE_SECURE=false` (plain cookie names, no `Secure` flag) is for local development over HTTP only. Without the full origin in `API_ALLOWED_ORIGINS`, **login fails with 403** and the live feed is refused, so set it before you try to sign in. Also set `API_ALLOWED_HOSTS` to the tunnel's host name, or the API accepts any `Host`.

Set `AUTH_TRUSTED_PROXIES` to the CIDR range of the machine that runs the tunnel. Then the API takes the client address from the tunnel's `CF-Connecting-IP` header, but only for requests that really come from that range. Without it, every login attempt appears to come from the tunnel, and the per-address login limit becomes one limit for everybody.

## Data volumes and backups

### The volumes are external

Every data volume (`db-data`, `redis-data`, `quarantine`, `ssh-hostkeys`, `vpn-config`, `geoip-data`, `backups` and the sensor data volumes) is declared `external: true` in `docker-compose.yml`, named `${SUCKERPOT_VOLUME_PREFIX}_<volume>` (live: `suckerpot_<volume>`). `SUCKERPOT_VOLUME_PREFIX` is a **required** variable from `.env` (`.env.example` ships it commented out: uncomment it as `SUCKERPOT_VOLUME_PREFIX=suckerpot` in the live `.env` only): a checkout without `.env` cannot run any compose command, so it can never mount the live data. Compose fills in `COMPOSE_PROJECT_NAME` from the folder name on its own, which is why a separate variable is needed. When you upgrade an existing install, add `SUCKERPOT_VOLUME_PREFIX=suckerpot` to `.env` first. Compose never creates, owns or deletes an external volume, so `docker compose down -v`, a different project name or a checkout in another folder cannot wipe the live data. (A second stack that mounts the same volumes is still a bad idea: never run two databases on one data directory.)

`just up` runs `scripts/ensure-volumes.sh` first. It creates the missing volumes (`docker volume create` is idempotent) and never touches the data of an existing one. Plain `docker compose up` on a host where they do not exist fails with "external volume not found" instead of starting empty.

The test overlays (`docker-compose.it.yml` for `just test-integration`, `docker-compose.ci.yml` for CI and `just up-test`) turn every volume back into a project-local one with an explicit name `test-<prefix>_<volume>`, which can never equal a live `<prefix>_<volume>` name, even when a test is given the live project name. The live recipes also refuse to run from a linked git worktree, and `just restore` restores the dump into a side database first and swaps it in only when that worked. Guardrail tests (`just guardrails`, in CI) assert that no service of either overlay mounts an external or `suckerpot_*` volume, and that the base file's data volumes are external. `just test-integration` also refuses to run unless its project name contains `-it-`, and `just up-test` never uses the live project name. Never copy `.env.example` to make a test `.env`: its project name and volume prefix are the live ones. The live recipes (`up`, `down`, `ps`, `logs`, `backup*`, `restore`, `psql`, `demo`, `egress-check`) refuse to run unless both variables are set, and `just test-integration`, `just up-test` and the CI job set their own throwaway values.

### Missing database volume

If `suckerpot_db-data` is missing but `suckerpot_backups` holds dumps, `just up` stops with a message instead of silently creating an empty database. Then either restore (create the volumes with `scripts/ensure-volumes.sh --force-empty`, start only the database with `docker compose up -d --wait db`, then `just restore latest`), or start from scratch on purpose with `just up --force-empty` (or `SUCKERPOT_ALLOW_EMPTY_DB=1`).

### Daily backups

The `backup` service (backend network only, no route out, non-root, read-only) runs `pg_dump -Fc` (TimescaleDB data included) with the database owner account, once a day, into the `suckerpot_backups` volume. It also dumps at start when the newest dump is older than 24 hours (a failed dump is retried after 30 s, then 60 s, 120 s and so on, never later than the hourly check), keeps the newest 7 (`BACKUP_KEEP`) plus the newest dump of each of the last 4 weeks and 3 months. It needs 2 GiB plus twice the last dump free (it prunes to 6 daily dumps first when tight, and fails if that is not enough). A dump smaller than half of the previous one is kept but **nothing is pruned** and the service turns unhealthy (marker file `/backups/.shrunk`: look at the database, then remove it). The healthcheck also fails when no dump younger than 26 hours exists, so `docker compose ps` shows a failing backup. One backup runs at a time (`just backup` and the daily loop share a lock). The test overlays keep this service behind the profile `backup`, so `just up-test` and CI never start it.

```bash
just backup      # dump now into the backups volume
just backups     # list the dumps
just backup-host # dump into the host folder ./backups (BACKUP_DIR, BACKUP_KEEP), for copies off the machine
```

The quarantine volume is not backed up: it holds captured malware that can be fetched again.

A volume lives on the same disk as the data it protects. For a real safeguard, copy dumps off the machine to storage you control (for example `just backup-host`, then copy `./backups`), and keep Proxmox snapshots too.

To restore:

```bash
just restore latest                          # newest dump of the backups volume
just restore volume:suckerpot-20261101T020000Z.dump
just restore backups/suckerpot-20261024T020000Z.dump   # a dump file on the host
```

This **replaces the whole database**, but only once the dump has restored cleanly. The script asks you to type `restore` (or pass `--yes`), prints the size of the dump, and then:

1. checks the dump with `pg_restore -l`;
2. restores it into a **side database** (`<db>_restore`) while ingest and the API keep running on the live database. A leftover side database of an earlier failed run is dropped first;
3. checks the side database: `alembic_version` has exactly one row and the `events` hypertable exists. If any step fails, it drops the side database, says that nothing was changed and exits with an error. The live database and the services are untouched;
4. only now stops ingest, the API and the backup service, refuses new connections, terminates the remaining ones (TimescaleDB keeps a background worker connected to every database with the extension) and swaps the two databases with one transaction of `ALTER DATABASE ... RENAME`: the live one becomes `<db>_before_restore`, the restored one becomes the live one. The restore refuses to start while a `<db>_before_restore` exists (see below);
5. restarts the TimescaleDB background jobs on the restored database (a renamed database loses its scheduler), runs the migrations (which re-apply the role grants), starts ingest, the API and the backup service and waits until they are healthy. Then it drops `<db>_before_restore`, unless you pass `--keep-previous`.

Sensors keep running during a restore: their events wait in Redis and are ingested afterwards.

**Disk space.** Until the swap, the side database lives next to the live one, so the restore needs room for a second copy of the database (and `--keep-previous` keeps the old one until you drop it by hand). Check `docker system df` and the size of the `db-data` volume first.

**A kept previous database blocks the next restore.** After `--keep-previous`, or after a restore that failed after the swap, `<db>_before_restore` may be the only copy of the data it replaced. The next restore refuses to start while it exists, changes nothing and prints this command. Drop it by hand once you no longer need it (replace `suckerpot` with your `POSTGRES_DB`):

```bash
docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE \"suckerpot_before_restore\" WITH (FORCE)"'
```

A database name longer than 47 characters is refused, because PostgreSQL cuts names at 63 bytes.

**If the migration or the start fails after the swap**, both databases stay in place and the script prints the exact commands to swap back. They are:

```bash
docker compose stop ingest api backup
docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d postgres' <<'SQL'
ALTER DATABASE "suckerpot" ALLOW_CONNECTIONS false;
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'suckerpot' AND pid <> pg_backend_pid();
ALTER DATABASE "suckerpot" RENAME TO "suckerpot_bad_1";
ALTER DATABASE "suckerpot_before_restore" RENAME TO "suckerpot";
ALTER DATABASE "suckerpot" ALLOW_CONNECTIONS true;
SQL
docker compose exec -T db sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -v ON_ERROR_STOP=1 -h 127.0.0.1 -U "$POSTGRES_USER" -d suckerpot -c "SELECT timescaledb_post_restore()"'
docker compose up -d --wait ingest api backup
```

Replace `suckerpot` with your `POSTGRES_DB`. The last `psql` call starts the TimescaleDB background jobs on the database you just renamed. The same commands work later if you used `--keep-previous` and want to go back.

`just test-backup-restore` (and the CI job `backup-restore`) proves the whole path on a throwaway project: it dumps a known data set with the `backup` service, changes the data, restores the dump with `restore-db.sh`, checks the row counts, the migration head, the role grants and the TimescaleDB jobs, and then checks that a truncated dump is refused and leaves the live database alone. It refuses to run unless `COMPOSE_PROJECT_NAME` is a throwaway name and `SUCKERPOT_VOLUME_PREFIX` equals it.

### Deleting data on purpose

Nothing in the stack deletes a live volume. To wipe one deliberately, stop the stack (`just down`), then remove the volume by name, for example `docker volume rm suckerpot_db-data`. Do it only after `just backup-host` and a check that the copy is readable. Never run `docker volume prune` or `docker system prune --volumes` on this host.

```{warning}
Dumps contain captured attack data: attacker addresses, credentials and payload fragments. Keep them private. Never commit them, never put them in a public place, and copy them off the machine only to storage that you control.
```

## Snapshot

Take a snapshot of the VM, or a full image of the machine, in a clean state **after** the stack works and **before** the first exposure. If the host is compromised, you can restore a clean state in minutes. Name it clearly, for example `clean-before-internet`. Update it when you change the setup.

## Forward the ports

Forward the sensor ports to the host, then verify each one. Forward only the ports of sensors that are actually running. Each row is one host port. The variable is the one in `.env` that sets it.

| Sensor | Port | Protocol | Variable |
| --- | --- | --- | --- |
| SSH | 22 | TCP | `SSH_HOST_PORT` |
| Telnet | 23 | TCP | `TELNET_HOST_PORT` |
| ADB | 5555 | TCP | `ADB_HOST_PORT` |
| Web | 80 and 443 | TCP | `HTTP_HOST_PORT` and `HTTPS_HOST_PORT` |
| Docker API | 2375 | TCP | `DOCKER_HOST_PORT` |
| Redis | 6379 | TCP | `REDIS_HOST_PORT` |
| MySQL | 3306 | TCP | `MYSQL_HOST_PORT` |
| MSSQL | 1433 | TCP | `MSSQL_HOST_PORT` |
| RDP | 3389 | TCP | `RDP_HOST_PORT` |
| SMB | 445 | TCP | `SMB_HOST_PORT` |
| SIP | 5060 | UDP **and** TCP | `SIP_HOST_PORT` |
| Synology DSM | 5000 and 5001 | TCP | `SYNOLOGY_HTTP_HOST_PORT` and `SYNOLOGY_HTTPS_HOST_PORT` |

The dashboard port (`DASHBOARD_PORT`, 8443 by default) and the admin SSH port are **never** forwarded. Keep them off the list.

The host must not run its own service on any of these ports. For example, a Samba server on 445 or a MySQL server on 3306 would collide with the sensor.

```{warning}
A DMZ forwards **every** port to the host, including the dashboard port and the admin SSH port. Use one only after the host firewall and the upstream dashboard filter are in place. If your router can forward only the ports you need, prefer that.
```

### SIP needs the real source address

The SIP sensor answers each UDP datagram to the address that sent it. Its per-source limits and its verification of the source depend on that address being the attacker's. Docker can break this. For a published port, Docker uses NAT (iptables), which keeps the source address. But when the userland proxy (`docker-proxy`) handles the port, the sensor sees the proxy's address for every datagram. Then every attacker looks like one source.

The userland proxy is on by default and applies to all published ports. To keep the source addresses for SIP, the host owner must turn it off:

1. Add `"userland-proxy": false` to `/etc/docker/daemon.json`. Keep any other keys in the file.
2. Restart the Docker daemon. This stops the containers unless `live-restore` is set, so plan a short window.
3. Test from a machine outside your network. Send one SIP `OPTIONS` request to UDP 5060 and check the `connect` event in the dashboard. Its source address must be the address of the test machine. It must never be a private address of the Docker bridge.

With the proxy off, a connection from the host to its own published ports may stop working. The internet path is the one that matters, and it uses NAT.

## Verify from outside

From a machine outside your network:

- [ ] The sensor ports answer (a connection to port 22 gets an OpenSSH banner, and a connection to 6379 gets a Redis reply).
- [ ] UDP 5060 answers an OPTIONS request, and the SIP `connect` event shows the real source address.
- [ ] The dashboard port does not answer.
- [ ] The admin SSH port does not answer.
- [ ] The tunnel URL reaches the dashboard, and the Live indicator reads "Live" without the "Polling" note.

Then check the logs for new events:

```bash
docker compose logs --tail=50 ingest
```

## Upgrading

Use `just update`. It takes a database dump first, checks the image signatures and records how to go back. `just rollback` puts the previous state back. See [Updates and rollback](updates.md).

Migrations run on start. Read the [changelog](https://github.com/selfhostr/suckerpot/blob/main/CHANGELOG.md) first for anything that needs a change in `.env`.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| After an upgrade the browser shows only the dark background. | The browser kept old app files. Close every tab of the dashboard, then hard-reload with `Ctrl+Shift+R`. |
| The dashboard is very slow through a tunnel, but the server is idle. | Usually the uplink is saturated. Compare a ping to your gateway with a ping to an internet host (for example `ping -c 10 192.0.2.1` for the gateway and `ping -c 10 example.com`). High loss or delay on both points at the uplink, not at SuckerPot. |
| The first image build fails with a DNS error. | A transient name-resolution failure while pulling a base image or package. Run `docker compose build` again. |

## After go-live

- Watch the disk usage. Attackers can send a lot of data. Check it every day for the first week.
- Check `docker compose ps` for restarting sensors. A sensor that restarts often points at an attack that hits a limit.
- Keep the host updated. Apply security updates regularly.
- Keep the snapshot up to date when you change the setup.
- Read the logs of the admin SSH service, not only of SuckerPot.

## Planned

- API rate limits beyond the login limits (M8).
