# Install SuckerPot

This page shows how to install SuckerPot with one command. The installer checks the machine, asks a few questions, creates every secret on this host and starts the stack. The dashboard then walks you through the rest.

The manual path, with no installer, is still described in [Getting started](getting-started.md#manual-setup).

```{warning}
SuckerPot is built to be attacked. Install it on a dedicated machine that holds nothing else you care about. Read [Getting started](getting-started.md#read-this-first) first.
```

## Requirements

| Item | Needed | Notes |
| --- | --- | --- |
| Operating system | Linux, on `x86_64` (amd64) or `aarch64` (arm64) | A VM or a small server is fine. See [low-memory hosts](#low-memory-hosts) for small machines. |
| Shell tools | Bash 4 or newer, `git`, `curl`, and the usual GNU tools (`awk`, `sed`, `tr`, `base64`) | `ss` (from iproute2) is used for the port check. Without it the check is skipped. |
| Docker Engine | 24 or newer, 28 or newer recommended | Before 28 the internal networks are not isolated from the host (the installer warns). Your user must run `docker` without `sudo`. The installer tells you how to add the group if not. |
| Docker Compose | v2.24 or newer | The Compose plugin (`docker compose version` must work). |
| Memory | 2 GiB minimum | Use [low-memory mode](#low-memory-hosts) below 6 GiB. A machine sold as "2 GB" reports about 1.9 GiB and is accepted: it runs the low-memory setup, so add swap. The installer accepts 1.75 GiB (1,835,008 kB) or more; below that it refuses a full install and points to `--participant --lite`. |
| Free disk | 15 GiB minimum under Docker's data folder | The installer warns below 30 GiB. Logs and captured payloads need room. |
| Outbound access | Yes, for the install | The host pulls images from the registry and checks their signatures. This traffic uses the host's own address. See [Anonymous egress](#what-leaves-this-machine). |
| Router | Forwarding for the sensor ports you chose | See [Ports to forward](#ports-to-forward). |

The memory figures are sizing targets. Check the real use on your host with `docker stats` after the first day.

## Participant mode and full mode

| Mode | What runs | Use it when |
| --- | --- | --- |
| `full` (default) | Everything: sensors, database, ingest, API and dashboard, and the VPN service (optional; idle until you add a WireGuard file) | You want the dashboard, reports and blocklists |
| `participant` (`--participant`) | Sensors, database, ingest and the network node. No dashboard, no admin account, no VPN needed | You only want to help the network. See [Join the network](participate.md) |

Participant mode has its own flags: `--pseudonym`, `--no-pseudonym`, `--country`, `--show-country`, `--verifier`, `--no-auto-update`, `--feeds`, `--self-address` and `--repair`. It refuses the dashboard flags (`--dashboard-*`, `--public-host`, `--admin-*`, `--allow-lan`). Choosing it is your consent to join the network.

To switch an existing participant install to full mode, run `./scripts/install.sh --full`. It asks the dashboard questions, takes a backup and keeps your data. The other way (full to participant) is not supported. Running the installer again on an existing install only prints its status. Add `--repair` to run the volume, start and schedule steps again.

## Images or source build

| Mode | What runs | Use it when |
| --- | --- | --- |
| `images` (default) | Signed release images from the registry. The installer checks each signature before it runs anything. | You want a released version. This is the normal choice. |
| `source` | Images built on this machine from the checkout. | You want to run your own changes, or no release is published yet. It takes longer. |

The mode is saved as `SUCKERPOT_INSTALL_MODE` in `.env`. Updates use the same mode.

## Install in one command

Clone a release tag, then run the installer from the checkout:

```bash
git clone --depth 1 --branch v0.11.4 https://github.com/selfhostr/suckerpot.git
cd suckerpot
./scripts/install.sh
```

Replace `v0.11.4` with the release you want. The tag is the release name on the repository's Releases page.

If you clone without a tag, or you want to build from source, run:

```bash
./scripts/install.sh --source
```

The installer does not use `curl | bash`. Read the script first, then run it from the checkout.

To install without questions, use `--yes`. It takes the default for every question. **It does not join the SuckerPot network**: that needs your explicit `--join-network`. The admin password is then generated and printed once, or you can pass your own on standard input:

```bash
./scripts/install.sh --yes --sensors recommended
# add --join-network to join the SuckerPot network (experimental preview)
```

```bash
read -rs -p "Admin password: " PW && echo
printf '%s\n' "$PW" | ./scripts/install.sh --yes --admin-password-stdin --sensors recommended
unset PW
```

The second form keeps the password out of the command line and out of your shell history.

## What the installer asks

Each question has a default. Press Enter to accept it. With `--yes`, every question takes its default.

| Question | Default | Notes |
| --- | --- | --- |
| Install mode | `images` | `images` or `source`. See [images or source build](#images-or-source-build). |
| Sensors | `recommended` | `recommended` is SSH, Telnet, Web, Redis, Docker and ADB. `all` turns on all twelve. Or type a list such as `ssh,web`. |
| How the dashboard is reached | local | `l` for this machine or an SSH tunnel. `h` for an HTTPS tunnel such as cloudflared. With `h` the installer asks for the public host name, for example `dash.example.com`. |
| Admin user name | `admin` | Letters, digits, `.`, `_` and `-`. |
| Admin password | generate one | Type it twice, at least 12 characters. Leave it empty to generate a 24-character password. The generated password is shown once. |
| Low-memory mode | `yes` below 6 GiB, `no` above | Only asked on machines with less than 6 GiB. See [low-memory hosts](#low-memory-hosts). |
| Daily update check | `no` | One request a day through the VPN, off by default. See [updates](updates.md#the-optional-update-check). |
| WireGuard `.conf` file | empty | Path to the file from your VPN provider. Empty means you upload it later in the dashboard. See [the VPN](#the-vpn-before-a-wireguard-file-is-uploaded). |
| Join the SuckerPot network? | `no` | An experimental preview. Shows what would be shared, then asks `[y/N]`. An empty answer is a no. A yes writes a consent record and a random pseudonym; the join waits for a VPN. `--yes` alone never joins: use `--join-network` to join without the question, or `--no-network` to skip it. See [the network](network.md). |
| Your own public address | empty | Optional. The installer never looks it up. If you type it, it goes to `INDICATORS_IGNORE`, so it never shows up as attack infrastructure. |
| Port in use | depends | Asked only when a port the chosen sensors need is already taken. See [port 22](#port-22-is-already-in-use). |
| Admin SSH port | empty, or `22` when port 22 is busy | The port of this machine's own SSH daemon. It is protected so no sensor can take it. `sudo ./scripts/move-admin-ssh.sh` moves it off port 22 for you. |

## What the installer does

The installer prints one line per step, `[n/10]`. It stops at the first failure and says why.

1. **Check this machine.** Linux, CPU, Docker, Compose, memory, disk, existing install, existing data.
2. **Settings.** Asks the questions above.
3. **Check ports.** Looks at the host ports of the chosen sensors and the dashboard port.
4. **Generate secrets.** Every database, Redis and proxy password, the session secret and the settings encryption key. Each is at least 24 characters, and no two are equal.
5. **Hash the admin password.** The password goes to a container with no network, through standard input. It never appears in a command line, an environment variable or a file.
6. **Write `.env`.** The file is created with mode `0600`. The secrets are written only to this file.
7. **Create the data volumes.** The volumes are created. Existing volumes are never touched.
8. **Check the port layout and the VPN settings.** The same guards that `just up` runs.
9. **Start the stack.** Images are verified, pulled and started (or built, in source mode). The installer waits until every service is healthy.
10. **Done.** Prints the dashboard address and the next steps.

A log without any secret goes to `install.log` in the checkout. The file is ignored by git.

## Flags

| Flag | Meaning |
| --- | --- |
| `--yes`, `-y` | Take the default for every question. Use `--admin-password-stdin` for your own password, or the password is generated. |
| `--images` | Install from signed release images. This is the default. Needs a release version (see `--version`). |
| `--source` | Build the images from this checkout. |
| `--version vX.Y.Z` | Release to install in images mode. Default: the tag of the checkout. |
| `--project NAME` | Compose project name. Default `suckerpot`. Lowercase letters, digits, `-` and `_`, at most 41 characters. |
| `--prefix NAME` | Prefix of the data volumes. Default: the same as `--project`. Same rules. |
| `--sensors LIST` | `recommended`, `all`, or a list such as `ssh,telnet,web`. |
| `--dashboard-bind ADDR` | IPv4 address the dashboard port binds to. Default `127.0.0.1`. |
| `--dashboard-port N` | Host port of the dashboard. Default `8443`. |
| `--public-host HOST` | The host name of an HTTPS tunnel, for example `dash.example.com`. Sets `API_ALLOWED_HOSTS`, `API_ALLOWED_ORIGINS=https://HOST` and `COOKIE_SECURE=true`. |
| `--allow-lan` | Allow a bind on a network address with no tunnel. The dashboard then uses plain http and cookies lose `Secure`. Only for a network you trust. Never for the internet. |
| `--admin-user NAME` | Dashboard user name. Default `admin`. |
| `--admin-password-stdin` | Read the admin password from the first line of standard input. |
| `--admin-ssh-port N` | Port of this machine's own SSH daemon, protected from the sensors. |
| `--lowmem auto\|on\|off` | Low-memory overlay. Default `auto`: asked below 6 GiB. `on` requires the overlay file in the checkout. |
| `--lite` | Participant mode only, fresh install: 1 GiB machines (VPS, Raspberry Pi). Adds `docker-compose.lite.yml` on top of the low-memory overlay and defaults the sensors to `ssh,telnet,web,redis`. Needs 1 GiB of memory. See [VPS guide](vps.md). |
| `--wg-conf PATH` | WireGuard `.conf` file from your VPN provider. It is read as plain text and never run. |
| `--skip-verify` | Do not check the image signatures. Not recommended. See [updates](updates.md#image-signatures). |
| `--dry-run --env-out PATH` | Write the `.env` that would be made to `PATH`, with a placeholder hash. Makes no Docker call. Used to test the installer. |
| `-h`, `--help` | Print the usage. |

## What the installer refuses

The installer stops before it changes anything when one of these is true.

| Situation | What to do |
| --- | --- |
| A `.env` already exists in the checkout. | SuckerPot is installed here. Use `just update`. The installer never overwrites `.env`. |
| The checkout is a linked git worktree. | Install from a normal clone. |
| Docker is missing or does not answer for your user. | Install Docker, or run `sudo usermod -aG docker $USER`, then log in again. |
| Docker Engine is older than 24, or Compose older than 2.24. | Upgrade Docker. |
| Less than about 1.75 GiB of memory. | Read the memory size in the message. A machine sold as "2 GB" is above this limit and is accepted. Below it, participant mode offers the lite setup (same as `--lite`) when the machine reports about 1 GiB or more. Full mode refuses and prints `./scripts/install.sh --participant --lite`; otherwise use a bigger machine. |
| Less than 15 GiB free under Docker's data folder. | Free disk space. |
| Volumes named `<prefix>_*` already exist. | An earlier install used this prefix. Restore your old `.env`, or pass another `--prefix`. The installer never adopts old volumes: the database password is stored inside them. |
| Containers of the chosen `--project` already exist. | Pick another `--project`, or remove that stack yourself. |
| The project or prefix name is invalid, or is one of the test names (`sp-it-*`, `sp-test`, `sp-ci`). | Pick another name. |
| `--dashboard-bind` is not `127.x.x.x`, and there is no `--public-host` and no `--allow-lan`. | Keep `127.0.0.1` and use an SSH tunnel, or give `--public-host` for an HTTPS tunnel. |
| The dashboard port is in use. | Pass `--dashboard-port` with a free port. |
| Port 22 is in use and you chose to keep it. | Move your own SSH to another port first with `sudo ./scripts/move-admin-ssh.sh` (see [VPS](vps.md#move-your-admin-ssh-off-port-22-first)). The installer itself never edits `sshd_config`. Then run the installer again. |
| The admin password is shorter than 12 characters, or the two entries differ. | Enter it again. |
| Images mode, and no release version. | Clone a release tag, or pass `--version vX.Y.Z`, or use `--source`. |
| `--version` does not look like `vX.Y.Z`. | Fix the version. |
| An image signature cannot be checked. | Nothing is started. See [updates](updates.md#image-signatures). |
| `--lowmem on`, but the checkout has no `docker-compose.lowmem.yml`. | Use a current release. |
| The WireGuard file lacks a key or the endpoint, or its endpoint is a host name. | Upload the file in the dashboard instead. Settings > VPN. |
| An unknown sensor name in `--sensors`. | Use one of: `ssh telnet web rdp redis docker mysql adb mssql smb sip synology`. |

The installer never does these things:

- It never overwrites an existing `.env`.
- It never adopts, changes or deletes an existing data volume.
- It never edits the host's SSH configuration.
- It never looks up the machine's public address.
- It never sends any information about the install to the project.

## Ports to forward

Each sensor listens on a host port. Your router forwards the standard port of the service to that host port. The installer picks the host ports, and it shows the result on the **Sensors & ports** tab of Settings.

| Sensor | Switch in `.env` | Port on your router | Host port variable | Default host port | Protocol | In `recommended` |
| --- | --- | --- | --- | --- | --- | --- |
| SSH | `SENSOR_SSH` | 22 | `SSH_HOST_PORT` | 22 | TCP | yes |
| Telnet | `SENSOR_TELNET` | 23 | `TELNET_HOST_PORT` | 23 | TCP | yes |
| Web | `SENSOR_WEB` | 80 and 443 | `HTTP_HOST_PORT`, `HTTPS_HOST_PORT` | 80, 443 | TCP | yes |
| Redis | `SENSOR_REDIS` | 6379 | `REDIS_HOST_PORT` | 6379 | TCP | yes |
| Docker API | `SENSOR_DOCKER` | 2375 | `DOCKER_HOST_PORT` | 2375 | TCP | yes |
| ADB | `SENSOR_ADB` | 5555 | `ADB_HOST_PORT` | 5555 | TCP | yes |
| RDP | `SENSOR_RDP` | 3389 | `RDP_HOST_PORT` | 3389 | TCP | no |
| MySQL | `SENSOR_MYSQL` | 3306 | `MYSQL_HOST_PORT` | 3306 | TCP | no |
| MSSQL | `SENSOR_MSSQL` | 1433 | `MSSQL_HOST_PORT` | 1433 | TCP | no |
| SMB | `SENSOR_SMB` | 445 | `SMB_HOST_PORT` | 445 | TCP | no |
| SIP | `SENSOR_SIP` | 5060 | `SIP_HOST_PORT` | 5060 | UDP and TCP | no |
| Synology DSM | `SENSOR_SYNOLOGY` | 5000 and 5001 | `SYNOLOGY_HTTP_HOST_PORT`, `SYNOLOGY_HTTPS_HOST_PORT` | 5000, 5001 | TCP | no |

Rules:

- Forward only the ports of the sensors you turned on. A sensor that is off publishes nothing.
- Never forward the dashboard port (`DASHBOARD_PORT`, 8443 by default) or your own admin SSH port.
- Do not put the machine in your router's DMZ in full mode. A DMZ forwards every port, the dashboard's included. In participant mode a DMZ is acceptable only if the machine runs nothing else, its admin SSH port is not 22, and you accept that the host firewall does not filter internet traffic to the machine's own services (use key-only SSH and a rule for the admin port); port forwards are better. See [Deployment](deployment.md#forward-the-ports).
- If your router's WAN address is in `100.64.0.0/10` (carrier-grade NAT), forwarding cannot work. Ask your provider for a public address.
- SuckerPot cannot test the forwarding from outside, and it does not try. Bots arrive within minutes. The Ports page shows **Receiving** once a sensor gets its first event.
- To know whether the internet reaches your sensors, run `./scripts/participant.sh ports-check`. It makes no outside connection: it looks for sessions from public addresses already recorded by your sensors. See [Participate](participate.md#check-that-the-ports-are-open).

Set up the host firewall too. See [Deployment: host firewall](deployment.md#host-firewall).

### Port 22 is already in use

Most hosts run their own SSH daemon on port 22. When the installer finds port 22 taken, it offers three choices:

| Choice | Result |
| --- | --- |
| `m` (map), the default | The SSH sensor listens on host port 2222. Your router forwards its port 22 to 2222. Your own SSH keeps port 22. |
| `o` (off) | The SSH sensor stays off. |
| `k` (keep) | The installer stops. Move your own SSH to another port first with `sudo ./scripts/move-admin-ssh.sh`, then run the installer again. |

With `--yes`, the SSH sensor is mapped to 2222 and the other sensors whose ports are busy are turned off, with a warning for each.

## Choosing the sensors later

Each sensor has a switch, `SENSOR_<NAME>`, set to `1` (on) or `0` (off). Every sensor is on by default, so an install that predates the switches keeps all of them.

```bash
just sensors                    # show the current selection
just sensors ssh,telnet,web     # keep only these three
just sensors recommended        # SSH, Telnet, Web, Redis, Docker, ADB
just sensors all                # all twelve
```

`just sensors` writes the switches to `.env`, checks the port layout, and then starts the stack again. A sensor set to `0` is not started, and one that was running is stopped and removed (the same applies to `just set SENSOR_<NAME>=0`). Check with `docker compose ps`.

After a change, forward the new set of ports on your router. The Ports page shows the list.

## First-run setup in the dashboard

After the installer finishes, sign in as the admin user. The setup opens by itself, once per browser session, until you finish or skip it. Only the admin sees it.

| Step | What it does | Can be skipped |
| --- | --- | --- |
| Welcome | Explains the three rules: a dedicated machine, no credentials on it, the dashboard never public. | No |
| Your sensors | Shows the enabled sensors and the `just sensors` command for your choice. The page shows the command. It never runs it. | No |
| Open the ports | The Ports table, with a live status for each row. | Yes |
| Anonymous egress | The VPN state, and the upload of a WireGuard file. | Yes |
| Your own address | Asks for your own public address, so it never goes into a report or alert. | Yes |
| Abuse reports | The reply contact for reports. Reports are drafts you send yourself. | Yes |
| Alerts | Link to the alert channels. | Yes |
| The SuckerPot network | Shows what joining means. The network is an experimental preview and is off by default. Joining needs `NETWORK_ENABLED=true` and a password. | Yes |
| You are set | The checklist of what is left, the tour, and "Go to Today". | No |

Controls:

- **Finish later** keeps your place. Settings > General offers to resume.
- **Skip setup** closes the setup for good.
- **Open the setup again** is in Settings > General, after you skipped or finished it.

## Low-memory hosts

The low-memory mode lets SuckerPot run on a machine with about 2 GiB of memory, with some swap. It uses a second Compose file, `docker-compose.lowmem.yml`.

The installer turns it on when you say yes to the question, or with `--lowmem on`. It writes this line to `.env`:

```text
COMPOSE_FILE=docker-compose.yml:docker-compose.lowmem.yml
```

Because of that line, plain `docker compose` and every `just` recipe use the smaller limits too.

What changes:

- Memory limits of the database, Redis, ingest, the API, the analyzer, the collector and each sensor are lower.
- The database uses smaller buffers and fewer connections.
- Redis uses a 96 MiB ceiling (`REDIS_MAXMEMORY_MB=96`).
- Each sensor is told its limit, so it sheds load before the container reaches it.

What does not change: networks, volumes, capabilities, ports and the sensor list.

Tips:

- Add swap on the host. The low-memory mode expects it.
- Turn off the sensors you do not need with `just sensors`. Each sensor costs memory.
- Under heavy traffic, sensors refuse new connections before they run out of memory. Expect fewer captured sessions in that case.
- To go back to the normal limits, remove the `COMPOSE_FILE` line from `.env` by hand (`just set` does not change it), then run `just up`.

Sizing targets, from the design:

| Machine | What it can run |
| --- | --- |
| 2 GiB, low-memory mode | Up to five sensors. |
| 4 GiB | All twelve sensors, normal limits. |
| 6 GiB or more | All twelve sensors, with the collector and the analyzer busy. |

## The VPN before a WireGuard file is uploaded

The installer always turns on the egress profile (`COMPOSE_PROFILES=egress`). This starts three services: `vpn`, `collector` and `analyzer`. SuckerPot makes every outside lookup through the VPN, and the VPN is the only service with a route to the internet. See [Configuration: anonymous egress](configuration.md#anonymous-egress-and-payload-collection-m21).

You can finish the install before you have a VPN configuration. Then the `vpn` service waits in **idle mode**:

- It runs no tunnel and no proxy.
- It has no route out at all.
- Its health check passes, so the stack still starts.
- Every outside lookup stays closed. The dashboard shows the gate as closed.

To finish the VPN set-up, use one of these:

- **Upload the file in the dashboard.** Settings > VPN. The `vpn` service restarts on it.
- **Pass the file to the installer.** `./scripts/install.sh --wg-conf /path/to/wg0.conf`. The installer reads the `[Interface]` and `[Peer]` values with a fixed parser and writes them to `.env` (mode `0600`). The endpoint must be an IPv4 address, not a host name. Otherwise, upload the file in the dashboard.

A WireGuard configuration that is only half filled is not idle. The `vpn` service refuses to start the tunnel, so nothing leaves the machine. Fill in every value or remove them all.

Use a VPN provider and a configuration that you trust. The provider sees all outbound traffic of SuckerPot.

## What leaves this machine

SuckerPot sends its outside lookups through the VPN. The installer and the updates are different. They use the host's own network connection, not the VPN:

- `git clone` and `git fetch`.
- Image pulls from the registry, and the signature checks of [updates](updates.md#image-signatures).
- The Docker Hub or registry pulls of the database and VPN images.

This traffic shows the host's address to the registry and to GitHub. It is outside the anonymous egress of the stack, and it is documented here on purpose. If you want the host itself to use a proxy, configure Docker's proxy settings for the host.

## After the install

1. Sign in and finish the setup, or skip it and come back later.
2. Forward the ports for your sensors. See [Ports to forward](#ports-to-forward).
3. Install the host firewall. See [Deployment: host firewall](deployment.md#host-firewall).
4. Take a snapshot of the machine. See [Deployment: snapshot](deployment.md#snapshot).
5. Keep the install up to date with [updates and rollback](updates.md).
6. Store the admin password in a password manager. The installer does not keep it.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `Docker does not answer for this user`. | Run `sudo usermod -aG docker $USER`, log in again, and retry. |
| `Data volumes named ... already exist`. | An earlier install used this prefix. Use the old `.env`, or install with `--prefix` set to a new name. |
| `The stack did not become healthy`. | Run `docker compose ps` and `docker compose logs --tail=100`. Fix the cause, then run `just up`. Do not delete `.env` to retry: the volumes already hold the database. |
| `The dashboard does not answer on .../healthz`. | Run `docker compose logs api`. The API may still be starting. Wait a minute, then try again. |
| `the image signatures could not be verified`. | Nothing was started. Check the version name, then see [image signatures](updates.md#image-signatures). |
| `port 22 is still in use`. | Move your own SSH to another port with `sudo ./scripts/move-admin-ssh.sh`, then run the installer again. The installer itself never edits `sshd_config`. |
| The Ports page shows **Waiting for the first connection** for a long time. | Check the router forwarding, the host firewall and the CGNAT note above. Bots normally arrive within minutes. |

## Next steps

- [Join the network in three commands](participate.md)
- [Updates and rollback](updates.md)
- [Configuration](configuration.md#install-updates-and-sensor-switches-m28)
- [Deployment](deployment.md)
