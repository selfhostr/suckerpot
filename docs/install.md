# Install SuckerPot

This page shows how to install SuckerPot with one command. The installer checks the machine, asks at most two questions (the install type, and the consent of a participant install), creates every secret on this host and starts the stack. The dashboard then walks you through the rest.

The manual path, with no installer, is still described in [Getting started](getting-started.md#manual-setup).

```{warning}
SuckerPot is built to be attacked. Install it on a dedicated machine that holds nothing else you care about. Read [Getting started](getting-started.md#read-this-first) first.
```

## Requirements

| Item | Needed | Notes |
| --- | --- | --- |
| Operating system | Linux, on `x86_64` (amd64) or `aarch64` (arm64) | A VM or a small server is fine. See [low-memory hosts](#low-memory-hosts) for small machines. |
| Shell tools | Bash 4 or newer, `git`, `curl`, and the usual GNU tools (`awk`, `sed`, `tr`, `base64`) | `ss` (from iproute2) is used for the port check. Without it the check is skipped. |
| Docker Engine | 24 or newer, 28 or newer recommended | Before 28 the internal networks are not isolated from the host (the installer warns). Your user must run `docker` without `sudo`. The installer tells you how to add the group if not. When Docker is missing, it offers to install it from Docker's own package repository (see [what the installer asks](#what-the-installer-asks)). |
| Docker Compose | v2.24 or newer | The Compose plugin (`docker compose version` must work). |
| Or: Podman (experimental) | Podman 5.4 or newer, rootful, with `docker-compose` 2.26 or newer | Supported on Debian 13 and Ubuntu 26.04; Fedora and the RHEL 10 family are experimental. The host firewall is required. See [Podman](#podman-experimental). |
| Memory | 2 GiB minimum | Use [low-memory mode](#low-memory-hosts) below 6 GiB. A machine sold as "2 GB" reports about 1.9 GiB and is accepted: it runs the low-memory setup, so add swap. The installer accepts 1.75 GiB (1,835,008 kB) or more; below that it refuses a full install and points to `--participant --lite`. |
| Free disk | 15 GiB minimum under the container engine's data folder | The installer warns below 30 GiB. Logs and captured payloads need room. |
| Outbound access | Yes, for the install | The host pulls images from the registry and checks their signatures. This traffic uses the host's own address. See [Anonymous egress](#what-leaves-this-machine). |
| Router | Forwarding for the sensor ports you chose | See [Ports to forward](#ports-to-forward). |

The memory figures are sizing targets. Check the real use on your host with `docker stats` after the first day.

## Podman (experimental)

SuckerPot also runs on rootful Podman, with the same commands for the install, updates, status and
the participant tools. Podman support is experimental: Debian 13 and Ubuntu 26.04 are the supported
systems, Fedora and the RHEL 10 family are experimental, and Podman 4 hosts (Debian 12, Ubuntu
24.04) are refused. The host firewall is required, and the socket group the installer creates is
root-equivalent (see below).

- On a machine with Podman only, `./scripts/install.sh` uses it without a question.
- With both commands (Fedora's `docker-compose` package brings the `docker` command along): while
  Docker runs, Docker is used (Podman needs a machine where Docker is off). When Docker is off and
  Podman is a packaged install, a terminal install asks (Podman is the default), and an install
  without a terminal or with `--yes` uses Podman. `--engine podman` or `--engine docker` chooses.
- The installer gives your user access to the root Podman socket (sudo; see "Socket access"
  below) and starts itself again in the new group, installs the host firewall and the boot unit
  before anything starts (sudo; without a terminal, sudo must not need a password), and runs the
  signed release images only (`--source` is refused on Podman).

Requirements (the scripts check them and refuse with the reason):

- Podman 5.4 or newer, rootful (not rootless), netavark with its nftables firewall driver (the
  default on the supported distributions), cgroup v2, systemd;
- `docker-compose` 2.26 or newer (Debian 13: `sudo apt install podman docker-compose nftables`);
- Docker not active on the same machine. On Fedora the `docker-compose` package pulls in
  `moby-engine` with an enabled `docker.socket`: turn it off with
  `sudo systemctl disable --now docker.socket docker.service`.

What differs from Docker:

- **Socket access.** The scripts talk to the root Podman socket. `scripts/host/podman-socket.sh
  USER` creates the group `suckerpot-podman`, adds the user and opens the socket to that group
  (log out and in afterwards). The group is root-equivalent, like the `docker` group, and the user
  stays in it until `sudo scripts/host/podman-socket.sh --uninstall USER` (`participant.sh
  uninstall` offers it). The script also sets netavark's firewall driver to nftables
  (`/etc/containers/containers.conf.d/50-suckerpot.conf`); the boot unit checks it after each
  start.
- **Host firewall: required.** Podman ignores the Docker network options that keep sensors off the
  internet and away from each other. `./scripts/participant.sh firewall` installs the firewall and
  the boot unit `suckerpot-stack.service`, which starts the stack only after the firewall and stops
  it when the firewall stops. Every start refuses when the firewall is not in force, unless
  `SUCKERPOT_NO_FIREWALL=1` says you filter elsewhere.
- **Networks** are created by `scripts/ensure-networks.sh`, and `COMPOSE_FILE` lists
  `docker-compose.podman.yml`.
- **Logs** go to journald.
- `just status` shows an engine line and the boot unit; `just isolation-check` checks the sensor
  isolation (run it with `sudo` so it can read the firewall tables).

Design and test results: [docs/dev/design/podman.md](dev/design/podman.md).

## Participant mode and full mode

| Mode | What runs | Use it when |
| --- | --- | --- |
| `full` (`--full`; the default with `--yes`) | Everything: sensors, database, ingest, API and dashboard, and the VPN service (optional; idle until you add a WireGuard file) | You want the dashboard, reports and blocklists |
| `participant` (`--participant`; the default answer on a terminal) | Sensors, database, ingest and the network node. No dashboard, no admin account, no VPN needed | You only want to help the network. See [Join the network](participate.md) |

Participant mode has its own flags: `--pseudonym`, `--no-pseudonym`, `--country`, `--show-country`, `--verifier`, `--no-auto-update`, `--feeds`, `--lite`, `--no-firewall` and `--repair`. Without `--participant` or `--full`, the installer asks which one on a terminal (see [what the installer asks](#what-the-installer-asks)). It refuses the dashboard flags (`--dashboard-*`, `--public-host`, `--admin-*`, `--allow-lan`). Choosing it is your consent to join the network.

To switch an existing participant install to full mode, run `./scripts/install.sh --full`. It takes a backup, sets up the dashboard with a generated admin password (shown once) and keeps your data. The other way (full to participant) is not supported. Running the installer again on an existing install only prints its status. Add `--repair` to run the volume, start and schedule steps again.

## Images or source build

| Mode | What runs | Use it when |
| --- | --- | --- |
| `images` (default) | Signed release images from the registry. The installer checks each signature before it runs anything. | You want a released version. This is the normal choice. |
| `source` | Images built on this machine from the checkout. | You want to run your own changes, or no release is published yet. It takes longer. |

The mode is saved as `SUCKERPOT_INSTALL_MODE` in `.env`. Updates use the same mode.

## Install in one command

```bash
curl -fsSLO https://github.com/selfhostr/suckerpot/releases/latest/download/get.sh && sh get.sh
```

`get.sh` needs only `curl`, `tar`, `gzip`, `sha256sum` and `bash`, runs as your user and never uses `sudo`. Before anything, it prints what it will do and asks. Then:

1. it asks GitHub for the newest release (or takes `--version vX.Y.Z`);
2. it downloads that release's **node bundle** (`suckerpot-node-vX.Y.Z.tar.gz`: the files of `config/node-bundle.list`, the compose files, scripts and settings a node needs, not the sources), its signed release manifest and the manifest's Sigstore signature;
3. it downloads cosign (a pinned release, checked against its pinned SHA-256) and checks that the manifest is signed by this repository's release workflow for that very tag, then that the bundle has the SHA-256 the manifest names and the commit it names. Any failure stops here, and nothing is written outside a temporary folder;
4. it creates `~/suckerpot` (`--dir` for another folder; it must not exist or be empty, and a folder that already holds a node is never touched) and unpacks the bundle there, refusing links and paths outside the folder;
5. it starts `~/suckerpot/suckerpot.sh`, the menu (`--no-menu` to stop before).

Everything after that happens with `~/suckerpot/suckerpot.sh`: install, status, edit, update, remove. An update of a bundle install downloads the new release's bundle and checks it the same way (the signed manifest names its SHA-256) before it replaces the files; `just rollback` puts the previous files back. A bundle install runs the signed release images only; to build from source, use a git checkout (below).

You can read `get.sh` before you run it; the command above downloads it first on purpose (the project never pipes a script into a shell in its docs).

### Testing a branch (not signed)

To test a branch before it is released (the `dev` branch, for example):

```bash
curl -fsSLO https://raw.githubusercontent.com/selfhostr/suckerpot/dev/scripts/get.sh && sh get.sh --ref dev
```

This fetches the branch as GitHub archives it and keeps only the files of the bundle. **Nothing is signed**: only HTTPS protects the download, and `get.sh` says so and asks you to type `yes`. The node then runs the scripts of the branch with the signed images of the newest release; its updates change only the images (run `get.sh --ref dev --dir NEW` again for newer scripts).

### From a git checkout

Clone the repository, switch to the latest release, then run the installer from the checkout:

```bash
git clone https://github.com/selfhostr/suckerpot.git && cd suckerpot
git switch --detach "$(git describe --tags --abbrev=0)"
./scripts/install.sh --full
```

The second line switches to the newest release tag, so these commands always install the latest release. For an older release, run `git switch --detach vX.Y.Z` instead, with a release name from the repository's Releases page.

If you clone without a tag, or you want to build from source, run:

```bash
./scripts/install.sh --full --source
```

The installer does not use `curl | bash`. Read the script first, then run it from the checkout.

### Or use the menu

`./suckerpot.sh` at the top of the checkout opens a menu in the terminal (also `just menu`). Move with the arrow keys (or `j` and `k`) and press Enter, or press the key shown before an item; `q` quits. It works over SSH, in an 80x24 terminal and without colour (`NO_COLOR`). Before an install it offers:

```
  1  Install a participant node   sensors only, joins the network (a VPS with 1 GiB or more)
  2  Full install                 sensors, dashboard, VPN egress, reports (2 GiB or more)
  3  Check this machine's ports   which sensor ports are free here
  q  Quit
```

Once something is installed, the same command shows what runs (the node name, the services, the network enrolment) and offers:

```
  1  Node status        stack, sensors, network enrolment, last batch
  2  Edit the node      name, country, sensors, VPN, updates, firewall
  3  Update now         the newest signed release, backup first
  4  Check the ports    does the internet reach the sensors?
  5  Logs               the network node, a service, the install
  6  Repair             run the install steps again, settings kept
  7  Leave the network  (or Join the network)
  8  Remove the node    uninstall; your data stays unless you say so
  q  Quit
```

Above the menu, a short list says what is missing or worth doing, each with its own key: an update is available (`u`), the node is not accepted by the hub yet (`w` waits for the answer), it has no node name (`n`) or no country (`c`), the host firewall is missing (`f`), automatic updates are off (`a`), the stack is not running (`r`). **Edit the node** opens the configuration of the node with its values (version, node name, country shown or not, sensors, VPN, automatic updates, host firewall); pick one to change it, and the screen comes back with the new value.

Each item runs one of the scripts below, so every item also works without the menu:

| Command | What it does |
| --- | --- |
| `./suckerpot.sh install [FLAGS]` | `./scripts/install.sh` with the same flags |
| `./suckerpot.sh status [--wait] [--brief \| --json]` | `./scripts/status.sh`: what runs, the network enrolment, the last batch, what needs attention. `--wait` first waits for the hub's answer to a join in progress (the proof of work of a new node can take minutes) |
| `./suckerpot.sh edit [SETTING [VALUE]]` | `./scripts/edit.sh`: `name`, `country`, `sensors`, `vpn`, `auto-update`, `firewall`. Without a value it asks; every change is applied at once |
| `./suckerpot.sh update` | `./scripts/update.sh` (as `just update`) |
| `./suckerpot.sh ports` | `./scripts/participant.sh ports-check` |
| `./suckerpot.sh logs [SERVICE]` | the last lines of the logs |
| `./suckerpot.sh repair` | `./scripts/install.sh --repair` |
| `./suckerpot.sh leave`, `./suckerpot.sh join` | leave the network, or join again (participant node) |
| `./suckerpot.sh remove` | `./scripts/uninstall.sh`, see [Remove SuckerPot](#remove-suckerpot) |

To install without any question, use `--yes`. With no `--participant`, it makes a full install. **It does not join the SuckerPot network**: that needs your explicit `--join-network`. The admin password is generated and printed once, or you can pass your own on standard input:

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

All questions come first, on the terminal; then the install runs by itself.

1. **What do you want to install?** `1` participant node (the default) or `2` full install. Asked only when neither `--participant` nor `--full` is given, and no flag of one mode already says it. Without a terminal, or with `--yes`, the installer makes a full install, as it always did.
2. **Join the SuckerPot network as described?** Participant installs only, after the consent screen. `--yes` counts as your consent. Without a terminal, a participant install needs `--yes`.
3. **Node name.** Participant installs on a terminal, unless `--node-name` (or `--pseudonym`) or `--no-node-name` answers it. The name the network shows for your node: a random name (the default), this machine's host name (the installer warns that it may identify you), your own, or none (the network then shows `Node` and a number). The rules are in [the network](network.md#pseudonyms). Do not use a name you use anywhere else.
4. **Show a country for this node?** Participant installs on a terminal, unless `--country` answers it. The default is no. If you say yes, you type the two-letter code, and the installer compares it with a GeoIP database on this machine, never with an outside service (see [the country check](network.md#the-country-check)). When the database places this machine elsewhere, it says so and you choose: keep your code, take the other one, type another, or show none.

**A checkout of a branch** (for example `git clone -b dev`) is not a release, so it has no images of its own. On a terminal the installer asks first: run the signed images of the newest release it knows (the default, verified like any release), or build this checkout from source (slower, for testing the branch). Without a terminal it stops and says which flag to add: `--version latest` (the newest release tag of the checkout), `--version vX.Y.Z` or `--source`. A later `./suckerpot.sh update` keeps the branch and changes only the images.

**sudo.** Three ways work, and none asks for a password twice:

- **As your user.** The scripts call `sudo` only for the steps that need root (Docker's setup, the host firewall, the Podman units). With passwordless sudo (`NOPASSWD`) nothing is asked. Otherwise they say once, before the first such step, that sudo asks for your password, and sudo itself asks; the scripts never read a password. Without a terminal, a step that would need a password is skipped with the command to run.
- **With sudo** (`sudo ./suckerpot.sh`, `sudo sh get.sh`). Everything runs as root and `sudo` is never called again. When you own the folder, `.env`, `install.log` and `.suckerpot-state` are given back to you, the update schedule goes into your crontab and Docker's setup adds you, not root, to the `docker` group.
- **As root** (a root login on a VPS). Everything runs as root, belongs to root, and no group is needed.

Without sudo and not root, a step that needs root says so and stops or is skipped.

`--non-interactive` never reads the terminal: the installer behaves as without one (the type needs a flag or `--yes`, the consent needs `--yes`, and no name or country question is asked).

While it runs, the screen shows the list of steps, one progress bar with the percentage and the time, and the result of each step on its right; the full output of every command goes to `install.log`. At the end it waits up to three minutes for the hub to accept a participant node. If the hub has not decided yet (a new node first solves a proof-of-work puzzle), it offers to wait ten more minutes; otherwise `./suckerpot.sh status --wait` shows the answer later. The final screen ends with the node's status: the stack, the sensors, the network enrolment and the first things to fix.

Everything else takes a default. Each default has a flag:

| Setting | Default | Flag |
| --- | --- | --- |
| Install mode | `images` | `--source`. See [images or source build](#images-or-source-build). |
| Sensors | `recommended` (SSH, Telnet, Web, Redis, Docker and ADB; on a lite node SSH, Telnet, Web and Redis) | `--sensors all` or a list such as `--sensors ssh,web` |
| How the dashboard is reached | this machine, `127.0.0.1:8443` (use an SSH tunnel) | `--public-host HOST` for an HTTPS tunnel, `--dashboard-bind`, `--dashboard-port` |
| Admin user name | `admin` | `--admin-user NAME` |
| Admin password | generated (24 characters) and shown once at the end | `--admin-password-stdin` reads your own from standard input |
| Low-memory mode | on below 6 GiB | `--lowmem on\|off`. See [low-memory hosts](#low-memory-hosts). |
| Lite setup (participant) | taken by itself on a machine with 0.875 to 1.75 GiB | `--lite` |
| Daily update check (full) | off | `--update-check`. See [updates](updates.md#the-optional-update-check). |
| WireGuard `.conf` file | none: upload it later in the dashboard | `--wg-conf PATH`. See [the VPN](#the-vpn-before-a-wireguard-file-is-uploaded). |
| The SuckerPot network (full) | not joined: join later in the dashboard | `--join-network` (shows the consent screen and joins). See [the network](network.md). |
| Your own public address | none: the dashboard learns it from traffic | `--self-address ADDR` (full and participant). The installer never looks it up. |
| Port 22 busy | the SSH sensor uses host port 2222 (forward router port 22 to it) | `--admin-ssh-port`, or move your SSH first: `sudo ./scripts/move-admin-ssh.sh`. See [port 22](#port-22-is-already-in-use). |
| Another port busy | that sensor stays off (the installer says which) | free the port, then `just sensors` |
| Admin SSH port | detected (`22` when port 22 is busy, else what sshd is configured for) | `--admin-ssh-port N` |
| Little swap | a warning, the install goes on | add swap, then `./scripts/install.sh --repair` |
| Host firewall (participant) | installed; `sudo` may ask for your password | `--no-firewall` |
| Container engine | the one installed; with both, Docker while it runs, else Podman (asked on a terminal) | `--engine docker\|podman` |

When Docker is not installed, the installer shows the commands that install Docker Engine from Docker's own package repository (Debian, Ubuntu, Fedora and the RHEL family): it downloads Docker's signing key, imports it into a throwaway keyring (a file with more than one key is refused), exports only the key with the fingerprint pinned in the script and gives that export to the package manager, adds the repository and installs `docker-ce`, `docker-ce-cli`, `containerd.io` and `docker-compose-plugin`. No script is piped to a shell. On a terminal it asks once, `Run them now? [Y/n]`, runs them with `sudo`, then starts again in the `docker` group (`sg docker`), so you do not need to log in again; if that is not possible it tells you to log out and back in. Without a terminal, on `n`, or on another distribution, it prints the commands (or the link to Docker's install guide) and stops with exit status 1. Podman is not offered yet.

## What the installer does

On a terminal, the installer shows a short list of steps with one progress bar, and the full output of every command goes to `install.log`. If a step fails, it shows that step, the last lines of the log and the log path. Without a terminal (CI, a redirected output, `TERM=dumb`) or with `--plain`, it prints `[n/10] title` when a step starts, `[n/10] ok` when it ends, the output of each command, and a last line for scripts: `result: ok type=... version=... engine=... log=...`, or `result: failed step=N log=...`. Either way it stops at the first failure and says why.

1. **Check this machine.** Linux, CPU, Docker, Compose, memory, disk, existing install, existing data.
2. **Settings.** The install type and the consent (see above), then the defaults and flags.
3. **Check ports.** Looks at the host ports of the chosen sensors and the dashboard port.
4. **Generate secrets.** Every database, Redis and proxy password, the session secret and the settings encryption key. Each is at least 24 characters, and no two are equal.
5. **Hash the admin password.** The password goes to a container with no network, through standard input. It never appears in a command line, an environment variable or a file.
6. **Write `.env`.** The file is created with mode `0600`. The secrets are written only to this file.
7. **Create the data volumes.** The volumes are created. Existing volumes are never touched.
8. **Check the port layout and the VPN settings.** The same guards that `just up` runs.
9. **Start the stack.** Images are verified, pulled and started (or built, in source mode). The installer waits until every service is healthy.
10. **Done.** Prints the dashboard address and the next steps.

`install.log` in the checkout gets the steps and the full output of every command, and never a secret. It has mode `0600` and is ignored by git. `NO_COLOR` keeps the progress display without colours.

## Flags

| Flag | Meaning |
| --- | --- |
| `--yes`, `-y` | Take the default for every question. Use `--admin-password-stdin` for your own password, or the password is generated. |
| `--images` | Install from signed release images. This is the default. Needs a release version (see `--version`). |
| `--source` | Build the images from this checkout. |
| `--version vX.Y.Z` | Release to install in images mode. Default: the tag of the checkout. `latest` takes the newest release tag of the checkout (for a branch checkout). |
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
| `--plain` | Plain line-by-line output, as without a terminal: no progress display, no colours, no cursor movement. |
| `--non-interactive` | Never read the terminal, even when there is one: the run behaves as in CI. A participant install then needs `--yes` for the consent. |
| `--node-name NAME`, `--no-node-name` | Participant mode: the node name, or none. The same as `--pseudonym NAME` and `--no-pseudonym`. |
| `--country CC`, `--show-country` | Participant mode: the country of the node, and show it to the network. |
| `--country-check local\|download\|off` | Participant mode: how `--country` is checked. `local` (the default) uses a GeoIP database already on this machine, if any; `download` first fetches DB-IP's free country list from `download.db-ip.com`; `off` skips the check. A mismatch is only a warning. |
| `--update-check` | Full mode: check once a day whether a newer release exists (one anonymous request through the VPN; it never installs anything). Off by default. |
| `--self-address ADDR` | Your own public address, so it never shows up as attack infrastructure. The installer never looks it up. |
| `--join-network` | Full mode: join the SuckerPot network (shows the consent screen). Without it, a full install does not join. |
| `--no-network` | Accepted for older scripts. The network is off unless `--join-network`. |
| `--no-firewall` | Participant mode: do not install the host firewall (you filter the sp-* bridges elsewhere). Writes `SUCKERPOT_NO_FIREWALL=1` to `.env`. |
| `--engine docker\|podman` | The container engine of a fresh install. Default: the one this machine has; with both, Docker while it runs, otherwise Podman (a terminal asks). Podman is experimental: see [Podman](#podman-experimental). |
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
| Abuse reports | The reply contact for reports. By default reports are drafts you send yourself; one-click or automatic sending is optional (see [Reporting attacks](reporting.md)). | Yes |
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

## Remove SuckerPot

`./suckerpot.sh remove` (or `./scripts/uninstall.sh`) shows what it will do and what it keeps, and asks first:

- a participant node leaves the network (the hub deletes the node and what it sent);
- the automatic update schedule is removed (and, on Podman, the boot unit);
- the containers are stopped and removed.

It keeps the data volumes, `.env` (the database password lives inside the data, so keep both or neither), `install.log` and the checkout. On a terminal it then asks whether to remove the host firewall too (`sudo`), and whether to delete the data volumes; deleting them needs you to type `DELETE`, and then `.env` is renamed to `.env.removed-<date>`, so the folder can install again. Without a terminal: `./scripts/uninstall.sh --yes [--remove-firewall] [--delete-data]`. With the data kept, `./scripts/install.sh --repair` starts the same install again.

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
| A restart takes minutes on a 1 GB VPS, or a change says ingest is still starting. | Normal on a loaded small machine: the scripts wait up to `SUCKERPOT_WAIT_TIMEOUT` seconds (900 on a small machine) and show the time; set it higher in the environment for very slow hosts. A change that ingest already took is never undone: `./suckerpot.sh status` shows it once ingest is up. The output of each restart is in `.suckerpot-state/stack.log`. |
| Ctrl-C during a restart. | The current step finishes first (the stack is never left half recreated), then the script stops. A change that was not made yet is put back. |
| `update: another update or rollback is running`. | It names who holds the lock and since when. The automatic update no longer holds it during its random wait; an older one that does can be stopped from the prompt. |
| `Docker does not answer for this user`. | Run `sudo usermod -aG docker $USER`, log in again, and retry. |
| `Data volumes named ... already exist`. | An earlier install used this prefix. Use the old `.env`, or install with `--prefix` set to a new name. |
| `The stack did not become healthy`. | Run `docker compose ps` and `docker compose logs --tail=100`. Fix the cause, then run `just up`. Do not delete `.env` to retry: the volumes already hold the database. |
| `The dashboard does not answer on .../healthz`. | Run `docker compose logs api`. The API may still be starting. Wait a minute, then try again. |
| `the image signatures could not be verified`. | Nothing was started. Check the version name, then see [image signatures](updates.md#image-signatures). |
| `port 22 is still in use`. | Move your own SSH to another port with `sudo ./scripts/move-admin-ssh.sh`, then run the installer again. The installer itself never edits `sshd_config`. |
| The Ports page shows **Waiting for the first connection** for a long time. | Check the router forwarding, the host firewall and the CGNAT note above. Bots normally arrive within minutes. |

## Next steps

- [Join the network in one command](participate.md)
- [Updates and rollback](updates.md)
- [Configuration](configuration.md#install-updates-and-sensor-switches-m28)
- [Deployment](deployment.md)
