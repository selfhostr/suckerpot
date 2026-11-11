# Join from a cheap VPS or a Raspberry Pi

You can join the SuckerPot network without a spare PC at home and without touching your router. This page covers the two small setups: a VPS with 1 GiB of memory, and a Raspberry Pi. Both use the `--lite` option of the participant installer.

Read [Join the network in three commands](participate.md) first. This page only adds what is different on a small machine.

```{warning}
SuckerPot is built to be attacked. Use a machine that holds nothing else you care about, and never one that carries your own services or keys.
```

## Why a VPS

- **No home address exposed.** The attackers see the address of the VPS, not your home connection.
- **No router change.** A VPS has a public address. You open ports in the provider's panel, or you open nothing at all if the provider has no firewall in front of the machine.
- **No machine to keep running at home.** It costs a few euros a month, and you can delete it at any time.

Any provider works. Choose one that allows Linux with a public IPv4 address and does not forbid honeypots in its terms. Check the terms before you buy: attack traffic is part of the deal.

## What you need

| Item | Needed |
| --- | --- |
| Machine | 1 GiB of memory, 1 vCPU, 15 GiB of free disk, `x86_64` or `aarch64` |
| System | Debian 12+ or Ubuntu 22.04+, 64 bit |
| Software | Docker Engine 24+ with the Compose plugin, `git`, `curl`, Bash 4+ |
| Swap | 1 GiB of swap or more (see below) |
| Access | Root or a sudo user, and SSH with a key |

## What `--lite` changes

```bash
./scripts/install.sh --participant --lite
```

`--lite` is for fresh participant installs only. It does two things:

1. **Lower memory limits.** It adds `docker-compose.lite.yml` on top of the low-memory overlay. The database and Redis get smaller limits and smaller buffers. Ingest and the sensors keep the low-memory values (320 MiB and 128 MiB each): ingest also runs the status and update commands inside its own limit, so it is not squeezed.
2. **Four sensors by default**: SSH, Telnet, web and Redis. Pass `--sensors LIST` to choose others.

The installer writes the overlays to `COMPOSE_FILE` in `.env`, so every later start and every automatic update keeps them. Nothing about security changes: the same read-only containers, dropped capabilities, `no-new-privileges`, process limits, internal networks and hub allow-list apply. A guardrail test fails if the lite overlay ever sets anything other than memory figures.

### Memory limits

Rendered with `docker compose config`, direct mode (no VPN), counting every container that runs after the install (the one-off `migrate` job is not counted):

| Setup | Sensors | Total memory limit |
| --- | --- | --- |
| Participant, default | 6 (ssh, telnet, web, redis, docker, adb) | 3,248 MiB |
| Participant, low-memory overlay (small machines) | the same 6 | 1,936 MiB |
| Participant, `--lite` | 4 (ssh, telnet, web, redis) | 1,424 MiB |

A limit is a ceiling, not what the containers use. Real use is lower, but a burst of attacks can push each container towards its limit. Under pressure the sensors refuse new connections before they run out of memory, so you capture fewer sessions rather than crash.

Know the limits of a 1 GiB machine. Containers never use swap (each memory limit equals its swap limit), so host swap only gives the whole machine some headroom. If the machine as a whole runs out of memory, the kernel may kill and restart a container, the database included. Your data stays consistent: sensors drop events when Redis is unavailable instead of buffering them, and ingest confirms an event only after it is saved. What can suffer is availability: a few minutes of missing events during a restart. A 2 GiB machine avoids this.

### Why these four sensors

The network gets the most value from the services that attackers scan most, at the lowest cost per sensor:

- **SSH** and **Telnet** receive the most brute-force and bot traffic, and every session shows credentials and commands.
- **Web** (ports 80 and 443) sees constant exploit and scanner traffic, including new vulnerabilities.
- **Redis** (port 6379) is the most scanned database port and is cheap to run.

Docker (2375) and ADB (5555) are also useful. They are not in the lite set because they cost more memory for less traffic. Add them with `--sensors ssh,telnet,web,redis,adb` if your machine has room, or later with `just sensors`.

### Add swap

A 1 GiB machine should have swap, as headroom for the host (the installer warns below 512 MiB and asks before it continues). Check what you have:

```bash
free -m
```

If the swap line shows 0, add a swap file (as root):

```bash
fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

Some providers ship images without swap and some already have it. If `swapon` fails on your provider, use a larger plan instead.

## Move your admin SSH off port 22 first

The SSH sensor listens on port 22, because that is where attackers look. Your own SSH daemon uses port 22 by default. On a VPS there is no router to translate ports, so **you must move your admin SSH to another port before you install**. One script does it, and it cannot lock you out: it opens the new port next to port 22, waits until you have logged in on the new port, and only then closes port 22.

It works on Debian and Ubuntu. For another system, use [By hand](#by-hand) below.

1. **Run it** from your SuckerPot folder, in your current SSH session:

   ```bash
   sudo ./scripts/move-admin-ssh.sh
   ```

   It moves your admin SSH to port `22222`. For another port, give it: `sudo ./scripts/move-admin-ssh.sh 48022` (any free port from 1024 to 65535 that SuckerPot does not use). It tells you what it will do and asks before it changes anything.
2. **Connect from a second terminal** on your computer, while the first one stays open:

   ```bash
   ssh -p 22222 your-user@203.0.113.10
   ```

   (Use your own port and your VPS address.) The script sees the login and closes port 22 by itself. If the login does not come within 5 minutes, or you press Ctrl-C, it puts everything back and port 22 stays as it was.
3. **Done.** Port 22 is free for the SSH sensor. Your admin SSH uses the new port from now on. If your provider has a firewall panel, allow TCP `22222` there before step 2: the script opens `ufw` or `firewalld` when one is active, but it cannot reach a provider panel.

To go back to port 22 at any time: `sudo ./scripts/move-admin-ssh.sh --undo`.

The installer still never edits your SSH configuration. This script is separate, and you run it on purpose. After it, also read [Turn off password logins](#5-turn-off-password-logins) and [Free port 22 for the sensor](#6-free-port-22-for-the-sensor).

## By hand

Use these steps on a system the script does not support, or if you prefer to see every change. They keep your current session open the whole time. Never close it until the last step works.

Pick a free port above 1024 for your admin SSH. This page uses `52022` as an example; choose your own, and do not reuse a sensor port. The sensors use 22, 23, 80, 443, 445, 1433, 2375, 3306, 3389, 5000, 5001, 5060, 5555 and 6379; pick a number outside that list.

### 1. Allow the new port first

If the provider has a firewall panel, add an inbound rule for TCP `52022` (from your own address if you can) before you change anything. Keep the rule for port 22 for now.

If the machine runs `ufw`:

```bash
sudo ufw allow 52022/tcp
```

### 2. Find out how SSH is started

```bash
systemctl is-enabled ssh.socket
```

- `enabled`: SSH uses systemd socket activation. This is the default on Ubuntu 24.04 and newer. Follow **Ubuntu 24.04 and newer** below.
- Anything else (`disabled`, `masked`, "No such file"): follow **Debian, and older Ubuntu** below.

### 3a. Ubuntu 24.04 and newer (socket activation)

With socket activation, `systemd` opens the port, not `sshd`. The `Port` line in `sshd_config` is **ignored**. You must change the socket instead:

```bash
sudo mkdir -p /etc/systemd/system/ssh.socket.d
sudo tee /etc/systemd/system/ssh.socket.d/override.conf > /dev/null <<'EOF'
[Socket]
ListenStream=
ListenStream=0.0.0.0:52022
ListenStream=[::]:52022
EOF
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
```

The empty `ListenStream=` line clears the default port 22. Both address lines are needed: Ubuntu's socket is IPv6 only by default. Check the result:

```bash
sudo ss -ltnp | grep -E ':(22|52022)\b'
```

You must see `52022` and no listener on port 22. If `ss` still shows port 22, restart the service too: `sudo systemctl restart ssh.service`. Your open session stays connected, because `sshd` keeps running for existing connections.

### 3b. Debian, and older Ubuntu

```bash
echo 'Port 52022' | sudo tee /etc/ssh/sshd_config.d/10-admin-port.conf
sudo sshd -t
sudo systemctl restart ssh
```

`sshd -t` prints nothing when the configuration is valid. If it prints an error, fix it before you restart. Check the result:

```bash
sudo ss -ltnp | grep -E ':(22|52022)\b'
```

If your `sshd_config` has no `Include /etc/ssh/sshd_config.d/*.conf` line (very old images), put the `Port 52022` line in `/etc/ssh/sshd_config` itself.

### 4. Test from a second terminal

Leave the first session open. In a new terminal on your computer:

```bash
ssh -p 52022 your-user@203.0.113.10
```

(Replace the address with your VPS address.) Do not close the old session yet: it stays open until the end of step 5. If this login fails, fix it from the session that is still open: undo the drop-in (delete the file, run `daemon-reload` and restart as above) and try again.

### 5. Turn off password logins

Attackers will try passwords on your admin port as well. Allow keys only. First make sure your key login works in the second terminal (step 4), then:

```bash
echo 'PasswordAuthentication no' | sudo tee /etc/ssh/sshd_config.d/20-keys-only.conf
sudo sshd -t
sudo systemctl reload ssh
```

On Ubuntu with `ssh.socket`, `reload ssh` still works (use `ssh.service` if your system names it so). Some images already set `PasswordAuthentication yes` in a file that sorts earlier, which wins: check with `sudo sshd -T | grep -i passwordauthentication`, which must print `no`. Then open a third terminal and log in with your key, still before you close the old session. If it fails, undo the file from the open session.

### 6. Free port 22 for the sensor

If a provider rule limited port 22 to your own address, remove it, and remove the `ufw` rule for 22 if you added one. Port 22 is about to belong to the SSH sensor and must be open to everyone. Make sure nothing still listens on it: `sudo ss -ltnp | grep ':22 '` must print nothing.

## Install

```bash
git clone --depth 1 --branch v0.11.0 https://github.com/selfhostr/suckerpot.git
cd suckerpot
./scripts/install.sh --participant --lite
```

The installer finds your admin SSH port from what `sshd` listens on (here 52022) and records it as `ADMIN_SSH_PORT`, so the host firewall protects it. You can check it with `grep ADMIN_SSH_PORT .env`. It never edits your `sshd` configuration. Say yes to the host firewall when it asks. More about the installer: [Join the network](participate.md).

## Open the ports in the provider panel

If your provider has a firewall in front of the machine, allow these inbound TCP ports from anywhere:

| Port | Sensor |
| --- | --- |
| 22 | ssh |
| 23 | telnet |
| 80 | web |
| 443 | web |
| 6379 | redis |

Keep your admin SSH port (52022 in the example) limited to your own address if the panel allows it. There is no router and no port mapping on a VPS: the port in the panel is the port on the machine.

Then check that the internet reaches the sensors:

```bash
./scripts/participant.sh ports-check
```

A VPS gets scanned within minutes, so the check usually succeeds quickly.

## Raspberry Pi

A Raspberry Pi 4 or 5 with 1 GiB or more works with `--lite`, at home or anywhere else you can forward ports.

- **64-bit system required.** Use Raspberry Pi OS (64-bit) or Ubuntu Server for the Pi. Check with `uname -m`: it must print `aarch64`. On a 32-bit system (`armv7l`) the images do not run.
- **arm64 images.** The release images are multi-arch (`amd64` and `arm64`) and signed, so the installer pulls the right one by itself. No local build is needed.
- **Use a good SD card, or better a USB SSD.** The database and the logs write a lot, and cheap cards wear out. Keep 15 GiB free.
- **Swap.** Raspberry Pi OS ships a small swap file. Raise it to 1 GiB (`CONF_SWAPSIZE` in `/etc/dphys-swapfile`) if you have 1 GiB of memory.
- **Admin SSH.** If you use SSH to reach the Pi and want the SSH sensor on port 22, move your SSH off port 22 first with `sudo ./scripts/move-admin-ssh.sh`, as in the VPS steps above.
- **At home, the router steps apply.** The Pi has no public address of its own: follow the port table in [Join the network](participate.md#open-the-ports).

Then run the same installer:

```bash
./scripts/install.sh --participant --lite
```

## After the install

```bash
./scripts/status.sh
```

shows the sensors, your standing in the network and the last contact with the hub. Updates install themselves and keep the lite settings, because they live in `.env`. To go back to the normal limits, remove the `docker-compose.lite.yml` and `docker-compose.lowmem.yml` entries from the `COMPOSE_FILE` line of `.env` by hand and run `just up` (see [low-memory hosts](install.md#low-memory-hosts)).
