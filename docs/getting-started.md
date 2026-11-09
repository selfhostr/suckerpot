# Getting started

This page shows how to run SuckerPot on a single host with Docker Compose. It also covers the warnings you must read first.

The main path is the installer. It checks the machine, creates the secrets and starts the stack in one command. See [Install SuckerPot](install.md). The manual path, with every step by hand, is in [Manual setup](#manual-setup).

## Read this first

```{warning}
**SuckerPot is designed to be attacked.** Once its ports face the internet, bots will probe it within minutes. Expect constant scans, login attempts and exploit traffic.

- Use a **dedicated machine or VM** that you are ready to lose. Do not reuse a machine that holds other work.
- **Never keep credentials that matter on the host.** No cloud keys, no SSH keys for other systems, no password manager exports and no personal files.
- **Do not run SuckerPot on a machine that you also use for development.** Development tools often keep tokens in plain files.
- **Do not expose the dashboard directly to the internet.** Reach it through a reverse tunnel. See [Deployment](deployment.md).
```

## Requirements

| Requirement | Notes |
| --- | --- |
| A Linux host, such as a VM | Dedicated and isolated (see the warning above). Amd64 and arm64 are supported. |
| Docker Engine 24 or newer, with Compose 2.24 or newer | `docker compose version` must work for your user. |
| Memory | 4 GiB for all sensors. About 2 GiB with the [low-memory mode](install.md#low-memory-hosts) and fewer sensors. |
| Disk | 15 GiB free under Docker's data folder at least. 30 GiB or more is better. |
| `git` and `curl` | Used by the installer and by the health checks. |
| `just` | Optional, but recommended. It wraps the common commands. |

No Python, Node.js or database has to be installed on the host. Everything runs in containers. The full list, with the reasons, is in [Install SuckerPot](install.md#requirements).

## 1. Install with the installer (recommended)

Clone a release tag and run the installer from the checkout:

```bash
git clone --depth 1 --branch vX.Y.Z https://github.com/<your-account>/suckerpot.git
cd suckerpot
./scripts/install.sh
```

Replace `vX.Y.Z` with the release you want. The installer asks a few questions. The six recommended sensors are on by default, and the SuckerPot network is off unless you answer yes to its question. It then writes `.env` with new secrets, starts the stack and prints the dashboard address. Every question and every flag is explained in [Install SuckerPot](install.md).

When the installer is done, sign in. The first-run setup opens by itself. It walks you through the sensors, the ports to forward, the VPN and the rest. See [the first-run setup](install.md#first-run-setup-in-the-dashboard).

To keep the install up to date, read [Updates and rollback](updates.md).

## 2. Open the dashboard

By default the dashboard listens on `127.0.0.1`, so only the host itself can reach it. Check it from the host:

```bash
curl -s http://127.0.0.1:8443/healthz
```

The `/healthz` path returns `{"status": "ok", "db": "ok"}` when the API can reach the database. The live feed is at `/api/v1/live` (WebSocket). See [API](api.md).

To use the dashboard from another machine, open an SSH tunnel to it. The installer prints the command. For example:

```bash
ssh -L 8443:127.0.0.1:8443 <you>@<this-host>
```

Then open `http://127.0.0.1:8443` in the browser on your own machine.

The dashboard has a login. The installer sets it up with a hash of your password. In the manual path, you set `ADMIN_PASSWORD_HASH` and `SESSION_SECRET` yourself, as described in [Deployment](deployment.md#dashboard-login). `just up` refuses to start without them.

For a throwaway local trial, `just up-test` starts the stack with the login off (it uses `docker-compose.ci.yml`). Never use that on a host that other people can reach.

```{note}
The API documentation pages (`/docs`) are off by default. To turn them on while you develop, set `API_ENABLE_DOCS=true` and restart the stack. Keep them off on any host that is reachable from outside.
```

## 3. Load demo data (optional)

The database is empty on the first start. Load demo data if you want the dashboard to have something to show before the first real attack arrives:

```bash
just demo
```

This generates synthetic attacks for the last 30 days. See [Demo data](demo-data.md) for the options.

```{warning}
Demo data is fake. Do not mix it with real captures. To start clean, stop the stack and delete the database volume. Deleting a volume removes all its data.
```

## Stop and clean up

| Command | Effect |
| --- | --- |
| `just down` or `docker compose down` | Stops the containers. Data volumes are kept. |
| `docker compose down -v` | Stops the containers. The data volumes are external, so Compose keeps them. Remove one by name only on purpose: see [Deployment](deployment.md#deleting-data-on-purpose). |

## Manual setup

Use this path if you do not want the installer, or if you want to set up every file yourself. It does the same things by hand.

### Get the code

```bash
git clone https://github.com/<your-account>/suckerpot.git
cd suckerpot
```

Use the URL of your own fork or of the project repository. To run a release instead of the latest code, add `--branch vX.Y.Z`.

### Create your `.env` file

Copy the template and edit it:

```bash
cp .env.example .env
chmod 600 .env
```

On the live install set `COMPOSE_PROJECT_NAME=suckerpot` and `SUCKERPOT_VOLUME_PREFIX=suckerpot` in your `.env` (the second names the data volumes; both are commented or placeholders in the template on purpose, see [Deployment](deployment.md)). Run `scripts/ensure-volumes.sh` once to create the volumes, or use `just up`, which does it for you.

Every `change-me` value must be replaced. Each secret must be at least 24 characters, and no two secrets may be equal. Generate each one separately:

```bash
openssl rand -base64 32
```

Also set the dashboard login: `SESSION_SECRET` (at least 32 bytes) and `ADMIN_PASSWORD_HASH` (make it with `docker compose run --rm api python -m api.hashpw`, and put it in `.env` in single quotes). See [Deployment](deployment.md#dashboard-login).

Choose your sensors with the `SENSOR_<NAME>` switches. A value of `0` turns a sensor off. The template turns all twelve on (the installer turns on six by default, so a hand-made `.env` runs more sensors). `NETWORK_ENABLED` is off unless you set it. See [Choosing the sensors](install.md#choosing-the-sensors-later) and [Configuration](configuration.md#install-updates-and-sensor-switches-m28).

The stack refuses to start with a short or repeated secret, and the error names the variable (never its value). Do not commit `.env` to git. The full list of variables is in [Configuration](configuration.md).

```{note}
Passwords and secrets are read by the containers at start-up. If you change one later, restart the stack with `docker compose up -d`.
```

### Start the stack

```bash
docker compose up -d --build --wait
```

`--wait` returns when every service is running and healthy. The first build takes a few minutes.

With `just`, the same command is:

```bash
just up
```

To check the state of the services:

```bash
docker compose ps
```

### Open the dashboard

Open the dashboard as described in [section 2](#2-open-the-dashboard). The port is set by `DASHBOARD_PORT` in `.env` (8443 in the template), and it binds to `DASHBOARD_BIND` (`127.0.0.1` by default).

## Next steps

- [Install SuckerPot](install.md): the installer, the sensor ports and the low-memory mode.
- [Updates and rollback](updates.md): how to update safely, and how to go back.
- [Deployment](deployment.md): the go-live checklist, the host firewall and secret rotation.
- [Sensors](sensors/index.md): what each fake service does and records.
- [Dashboard](ui.md): the pages and the screenshot mode.
- [Configuration](configuration.md): every setting.
- [Architecture](ARCHITECTURE.md): how the services fit together.
