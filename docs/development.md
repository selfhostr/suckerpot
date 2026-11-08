# Development

This page is for people who change the code. It explains the repository layout, the tools and how to run them. The tools run inside containers, so the host needs only Docker and `just`.

## Ground rules

- **English everywhere.** Code, comments, commit messages, docs and UI strings.
- **The repository is public.** Never commit `.env`, captured data, screenshots of real attacks, private IP addresses or host names. Use the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples.
- **Docker Compose only.** Every component is a service in `docker-compose.yml`.
- **Read the [Security](SECURITY.md) page** before you change a sensor, the network layout or a Dockerfile.

## Set up

1. Install Docker with the Compose plugin, and `just`.
2. Install the git hooks, once:

   ```bash
   scripts/install-hooks.sh
   ```

   The script installs `pre-commit` if it can, and falls back to a plain git hook. Both run `gitleaks` before each commit and block commits that contain secrets. The fallback installs a pinned `gitleaks` binary in `~/.local/bin`.

3. Create your `.env`, as described in [Getting started](getting-started.md).

## Common commands

All commands are `just` recipes. Run `just` with no arguments to list them.

### Stack

| Recipe | What it does |
| --- | --- |
| `just up` | Run the port guard, build the images and start the stack. Waits until everything is healthy. |
| `just up-test` | Start the stack with dashboard login **off**, through `docker-compose.ci.yml`. For tests and local trials only: the end-to-end recipes below need it. Never on a machine that other people can reach. |
| `just down` | Stop the stack. Data volumes are kept. |
| `just logs [service ...]` | Follow the logs. For example, `just logs ingest api`. |
| `just ps` | Show the state of the services |
| `just ports` | Run `scripts/check-ports.sh`: refuse a port layout that exposes the wrong thing (see [Deployment](deployment.md#port-guard)) |
| `just config` | Run the port guard, then check that `docker-compose.yml` is valid |
| `just psql` | Open a `psql` shell as the database owner, inside the database container. Maintenance only. |

### Backup and restore

| Recipe | What it does |
| --- | --- |
| `just backup` | Dump the database now into the `suckerpot_backups` volume (the `backup` service also does it daily, 7 kept). See [Deployment](deployment.md#data-volumes-and-backups). |
| `just backups` / `just backup-host` | List the dumps in the volume / dump into the host folder `./backups` (`BACKUP_DIR`, `BACKUP_KEEP`). |
| `just restore latest\|FILE\|volume:NAME` | Replace the whole database with a dump. Asks for confirmation. |
| `just up --force-empty` | Start even though the database volume is missing and dumps exist. Only to start from scratch on purpose. |

### Data and end-to-end checks

| Recipe | What it does |
| --- | --- |
| `just demo [args]` | Generate demo data. For example, `just demo --sessions 200 --days 3`. |
| `just demo-live` | Keep sending demo traffic until you press Ctrl+C |
| `just ssh-test` | Log in to the SSH sensor for real from a throwaway container, run two commands (one is a fake download), and wait until the session shows up in the API. The same script runs in CI. |

### Python

| Recipe | What it does |
| --- | --- |
| `just lint` | `ruff check` and `ruff format --check` on every Python package, then the web lint |
| `just fmt` | Fix and format the Python code with `ruff` |
| `just typecheck` | `mypy` (strict) on every Python package |
| `just test` | Unit tests of every Python package, then the web unit tests. Integration tests are skipped. |
| `just test-integration` | Integration tests against a real database and Redis. It uses its own throwaway Compose project (`<project>-it`) and removes its volumes afterwards, so your real data is never touched. |
| `just check` | Everything: `lint`, `typecheck`, `test` and `web-build` |

`just test-integration` runs `docker-compose.it.yml` on top of `docker-compose.yml`. The overlay keeps `redis` on the `backend` network only, and drops its per-sensor networks. So the throwaway project fits in Docker's default address pools, next to the live stack, which holds its own networks.

### Web

| Recipe | What it does |
| --- | --- |
| `just web-install` | Install the web dependencies from the lock file |
| `just web-lint` | `eslint`, `prettier` check and the TypeScript type check |
| `just web-test` | Unit tests (`vitest`) |
| `just web-build` | Production build into `web/dist` |
| `just web-dev` | Vite dev server on `http://127.0.0.1:5173` with mock data (Ctrl+C to stop) |

## Tooling runs in containers

The host needs only Docker and `just`. No Python, Node.js or database is installed on it.

- **Python.** `lint`, `typecheck` and `test` run in a pinned `uv` image, once per package, as your user. The virtual environments live inside the container, and the `uv` download cache lives in a Docker volume (`suckerpot-uv-cache`). Nothing is written to the repository.
- **Web.** The web recipes run in a pinned Node image, with `pnpm` enabled through Corepack. A Docker volume (`suckerpot-web-cache`) holds the Corepack and `pnpm` caches. The lock file is always installed with `--frozen-lockfile`.
- **Images.** Every base image is pinned to a version, so a build today and a build next month use the same tools.

## Repository layout

```
suckerpot/
├── docker-compose.yml      # all services, networks and volumes
├── justfile                # task runner
├── .env.example            # configuration template (placeholders only)
├── redis/                  # Redis image and the ACL entrypoint
├── sensors/
│   ├── common/             # suckerpot-common: the shared Event schema
│   ├── ssh/                # SSH sensor
│   ├── telnet/             # Telnet sensor
│   ├── adb/                # ADB sensor (Android TV box)
│   ├── web/                # web sensor
│   ├── docker/             # Docker Engine API sensor
│   ├── redis/              # Redis sensor
│   ├── mysql/              # MySQL sensor
│   ├── mssql/              # MSSQL sensor
│   ├── rdp/                # RDP sensor
│   ├── smb/                # SMB sensor
│   ├── sip/                # SIP sensor
│   └── synology/           # Synology NAS sensor
├── ingest/                 # suckerpot-ingest: consumer, writer, enrichment, rules/*.yaml
├── api/                    # suckerpot-api: FastAPI app
├── db/                     # suckerpot-db: SQLAlchemy models and Alembic migrations
├── web/                    # React app (design system in web/DESIGN.md)
├── scripts/
│   ├── demo/               # suckerpot-demo: demo data generator
│   ├── host/               # host firewall (nftables) and its systemd unit
│   ├── check-ports.sh      # port layout guard
│   ├── ssh-test.sh         # end-to-end check of the SSH sensor
│   └── install-hooks.sh    # git hooks (gitleaks)
└── docs/                   # this documentation site
```

All twelve sensors are in `docker-compose.yml`.

## Python packages

Each package has its own `pyproject.toml` and a committed `uv.lock`. The code targets Python 3.15. The tools are `uv`, `ruff` (line length 100), `mypy` (strict) and `pytest`.

| Directory | Distribution name | Import name | Purpose |
| --- | --- | --- | --- |
| `sensors/common` | `suckerpot-common` | `suckerpot_common` | Event model, stream helpers, Redis publisher |
| `scripts/demo` | `suckerpot-demo` | `demo` | Demo data generator |
| `db` | `suckerpot-db` | `suckerpot_db` | Models and migrations |
| `ingest` | `suckerpot-ingest` | `ingest` | Redis consumer, validation and database writes |
| `api` | `suckerpot-api` | `api` | REST API and live feed |
| `sensors/ssh` | `suckerpot-sensor-ssh` | `ssh_sensor` | SSH sensor |
| `sensors/telnet` | `suckerpot-sensor-telnet` | `telnet_sensor` | Telnet sensor |
| `sensors/adb` | `suckerpot-sensor-adb` | `adb_sensor` | ADB sensor |
| `sensors/web` | `suckerpot-sensor-web` | `web_sensor` | Web sensor |
| `sensors/docker` | `suckerpot-sensor-docker` | `docker_sensor` | Docker Engine API sensor |
| `sensors/redis` | `suckerpot-sensor-redis` | `redis_sensor` | Redis sensor |
| `sensors/mysql` | `suckerpot-sensor-mysql` | `mysql_sensor` | MySQL sensor |
| `sensors/mssql` | `suckerpot-sensor-mssql` | `mssql_sensor` | MSSQL sensor |
| `sensors/rdp` | `suckerpot-sensor-rdp` | `rdp_sensor` | RDP sensor |
| `sensors/smb` | `suckerpot-sensor-smb` | `smb_sensor` | SMB sensor |
| `sensors/sip` | `suckerpot-sensor-sip` | `sip_sensor` | SIP sensor |
| `sensors/synology` | `suckerpot-sensor-synology` | `synology_sensor` | Synology DSM sensor |

The recipes `just lint`, `just typecheck` and `just test` run over every directory in the `packages` variable of the `justfile`: all twelve sensors, `sensors/common`, `scripts/demo`, `db`, `ingest` and `api`. The CI `python` job uses the same list. Each package also has its own `pyproject.toml`, so you can run `uv sync`, `uv run ruff check`, `uv run mypy .` and `uv run python -m pytest` from its directory.

Every sensor has a `tests/test_static.py`. It reads the sensor's own code and fails on forbidden calls (`subprocess`, `eval`, `exec` and the like), on outbound sockets and on file writes outside the data folder. Several sensors also ship a `tests/blackbox.sh` script that runs real clients (such as `nmap`) against the sensor. Read the header of the script for the tools it needs.

Packages depend on each other by path. For example, `ingest` depends on `suckerpot-common` and `suckerpot-db`.

## Docker images

Every service image is built from a multi-stage Dockerfile:

- A pinned Python base image (`python:3.15.x-slim-trixie`).
- The `uv` binary copied from a pinned `uv` image.
- A final stage with a non-root user, no build tools and `PYTHONDONTWRITEBYTECODE=1`.
- A health check.

Build contexts are the repository root for the Python services, so that path dependencies resolve.

## Commits and branches

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(ingest): ...`, `fix(api): ...`, `docs: ...`, `chore: ...`.
- Keep commits small and focused.
- Work on a branch per milestone (`feat/m1`, and so on). Merge it into `main` when the milestone is done.

## Continuous integration

The GitHub Actions workflows run on every push and pull request to `main`:

| Workflow and job | Checks |
| --- | --- |
| `ci.yml`, `gitleaks` | Scans the full git history with `gitleaks` |
| `ci.yml`, `python` | Lint, type check and unit tests of each Python package |
| `ci.yml`, `web` | Install, lint, type check, unit tests and production build of the web app |
| `ci.yml`, `python-integration` | Integration tests against a real database and Redis |
| `ci.yml`, `compose` | Runs the port guard, builds the stack, checks the API health and the SSH sensor health, runs a real SSH login (`scripts/ssh-test.sh`), generates demo data, and waits until the API shows the stored sessions |

Dependabot keeps the pinned actions, base images and dependencies up to date.

The `compose` job is the only place where the placeholder secrets are allowed. It sets `SUCKERPOT_ALLOW_DEFAULT_SECRETS=1` in a throwaway `.env`, and moves the SSH sensor to another host port because the runner's own `sshd` uses port 22. Never copy that setting to a real host.

## These docs

The documentation is the Markdown in `docs/`. It reads on GitHub as it is, and it is published at https://suckerpot.selfhostr.io/docs/ by the shared selfhostr docs kit (Starlight), which lives outside this repository. The kit converts these files on each publish: the `{toctree}` blocks in `docs/index.md` become the sidebar, and MyST admonitions such as `{note}` and `{warning}` become callouts. Keep using that syntax, and link pages with relative `.md` paths.

## Before you commit

1. Run `just lint`, `just typecheck` and `just test`.
2. Read `git diff --staged`. Look for secrets, private addresses, host names and captured data.
3. Commit with a Conventional Commit message.
