# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Hub: public network observatory (design M34). With `HUB_OBSERVATORY_ENABLED=true` (off by default) the worker publishes `network.json` (schema `selfhostr-network-stats/1`, CC0) on the feed site once a day, independent of `HUB_FEED_MODE`: node counts, the bootstrap state against `HUB_MIN_NODES`, confirmations, reports and takedowns, attack traffic per day and the most targeted services, tags and malware families. Every figure is a network total from consensus-eligible nodes only, at day level, published with a delay, rounded, and coarse (weekly, one significant figure, small figures left out) while fewer than three eligible nodes contribute; outcomes are exact only with production consensus thresholds, and bootstrap figures are counted once a week. No per-node value appears. Caddy allows one browser origin to read it (`HUB_OBSERVATORY_ORIGIN`, default `https://suckerpot.selfhostr.io`, `GET` only).
- Hub migration `h0010`: `observatory_daily`, network-wide aggregates of each final day, counted once (the worker role cannot update them) and kept 400 days.
- CI job `licences`: fails when a Python (`uv.lock`) or web (pnpm) dependency has a licence outside the open-source allow-list (MIT, Apache-2.0, BSD, ISC, MPL-2.0, OFL-1.1, CC0, Unlicense, 0BSD, Zlib, BSL-1.0, LGPL/GPL/AGPL). `pnpm run licences` runs the web half locally.
- `scripts/install.sh --participant --lite` for a 1 GiB VPS or Raspberry Pi: a new `docker-compose.lite.yml` overlay (stacked after the low-memory overlay, recorded in `COMPOSE_FILE` so updates keep it) lowers the database and Redis limits, and the default sensors become SSH, Telnet, web and Redis. Total memory limit of the participant stack: 3,248 MiB by default, 1,936 MiB with the low-memory overlay, 1,424 MiB with `--lite`. No security setting changes; a new guardrail test only allows memory figures in the overlay, and the CLI guardrail renders it.
- `docs/vps.md`: join the network from a cheap VPS (no home address, no router change) with the steps to move admin SSH off port 22 first, including the `ssh.socket` case of Ubuntu 24.04 and newer, and a Raspberry Pi section (64-bit system, arm64 images).

### Changed

- The message broker is now Valkey 9.1 (`valkey/valkey:9.1.3-alpine3.24`, BSD-3-Clause) instead of Redis 8.10. It is a drop-in replacement: same protocol, same configuration and ACL file, same volumes and ports, and the Streams data is reused as is. The container now runs `valkey-server` and the health check `valkey-cli`.


## [0.10.0] - 2026-11-06

### Upgrading

- Images are rebuilt on Python 3.15 and Debian trixie: participants pull the new signed images as usual (`just update v0.10.0`), source installs rebuild with `docker compose up -d --build`.
- The database image moves to TimescaleDB 2.31, still on PostgreSQL 17, so the data volume is reused as is. An existing database keeps loading its current TimescaleDB extension version until `ALTER EXTENSION timescaledb UPDATE;` is run, which is optional.

### Changed

- Every dependency is upgraded in one go:
  - Python 3.13 -> 3.15 (`python:3.15.2-slim-trixie`) in every image, and uv 0.8.24 -> 0.13.7. The test and tooling image is `ghcr.io/astral-sh/uv:0.13.7-python3.15-trixie-slim` (uv no longer publishes bookworm variants), CI uses Python 3.15, and every package targets 3.15 (`requires-python`, ruff, mypy). Debian moves from bookworm to trixie in the Python and Node images. `ruff format` now writes `except A, B:` without parentheses (PEP 758), and string annotations are unquoted.
  - Every `uv.lock` is refreshed. Notable: asyncpg 0.32 (first release with Python 3.15 wheels), SQLAlchemy 2.1, redis-py 8 (RESP3 on the wire by default, same response shapes). The `db` package now allows `sqlalchemy <2.2` and `asyncpg >=0.32,<0.33`, `ingest` allows `redis <9`.
  - PyYAML has no Python 3.15 wheel yet: it is built from its source archive, without the libyaml C extension (pure Python, slower). It only reads rule and configuration files and writes small report documents.
  - Node 22 -> 26 in the web build stage and the justfile. Node 25+ no longer bundles corepack, so a pinned corepack (0.36.0) is installed first; it still provides the pnpm version from `packageManager` (pnpm 10.34.9).
  - Web: react-router 8, ESLint 10 and @eslint/js 10, TypeScript 6.0 (`baseUrl` removed, path aliases via `paths`), @types/node 26, jsdom 31, Playwright 1.65 (screenshot image `v1.65.0-noble`) and the latest minor of every other package.
  - Redis 7.4 -> 8.10 (`redis:8.10.3-alpine3.23`); the configuration and the ACL file are unchanged.
  - TimescaleDB 2.22.1 -> 2.31.0 (still PostgreSQL 17), gluetun v3.41.1 -> v3.41.3.
  - Hub: PostgreSQL 17.6 -> 17.11, Caddy 2.11.2 -> 2.11.9, Alpine 3.21 -> 3.24.
  - GitHub Actions: checkout v7, setup-uv v10, setup-node v7, pnpm/action-setup v6, upload-artifact v7, download-artifact v8.
- Dependabot runs monthly, with one entry per ecosystem over all its directories: minor and patch updates come as one grouped pull request per ecosystem, major updates as another.

### Fixed

- With TimescaleDB 2.31, the aggregate backfill run by `migrate` failed with SQLSTATE 55P03 when the hourly refresh policy ran at the same moment. It now retries with a short backoff.
- Ingest reads both reply shapes of `XREADGROUP` that redis-py 8 declares.
- API types follow SQLAlchemy 2.1, which types `Select` and `Row` by their columns.

### Deliberately held back

- The hub stays on PostgreSQL 17. PostgreSQL 18 images moved `PGDATA` and an existing hub database needs a `pg_upgrade` or a dump and restore, so the major upgrade is done by hand; Dependabot ignores PostgreSQL majors.
- TypeScript stays on 6.0: typescript-eslint, the lint toolchain, does not support TypeScript 7 yet (its peer range is `<6.1.0`). Dependabot ignores TypeScript majors until it does.
- pnpm stays on 10.x (latest 10.34.9); pnpm 11 and 12 are majors with a new lockfile and settings format, left for a separate change.

## [0.9.0] - 2026-11-04

### Added

- `./scripts/participant.sh ports-check [--wait SECONDS] [--since ISO | --since-install]` tells whether the internet reaches your sensors, and the participant installer runs it at the end and offers to re-check after you open the ports on your router. It makes no outside connection: it counts sessions from public addresses that your sensors already recorded, prints no address, reads the database in a read-only transaction, and exits 0 (reached) or 3 (nothing yet). `status.sh` points to it.

### Changed

- The participant installer no longer prints a fixed "14 days" date. The hub decides the probation period; `./scripts/status.sh` shows the date from which the sensor counts.
- Participant docs and installer summary: use port forwards rather than a DMZ, explain the DMZ risk, and say precisely when the route-out restriction holds (host firewall loaded) and that the firewall does not filter internet traffic to the machine's own services.

### Security

- Host firewall for participant mode: `scripts/host/firewall-participant.nft` loads with no placeholder other than the admin SSH port, rendered by `scripts/host/render-firewall.sh` and installed with `scripts/host/install-firewall.sh` (systemd unit, survives a reboot, `--uninstall` to undo). In its own nft table, it drops everything new, invalid or untracked from the sensors' uplink to the host and to the internet or the LAN, and limits `hubproxy`'s uplink to TCP 443 on public addresses plus UDP DNS to the resolvers Docker uses. The full-mode template's DNS rule is narrowed the same way. The renderer refuses a host bridge that is not Docker's but matches the rule names, to avoid a lockout.
- Every internal network has an isolated gateway (`gateway_mode_ipv4: isolated`), a fixed bridge name and IPv6 off, so a compromised container no longer reaches services on the host through its bridge. This needs Docker Engine 28 or newer, and the first update recreates the stack once (see `docs/updates.md`).
- A guardrail checks the hardening of every service of every supported stack: read-only root, all capabilities dropped, no-new-privileges, a non-root `uid:gid`, memory, CPU and process limits, a healthcheck, `noexec,nosuid,nodev` tmpfs, no host namespaces, devices, Docker socket or unlisted bind mounts, isolated internal networks, and third-party images pinned by digest.
- The TimescaleDB image is pinned by digest.
- The installers offer to install the host firewall at the end (participant mode; asks before using sudo, never blocks, prints the two commands otherwise; `participant.sh vpn` reminds you to re-run it), and `./scripts/participant.sh firewall [install|uninstall|status]` does it later.
- Updates and rollbacks recreate the stack once (`down --remove-orphans`, never `-v`) when compose says an existing network cannot be reused (matched on its wording, not on any mention of a network); a foreign container attached to one of our networks stops the run with instructions instead of being disconnected.
- CI pins the TimescaleDB test image by digest, like `docker-compose.yml`.
- Automatic updates: the minimum release age is now at least 48 h whatever the release's own manifest says; `AUTO_UPDATE_MIN_AGE_H` in `.env` can raise it.
- Automatic updates: a release that is unsigned, does not match its tag or has a signature cosign rejects is marked bad with its reason (network, Docker, Sigstore or disk problems are never held against a release) and the next newest release of the same major version is tried (3 at most per run), so one bad tag no longer blocks updates.
- The installer warns when Docker Engine is older than 28, where internal networks are not isolated from the host.

## [0.8.0] - 2026-11-04

### Changed

- The offline mock-data demo moved to https://suckerpot.selfhostr.io/demo/. GitHub Pages and `site/` are removed from the repo (the product site is maintained separately).
- Documentation moved from Read the Docs to https://suckerpot.selfhostr.io/docs/ (Selfhostr docs kit, Starlight). `.readthedocs.yaml`, `docs/conf.py`, `docs/requirements.txt` and the Sphinx CI job are removed; `docs/` stays the source.
- The project moved from `github.com/Theroxat/suckerpot` to `github.com/selfhostr/suckerpot`. Release images are now published as `ghcr.io/selfhostr/suckerpot-*` and signed by the release workflow of the new repository, and the documentation is at `https://suckerpot.selfhostr.io/docs/`. `scripts/env-migrate.sh` rewrites the old default `SUCKERPOT_IMAGE_PREFIX` and `UPDATE_CHECK_REPO` in an existing `.env`; the signature checks are as strict as before (exact repository, `release.yml`, exact tag). An install on v0.7.1 verifies releases against the old repository, so its first update needs `SUCKERPOT_IMAGE_PREFIX=ghcr.io/selfhostr/suckerpot` set in `.env` by hand; see `docs/updates.md`.
- The network is now called the SuckerPot network, and the blocklists the SuckerPot blocklists. Selfhostr is the small organisation that makes SuckerPot, no longer the name of the product or the network.
- New addresses: the site is `https://suckerpot.selfhostr.io/` (hosted on Cloudflare Pages), the hub is `https://suckerpot-hub.selfhostr.io` and the feeds are `https://suckerpot-feeds.selfhostr.io/v1`. The old `selfhostr.io` site, `hub.selfhostr.io` and `feeds.selfhostr.io` are gone. Nodes pick up the new hub address with the next release; the hub keys are unchanged. `abuse@selfhostr.io` stays.

## [0.7.1] - 2026-11-04

### Fixed

- Settings → Network said "No network hub is configured" and greyed out the join button on installs whose `.env` does not set `NETWORK_HUB_URL`, which is every install made by the installer. The dashboard now uses the hub address and key shipped with each release, like ingest already did.
- Clicking Join again while a join is pending showed "The change could not be made". It now says the system has already asked to join and refreshes the page.
- A new node's standing no longer promises "two weeks": the hub's thresholds are configurable, so the page points to the Eligibility date instead.

## [0.7.0] - 2026-11-04

### Added (M33)

- The network is on by default. The full installer asks "Join the Selfhostr network? [Y/n]" (default yes; `--no-network` declines) and the node joins at first start, through the VPN only. Design: [M33](docs/design/m33.md).
- Joining in the dashboard is one button: the dialog lists what is shared and asks for your password. Leaving is one button, and a node that left can join again. Setup step 8 has the join button.

### Fixed

- The setup wizard's sensor list timed out on busy systems. It now reads the newest event per sensor from the index.

### Upgrade note

- The network feature is now on by default (`NETWORK_ENABLED=true`). When you update an install that was made before this change and its `.env` has no active `NETWORK_ENABLED` line, the update adds `NETWORK_ENABLED=false` (and a `NETWORK_DEFAULT_PINNED=1` marker), so nothing changes for you. To use the network, run `just set NETWORK_ENABLED=true` and join in the dashboard.

### Changed

- The installer consent record is spent after 7 days: ingest joins from it only within 7 days of its date, so restoring an old database cannot undo a leave. `just set NETWORK_CONSENT=` (empty value only) clears the record. `SELF_TERMS_AUTO_CONFIRM` only applies in participant mode.
- The installer's network question treats end of input as an error, not as a yes. `--yes` also joins the network unless `--no-network` is given.

## [0.6.0] - 2026-11-03

### Added (M32)

- Participant mode (M32). `./scripts/install.sh --participant` installs sensors, database, ingest and the network node only: no dashboard, no admin account, no wizard, no API key and no VPN needed. Choosing it is the consent to join; a random pseudonym is generated. Three commands, then open the printed ports. Guide: [Join the network](docs/participate.md). `--full` switches an existing participant install to the full product and keeps its data.
- `hubproxy` (profile `direct`, M32): a small allow-list proxy that lets a participant without a VPN reach the hub and nothing else. Ingest keeps no route out. The overlay is `docker-compose.participant.yml`.
- Honest privacy note: without a VPN the hub, and a tunnel provider in front of it, see the participant's home address. The hub never stores it. A VPN can be added at any time with `./scripts/participant.sh vpn <file>`.
- `scripts/participant.sh` (`status`, `leave`, `join`, `vpn`, `auto-update`, `uninstall`) and `scripts/status.sh` (sensors, network state, what was sent, updates; exit codes 0, 1, 2; `--json`, `--last-batch`).
- Automatic signed updates (M32). A daily job in the user's crontab runs `scripts/auto-update.sh`: it verifies a signed release manifest and the image signatures, accepts only releases at least 48 hours old and of the same major version, takes a backup, and rolls back and blocks a release that fails. On by default in participant mode, off in full mode. Turn off: `./scripts/participant.sh auto-update off`. A compromised release channel would reach every auto-updating participant. See [Updates](docs/updates.md#automatic-updates).
- Verifier nodes (M32). When two nodes report the same download link, the hub can ask a verifier to fetch it through its VPN and attest its hash, size, type and family. The role is opt-in on the node and granted by the hub operator. An attestation never counts as a sighting.
- The hub address and key ship inside each release, with a key rollover that auto-updating participants follow.
- Documentation: [Join the network](docs/participate.md) (new), participant mode in [Install](docs/install.md), participants and verifiers in [The network](docs/network.md), a "Help the network" section on the project site.

### Added

- Community blocklist feeds (M30). The hub publishes five free, signed lists for firewalls: `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`. They come as plain text (IPv4 and IPv6 files too), nftables, ipset, MikroTik, CSV, JSON and STIX 2.1. An entry needs observations from at least five independent sensors (k-support). Inbound entries need TCP evidence. Outbound entries need a fetched payload with a known malware family, or a high-confidence command server seen in two samples. Tor exit relays, CDN ranges, public resolvers and shared hosting names are never listed. A hold, expiry, size caps and a change breaker sit between the data and the files. Every file is signed with minisign, with a feed key that is separate from the hub key. The hub feed is off by default (`HUB_FEED_MODE=off`). Operators: [hub/README.md](hub/README.md#public-feeds). Users: [Community blocklist feeds](docs/feeds.md), with steps for OPNsense, pfSense and pfBlockerNG, nftables, ipset, MikroTik, MISP and DNS filters. The lists are CC0 1.0.
- Delisting and lookup (M30). Anyone can ask for a removal through a form, or the API, with a small proof-of-work puzzle. Requests get a decision target of 72 hours. An inbound value is hidden until the decision, within a daily cap. Outbound values wait for review. `GET /v1/lookup` answers `listed`, `removed` or `not_listed` for one value. Migration `h0005` (hub database).
- Node side of the community lists (M30). `NETWORK_FEED_ENABLED` (off by default) fetches the public lists through the VPN gate, independent of membership. A file is stored only after its signature, its serial (no rollback), its expiry and its sha256 check out. Migration `0029` (node database). The Blocklists page has a Network tab with the state, one card per list, copy-URL menus, a filterable table and a plain "why join" card. API: `GET /api/v1/network/feed/status` and `/entries`.
- Local mirror of the community lists (M30). With `FEEDS_ENABLED=true` and a token of kind `network`, a firewall can fetch the entries that the node verified from its own dashboard, as text or CSV. Overrides still apply, and the mirror is empty when the lists are stale.
- `scripts/feeds/fetch-verify.sh` (M30): a short POSIX shell script that downloads `index.json` and a list, verifies both with `minisign`, checks the sha256 and replaces the local file only after every check passed.
- Documentation: [Community blocklist feeds](docs/feeds.md) (new), with the Network tab in [Defend](docs/defend.md), the network section in [The Selfhostr network](docs/network.md), the threat model in [Security](docs/SECURITY.md#community-lists-m30), the settings in [Configuration](docs/configuration.md#community-lists-m30) and the endpoints in [API](docs/api.md#community-lists-m30).
- Replies to reports (M26): Selfhostr can read the answers to your abuse reports from a dedicated mailbox, through the VPN only. Replies are matched by a reference in the subject, by Message-ID (only from parties you wrote to), by delivery failure notices, by ticket number or by sender domain, and are verified before they change an outcome (DKIM or DMARC with the trusted provider name, or your confirmation). Each reply is classified (resolved, rejected, ticket opened, automatic receipt, bounce, answered by a person, or not understood). Mail is only marked as read or moved, never deleted. Replies can also be pasted or uploaded as `.eml`, with no mailbox. Off by default (`ABUSE_REPLIES_ENABLED`). Migration `0026`, `/api/v1/abuse/imap`, `/api/v1/abuse/replies` and `/api/v1/abuse/outcomes`. See [Replies to reports](docs/replies.md).
- Results page (M26, M27): "did anyone answer", how fast providers answer, reports over time and a provider table, with one plain sentence per card. The **Results** and **Submissions** tabs sit next to **Reports** in the Abuse reports hub.
- Takedown tracking (M27): the collector re-checks each reported payload URL with one bounded GET through the VPN (only URLs that already served a sample; C2 servers and attacking addresses are never contacted). The worker follows the targets with passive signals and URLhaus, ThreatFox and AbuseIPDB lookups within quotas. Each target gets a state (still serving, serving a new file, down, active, quiet, unknown), and the Results page shows the share taken down within 48 hours, 7 days and 30 days, with right-censoring, and the median time to takedown. Off by default (`TAKEDOWN_ENABLED`). Migration `0027`, `/api/v1/takedown/*`. See [Takedowns](docs/takedowns.md).
- abuse.ch submission (M27, optional): captured malware URLs can be submitted to URLhaus, and C2 `ip:port` addresses to ThreatFox, after a lookup that the value is not already known. Off by default, twice: the server switch `ABUSECH_SUBMIT_ENABLED` and a mode in Settings (Off, Review each, Automatic). The submission Auth-Key is stored encrypted and is write-only. The body passes the identity check and is delivered at most once. The abuse.ch answer codes are not yet confirmed against a live answer.
- Installable Selfhostr (M28). Install with one command from a release tag: `./scripts/install.sh` (also `just install`). The installer checks the machine, asks a few questions, creates every secret on the host, writes `.env` (mode `0600`), creates the data volumes and starts the stack. It never overwrites `.env`, never adopts existing volumes and never looks up the public address. Guide: `docs/install.md`.
- Two install modes: signed release images (default) and a build from the checkout (`--source`).
- Sensor switches `SENSOR_<NAME>` (default `1`). Choose the sensors with `just sensors`, or change any allowed setting with `just set`. The port guard follows the selection.
- First-run setup in the dashboard (`/setup`, migration `0025`): welcome, sensors, ports, VPN, own address, abuse reports, alerts and a checklist. It can be skipped, finished later and opened again from Settings. Settings has a new "Sensors & ports" tab with the router port and the state of each sensor.
- Safe updates: `just update` takes a database dump first, records how to roll back and checks the health of the new version. An update that did not finish blocks the next one until `--force` or a rollback. `just rollback` restores the previous code, images and database after confirmation. Guide: `docs/updates.md`.
- Signed images: the release workflow publishes amd64 and arm64 images on version tags, signs them with cosign (keyless) and runs an install smoke test. `scripts/verify-images.sh` checks the signatures, and the installer and the updater refuse to run an image that does not verify (fail closed).
- Low-memory mode (`docker-compose.lowmem.yml`) for machines of about 2 GiB.
- The running version is shown in the dashboard. An optional daily update check (`UPDATE_CHECK_ENABLED`, off by default) asks GitHub through the VPN only, sends no version or identifier, and never installs anything.
- VPN idle mode: the egress profile starts before a WireGuard file is uploaded. The tunnel stays closed, with no route out, until a configuration is uploaded or passed to the installer.
- The Selfhostr network (M29): an opt-in, anonymous pool of what many Selfhostr sensors see. Joining needs `NETWORK_ENABLED=true` in `.env` (`just set NETWORK_ENABLED=true`) and an administrator's join in Settings, Network, with the password typed again and five consents ticked. Nothing is sent before both. A member's batch carries attacker addresses, rounded counts, blinded download links, malware hashes and command servers, never credentials, commands, ports, exact times or anything of the member's own. A target is confirmed only by consensus of at least five eligible nodes. Leaving deletes the node's data at the hub. Documented in [The Selfhostr network](docs/network.md), [Network protocol](docs/network-protocol.md) and [configuration](docs/configuration.md#suckerpot-network-m29).
- The Network pages: Overview and Members under Defend, a Network tab in Settings, a Network item in the setup checklist and an optional Network step in the first-run setup. The pages show what the network did in the last 30 days and what the sensor helped confirm.
- The hub (`hub/`): the server of the network, deployed separately with its own compose file, Caddy, PostgreSQL, daily backups and an operator CLI. It keeps no client address. It sends grouped abuse reports for confirmed targets, one review at a time by default. Command-server reports are never sent automatically. See [hub/README.md](hub/README.md).
- The `spn/1` protocol library (`netproto/`): Ed25519 request and answer signatures bound to the whole request, replay protection, blinding of links and domains, proof of work for enrolment, and golden test vectors.
- Migration `0028` (node database): membership, submissions, the network's targets and summary, with their roles and retention.

### Known limits

- Network takedown checks are not active yet. M27's local re-checks exist, but the network adapter (`ingest/ingest/network/takedown.py`) does not read them yet, so members send no re-check results and no network target becomes taken down for now.

### Changed

- `docs/deployment.md` "Upgrading" now points to `just update`. The old `git pull` and `docker compose up` steps are replaced.
- Renamed to Selfhostr. The product name in the dashboard, documentation and exported reports changes; technical names (packages, volumes, environment variables, database roles) keep the `suckerpot` prefix so existing installs and data are unaffected.
- Abuse report wording is now optional (owner decision of 2026-11-01). Only the reply contact is required. An empty introduction, closing, note or signature is left out of every rendering (text, X-ARF, `.eml`), an empty subject template gives `Abuse report for <address>`, and an empty X-ARF user agent gives `Mozilla/5.0`. The `custom_intro_required` gate on marking a report reviewed is gone, and the report detail answers `missing` instead of `custom_intro`. The setup checklist item is green once the reply contact is set. The `default_wording` identity check still refuses text that equals wording published earlier.

## [0.5.0] - 2026-11-01

### Added

- Sending abuse reports (M25): a "To send" queue on the Abuse reports page opens each ready report in the mail app (the full text is copied to the clipboard), then marks it sent and moves on, with keyboard shortcuts. Free Proton addresses have no SMTP access, so this is the way to use them.
- Optional SMTP for reports, configured in Settings > Reporting > Sending (password encrypted and write-only, re-authentication, a preset for Proton paid plans with a custom domain). Three modes: off (the default: nothing is ever sent), send on click, and automatic after a waiting time with Cancel and a daily cap. Mail leaves only through the VPN, after a last identity check on the complete message (headers, envelope, EHLO name and every part); with the tunnel down nothing is sent. Delivery is at most once: a send whose outcome is unknown is never retried. Migration `0022`, `/api/v1/abuse/smtp`, `/api/v1/abuse/send-queue` and `/api/v1/abuse/reports/{id}/send`.

### Changed

- Alerts (email, Discord, Teams) now go through the identity check too: the honeypot's own addresses and terms are masked, and alerts pause until the owner's own address is confirmed in Settings > Reporting.
- The SMTP EHLO name of alert emails is the sender's domain, never the container's host name.

## [0.4.0] - 2026-11-01

### Added

- Guided tour (M24): a seven-step tour opens on each account's first login and can be replayed from the "Tour" button in the top bar. It explains daily reading, campaigns and tools, how payloads are fetched and analysed without ever being run, the VPN and its kill switch, abuse reports and alerts, each with a small flow diagram.
- Page help: a "?" next to every page title says what the page shows, where its data comes from and one useful action.
- Setup checklist: `GET /api/v1/setup/status` and a card in Settings > General (and the tour's last step) show, from the real state, what is done and what is left: sensor traffic, the outbound gate, the payload collector, report wording, your own address, abuse report drafts, alert channels and reputation keys.
- VPN tab: "Check now" asks the gate to re-check at once (`POST /api/v1/settings/vpn/check`, table `egress_check_requests`, migration `0021`) and "Reconnect" restarts the tunnel after asking for the password again (`POST /api/v1/settings/vpn/reconnect`, a marker file the `vpn` entrypoint watches).

### Changed

- While the egress gate is closed it re-checks every 20 seconds (for ten tries, then at the normal interval) instead of waiting the full interval, so lookups resume within a minute after a tunnel restart.

### Fixed

- Two flaky tests: the auth event-loop check and the collector table reset.

## [0.3.0] - 2026-11-01

### Changed

- `just test-integration` uses `docker-compose.it.yml`, an overlay that keeps `redis` on the backend network only, so the throwaway project fits in Docker's default address pools next to the live stack.
- The sidebar is grouped into ten entries. Related pages sit behind one entry with tabs: Attacks (Sessions, Attackers, Networks), Campaigns (Campaigns, Techniques), Tools (Scripts, Malware, Infrastructure), Trends (Activity, Patterns), Protection (Blocklists, Detections) and Exposure (Your exposure, CVE watch). Every old URL still works; `/attackers?view=asns` now redirects to `/networks`.
- Today is a visual story of the last 24 hours in plain words: a flow from country to service to how far each visit got, an hour-by-hour strip, and three to five stories of the day with their technical details one click away. Hard words have a short definition on hover.

### Added

- VPN configuration upload (M23): Settings > VPN takes the WireGuard `.conf` from your VPN provider, parses it strictly (no `PostUp` and the like, IP endpoint only, full tunnel) after asking for the password again, and writes it to the new `vpn-config` volume. The `vpn` service notices the new file and restarts on it; nothing leaves outside the tunnel during the switch, and the API gets no Docker socket. A new exit address stays blocked until the owner trusts the /24 the gate observed (table `egress_trusted_exits`, migration `0020`); an exit inside the honeypot's own addresses or in an AS listed in the new `EGRESS_DENY_ASNS` can never be trusted, and the exit's AS is shown next to it. `/api/v1/settings/vpn` endpoints, new guardrails.
- Anonymous reporting (M22): an ingest worker (`ABUSE_REPORTS_ENABLED`, off by default) finds abuse contacts over RDAP through the egress gate and prepares draft reports per recipient. The new `reporting/` package renders plain text, X-ARF v0.2, `.eml`, STIX 2.1 and MISP JSON and builds password-protected sample bundles. An identity guard checks every artefact before it is returned and fails closed. Learned self terms need the owner's confirmation. The package ships no wording: the owner writes it in Settings > Reporting. Nothing is ever sent by the stack. Migration `0019`, `/api/v1/abuse` endpoints, the Abuse reports page, Export for CERT, the sample bundle and the Reporting tab in Settings, `just abuse-guard-check` and the `ABUSE_*` settings.
- Anonymous egress (M21): a `vpn` service (WireGuard through gluetun, profile `egress`) with a kill switch and an HTTP proxy is the only container with a route to the internet. `ingest` and the new `collector` go through the proxy, an egress gate pauses outbound work when the tunnel or its exit address looks wrong, and the old `egress` network is removed. New `just guardrails` and `just egress-check`, new host firewall rules for `sp-vpn`, `sp-egress` and `sp-samples`.
- Payload collection and static analysis (M21): the `collector` service fetches captured download URLs through the VPN into a quarantine volume (SSRF validator, size, time and rate caps, never executed), and the network-less `analyzer` service identifies, hashes, scans with YARA, deobfuscates shell scripts and extracts C2 addresses in a limited child process. Migration `0018`, roles `suckerpot_collector` and `suckerpot_analyzer`, the `/api/v1/samples` and `/api/v1/egress` endpoints, a Samples tab, a sample page and an Egress card in Settings. `FETCH_PAYLOADS`, `PAYLOAD_MAX_BYTES` and `PAYLOAD_TIMEOUT_SECONDS` are replaced by `COLLECTOR_ENABLED` and the `COLLECTOR_*` and `QUARANTINE_*` settings.
- Synology NAS sensor (M20): a fake unpatched Synology NAS on DSM 7.2.1 (Update 11), with the DSM login page and Web API on HTTP 5000 and HTTPS 5001. Logins always fail with real DSM error codes and are recorded. Requests that match the forged-session and SCGI shapes of CVE-2026-13639 and CVE-2026-13684 are tagged `synology-exploit`, ransomware indicators of the C3RB3R campaign are tagged `c3rb3r`, and DSM API calls are tagged `synology-dsm`. Migration `0017` adds the sensor to the inventory.
- Probable C2 lookups ignore VirusTotal contacts in big shared networks (Google, Cloudflare, Microsoft, Akamai, Fastly, Meta, Apple, from the local ASN database) and CDN or update domains, and clean up already stored rows on start.
- Probable C2 addresses: for file hashes that VirusTotal or abuse.ch already know, ingest reads which addresses sandboxes saw the malware contact (VirusTotal relationships, ThreatFox `botnet_cc`), with the same fixed hosts, quotas and 24 h cache as the other intel lookups and no contact with the addresses. New table `indicator_contacts` (migration 0016), `GET /api/v1/indicators/c2`, and a blocklist reason "probable C2" (75 for ThreatFox, 40 for VirusTotal, capped at 45 when no sensor computed the hash and fewer than three networks dropped it).
- `GET /api/v1/story`, the plain-language summary behind Today.
- A `stage` filter on `GET /api/v1/sessions` and on the Attacks page (looked, guessed, got in, ran commands, tried to install, sent an exploit), plus `since` and `until` in the Attacks URL.

### Fixed

- The abuse, alerts and intel workers no longer wait up to an hour for their first run on a host that booted recently.
- CVE watch: the NVD window is 60 days (was 30) and is read in one-day chunks, oldest first, with a page budget, so a busy day no longer loses CVEs silently at the 10,000-result limit. A run that stops early resumes from its last complete chunk.
- CVE watch: GitHub advisories are read in seven-day chunks, oldest first. A one-time start-up rewind refills a shallow history, and watched CVEs that are missing from the table are fetched by id (at most 10 per run, once per id per 24 hours).

### Docs

- A "Provider API keys" guide: what each optional key adds and how to get it, step by step.
- A Troubleshooting section in the deployment guide, and the upgrade command.
- Refreshed screenshots and a new README gallery for the three-space navigation.

## [0.2.0] - 2026-10-26

### Added

- Seven more sensors (M9): Redis, Docker Engine API, MySQL, Microsoft SQL Server, Android ADB, SMB and SIP (UDP and TCP), each with real-client tests, per-IP fairness for CPU, memory and events, and a security review. SIP never sends a reply larger than its request.
- Provider keys in Settings (M11): AbuseIPDB, GreyNoise and MaxMind keys stored encrypted (AES-256-GCM), write-only in the UI, with re-authentication and a "Test key" button.
- CVE watch (M12): daily CISA KEV, NVD and GitHub advisory feeds ranked by relevance to the emulated services, with "seen in our traffic" counts and a trap-proposal sheet.
- Indicators and threat intelligence (M13): URLs, domains, IPs and hashes extracted from events, enriched by URLhaus, ThreatFox and VirusTotal, shown on an Infrastructure page with CSV and STIX export. Passive only.
- Users and roles (M14): admin and read-only viewer accounts, one-time temporary passwords, per-source lockout and an audit log. The `.env` owner account stays the root of trust.
- Campaigns and MITRE ATT&CK (M15): sessions that share a script, payload host, hash, malware family, exploit or credential list are grouped into campaigns, with a Techniques heatmap. Off by default (`CAMPAIGNS_ENABLED`, `ATTACK_ENABLED`).
- Defend (M16): scored blocklists, overrides, exports for OPNsense and pfSense aliases, an opt-in token feed (`FEEDS_ENABLED`), Sigma and Suricata rules marked "review before deploying", and "Your exposure".
- Script library (M17): command scripts with plain-English explanations, and an optional LLM explainer (`LLM_ENABLED`, off by default) that sees only normalised script text.
- Alerts and reports (M18): Discord, Microsoft Teams and e-mail (TLS) channels, alert rules that are off until switched on, a test message button, and a weekly report with a printable view. Off by default (`ALERTS_ENABLED`, `REPORTS_ENABLED`).
- Today, search and research scanners (M19): a Today home page, a global search box, a glossary, and known research scanners labelled benign by network ownership.
- Migrations `0011` to `0015` add the campaign, ATT&CK, Defend, script, alert and search tables and columns.

- RDP sensor (M10): the NTLM challenge flow, so `nmap --script rdp-ntlm-info` returns the full Windows Server 2022 identity and logins arrive as `rdp-ntlm` events with the user name and domain.
- RDP decoy accounts (`RDP_ACCOUNTS`): a login with a decoy password is verified against the NTLM response and tagged `weak-credentials`. Nothing else is ever checked.
- Optional NLA-off mode (`RDP_NLA_MODE=optional`, off by default): records the cleartext user name and password from clients that skip NLA (`rdp-nla-off` events), tagged `rdp-cleartext`.
- RDP client tool identification (nmap, FreeRDP, rdesktop, ncrack, mstsc), stored on sessions as `client_tool` and shown on the session page.
- Tag `bluekeep` for RDP sessions that bind the `MS_T120` channel.
- RDP limit `RDP_MAX_TLS_PER_IP` (default 4), so a few addresses cannot hold every TLS slot.

### Changed

- Migration `0007` adds the nullable `sessions.client_tool` column.
- Live page: the 3D globe is replaced by a flat world map (Equal Earth) with per-country arcs for the last 15 minutes, a stats strip, a ticker of the newest events and rankings of addresses, countries and networks. `SITE_HOME_LAT`, `SITE_HOME_LON`, `SITE_HOME_LABEL` and `GET /api/v1/settings/site` are unchanged.

## [0.1.0] - 2026-10-25

### Added

- Bootstrap (M0) and foundations (M1): MIT licence, project rules, roadmap, architecture and security docs, a gitleaks pre-commit hook and CI; the shared event schema, a Redis Streams pipeline, a TimescaleDB schema with Alembic migrations, an ingest consumer and an API with a live WebSocket feed.
- Demo data generator (`just demo`): synthetic sessions across all four sensors with documentation IP ranges only, plus a live mode.
- SSH sensor: OpenSSH 9.6 fingerprint, configurable weak logins, an emulated shell on a fake filesystem, download recording without fetching, and timed session recording for replay.
- Telnet sensor: BusyBox telnetd look-alike with Mirai-style flows.
- Web sensor: byte-identical Apache 2.4.58 with PHP 8.3, fake WordPress and phpMyAdmin pages, and PHP2Shell (upload-progress) detection.
- RDP sensor: Windows Server look-alike with NLA and username capture.
- Enrichment: GeoIP and ASN from DB-IP Lite (no key) or MaxMind GeoLite2, optional AbuseIPDB and GreyNoise Community reputation with a 24 h cache and enforced daily quotas.
- Tagging: a declarative YAML rules engine without regular expressions (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).
- Dashboard: Live (3D globe and event feed), Overview (KPIs and auto-written insights), Attacks, Session detail with terminal replay, Attackers, Trends, Malware (defanged URLs) and Settings, in dark and light on desktop and mobile; a design system; a screenshot mode (`?mask=1`); Playwright screenshots.
- Dashboard login: a single admin account with an argon2 password hash, CSRF protection and a rate-limited login.
- Retention and storage: raw events kept 90 days, aggregates forever, compression, a disk guard, and `just backup` / `just restore`.
- Hardened Docker Compose stack with a host firewall template in `scripts/host/`.
- Documentation site (Sphinx, Read the Docs) and a project page.
- Repository meta: README, `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates, Dependabot and release-note configuration.

### Security

- No attacker input is ever executed: every sensor passed several rounds of adversarial security review (the web sensor's final review is pending).
- Isolation: four networks with an internal backend, one Redis ACL user per sensor limited to `XADD` on its own stream, least-privilege database roles, no outbound route for the API, non-root read-only containers with all capabilities dropped.
- The first review of the M1 stack found unbounded stream growth, egress, poison-message and default-credential issues; all were fixed and the second pass passed.

[Unreleased]: https://github.com/selfhostr/suckerpot/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/selfhostr/suckerpot/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/selfhostr/suckerpot/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/selfhostr/suckerpot/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/selfhostr/suckerpot/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/selfhostr/suckerpot/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/selfhostr/suckerpot/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/selfhostr/suckerpot/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/selfhostr/suckerpot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/selfhostr/suckerpot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/selfhostr/suckerpot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/selfhostr/suckerpot/releases/tag/v0.1.0
