# Progress log

Newest entries at the bottom. One entry per milestone or significant step: date, what was done, what is left.

## 2026-10-24 — M0 Bootstrap

- Created `.gitignore` first, then `CLAUDE.md`, project subagents in `.claude/agents/`, roadmap, architecture and security docs, README skeleton, MIT licence and `.env.example` (placeholders only).
- Added a gitleaks pre-commit hook (`scripts/install-hooks.sh`, custom rule for private IPv4 ranges) and a CI workflow (gitleaks over full history, Python/web lint and tests, compose config check).
- Left open: CI to be confirmed green on GitHub; secret scanning and push protection to be enabled in the repo settings by the owner.

## 2026-10-24 — M1 Foundations

- Shared Event schema and Redis publisher (`sensors/common`), demo generator (`scripts/demo`: ~3,000 realistic sessions over 30 days across SSH, Telnet, Web and RDP, plus a live mode).
- TimescaleDB schema with Alembic (events hypertable, sessions), least-privilege roles for ingest and the API with statement timeouts.
- Ingest: Redis Streams consumer, batched writes and session upserts, stream trimming after ACK, dead-lettering of poison messages.
- API: sessions, events and summary endpoints with keyset pagination; the live WebSocket feed and SPA serving (early M3 backend work) with security headers.
- Compose stack with four networks, Redis ACL users (admin, sensor, ingest, health), full container hardening and no added capabilities; justfile; CI with lint, typecheck, unit and integration tests and a full compose smoke test.
- Documentation site (Sphinx + MyST, Read the Docs config).
- Security review: first pass FAIL (unbounded stream, egress, poison messages, defaults), all fixed; second pass PASS. Remaining low/medium follow-ups are listed under M2.
- Verified: all services healthy, demo data end to end, WebSocket live feed, only the dashboard port published (loopback by default).

## 2026-10-25 — M2 to M7, most of M8

- Sensors: SSH (OpenSSH 9.6 fingerprint, emulated shell with fake filesystem, terminal replay), Telnet (BusyBox telnetd, Mirai flows), Web (Apache 2.4.58 + PHP 8.3 byte-identical error pages, WordPress/phpMyAdmin, PHP2Shell detection), RDP (Windows NLA, username capture). Each has its own ingress network without NAT, internal network to Redis, Redis user limited to XADD on its stream, watchdog, cgroup memory guard and per-connection/IP/global budgets.
- Security reviews: SSH 4 passes, Web 4 passes, Telnet 2, RDP 2, auth 1 — all PASS. No path executes attacker input.
- Pipeline: per-sensor streams, multi-stream ingest with never-trim-past-pending, enrichment (DB-IP Lite or MaxMind, AbuseIPDB/GreyNoise with quotas), regex-free YAML tagging, publisher byte backstop, retention (90 d raw, compression, continuous aggregates) and disk guard.
- API and UI: analytics, insights, trends, malware, settings, single-admin auth (argon2, CSRF, rate limits); pages Live (3D globe), Overview, Attacks, Session detail with safe terminal replay, Attackers, Trends, Malware, Settings, login; screenshot mode.
- Ops: backups, host firewall template, port guard, CI overlay, Sphinx docs, project page and offline demo for GitHub Pages.
- Left for v0.1.0: owner actions (firewall, disk, GitHub Pages/RTD/secret scanning), then the release.

## 2026-10-25 — M9 Seven more sensors

- Sensors: Redis 7.2 (6379), Docker Engine API 27.3 (2375), MySQL 8.0 (3306), SQL Server 2019/2022 with TLS inside PRELOGIN (1433), Android ADB TV box (5555), SMB2/3 with NTLM capture and SMB1 disabled (445), SIP/Asterisk over UDP and TCP (5060). Each tested with real clients (redis-cli, docker CLI, mysql/PyMySQL/hydra, impacket/sqlcmd, adb, smbclient, sipsak/SIPVicious) and nmap.
- New sensor contract lessons 16–18: wall-clock CPU budgets with per-IP buckets, pending output charged to the memory budget, per-IP event fairness with a priority path and a disconnect reserve. SIP never sends a reply larger than its request (measured amplification under 0.001 during a flood).
- Security reviews: Redis 2 passes, MySQL 2, MSSQL 3, ADB 2, Docker 2, SMB 2, SIP 2, compose and Redis ACLs 1 — all PASS. Every first-pass failure was a denial of service; no path executes attacker input, writes outside its data directory or opens outbound connections.
- Pipeline and UI: tags and severities for the new flags, per-IP brute-force tagging and insight, multi-sensor filters, readable scan summaries, demo data for eleven sensors; sensors grouped into four colour families; a flat world map is now the default Live view, with the globe as an option.
- Ops: memory limits sized from measured peaks, OOM and CPU priorities that protect db/redis/ingest, a shorter stream cap for the new sensors, port guard extended, conntrack sysctl and optional sensor slice templates.

## 2026-10-25 — M13 Indicators and threat intelligence

- Ingest extracts URLs, domains, IPs and file hashes from stored events (bounded scanning, no regular expressions; credentials stripped, private, documentation and own values dropped) into `indicators` and bounded `indicator_sessions` (migration 0009, retention aligned with raw events).
- Passive enrichment: URLhaus and ThreatFox (one abuse.ch Auth-Key) and VirusTotal for hashes only, at three fixed hosts, no redirects, byte caps, timeouts, persisted daily quotas (VirusTotal default 400) and a 24 h cache. Keys come from `.env` or Settings, like the other providers.
- API: indicators list, detail, a bounded infrastructure graph, and owner-triggered CSV and STIX 2.1 export.
- Web: an Infrastructure page (finding, flow diagram of addresses, indicators and families, list fallback on mobile, filterable table, detail panel, export buttons). Indicators are defanged text, never links.
- Open: migration 0009 follows 0007 (0008 reserved), to be re-chained at merge.

## 2026-10-25 — M11 Settings you can edit

- AbuseIPDB, GreyNoise and MaxMind keys can be set, replaced and removed from Settings. Keys are stored with AES-256-GCM (key derived from `SETTINGS_ENCRYPTION_KEY`, provider bound as associated data), shown only by their last four characters, and every change needs the admin password again; five wrong passwords end the session.
- Ingest reloads keys every 30 s without a restart; Settings shows where each key comes from (`.env` or Settings). "Test key" asks ingest for one quota-counted check, at most 10 per provider per day.
- Security review PASS; follow-ups fixed (MaxMind redirect, shared re-auth budget, test cap, no forced GeoIP re-download, weak or reused master keys refused). A sealed-box scheme so the API can only encrypt is listed for later.

## 2026-10-25 — M10 RDP sensor, deeper

- CredSSP now goes as far as the NTLM challenge: every brute-force attempt records domain, user, workstation and NTLM version (an 8-byte response preview only). Responses for a short list of public decoy accounts are verified against their known passwords, so weak-password attempts are recognised; nothing is ever cracked and no session is granted.
- Optional "NLA disabled" mode (off by default) runs the MCS/GCC sequence up to the Client Info PDU and records the cleartext credentials TLS-only clients send.
- Client tool identification (nmap, FreeRDP and the tools built on it, rdesktop, mstsc) from JA3, cookie, NTLM and GCC data, stored on the session and shown on the session page; new tags `bluekeep`, `weak-credentials` and `rdp-cleartext`.
- Security review: first pass FAIL (a busy loop in the optional MCS path, TLS slots without a per-IP cap), both fixed; second pass PASS in both modes. Contract lessons 16–18 now apply to RDP too.

## 2026-10-25 — M12 CVE watch

- Ingest: a daily job mirrors the CISA KEV catalogue, recent NVD CVEs (API 2.0, paced to the rate limit) and GitHub security advisories into a new `cve` table. Downloads are capped in size and time, never follow redirects and are validated item by item; every request spends a persisted daily quota, and a failing feed is retried after an hour without stopping the others. NVD and GitHub keys are optional and set from Settings like the other provider keys.
- Relevance: `ingest/rules/cve/relevance.yaml` maps the emulated services (Apache + PHP, WordPress, phpMyAdmin, OpenSSH, BusyBox telnetd, RDP, Redis, Docker, MySQL, SQL Server, ADB, SMB, Asterisk/SIP) to CPE vendors and keywords and gives each CVE a relevance (high, medium, none) and matched services. The same file links CVE ids to our tags so "seen in our traffic" counts real sessions. Non-KEV, non-relevant CVEs are pruned after 180 days.
- API: `GET /api/v1/cves` (keyset pagination, filters for relevance, KEV, severity, period and text, rank or date order), `GET /api/v1/cves/{id}` (with traffic counts) and `GET /api/v1/cves/sync` (feed status). The enrichment settings now report the NVD and GitHub keys.
- UI: a "CVE watch" page that opens with a plain-English finding, a ranked list with severity, KEV, relevance, matched services and traffic counts, a detail panel, a feed status card and a "Propose a trap" button that only copies a trap-sheet template. Settings gets NVD and GitHub key rows. Demo data (fictional `CVE-2099-*` ids) lives in the MSW mocks.
- Left open: the owner reviews trap proposals before anything is built; security and UI reviews.

## 2026-10-25 — M14 Users and roles

- Database users with the roles `admin` and `viewer`, next to the `.env` owner account, which still works exactly as before (always an admin, usable without the database, password only in `.env`). New tables `users` and `audit_log` (migration 0010); the API role manages `users` and appends to `audit_log`, ingest has no access to either. The audit log is pruned after a year by a database job.
- Roles are enforced on the server with a default-deny check attached to every `/api/v1` route when it is included: only sign in, sign out and changing one's own password are open to a viewer. `tests/test_authz.py` calls every state-changing route as a viewer from the OpenAPI route table. The live WebSocket works for both roles.
- Sessions now carry the account and a per-user session version, checked against the database on each request: password change or reset, disable, role change, deletion and "Sign out everywhere" end the user's sessions at once (the WebSocket within five seconds).
- Login hardening: per-username limit next to the per-address and global ones, per-source lockout that grows (5 wrong passwords lock one source for a minute, doubling up to 15) with a high account-wide ceiling that spares the user's known sources (admins can unlock), the owner never limited by name, global and per-name windows that count failures only, the same argon2 work and the same message for unknown names. Passwords: 12 to 256 characters, a bundled list of 1000 common passwords, not the username.
- Onboarding: an admin creates a user and sees a one-time temporary password (hash stored only); the person must choose their own password before any other route answers. Admin actions re-authenticate with the admin's own password (the M11 helper, now shared) and write an audit entry; provider key changes are audited too.
- Web: Settings > Users and Audit log for admins, a read-only shell for viewers (badge, no write controls), a Set your password screen, an account menu with Change password and Sign out, mock data with `?as=viewer` and `?as=first-login`.
- Left open: security and UI reviews; optional TOTP; the owner is never locked out by failures (rate limits still apply).

- Security review follow-up: structural route test, `system` actor and ids in audit details, WebSocket closes with 1013 after repeated session-check failures, THIRD_PARTY_NOTICES.md for the common-password list.

## 2026-10-25 — M15 to M19: campaigns, ATT&CK, Defend, scripts, alerts, Today

- **M15 Campaigns and ATT&CK.** A shared command normaliser, a bounded clustering job that groups finished sessions by shared keys (script, exploit, credential list, payload host, file hash, malware family), campaign pages with a plain-English story, an ATT&CK catalogue synced hourly and event rules that tag sessions with techniques, and a Techniques heatmap. Migration 0011.
- **M16 Defend.** Scored blocklists (addresses, hosts, URLs, hashes) with a reason for every point, a never-list for resolvers, big SaaS and CDN names and the owner's own addresses, overrides with audit entries, exports for OPNsense and pfSense aliases, plain text and CSV, an opt-in token feed under `/feeds` (off by default), Sigma and Suricata rules marked "review before deploying", and "Your exposure", an inventory compared with recorded attacks. Migration 0012. Documented in [Defend](defend.md).
- **M17 Script library.** Sessions with two or more commands are fingerprinted into scripts, explained by a declarative annotation base, with an optional LLM explainer (`LLM_ENABLED`, off by default) that sees only the normalised script text, under a daily call quota and a monthly token cap. Migration 0013.
- **M18 Alerts and weekly report.** Discord, Microsoft Teams and e-mail (TLS only) channels with validated, encrypted targets, four event alert rules and a weekly report rule, all off until switched on, a rate-limited outbox with a test button, and a weekly report with a printable view. Migration 0014.
- **M19 Today, search and research scanners.** A Today home page, a global search box, a glossary, and research scanners (for example known internet crawlers) labelled benign by the network that owns them. Benign is an allowlist of harmless behaviour, decided on what the session did, never on its user agent. Migration 0015.
- **Security reviews.** Each milestone went through a security review. The first pass of each one returned FAIL or findings, which were fixed. A second pass returned PASS.
- **Left open.** The campaign cap per network and ASN, commit per chunk in clustering, and payload analysis in quarantine (to be framed with the owner). See the [roadmap](ROADMAP.md) "Later" list. The M14 security and UI reviews are still unticked.

## 2026-10-27 — Simpler navigation and a story-style Today

- Navigation: 18 sidebar entries became 10 hubs with an underline tab strip above the page title, defined once in `web/src/app/nav.ts`. Detail pages light up their hub; the Styleguide shows only in dev builds; a new `/networks` route holds the ASN view.
- Today: rewritten around `GET /api/v1/story` (bounded queries on `sessions`, 3 s statement timeout, 30 s cache). A Sankey of origin, door and deepest stage reached, an hour strip that links to the matching sessions, and story cards whose plain sentences come from templates while attacker text stays in the technical details, clipped. The previous "what you can do" cards remain at the bottom.
- Attacks: new `stage`, `since` and `until` filters, so every number on Today opens the sessions behind it.
- Reviews: security review PASS (three low findings fixed: statement timeout on the stage filter, quoted hrefs, clipped org names); design review fixes applied (Sankey labels, stage colours, underline tabs, no duplicated navigation, attacker row width, hour strip key and ticks).

## 2026-10-30 — M20 Synology NAS sensor and CVE watch fixes

- **Synology sensor.** A twelfth sensor that looks like an unpatched Synology NAS on DSM 7.2.1 (Update 11). It serves the DSM login page and the Web API on HTTP 5000 and HTTPS 5001. Logins always fail with real DSM error codes, and the credentials are recorded. Nothing a client sends is run, written or fetched. Documented in [Synology](sensors/synology.md).
- **Tags for the C3RB3R campaign.** Forged session IDs and SCGI header injections (CVE-2026-13639 and CVE-2026-13684) are tagged `synology-exploit`, and ransomware indicators `c3rb3r`. Both are severe. DSM API calls are tagged `synology-dsm`. ATT&CK mapping: T1190 and T1486. Migration 0017 adds the sensor to the inventory.
- **Compose and ports.** `sensor-synology` with its own network, Redis user and volume, `SYNOLOGY_*` settings in `.env.example`, and 5000 and 5001 in the port guard.
- **CVE watch.** The NVD window is 60 days. It is read in one-day chunks, oldest first, with a page budget, so a busy feed no longer loses CVEs silently at 10,000 results. A partial run resumes from its last complete chunk. GitHub advisories are read in seven-day chunks. A one-time start-up rewind refills shallow history, and watched CVEs missing from the table are fetched by id.
- **Integration tests.** `just test-integration` uses `docker-compose.it.yml`, an overlay that keeps `redis` on the backend network only, so the throwaway project fits next to the live stack.
- **Closed on 2026-10-31.** Security review passed. Deployed: every service healthy, and the Synology ports receive internet traffic. An `INGEST_STREAMS` override written before M20 left out `events:synology`; ingest now logs a warning when the override omits a built-in sensor stream.
- **CI.** Python is pinned to 3.13 in the uv jobs. Two flaky tests are fixed: the Docker sensor no longer answers 409 to an unnamed create whose random name was taken, and the alert test fixtures retry a table reset picked as a deadlock victim.

## 2026-10-31 — M21 Anonymous egress, payload collection and static analysis

- **Anonymous egress.** A `vpn` service (WireGuard through gluetun, profile `egress`) is now the only container with a route to the internet. It has a kill switch, an HTTP proxy and a read-only control server. The old `egress` network is gone. `ingest` and the new `collector` reach the internet only through the proxy, using the shared `suckerpot_egress` package. An egress gate runs a self-check every 5 minutes (tunnel up, two echo services agree, the address matches gluetun's, is global and is in the allowed network) and pauses all lookups when it fails. Events are still stored. Without the profile every outbound feature stays idle.
- **Guardrails.** `just guardrails` is a static test of the compose files (networks, members, capabilities, DNS, proxy variables). `just egress-check` proves the isolation on the running stack, including a tunnel-down test. The host firewall (`scripts/host/firewall.nft`) gets rules for `sp-vpn`, `sp-egress` and `sp-samples`.
- **Collector and analyzer.** The collector fetches captured download URLs through the proxy with an SSRF validator, size, time, redirect and rate caps, and writes files to a quarantine volume under their sha256 name (mode 0400, never executed). The analyzer has no network. It identifies the type and architecture, hashes (sha256, sha1, md5, TLSH), extracts strings, runs YARA rules, deobfuscates shell scripts as text and extracts next-stage URLs and C2 addresses, in a resource-limited child process. Migration 0018 and two new database roles.
- **API and UI.** `/api/v1/samples`, the chain, an admin-only password-protected archive download, and `/api/v1/egress`. A Samples tab on Malware, a sample page and an Egress card in Settings.
- **Reviews.** Security review passed (egress, quarantine, parser safety on hostile files). UI review passed.
- **Not deployed.** The owner still has to add the VPN settings, apply the new host firewall rules and run `just egress-check`. See [Deployment](deployment.md#anonymous-egress-vpn). TFTP and FTP URLs are recorded but not fetched.

## 2026-10-31 — M22 Anonymous reporting

- **Reports.** A new `reporting/` package (evidence allow-list, redaction, identity guard, renderers for plain text, X-ARF v0.2, `.eml`, STIX 2.1 and MISP, encrypted sample bundle) and an ingest worker (`ABUSE_REPORTS_ENABLED`, off by default) that finds abuse contacts over RDAP through the egress gate and builds drafts per recipient and kind. Migration 0019 and the API under `/api/v1/abuse`. The stack never sends anything and stores no mail settings.
- **Identity guard.** Every artefact is checked right before it is returned and refused with reason codes only. It fails closed when no confirmed address of the monitored system is known. Learned self terms (seen from at least two distinct /24 or /48 networks, or declared by sensors in `data.self_identity`) stay inactive until the owner confirms them, and count only while fresh (72 h). `just abuse-guard-check` proves it on the live data.
- **Wording.** The package ships none. The owner writes the introduction, closing text, note and subject template in Settings > Reporting, because shipped text in a public repo could be searched. Times are rounded to the minute by default.
- **UI.** The Abuse reports page and report page, Export for CERT, the sample bundle dialog and the Settings > Reporting tab.
- **Decisions.** X-ARF v0.2 by mail only, domains go to the registrar only, CERT exports default to TLP:GREEN with both STIX and MISP.
- **Known limit.** A reported network can match times and ports against its flow logs. See [Security](SECURITY.md#anonymous-reporting-m22).
- **Reviews.** Security review passed.
- **Not deployed.** The owner still has to turn the worker on, fill Settings > Reporting, confirm the self terms and run `just abuse-guard-check`. See [Deployment](deployment.md#anonymous-reporting).

## 2026-11-01 — M23 Upload the VPN configuration from the dashboard

- **Upload.** Settings > VPN takes the WireGuard `.conf` from the VPN provider after asking for the password again. The API parses it strictly (no `PostUp` and the like, IP endpoint only, global address, full tunnel, canonical keys) and writes a rebuilt `wg.env` into the new `vpn-config` volume, mounted read-write in `api` and read-only in `vpn` only. The private key is never shown again; audit rows hold the endpoint and a key fingerprint only.
- **Switch.** The `vpn` entrypoint reads the file with fixed patterns (never sourced), refuses a non-global endpoint, and restarts the container when the file changes. During the restart nothing leaves: the other services have no route of their own. The API gets no Docker socket and no new network.
- **Trusted exits.** A new exit address stays blocked until the owner trusts the /24 the ingest gate observed (table `egress_trusted_exits`, migration 0020, at most 8 rows). An exit inside the honeypot's own addresses (Settings > Reporting) or in an AS listed in `EGRESS_DENY_ASNS` closes the gate and can never be trusted. The exit's AS and organisation (local GeoLite2) are shown next to it.
- **Reviews.** Security review passed; its findings (home-IP trust, collector-planted candidate, IPv6 scope ids, entrypoint endpoint check, a read/checksum race, body size, stale temp files) are fixed. UI review approved.
- **Fixed on the way.** The abuse, alerts and intel workers no longer wait up to an hour for their first run on a host that booted recently (this made CI fail on fresh runners).

## 2026-11-01 — M24 Guided tour, setup checklist and tunnel controls

- **Tour and help.** A seven-step tour on first login, replayable from the top bar, and a "?" help on every page and Settings tab. The texts were checked against the design documents: nothing overpromises (the stack never sends a report itself, the sensors still answer attackers on the home address).
- **Setup checklist.** `GET /api/v1/setup/status` computes eight items from the real state and links each one to the screen that fixes it. The host firewall is outside the stack's view: the card points to `just egress-check`.
- **Tunnel controls.** "Check now" (no password, one per 10 s, migration 0021) and "Reconnect" (password, one per minute, a marker file the `vpn` entrypoint watches without reading it). A closed gate re-checks every 20 s, so a tunnel restart no longer pauses lookups for five minutes.
- **Reviews.** UI review approved after two rounds (copy accuracy, duplicated VPN controls, tour layout on phones).

## 2026-11-01 — M25 Sending abuse reports: send queue and optional SMTP

- **Decision change.** M22 said the stack never sends mail. The owner asked for optional sending: it is off by default, and the manual queue stays the main path (free Proton addresses have no SMTP).
- **Send queue.** One ready report at a time: open in the mail app with the full text on the clipboard, then "Sent, next".
- **SMTP.** Profile in Settings > Reporting (encrypted password the API cannot read back, re-authentication, Proton preset), modes off / click / automatic with a hold time, Cancel and a daily cap. The API only queues requests; ingest sends through the VPN proxy after re-checking the report and running the identity guard on the complete message, envelope and EHLO name. Closed gate: nothing is sent (tested at the socket level). At-most-once delivery with a `sending` state and an `unknown_outcome` result that is never retried.
- **Alerts.** Alert emails and webhooks now go through the identity check: own addresses and terms are masked, and alerts pause until the owner's own address is confirmed.
- **Reviews.** Security review passed; its findings (re-send after a crash, unguarded alerts, an in-thread deadline, request picking, profile locking, a lock timeout, a test address) are fixed. UI review approved.

## 2026-11-01 - Safety: protected volumes and daily backups

- **Incident.** Every live volume of the production project was destroyed, most likely by compose commands in a throwaway checkout whose `.env` copied the live `COMPOSE_PROJECT_NAME`.
- **Fix.** Data volumes are external, named from the required `SUCKERPOT_VOLUME_PREFIX` (no `.env`, no compose), and are created by `just up` (`scripts/ensure-volumes.sh`), which also refuses to start an empty database when dumps exist. The IT and CI overlays make them local; guardrail tests enforce it. `just test-integration` refuses non-`-it-` projects, `just up-test` never uses the live name, and the live recipes need `COMPOSE_PROJECT_NAME` and `SUCKERPOT_VOLUME_PREFIX` from `.env`.
- **Backups.** A `backup` service dumps daily into the external `backups` volume (7 kept); `just backup`, `just backups`, `just restore latest`.

## 2026-11-02 — M28 Installable by anyone

- **Install.** `scripts/install.sh` (also `just install`) checks the machine, asks a few questions, generates every secret on the host, writes `.env` (mode 0600), creates the volumes and starts the stack. It refuses an existing `.env`, existing volumes or containers of the project, and a non-loopback dashboard bind without `--public-host` or `--allow-lan`. Two modes: signed release images (default) or a build from the checkout.
- **Sensor switches.** `SENSOR_<NAME>` (default on) with `just sensors` and `just set`; a sensor switched off while running is stopped and removed, and the port guard follows the selection.
- **First-run setup.** `/setup` wizard (migration 0025) and a Settings "Sensors & ports" tab. The ports step puts the never-forward rule (dashboard, admin SSH, DMZ) first; the VPN step has an idle state.
- **Updates.** `just update` (pre-update dump kept outside retention, signature check before anything runs, pull by verified digest, health check, unfinished-update lock) and `just rollback`. The update check is off by default and goes through the VPN only.
- **Release.** Signed multi-arch images (cosign keyless) published only from a pushed `v*` tag; locally built images are named per compose project, so test stacks can no longer retag the live images.
- **Low memory and VPN idle.** `docker-compose.lowmem.yml`; the VPN stays idle, with no route out, until a WireGuard file is uploaded.
- **Reviews.** Security review failed once (image name collisions, stale dotenv values, mediums), then passed after fixes; the re-review findings (idle mode never starting, unverified image paths, rollback state) are fixed. UI review approved.
- **Deployed.** Backup taken first; migration 0025 applied; every service healthy; no event lost.

## 2026-11-02 — M26 Report outcomes and M27 Takedown tracking

- **Replies (M26).** An optional IMAP reader (`ABUSE_REPLIES_ENABLED`, through the VPN only) reads the reply mailbox header-first, never deletes (seen flag or move only), matches replies to reports by a reply token in the subject, a quoted Message-ID or a bounce, and classifies them with YAML rules. Only a party we wrote to can set an outcome; authentication alone vouches for a genuine bounce and nothing else. Shared-mailbox and trusted provider name (`trusted_authserv_id`) settings.
- **Takedowns (M27).** Reported payload URLs are re-checked by the collector with one bounded GET through the VPN; attacking addresses and C2s are never contacted and are followed passively only. States, time to takedown and per-provider statistics under a 48 h rule. Optional URLhaus/ThreatFox submissions (`ABUSECH_SUBMIT_ENABLED`, off by default) with a review queue and a lookup before each submission.
- **Dashboard.** Results (KPIs, takedown curve, targets and providers, answers), target detail, Submissions with the evidence behind each URL, reply and outcome cards on each report, and Settings → Reporting with IMAP, abuse.ch, a section nav and unsaved-change hints.
- **Migrations.** Renumbered to 0026 and 0027 after the deployed 0025; a test upgrades from 0025 with data to head and back.
- **Reviews.** Security review failed (a poison-pill mail, forged replies, freemail relevance, re-checks reaching attackers, token exposure), then passed after fixes. The merge review caught the forged-reply path reopened by a test-driven change; it is reverted and covered by negative tests. UI review approved after two rounds.
- **Deployed.** Backup taken first; migrations 0026 and 0027 applied; every service healthy; no event lost. Every new worker stays off until its flag is set.

## 2026-11-02 — M29 Opt-in anonymous network

- **Protocol.** `spn/1` in the new `netproto/` package: Ed25519-signed requests and answers bound to each other, replay protection, proof of work at enrolment priced per address prefix, blinding of URLs and domains until consensus, golden test vectors.
- **Hub.** `hub/`, deployed separately and never on a member's home line: enrolment, signed daily batches, consensus (5 eligible nodes, 2 days, cohort cap, corroboration), reputation, grouped reports reviewed by the operator (C2 reports never automatic), no client address stored or logged.
- **Node.** A worker in ingest (migration 0028), off unless `NETWORK_ENABLED` is set and the admin joins with re-authentication and five consents. VPN egress only; allow-listed aggregates guarded against the owner's identity on every item and batch, resent batches guarded again, demo sessions never shared, a random delay of at least 2 h. Leaving deletes everything on both sides.
- **Dashboard.** Network overview, members (pseudonyms, k-anonymous countries), Settings → Network and an optional setup step; `just set` accepts the hub URL and public key with strict validation.
- **Reviews.** Hub review failed (reportability counted ineligible nodes, corroboration on addresses only), then passed. The integration review passed with findings (demo sessions, hub URL validation, resent batches, reveals without an own address, report suppression window, unbounded hub fields), all fixed. UI review approved after fixing a join dialog that could not be completed.
- **Deployed.** Backup taken first; migration 0028 applied; every service healthy; no event lost. The node stays off; no hub is configured.

## 2026-11-02 — M30 Community blocklist feeds

- **Formats.** `netproto` renders the inbound, outbound and outbound-domains lists (plus high tiers) as plain text, nftables, ipset, MikroTik, CSV, JSON and STIX 2.1, re-validating every value so nothing can break firewall syntax; minisign signatures (checked against the upstream `minisign -V`) on a signed `index.json` with a monotonic serial and `valid_until`.
- **Hub.** Feeds are built only from k-supported consensus targets: TCP-proven inbound activity (SIP and scans never list), payload hosts and C2s only with fetch or dropper evidence from several nodes, a 6 h hold, expiry, caps, a change breaker and `HUB_FEED_MODE` (off by default). Tor exits and CDN ranges are always excluded and fail closed when stale. Atomic publication on a log-free Caddy site; public delisting (proof of work, no client address stored) and lookup; operator CLI.
- **Node.** An optional feed worker (`NETWORK_FEED_ENABLED`, off) downloads through the VPN, verifies signatures, rollback and expiry, and swaps entries in one transaction (migration 0029). The dashboard has a Network tab on Blocklists and a local mirror for firewalls (feed token kind `network`).
- **Reviews.** Security review failed twice (an inbound delisting removing outbound hosts, SIP and typed `wget` hosts as attack evidence, high tier and payload links not k-supported, then payload hosts reportable without a fetch), then passed. UI review approved.
- **Deployed.** Backup taken first; migration 0029 applied; every service healthy; no event lost. The feed worker stays off and no hub exists yet.

## 2026-11-03 — M31 Hub pre-production and abuse.ch first

- **Tunnel mode.** The hub can run behind a Cloudflare Tunnel on a host whose ports 80 and 443 are taken: Caddy on one private HTTP port, client addresses trusted only from the connector, and every outbound call (RDAP, range lists, abuse.ch, SMTP over CONNECT) through the VPN proxy, with no direct route and a startup refusal if one appears.
- **abuse.ch first.** Confirmed malware URLs go to URLhaus (optionally automatic), C2s to ThreatFox only after manual approval; bodies carry the indicator and a family only. Payload hosts now need malware-like content everywhere.
- **Site.** A blocklist policy page: listing rules, removal, data protection.
- **Reviews.** Security review failed (one node could get an ordinary page submitted to URLhaus; disputed or delisted targets still submitted; trust of private ranges), then passed after fixes.
- **Deployed.** Main stack: backup first, every service healthy, no event lost. Pre-production hub (temporary, on the same host behind the tunnel) migrated to h0008; feeds, reports and abuse.ch stay off or in review. Known flaky: the mssql `test_expensive_batches_from_two_ips_do_not_delay_a_victim` timing test fails under host load, on main as well.

## 2026-11-03 — M32 Join the network in three commands

- **Participant mode.** `./scripts/install.sh --participant`: one consent prompt, a random pseudonym, sensors, database, ingest and the network node only, no dashboard and no setup beyond opening the printed ports. `./scripts/status.sh` and `./scripts/participant.sh` (leave, join, VPN, auto-update, uninstall); `--full` later keeps the data.
- **No VPN needed.** A new `hubproxy` service is the only way out in that mode: authenticated `CONNECT` to the hub and feed names on 443 only, global addresses only, the TLS SNI must match. The egress gate gets a direct mode scoped to those hosts. The owner's full-mode rendering is unchanged (snapshot test).
- **Verifier nodes.** The hub queues download links reported by 2 or more eligible nodes (migration h0009); a verifier node (role granted by the operator, VPN and collector required) fetches them with every collector guard and no recursion (node migration 0030) and returns an attestation. URLhaus path B needs two reporters plus a malware-like attestation. Off by default, review when enabled.
- **Releases.** Hub and feed public keys ship in the release; nodes pin up to three hub keys and the hub can sign with an alternate key for a rollover. Participants update daily from a cosign-signed release manifest bound to the tag's commit and image digests, 48 h minimum age, rollback on a failed health check.
- **Tests.** End-to-end participant install against a throwaway test hub (48 checks); it found that leaving kept the node at the hub and that switching to full mode failed at its backup, both fixed. Releasing the real keys showed the feed key was validated as a hub key set; fixed.
- **Reviews.** Security review PASS with six low findings (domain fronting through the hub edge, checkout by tag name, manifest digests unchecked, a decoy self address opening the reveal guard, the firewall rule, consent wording), all fixed. UI review asked for a clearer network-check badge; fixed.

## 2026-11-03 — v0.6.0 released

- Tag `v0.6.0` pushed; the release workflow built the 19 images for amd64 and arm64, signed them, passed the smoke install and attached the signed release manifest.
- Verified on a separate machine: `scripts/verify-release.sh v0.6.0` (signer, commit, network defaults hash) and `just verify-images v0.6.0` (all 19 signatures) pass.
- The participant end-to-end job that failed once on CI passed on the next run with no code change: a CI flake, not a regression.

## 2026-11-04 — M33 Network on by default, one-button join

- `NETWORK_ENABLED` defaults to true. The full installer asks "Join the SuckerPot network? [Y/n]" (default yes, `--no-network` declines); ingest joins from the dated consent record in both modes, once, within 7 days, through the VPN only in full mode. A leave stays final; `just set NETWORK_CONSENT=` clears the record. Updates pin `NETWORK_ENABLED=false` on pre-M33 installs that never set it.
- Dashboard: the join dialog lists what is shared and asks only for the password; leave is one button; setup step 8 joins directly.
- Fixed: the setup wizard's sensor list timed out on busy systems (24 h group-by over ~1.3 M events); it now reads the newest event per sensor from the `(sensor, ts)` index.
- Security review PASS; its two medium and five low findings fixed. Lint, typecheck, unit, integration, guardrails and the participant end-to-end test (48/48) green. One collector timing test failed once and passed on rerun.

## 2026-11-04 — v0.7.0 released

- Tag `v0.7.0` built, signed and published by the Release workflow. `scripts/verify-release.sh v0.7.0` checks the manifest (commit a5000af); `just verify-images v0.7.0` reports all 19 image signatures valid.
- Docs build fixed: `design/m33` added to the docs toctree.

## 2026-11-04 — v0.7.1 (fixes)

- The dashboard read the hub address only from `.env`, so Settings → Network said "No network hub is configured" on every installer-made install. The API now uses `suckerpot_netproto.defaults.effective`, like ingest.
- A repeated join while one is pending now explains itself instead of showing a generic error; the "new" standing text no longer states a fixed two-week delay.
- The owner's node joined the network through the dashboard; enrolment went through the VPN (egress-check PASS).

## 2026-11-04 — v0.8.0 (move to Selfhostr)

- Repository transferred to `selfhostr/suckerpot`; every link, default image prefix (`ghcr.io/selfhostr/suckerpot`), update source and signature identity follow it. The checks stay strict: exact repository, `release.yml`, exact tag.
- Network defaults point at `suckerpot-hub.selfhostr.io` and `suckerpot-feeds.selfhostr.io/v1`; the hub keys are unchanged. The product name in these hostnames is visible in DNS and SNI, documented in `docs/network.md`.
- Docs moved from Read the Docs to `suckerpot.selfhostr.io/docs/`, the mock-data demo to `/demo/`; `site/`, the Pages and Sphinx workflows are removed. README screenshots refreshed on mock data.
- Full compose build healthy (20/20), egress-check PASS, CI green on the new repository.

## 2026-11-04 — v0.9.0 (participant hardening)

- Hub feeds turned on in `review` mode with the existing feed key (it matches the key shipped to nodes); the first signed publication verifies from a node through the VPN.
- Participant install: port reachability check (local evidence only), host firewall offered with sudo, DMZ advice; the "14 days" date is gone.
- Security review of participant mode: first pass FAIL (no participant host firewall, a release could lower its own update delay, host reachable through internal bridges, no generic hardening guardrail, wide DNS rule, no DMZ warning); all fixed. Second pass PASS; its two medium findings (transient failures marking releases bad, a too-broad network-recreate trigger) and the low ones fixed as well.
- Checked on this host with a throwaway project: compose recreates a changed network by itself, and refuses with "has active endpoints" when a container of another project is attached; the update path stops with instructions in that case.
- Lint, typecheck, unit tests (Python and vitest), guardrails (742 passed) and web build green.

## 2026-11-06 — v0.10.0 (dependency refresh)

- One coordinated upgrade replaces the 24 open Dependabot pull requests: Python 3.15 and uv 0.13 in every image (Debian trixie), Node 26, react-router 8, ESLint 10, Redis 8.10, TimescaleDB 2.31, gluetun v3.41.3, hub Caddy 2.11.9 and Alpine 3.24, Actions majors pinned by SHA.
- Found and fixed on the way: the TimescaleDB 2.31 concurrent-refresh error in the `migrate` backfill (now retried), the redis-py 8 reply types in ingest, the SQLAlchemy 2.1 types in the api, a timing-dependent api test.
- Lint, typecheck, unit and integration tests (Python and vitest), guardrails, hub integration tests, web build and every image build green; CI green.

## 2026-11-07 - M34 (public network observatory)

- The hub worker can publish `network.json` (schema `selfhostr-network-stats/1`, CC0) on the feed site, once a day and independent of `HUB_FEED_MODE`; off by default (`HUB_OBSERVATORY_ENABLED`). Caddy serves it to one browser origin (`HUB_OBSERVATORY_ORIGIN`), `GET` only. Design: `docs/design/m34.md`.
- Final days are aggregated once from consensus-eligible nodes into `observatory_daily` (migration `h0010`, 400 days, no UPDATE grant). Figures are rounded, published with a delay, coarse (complete ISO weeks, one significant figure, small figures left out) below three eligible nodes, and outcomes are exact only with production consensus thresholds. Bootstrap figures are counted once a week, from Thursday on.
- Security review: first pass FAIL (Sybils could unlock precision, exact outcomes with relaxed thresholds, a daily-moving bootstrap, movable small figures, CVE tags, partial weeks, an UPDATE grant); all fixed. Second pass PASS; its two low findings (sliding rounded totals, a weekly count taken before late batches) fixed as well.
- Lint, full typecheck, hub unit tests and hub integration tests green.

## 2026-11-10: v0.11.0 (audit fixes)

- A review of the whole project produced 17 fixes, released together. The most serious: ingest could silently stop storing events about a week after install (migration `0031`, a savepoint around the retraction, isolated streams, a parked-event stream, and a dashboard banner plus `GET /api/v1/settings/pipeline` that say when the pipeline is stalled).
- Updates and restores no longer destroy a degraded node: health is judged against the node before the update, a rollback restores the database only when the schema moved, `just restore` loads a side database and swaps it, and the Valkey broker starts on a volume written by Redis 8.10.
- Safe defaults: the collaborative network is off unless asked for (installer default no, `NETWORK_ENABLED` unset means off), the GreyNoise quota follows the free tier (7 a day), sign-in can no longer be locked out by anonymous failures, and Settings reports the oldest stored event.
- Honesty and fingerprints: tags that name a family, a CVE or a fraud need specific evidence, and the SSH shell and the service sensors derive their identity per install. The hub counts a takedown vote only against a recheck it handed out (migration `h0011`), and releases only come from commits on main.
- Two optional features were removed: node-side abuse.ch submission and the LLM script explainer. Lookups of a session's events are bounded in time.
- Unit tests, integration tests, guardrails and the new backup-restore and broker jobs green on each pull request.

## 2026-11-11: v0.11.1 (admin SSH helper)

- New host helper `scripts/move-admin-ssh.sh`: one command moves the machine's own SSH daemon off port 22 on Debian and Ubuntu, so the SSH sensor can use port 22 on a VPS. It opens the new port next to the current one, waits for an authenticated login on it and only then closes the old port. A timeout, an interruption or a failure goes back to the port SSH was on.
- The same two-phase move serves a later change of port and `--undo`. Unusual setups are refused before any change. The installer still never edits the SSH configuration.
- `docs/vps.md` leads with the script and keeps the manual steps under "By hand".
- Two security review passes. Tests with stateful shims for both init paths, and a run against a real OpenSSH daemon in a container. A real systemd with socket activation is not covered by an automated test.

## 2026-11-11: v0.11.2 (first install on a small VPS)

- A first install on a rented 2 GB server showed two faults, both fixed here.
- Memory: a machine sold as "2 GB" reports about 1.9 GiB and was refused. The bar is now 1.75 GiB, so such a machine gets the default participant setup with the low-memory overlay. Below the bar and above the lite minimum, the installer offers the lite setup. The swap question is really asked in participant mode.
- First start: the `db` healthcheck used the Unix socket, which also answers while the image's temporary init server runs. `backup` then started its first dump too early, failed, and waited an hour, so the install timed out. The healthcheck now probes over TCP, and a failed dump is retried after 30 s, doubled each time up to the hour. An update recreates the `db` container once.
- Tests: guardrail tests for both, and the compose, participant and backup-restore jobs green. Neither fix was run on a real small server yet: the affected install was finished by hand on v0.11.1 (restart `backup`, then `./scripts/install.sh --repair`).
