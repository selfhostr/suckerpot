# Roadmap

Each milestone ends with the Definition of Done from `CLAUDE.md` §8: all services healthy, tests/lint/typecheck green, security review passed when relevant, docs updated, this file ticked, an entry in `PROGRESS.md`, merged to `main` and pushed.

## Blocked — needs owner

- [x] Docker Engine + compose plugin installed on the VM (needs `sudo`).
- [x] Push access to GitHub (fine-grained token scoped to this repo only, Contents: read/write).
- [ ] Enable secret scanning and push protection in the GitHub repo settings.
- [ ] Enable GitHub Pages (Source: GitHub Actions) and import the project on Read the Docs.
- [ ] Grow the VM disk (≥ 64 GB).
- [ ] Apply the host firewall (scripts/host/firewall.nft + suckerpot-firewall.service).

## Host / owner actions before go-live (from the M1 security review)

- [ ] Host firewall (nftables, applied by the owner): drop NEW connections from Docker bridge ranges to the host's admin SSH port and the dashboard port.
- [ ] Block NEW outbound connections from the `dashboard` and `ingress` bridges (DOCKER-USER chain), and/or enable the hypervisor IP filter on the VM NIC.
- [ ] Admin SSH: key-only, password login disabled.
- [ ] Optional: `"userland-proxy": false` in the Docker daemon config.
- [ ] Dashboard port filtered upstream so only the reverse tunnel can reach it.

## M0 — Bootstrap

- [x] `.gitignore` created first; private context file verified ignored with `git check-ignore`.
- [x] `CLAUDE.md` and project subagents in `.claude/agents/`.
- [x] `docs/ROADMAP.md`, `docs/PROGRESS.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, skeleton `README.md`, MIT `LICENSE`, `.env.example` (placeholders only).
- [x] gitleaks pre-commit hook; GitHub Actions workflow running gitleaks, lint and tests.
- [x] Staged diff reviewed, `chore: bootstrap repository` committed and pushed.

**Acceptance:** CI is green on `main`; `gitleaks detect` finds nothing; no private data in the tree.

## M1 — Foundations

- [x] `docker-compose.yml` with `redis`, `db` (PostgreSQL + TimescaleDB), `ingest` and `api` skeletons.
- [x] Networks from §3: `sensors`, `backend` (`internal: true`), `egress`, `dashboard`.
- [x] Hardening from §5 on every service: non-root, `read_only` + tmpfs, `cap_drop: [ALL]`, `no-new-privileges`, memory/CPU/pids limits, healthchecks.
- [x] Redis with password and a sensor ACL user limited to `XADD` on the events stream.
- [x] Shared Event schema (Pydantic) in `sensors/common`, with tests.
- [x] DB migrations (Alembic): events hypertable, sessions table.
- [x] Ingest skeleton: consumes the stream, validates events, writes to the DB.
- [x] API skeleton: `/healthz`, a paginated sessions/events endpoint.
- [x] Demo data generator (`just demo`): realistic sessions across all 4 sensors over the last 30 days, documentation IP ranges only in examples.
- [x] `justfile` with `up`, `down`, `test`, `lint`, `demo`.
- [x] CI runs Python lint, typecheck and tests.

**Acceptance:** `docker compose up -d --build` → all services healthy; `just demo` fills the DB and the API returns sessions; dashboard port only on a non-sensor port; security review PASS; CI green.

## M2 — SSH sensor

- [x] asyncssh on container port 2222, mapped from host 22.
- [x] Accepts logins on a configurable set of weak credentials; records every attempt.
- [x] Fake shell with a fake filesystem and common commands (`uname`, `cat /proc/cpuinfo`, `ls`, `cd`, `pwd`, `whoami`, `id`, `ps`, `w`, `free`, `history`, …).
- [x] `wget` / `curl` / `tftp` recorded as `download_attempt`, never executed or fetched.
- [x] Full session recording (timed I/O) for replay.
- [x] Realistic banner and hostname; connection caps, timeouts, field size limits.
- [x] Events land end to end in the DB.
- [x] Sensor networking (from the M1 security review): an `ingress` bridge with a fixed name, `enable_ip_masquerade: "false"`, `enable_icc: "false"`; `dns: ["127.0.0.1"]` on every sensor; ports published on explicit IPv4 (no docker-proxy on `[::]`); one internal network, one Redis stream and one ACL user per sensor, with ingest checking the `sensor` field against the stream.
- [x] Sensors drop and count events when Redis is unavailable, with bounded queues; per-IP event rate limit.
- [x] M1 review follow-ups (before go-live): stable ingest consumer name + trim never past the oldest pending entry; role passwords re-applied on every `migrate` run (rotation); dead-letter only on data errors; strict WebSocket Origin comparison; strip Unicode format characters in summaries; `connect-src 'self'`; NUL-safe SPA paths; per-row error isolation in the live poller; per-IP WebSocket cap; explicit per-table grants.
- [x] Ingest idempotency: no double counting when a batch is replayed after a crash between commit and ACK.

**Acceptance:** tests use a real SSH client against the container; no `subprocess`/`eval`/`exec` in sensor code; security review PASS.

> When M2 is done: remind the owner of the go-live checklist (see private environment notes).

## M3 — Design system + web shell

- [x] Design tokens (dark default + light), type scale, spacing, radius, sensor colours, severity scale.
- [x] Base components: Card, StatTile, TagBadge, EventRow, SessionStory, IPChip, CountryFlag, EmptyState, Skeleton.
- [x] App layout and navigation for all pages from §4.
- [x] Live event feed over WebSocket on demo data.

**Acceptance:** WCAG AA contrast; web lint, typecheck and tests green.

## M4 — Enrichment and tagging

- [x] GeoLite2 (needs a MaxMind licence key from the owner; degrade gracefully without it).
- [x] ASN / org.
- [x] AbuseIPDB and GreyNoise Community with a 24 h per-IP cache and enforced daily quotas.
- [x] YAML rules engine in `ingest/rules/*.yaml` with first rules (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).

**Acceptance:** enrichment works with and without API keys; quotas cannot be exceeded (tested); rules have unit tests.

## M5 — Core pages

- [x] Overview: 4 KPIs, activity per sensor over time, top countries, insights.
- [x] Attacks: filterable session list, one-line story per row, filters in the URL.
- [x] Session detail: timeline, xterm.js terminal replay at real speed, IP panel.
- [x] Replay safety contract (from the M2 review): no Clipboard addon (OSC 52), a `linkHandler` that never opens links (OSC 8), `onData`/`onBinary` never wired to anything (query replies), no image/sixel addons, attacker strings rendered as text only.
- [x] Attackers: profiles by IP and ASN.

**Acceptance:** pages load in under 1 s on demo data; lists virtualized and paginated server-side; `ui-designer` approval.

## M6 — More sensors

- [x] Telnet with Mirai-style flows.
- [x] Web: fake Apache + PHP 8.3.x (mod_php, unpatched), fake WordPress `wp-login.php` / `xmlrpc.php`, fake phpMyAdmin; `php2shell` tag on upload-progress abuse.
- [x] RDP: low interaction, handshake + username capture.
- [x] Optional: catch-all listener recording the first bytes on other ports.

**Acceptance:** each sensor tested with a real client; events end to end; security review PASS.

## M7 — Showcase

- [x] Live page: 3D globe with attack arcs + live feed.
- [x] Trends page: top usernames/passwords/commands/URLs, tags over time, day × hour heatmap, "new this week".
- [x] Auto-written insights.
- [x] Malware page: download URLs, hashes and VirusTotal links when payload fetching is enabled.

**Acceptance:** `ui-designer` approval on all pages; insights are correct on demo data (tested).

## M8 — Hardening and v0.1.0

- [x] Dashboard auth: argon2 hash from `.env`, secure session cookie, CSRF, rate-limited login.
- [x] Rate limits on the API.
- [x] Retention job: raw events 90 days, aggregates forever.
- [x] DB volume backup script.
- [x] Full security review.
- [x] README with demo-data screenshots.
- [x] GitHub release `v0.1.0`.
- [ ] Remind the owner of the go-live checklist (dashboard firewall rule, `/logout`, token revocation, snapshot, then DMZ).

## M9 — Seven more sensors

- [x] Redis (6379), Docker Engine API (2375), MySQL (3306), MSSQL (1433), Android ADB (5555), SMB (445), SIP (5060/udp + tcp).
- [x] Contract lessons 16–18 on every sensor: wall-clock CPU budget per loop turn, pending output charged to the memory budget, per-IP event fairness.
- [x] SIP: no UDP amplification (every reply ≤ its request, per-source and global reply caps).
- [x] Ingest rules and tag severities for the new flags; per-IP brute-force tagging (`credential-stuffing`) and the `brute_force` insight.
- [x] UI for 11 sensors (sensor families and colours); flat world map as the default Live view, with the 3D globe as an option.
- [x] Compose integration, demo data for the new sensors, docs.

**Acceptance:** each sensor tested with real clients and nmap; security review PASS for each; all services healthy.

## M10 — RDP sensor, deeper

- [x] CredSSP up to the NTLM challenge: record domain, user and workstation for every brute-force attempt, and check the NTLMv2 response against the configured weak passwords (nothing cracked).
- [x] Optional "NLA disabled" mode: standard TLS security up to the Client Info PDU, recording the user name and the cleartext password the client sends.
- [x] Client tool identification from JA3, CredSSP version and client OS version (nmap, hydra, ncrack, FreeRDP, mstsc, common brute-force bots), shown on the session page.
- [x] Lessons 1–18 kept; security review PASS.

**Acceptance:** hydra/ncrack/FreeRDP against the sensor record user names, and weak passwords are recognised; security review PASS.

## M11 — Settings you can edit

- [x] Enter, replace and remove enrichment API keys (AbuseIPDB, GreyNoise, MaxMind) from Settings, with no restart.
- [x] Keys stored encrypted at rest (key from `.env`), write-only in the UI (only the last 4 characters shown), every change logged, CSRF and re-authentication required; `.env` values stay a supported fallback.
- [x] Ingest picks up new keys within a minute; Settings shows where each key comes from (`.env` or Settings) and a "Test key" button that spends one quota call.

**Acceptance:** a key added in Settings turns the provider on without a restart; keys never leave the server in clear text; security review PASS.

## M12 — CVE watch

- [x] Ingest pulls new CVEs daily (CISA KEV, NVD, GitHub advisories) and ranks them by relevance to the services SuckerPot emulates.
- [x] A CVE page: recent relevant CVEs, and whether matching activity was already seen in our traffic.
- [ ] Trap proposals reviewed with the owner before anything is built. (The page only copies a trap-sheet template; the review itself is a conversation with the owner.)

**Acceptance:** the feed updates daily within its quotas; nothing is deployed automatically.

## M13 — Indicators and threat intelligence

- [x] Extract indicators (URLs, domains, IPs, hashes) from recorded events.
- [x] Enrich them with public threat-intelligence sources (quotas, caching, keys from Settings).
- [x] An Infrastructure view linking sources, indicators and malware families; export on demand.

**Acceptance:** passive only — nothing is executed, contacted beyond the intel APIs, or reported without the owner.

## M14 — Users and roles

- [x] Database users (`admin` and `viewer`) next to the `.env` owner account, which keeps working unchanged as the break-glass login.
- [x] Server-side roles with a default-deny check on every state-changing route, and a test that walks the route table.
- [x] Session versions: password change, reset, disable, role change, deletion and "Sign out everywhere" end the user's sessions at once.
- [x] Login hardening: per-username limit, lockout per source address with a high account-wide ceiling that spares known sources (admin can unlock), the owner never rate-limited by name, same argon2 work and same message for unknown names.
- [x] Password policy (12 to 256 characters, common-password list, not the username) and one-time temporary passwords with a forced change at first sign-in.
- [x] Settings > Users and Audit log for admins; a read-only shell for viewers; first-login "Set your password" screen; account menu with "Change password" and "Sign out".
- [x] Every admin action re-authenticates and writes an audit entry (kept one year).
- [x] Security and UI reviews.
- [x] Optional TOTP two-factor sign-in (future).

**Acceptance:** a colleague can be given read-only access and cannot change anything, by any request; disabling or resetting them ends their sessions at once; security review PASS.

## M15 — Campaigns and ATT&CK

- [x] One command normaliser (addresses, URLs, numbers and long blobs replaced by placeholders) shared by campaign clustering and the script library.
- [x] MITRE ATT&CK catalogue in `ingest/rules/attack/techniques.yaml`, synced hourly, and rules that tag each session with the techniques it used.
- [x] Campaign clustering of finished sessions by shared keys: script, exploit, credential list, payload host, file hash and malware family.
- [x] A campaign needs at least `CAMPAIGN_MIN_SOURCES` distinct sources, and one campaign links at most `CAMPAIGN_LINK_CAP` sessions.
- [x] Research scanners are never clustered.
- [x] Campaign pages with a plain-English story, and a Techniques page with a heatmap of ATT&CK techniques per day.
- [x] Campaign and ATT&CK endpoints in the API, open to both roles.

**Acceptance:** campaigns form from the demo data, a single source never makes one, and security review PASS after the fixes.

## M16 — Defend

- [x] Scored blocklists for addresses, host names, download URLs and file hashes, rebuilt every 15 minutes, with a plain-English reason for every point.
- [x] Scores count distinct source networks, so one attacker cannot fill a list by repeating an indicator.
- [x] A never-list: public resolvers, large SaaS and CDN domains, shared hosting names, reserved addresses, the owner's own addresses and `BLOCKLIST_NEVER`.
- [x] Overrides (always allow, always block) with a note, an optional expiry and an audit entry.
- [x] Exports for OPNsense and pfSense aliases, plain text and CSV; CSV cells are safe to open in a spreadsheet.
- [x] Opt-in token feed under `/feeds` (`FEEDS_ENABLED`): hashed tokens with limits, expiry and revocation.
- [x] Sigma and Suricata rules written from recorded behaviour, each marked "review before deploying".
- [x] "Your exposure" page: your own service inventory next to what the honeypot saw for the same kind of service.

**Acceptance:** the feed is off by default, blocklists stay off until enabled, and security review PASS after the fixes.

## M17 — Script library

- [x] Sessions that ran two or more commands are fingerprinted from their normalised command list. One row stands for one distinct script.
- [x] Script counters only grow, so they survive the deletion of old sessions.
- [x] Plain-English explanations from a declarative annotation base in `ingest/rules/annotations/*.yaml`, matched without regular expressions.
- [x] Optional LLM explainer (`LLM_ENABLED`, off by default) with a daily call quota and a monthly token cap. It sends only the normalised script text, and its answer is stored as text labelled "AI-generated, may be wrong".
- [x] Scripts list and script detail pages. Only an administrator can ask for an explanation ("Explain now").

**Acceptance:** with `LLM_ENABLED=false` nothing leaves the host, the explainer never executes or fetches what it reads, and security review PASS after the fixes.

## M18 — Alerts and weekly report

- [x] Alert channels: Discord and Microsoft Teams webhooks, and e-mail over TLS (STARTTLS or SMTPS). Targets are validated and encrypted at rest.
- [x] Alert rules for new campaigns, new download hosts, malware drops and watched CVEs. Every rule is off until it is switched on, and a rule never replays history.
- [x] A delivery outbox with rate limits and up to three attempts, a constant error code per failure, and a "send a test message" button.
- [x] Weekly report, built once a week after Monday 06:00 in `SITE_TIMEZONE`, with a one-page printable view and an optional alert.
- [x] Alerts never use research-scanner sessions or documentation addresses.

**Acceptance:** nothing is sent until a channel and a rule are both enabled, each channel type accepts a test message, and security review PASS after the fixes.

## M19 — Today, search and research scanners

- [x] Today home page: what changed in the last 24 hours, in plain English.
- [x] Global search for IP addresses, hashes, domains, CVEs and campaigns, from one box in the header.
- [x] Glossary of the terms used in the dashboard.
- [x] Known research scanners (`ingest/rules/scanners.yaml`) are labelled benign by the network that owns them, and left out of lists by default. The HTTP user agent never decides it.
- [x] Benign is an allowlist of harmless behaviour (connect, probe, plain GET, HEAD or OPTIONS). Any login, command, download, exploit or POST makes a session non-benign for good.
- [x] `include_benign` switch on the lists, so the scanners can be shown on request.

**Acceptance:** a research scanner never raises an alert, a session that does more than probe is never labelled benign, and security review PASS after the fixes.

## M20 — Synology NAS sensor and CVE watch fixes

- [x] Synology NAS sensor (`synology`): a DSM 7.2.1-69057 Update 11 look-alike on HTTP 5000 and HTTPS 5001, with the login page, the Web API (`SYNO.API.Info`, `SYNO.API.Auth` and the other APIs), logins always refused with DSM error codes, and every credential recorded.
- [x] Flags and tags for the C3RB3R campaign (CVE-2026-13639 and CVE-2026-13684): `synology-dsm`, `synology-exploit` and `c3rb3r`, mapped to ATT&CK T1190 and T1486. Downloads from DSM requests are recorded as `download_attempt`.
- [x] Compose: `sensor-synology`, network `sensors-synology`, volume `synology-sensor-data`, Redis user `sensor-synology` (`XADD` on `events:synology` only), port guard for 5000 and 5001, and the `.env.example` entries.
- [x] Migration `0017` adds `synology` to the inventory service list. The sensor belongs to the Web and APIs colour family, so the UI gets no new hue.
- [x] CVE watch: the NVD window is 60 days (was 30), read in one-day chunks, oldest first, with a page budget. A busy feed no longer loses CVEs silently at 10,000 results.
- [x] CVE watch: a run that stops early (quota or page budget) resumes from the last complete chunk. GitHub advisories are read in 7-day chunks.
- [x] CVE watch: a one-time start-up rewind refills a shallow history. Watched CVEs that are missing from the table are fetched by id from the NVD (at most 10 per run, once per id per 24 h).
- [x] `just test-integration` uses `docker-compose.it.yml`, so the throwaway project fits in Docker's default address pools next to the live stack.
- [x] Security review of the Synology sensor and of the Compose, port guard and migration changes: passed after fixes (TLS handshake-slot and handshake-rate exhaustion closed with per-IP caps and a full-ClientHello check, nginx error pages and asset sizes made realistic).
- [x] Full stack check: `docker compose up -d --build` with every service healthy, and the Synology ports reached from outside a test network.

**Acceptance:** a DSM client gets the DSM answers, every login attempt is recorded and refused, the forged-session and SCGI request shapes are tagged, the CVE watch fills 60 days without a silent gap, and the security review passes.

## M21 — Anonymous egress, payload collection and static analysis

- [x] `vpn` service: a WireGuard client (settings from `VPN_WG_*` in `.env`) with a kill switch: nothing leaves when the tunnel is down, and DNS goes through the tunnel. The only container with `NET_ADMIN` and `/dev/net/tun`; everything else in it stays hardened.
- [x] Every outbound connection of the stack (ingest enrichment, intel and CVE lookups, the collector) goes through `vpn`. Sensors and the dashboard keep their current paths, and the host itself is unchanged. A test proves that no service other than `vpn` has a direct route to the internet.
- [x] `collector` service: fetches captured download URLs (HTTP, HTTPS, TFTP) through `vpn` only, soon after capture, with size, time, redirect and per-host caps, a generic client identity, and a bounded follow of the next-stage URLs found in fetched scripts. Files go to a quarantine volume under their sha256, mode 0400, never executed, never served raw by the API.
- [x] Static analysis without execution: file type and architecture, sha256 and TLSH, printable strings, YARA rules (Mirai, Gafgyt, miners, Redis modules) kept in the repo, shell deobfuscation (base64, `echo -e` hex, variables), and C2 addresses fed back into the indicators.
- [x] Sample pages in the UI: where a sample came from, which sources dropped it, the chain script → binary → C2, YARA hits and the deobfuscated text. Download of a sample only as a password-protected archive, by an admin.
- [x] Security review (egress, quarantine, parser safety on hostile files) and UI review.

**Acceptance:** with the tunnel down nothing is fetched and no lookup leaves; captured URLs are fetched through the tunnel only; a hostile file cannot crash or escape the analyser; security review PASS.

## M22 — Anonymous reporting

- [x] Abuse reports per hosting provider (contact found through RDAP): standard X-ARF and plain-text bodies with UTC times, source addresses, commands, URLs and hashes. They never contain the honeypot's own address, host names or the project name.
- [x] Indicator export for national CERTs (STIX 2.1 and MISP JSON) and sample bundles ready for public malware repositories.
- [x] A Reports page where the owner reviews each report, copies it and marks it sent. The stack never sends mail and stores no mail credentials.
- [x] Security review (nothing identifying in any export) and UI review.

**Acceptance:** a report can be produced, reviewed and marked sent for a real campaign, and an automated check proves no export contains the honeypot's address or the project name.

## M23 — Upload the VPN configuration from the dashboard

- [x] Settings → VPN: upload a WireGuard `.conf` (strict parsing, re-authentication, the private key never shown again), and go back to the `.env` settings.
- [x] The `vpn` service picks up an uploaded file by itself and restarts on it; nothing leaves outside the tunnel during the switch, and the API gets no Docker socket.
- [x] A new exit address stays blocked until the owner trusts the range the gate observed.
- [x] Guardrail tests for the new volume, security review and UI review.

**Acceptance:** uploading a valid file switches the tunnel with no shell on the VM; an invalid or hostile file is refused; a new exit is unused until trusted; security review PASS.

## M24 — Guided tour, setup checklist and tunnel controls

- [x] A replayable guided tour on first login that explains each area and how payloads, the VPN, abuse reports and alerts work, plus a "?" help on every page.
- [x] A setup checklist computed from the real state (sensors, VPN, collector, reporting, alerts, keys).
- [x] VPN tab: "Check now" and "Reconnect", and a gate that re-checks quickly while closed.
- [x] UI review and security review (new routes, entrypoint change).

**Acceptance:** a new owner can tell from the dashboard what is left to set up; after a tunnel restart the gate reopens within a minute or on demand.

## M25 — Sending abuse reports: send queue and optional SMTP

- [x] A "To send" queue that opens each ready report in the mail app, copies the full text and moves on to the next one.
- [x] Optional SMTP configured in Settings > Reporting (password encrypted, re-authentication, Proton preset), with three modes: off (default), send on click, automatic after a hold time with a daily cap.
- [x] Mail leaves only through the VPN, after a last identity check on the complete message; neutral headers and EHLO name.
- [x] Security review and UI review.

**Acceptance:** with SMTP off nothing is ever sent; with SMTP on, a report is sent through the tunnel only after the guard passes, and the owner can cancel an automatic send during the hold time.

```markdown
## M26 — Report outcomes: did anyone answer?

- [x] A random reply token (`ref` plus 12 hex characters) in the subject of every report, stored per report and independent of every internal id, with the SMTP Message-ID kept for matching. The identity guard and its tests cover the token: never in exports, never derived from an internal id.
- [x] Optional mailbox in Settings > Reporting > Replies (IMAPS or STARTTLS, DNS host name only, password encrypted, re-authentication, admin only), off by default, with "Test connection" and "Check now".
- [x] Ingest replies worker (`ABUSE_REPLIES_ENABLED`, off by default) that reads the mailbox through the VPN tunnel only. Headers come first, unrelated mail is never stored or flagged, size caps apply, attachments are never decoded, HTML is never rendered, and mail is only marked read or moved, never deleted or answered.
- [x] Declarative reply rules in `ingest/rules/replies/` (auto-acknowledgement, ticket opened with ticket id, resolved, rejected, bounce, human reply, unknown) with generic defaults.
- [x] Matching by our Message-ID, then the token, the bounce's original headers, the ticket id and the sender domain. Only verified replies (our Message-ID, or authenticated from the provider's domain) change an outcome by themselves.
- [x] Paste a reply or upload an `.eml` by hand, set an outcome by hand, and confirm or link replies. Excerpts (2,000 characters at most) are kept 180 days.
- [x] Results page (Abuse reports hub): reports sent per kind, provider, ASN and country over time, answers by kind, response delays, each card opening with a plain-English finding.
- [x] Security review (hostile mail, egress, token) and UI review.

**Acceptance:** with no mailbox nothing connects and the owner can still paste replies and set outcomes; with a mailbox, a provider's reply is matched to its report through the tunnel only, classified, and shown with its delay; unrelated mail is never stored; no mail is ever deleted or answered; security review PASS.

## M27 — Takedown tracking and abuse.ch submission

- [x] Takedown targets from sent reports (attacking addresses, payload hosts and their malware URLs, C2 servers) and from abuse.ch submissions, each tracked for 30 days (`TAKEDOWN_ENABLED`, off by default).
- [x] Collector re-checks: one bounded GET through the VPN to a URL that already served malware, on a 0 h, 1 h, 6 h, 24 h, 48 h, then daily schedule, with the M21 URL validator on every hop and a daily quota. Nothing is stored unless the file changed. C2 servers and attacking addresses are never contacted.
- [x] Passive signals within quotas: URLhaus and ThreatFox listing status, AbuseIPDB (read only), whether our own sensors still see an attacking address, whether new samples still point to a C2.
- [x] States up, down, changed and unknown; down confirmed by two checks; time to takedown with its bounds; resurrections; monthly roll-up kept forever.
- [x] Optional abuse.ch submission behind `ABUSECH_SUBMIT_ENABLED` and an explicit owner switch (off, review each, automatic after a hold with a daily cap). Captured malware URLs go to URLhaus (optional C2 `ip:port` to ThreatFox) with an encrypted Auth-Key. A lookup comes first to skip known entries, the identity guard checks every body, delivery is at most once, and submissions show their status and form the audit log.
- [x] Results page: a finding sentence before each chart ("12 of 31 reported malware URLs went down within 48 h"), a time-to-takedown curve, a per-provider table (median time to takedown, % taken down, % answered), and a timeline per target; a Submissions tab.
- [x] CLAUDE.md §5 amended (owner approval) to allow takedown re-checks of URLs that served malware; security review and UI review.

**Acceptance:** with the flags off nothing is checked or submitted; with tracking on, a reported malware URL that goes offline is shown as down with its time to takedown, an unchanged file is never stored again, and no request ever reaches a C2 or an attacking address; with submission on, a URL is sent to URLhaus only after the guard passes and only if URLhaus did not know it; security review PASS.

## M28 — Installable by anyone

- [x] `scripts/install.sh`: checks Docker and Compose, RAM, disk and ports, asks a few questions, generates every secret and the admin password hash, writes `.env` (mode 0600) with `COMPOSE_PROJECT_NAME` and `SUCKERPOT_VOLUME_PREFIX`, creates the volumes, starts the stack and prints the URL and next steps. It never overwrites an `.env`, never adopts existing volumes and never looks up the public address.
- [x] Sensor choice: each sensor can be switched off (`SENSOR_<NAME>=0`, default on, so existing installs keep every sensor); `just sensors` and `just set` change `.env` from the host, and the port guard and the setup checklist follow the selection.
- [x] First-run setup in the dashboard (migration `0025`): welcome, sensors, ports, VPN upload, own address, reporting, alerts, then the M24 checklist and tour; can be skipped and reopened.
- [x] A "Sensors & ports" page listing what to open on the router, the port on this machine, and whether each sensor already receives traffic.
- [x] `just update` (backup, code, `.env` migration, pull or build, migrate, health check, rollback hint) and `just rollback` (restores the pre-update dump after confirmation).
- [x] Low-memory overlay (`docker-compose.lowmem.yml`) for 2 GiB machines, checked by the guardrails.
- [x] Version shown in the dashboard; a daily update check through the VPN only (no version or identifier sent, can be switched off).
- [x] Signed multi-arch images (amd64, arm64) on GHCR from a release workflow, with an install smoke test; build from source stays supported.
- [x] VPN idle mode, so the egress profile can start before a WireGuard file is uploaded.
- [x] Install guide, configuration and deployment updates; security review and UI review.

**Acceptance:** on a fresh Linux VM with Docker, `scripts/install.sh` brings a healthy stack from published images on amd64 and arm64 in one command, and the dashboard walks the owner through the rest; `just update` from the previous release keeps the data and a failed update prints a working rollback; the update check never leaves outside the tunnel and never sends the running version; guardrails and security review PASS.

## M29 — The SuckerPot network (opt-in, anonymous)

- [x] Protocol `spn/1` (JSON over HTTPS, Ed25519-signed requests and responses, nonce and timestamp replay protection, proof of work at enrolment) in a shared `netproto/` package and `docs/network-protocol.md`, with golden test vectors.
- [x] Hub service in `hub/` (own Dockerfile, compose file and migrations, deployed separately): enrol, signed daily observation batches, targets and network summary, reveals, takedown re-checks, leave and delete. No client address stored or logged, no analytics, 14-day observation retention, size caps and rate limits.
- [x] Consensus and anti-poisoning: at least 5 eligible nodes (14 days old, active, with reputation), 2 distinct days, a cap per enrolment cohort, external corroboration or twice the nodes, a never-list, and reputation that drops on disputes.
- [x] Grouped abuse reports sent by the hub from the project mailbox, deduplicated per recipient and target, under daily caps, reviewed by the hub operator in the first release; members' own M22 reports skip targets the network has reported.
- [x] Node worker in ingest (off by default, `NETWORK_ENABLED` plus an admin opt-in with re-authentication): VPN egress gate only, allow-listed aggregates (day buckets, count buckets, services and tags; URLs and domains blinded until consensus), the identity guard on every item and batch, a random delay after each day, never raw events or credentials. Migration `0028`.
- [x] Leaving is one click: the hub deletes the node and its data, the node deletes its key and every network row.
- [x] Network pages: overview (totals, weekly takedowns, k-anonymous country map, what the node helped confirm), members (pseudonyms, country only when 3 or more share it, coarse weekly activity), Settings > Network, the setup step, and figures for the M27 Impact page.
- [x] Threat model, user guide and hub operator guide; security review and UI review.

**Acceptance:** with `NETWORK_ENABLED=false` or no opt-in nothing is ever sent; seven test nodes against a local hub confirm a target only when the consensus rules hold, and a Sybil set of new or same-week nodes never does; planted self addresses in sensor data never reach a batch; a node that leaves has no row left at the hub; the public and member views carry no per-node observation; security review PASS.

## M30 — Community blocklist feeds

- [x] Feed format in `netproto` and `docs/network-protocol.md` ("Feeds"): lists `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`; plain text (dual-stack, IPv4 and IPv6 files), nftables, ipset restore, MikroTik script, CSV, JSON with per-entry metadata, and STIX 2.1 for the outbound lists. Single addresses and exact names only, never a prefix or a wildcard. minisign signatures (a dedicated feed key) on a signed `index.json`, a monotonic serial and `valid_until`, with golden test vectors.
- [x] Hub feed generator (`hub/hub/feeds/`, migration `h0002_feeds`), built only from M29 consensus targets plus stricter rules: TCP-proven inbound behaviour (scans, connects and UDP-only evidence never list), payload hosts only with fetched malware from 2 or more nodes or URLhaus, C2s only with 2 or more samples or ThreatFox, a high tier, and k-support for every published value and date, so one node's sighting changes nothing public.
- [x] Freshness: inbound entries expire after 7 days without k-supported sightings, payload hosts after 14 days or at once when taken down (M27/M29), C2s after 30 days. A 6 h hold before listing, size caps, a change breaker held for operator review, and `HUB_FEED_MODE` (`off` by default, `review`, `auto`).
- [x] Exclusions at render time: reserved and documentation ranges, public resolvers and shared hosts (kept in sync with M16 by a test), CDN front-end ranges, Tor exits, research scanners, an operator allow-list.
- [x] Public static feed site (`feeds.example.org/v1/`, Caddy): no account, no cookies, no logs of downloaders, no CDN by default, ETag/Last-Modified/304, precompressed gzip, atomic hourly publish that keeps unchanged files untouched, data under CC0 1.0, `stats.json` for the project site, `removed.json` (expired and taken-down entries only).
- [x] Delisting: a static form and an API with proof of work, per-day caps and a status token; inbound entries suppressed at once pending review (capped per day), outbound ones reviewed first; outcomes false positive, remediated, policy or rejected, with a reputation penalty only for false positives; 72 h decision target; requester data deleted on schedule.
- [x] Node consumer (`NETWORK_FEED_ENABLED`, off by default, members and non-members): VPN egress gate only, fetch from the feed host only, signature, sha256, rollback and expiry checks, strict parsing, migration `0029`. A verified local mirror under the M16 feed tokens where the always-allow overrides win; the local M16 lists stay unchanged.
- [x] Blocklists page tab "Network": a finding sentence, one card per list with copyable URLs per format, "seen here" and "you helped" badges, firewall setup help, and an honest card saying the lists are the same for everyone and joining makes them better.
- [x] `docs/feeds.md` with exact OPNsense, pfSense and pfBlockerNG steps, nftables, ipset, MikroTik, MISP and DNS filter recipes, signature verification, licence, accuracy statement and delisting; operator guide; threat model additions; M29 amendments (k-support on `/v1/targets`, `payload_ip`, Tor exits); security review and UI review.

**Acceptance:** with `HUB_FEED_MODE=off` the hub writes no list, and with `NETWORK_FEED_ENABLED=false` a node never contacts the feed host. In the seven-node test, a target appears on a list only when the M29 consensus and the M30 publication rules hold; scan-only, UDP-only, typed-URL-only and single-sample C2 targets never do; a Sybil set never does; and a single node re-sighting a listed address changes no published field. Every published file verifies with `minisign` against the feed key, an unchanged file answers `304`, and no file contains a node id, fingerprint, pseudonym, country or target id. A CDN, Tor, resolver or allow-listed address is never listed. An accepted delisting removes the entry at the next run. A node refuses a forged or rolled-back feed and keeps its last good copy. Security review PASS.

## Later (not part of the loop)

- Per-/24 or per-ASN daily cap on new campaigns, so one network cannot create many campaigns in a day.
- ATT&CK per-event mapping: compute the lower-case form of each event field once and share it between rules.
- Campaign clustering: commit per chunk instead of one transaction per cycle, so a long cycle does not hold locks.
- Provider keys: sealed-box (public-key) encryption so the API can store a key but never read it back, only ingest can.
- Public read-only page through Cloudflare Tunnel, IPs masked.
- LLM-backed SSH shell.
- RDP: a fake Windows logon screen that records keystrokes.

## M31 — Hub pre-production and abuse.ch first

- [x] "Behind a tunnel" hub mode (`hub/docker-compose.tunnel.yml`, `hub/Caddyfile.tunnel`): one private HTTP port for a Cloudflare Tunnel connector, client address trusted only from `HUB_TRUSTED_PROXY`, worker and admin egress only through an authenticated proxy on an internal network, startup refusal when a default route exists (IPv4 and IPv6).
- [x] Hub report mail through the proxy (HTTP CONNECT, TLS verified, no direct fallback; a proxy or VPN outage keeps reports queued).
- [x] abuse.ch submission from the hub (migration `h0008`): URLhaus for URLs fetched as malware by 2 or more eligible nodes, ThreatFox for C2s only after a manual approval, feed exclusions and withdrawals on dispute or delisting, `HUB_ABUSECH_MODE` off by default.
- [x] Payload hosts need malware-like content (a known family or an executable or script) before any report, feed entry or submission.
- [x] Neutral names in generated rules and exports; public blocklist policy page on the site.
- [ ] Move the hub to a dedicated server and regenerate its keys before the lists or reports go live; legal review of the policy.

## M32 — Join the network in three commands

Design: `docs/design/m32.md`.

- [x] Committed network defaults (`suckerpot-hub.selfhostr.io`, `suckerpot-feeds.selfhostr.io`, hub and feed public keys) inside the signed images and mirrored for host scripts; an explicit `.env` value wins. Nodes pin a set of up to three hub keys; the hub signs with a primary and an optional alternate key (`X-SPN-Hub-Signature-Alt`), so a key rollover ships in a release and auto-updated nodes follow.
- [x] Participant mode: `./scripts/install.sh --participant` with no question but one consent prompt (`--yes` skips it), a random pseudonym, sensors + database + ingest + network node only (no dashboard, no wizard, no API key), about 2 GiB, the consent recorded in `.env`, the port list printed. Re-running converges; `--full` later switches to full mode and keeps the data; full mode is unchanged.
- [x] No VPN needed: a new `hubproxy` service (profile `direct`) is the only route out in that mode and allows only `CONNECT` to the hub (and feed) names on 443. The egress gate gets a direct mode scoped to those hosts, so every other outbound worker idles; collector and enrichment stay off. With a VPN, a participant behaves as today.
- [x] `./scripts/status.sh` (and `just status`): sensors and ports, hub contact, membership and eligibility, what was sent per day (`--last-batch` prints the exact JSON), self-address state, update state, exit codes for monitoring. `./scripts/participant.sh` for leave, join, VPN, auto-update and uninstall.
- [x] Verifier nodes: role granted by `hub.admin node role grant` and turned on by the node (`NETWORK_VERIFIER`, VPN and collector required). The hub opens a verification task when 2 or more eligible nodes reported the same download link (migration `h0009`), asks those nodes to reveal it early, checks it (public host, never-list, shared hosts, exclusions, per-host and daily caps), holds it for review (`HUB_VERIFY_MODE`, `off` by default), and leases it to a verifier, whose collector fetches it with every M21 guard and no recursion (node migration `0030`) and returns an attestation.
- [x] URLhaus path B: 2 or more eligible reporters plus a malware-like verifier attestation; auto-approval only across two enrolment cohorts, review otherwise. New endpoints `/v1/verify/*` under `spn/1`; no existing message changes, so older nodes keep working.
- [x] Daily automatic updates in participant mode (user crontab, never a container with the Docker socket): signed release manifest checked with cosign against the tag's commit, images verified, 48 h minimum release age, same major version only, automatic rollback on a failed health check, off with one command.
- [x] Guardrails that fail if a participant service gains a route out, if `hubproxy` allows more than the hub names on 443, or if the owner's rendering changes; an end-to-end participant install against a test hub in a throwaway project; docs (`docs/participate.md`, install, network, protocol, updates, operator guide) and a "Help the network" section on the site; security review and UI review.
- [x] Release v0.6.0: hub and feed keys filled in, signed images and signed release manifest.

**Acceptance:** on a clean 2 GiB machine, the three commands and `--yes` produce a running participant with no dashboard, a member at the hub, and a status that reports OK. From that stack, nothing but `suckerpot-hub.selfhostr.io:443` is reachable (direct TCP, other names, IP literals and plain HTTP through `hubproxy` all fail), and the owner's full-mode rendering is unchanged. Two eligible nodes reporting the same link lead to a reveal, a review entry, a verifier fetch and a URLhaus candidate; one node never does, an unprivileged node cannot lease tasks, and a private or never-listed link is refused before any fetch. A pre-M32 node still enrols, submits and pulls against the new hub. An auto-update refuses an unsigned or mismatched release and rolls back after a failed health check. Security review PASS.

## M33 — Network on by default, one-button join

Owner decision (2026-11-04): joining the network is the recommended default and joining or leaving is one button. Design: `docs/design/m33.md`.

- [x] `NETWORK_ENABLED` defaults to true; an explicit `false` still switches everything off. An install that never answered the question never joins on upgrade.
- [x] Full installer asks "Join the SuckerPot network? [Y/n]" (default yes, `--no-network` declines) and writes the consent record; ingest joins from it in full mode too, through the VPN only, after a self address is confirmed. A leave is never undone by a restart.
- [x] Dashboard: the join dialog shows what is shared and asks only for the password; leave is one button; a node that left can join again; setup step 8 has the join button.
- [x] Setup wizard sensor list read from the `(sensor, ts)` index (it timed out on busy systems).
- [x] Security review (PASS; the stale consent record, upgrade pin, end-of-input and wording findings fixed), deploy.
- [x] Release (v0.7.0).

## Move to Selfhostr (v0.8.0)

Owner decision (2026-11-04): SuckerPot is the product and the network; Selfhostr is the small organisation that makes it.

- [x] Repository moved to `github.com/selfhostr/suckerpot`; release images under `ghcr.io/selfhostr/suckerpot-*`, signed by the new repository's release workflow. `scripts/env-migrate.sh` rewrites the old default prefix; installs on v0.7.1 make the move once by hand (`docs/updates.md`).
- [x] Hub at `suckerpot-hub.selfhostr.io`, feeds at `suckerpot-feeds.selfhostr.io/v1`, same keys.
- [x] Site, docs and mock-data demo at `suckerpot.selfhostr.io` (maintained outside the repo); Read the Docs, GitHub Pages and `site/` removed.
- [x] Release (v0.8.0).

## Participant hardening (v0.9.0)

Owner request (2026-11-04): a second person joins as a participant; the three-command install must be enough, and a compromised container must not be able to do anything outside its design.

- [x] Port reachability check at the end of the participant install and `participant.sh ports-check`, from local evidence only (no outside connection).
- [x] Host firewall for participant mode: rendered with no placeholder, offered by the installer (sudo, never blocking), `participant.sh firewall`.
- [x] Isolated gateways, fixed bridge names and IPv6 off on every internal network; one-time stack recreate on update; Docker Engine 28+ warning.
- [x] Generic hardening guardrail over every service; third-party images by digest.
- [x] Automatic updates: 48 h age floor no release can lower, only real verdicts mark a release bad, next candidate tried.
- [x] Two security reviews (first FAIL, all findings fixed; second PASS), release (v0.9.0).

## Dependency refresh (v0.10.0)

- [x] Every dependency upgraded in one coordinated change: Python 3.15, Node 26, Redis 8, TimescaleDB 2.31, web and GitHub Actions majors; TypeScript 7, PostgreSQL 18 (hub) and pnpm 11 held back with a reason.
- [x] Dependabot monthly, grouped per ecosystem (minor/patch and majors).
- [x] Release (v0.10.0).

## M34 — Public network observatory

Owner request (2026-11-07): the project site shows public, anonymised figures about the network, honest at one node. Design: `docs/design/m34.md`.

- [x] `network.json` (schema `selfhostr-network-stats/1`, CC0) on the feed site next to `stats.json`: nodes, bootstrap (eligible nodes missing against `HUB_MIN_NODES`, weekly), outcomes over 90 days, attack traffic per day and the 30-day services, tags and families.
- [x] Anonymity rules: no per-node value, eligible nodes only, day granularity with delay (outcomes 2 days, activity 4 days), final days counted once and never recounted, rounded counts, coarse weekly figures below three eligible nodes, outcome precision tied to the consensus thresholds, weekly bootstrap, minimum support for every named item, node countries only from three members.
- [x] Builder and daily publication in the hub worker (`HUB_OBSERVATORY_ENABLED`, off by default, independent of `HUB_FEED_MODE`), atomic write, migration `h0010` with 400-day retention.
- [x] Caddy: one CORS origin (`HUB_OBSERVATORY_ORIGIN`), `GET` only, in both Caddyfiles.
- [x] Tests: every anonymity rule, a key walker over the whole document, publication with feed mode off, freeze-once, end-to-end through the real Caddyfile.
- [x] Docs: network guide, feeds guide, hub operator guide, changelog.
- [ ] Observatory page on the project site.
- [x] Security review (PASS after one round of fixes: eligible nodes only, outcome precision tied to the consensus thresholds, weekly bootstrap, coarse low-volume fields, CVE tags, complete weeks, no UPDATE grant; then weekly rounded totals and a settled weekly count).
