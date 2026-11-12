# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Flood groups in the database. A source that opens many plain connections in one UTC hour (a
  credential spray, a scanner) no longer leaves one `sessions` row per connection: the new fold
  function merges them into one group row (`kind = 'burst'`, `connections = N`, id `burst-...`),
  keeping the sums, and never merges a connection that did something (a successful login, a
  command, a download, an HTTP request, 20 or more passwords, more events than its passwords
  explain, a campaign, an indicator or a demo event), whatever tag list it is given for CVE,
  payload and severe tags. Each call reads only the rows it folds and their own events, so its
  cost does not grow with what a source sent in the hour. A second function gives a folded
  connection that gets a late event its row back and takes it out of its group, so it is never
  counted twice. Events are never touched. Counts of sessions now sum `connections`, the hourly
  roll-up into `sessions_daily` included. Migration 0034; the ingest role gets `EXECUTE` on both
  functions and still has no `DELETE` on `sessions`; going back to 0033 is refused while a group
  exists.
  See [Data retention](docs/retention.md#flood-groups).
- Flood groups in ingest. The writer folds a connection into its group as soon as it closes, when
  its source has opened enough connections in the hour (`SESSION_FOLD_MIN`, default 20). A sweep
  worker (every minute: the last three hours, then the history, six hours at a time, resuming after
  a restart) folds what the writer did not: connections that never sent a disconnect, a flood
  already under way when ingest started, and the rows stored before this release. Which tags a
  plain connection may carry is `ingest/rules/floods.yaml`; ingest refuses to start when it lists a
  payload or severe tag, a CVE tag, `bluekeep` or `eternalblue`. A failing or slow fold never
  fails or delays a batch: the writer caps each call at 2 s, asks about a source and hour at most
  once a minute and pauses after a timeout; the sweep caps its statements at 10 s and backs off. A
  connection with no disconnect is idle against how far ingest has stored the streams, never the
  clock, so a backlog (a restart, a maintenance stop) never folds a live connection. An event
  whose session id starts with `burst-` is dropped and counted like a forged sensor, campaigns
  never cluster a group, and every count of sessions in ingest (abuse candidates, blocklists,
  network batches, reports, alerts, takedown sightings) now sums `connections`, so the numbers are
  the same with and without folding. New settings
  `SESSION_FOLD_ENABLED`, `SESSION_FOLD_MIN` and `SESSION_FOLD_IDLE_MIN`.
- Flood groups in the API. Sessions carry `kind` and `connections`; `/api/v1/sessions` takes
  `kind=session|burst`; `/api/v1/stats/summary` adds `flood_sessions` and `flood_sources`;
  `/api/v1/sessions/{id}?at=` finds the group a folded connection joined; a group's events
  are read from its source, sensor and port inside its hour, and the new
  `/api/v1/sessions/{id}/credentials` lists the usernames, passwords and pairs a session or
  group tried. Every count of sessions in the API sums `connections`, so folding changes no
  number, and the value filters of the session list still find a flood. The brute-force
  threshold of the CERT exports is per connection.

## [0.11.5] - 2026-11-12

### Fixed

- The collector no longer wanders the public web. It used to read every URL inside a fetched HTML
  page (and any other text file) as a possible next stage, so one connectivity check typed by an
  attacker queued the page's scripts, style sheets, images and links, and then theirs, down to the
  depth cap, and the Malware page filled with unknown text. The analyzer now recognises HTML, SVG
  and other XML, CSS, JSON and the JavaScript of a web page as their own kinds (`html`, `svg`,
  `xml`, `css`, `json`, `javascript`), at the lowest severity with no family unless a detection
  rule matched (any match raises it). A file gets a web kind only when it plausibly is that format
  (JSON must parse, a style sheet must be made of rules, JavaScript needs a token only JavaScript
  has) and its whole input holds no shell command, downloader, code runner or active content (ASP,
  JSP and PHP tags, HTA, scriptlets, WSH, PowerShell, `iex`, `certutil`, `bitsadmin`, `python -c`,
  `perl -e`, `php -r`, `ruby -e`, `node -e`, an interpreter fed by its input (`python3 -`,
  `perl -`, `python3 <<E`) or run on a path, `sh`/`bash`/`dash`/`ksh`/`zsh` as commands, through
  `env` or fed by a redirection, shell `eval`, `base64 -d`, `source <(...)`, `. /path`,
  `/dev/udp/`, gawk `/inet/tcp/`, `ftpget`, Node `child_process`, a Node module load used to write
  or run something, `eval` of anything but one plain string, the `Function` constructor directly
  or through `.constructor`, a global looked up by a built name such as `window["ev"+"al"]`);
  anything else keeps the `script` or `text` kind. Every one of these checks is linear in the file size (a 4 MiB hostile file
  classifies in well under a second). Samples already collected are classified again on their own
  after the update (the analysis version went from 1 to 2).
- The kind alone never spares a file, because a program can be dressed as a page. Web content is
  "plain web" only when no detection rule matched it AND the collector reached it only through the
  assets of other web content: every one of its sources is a fetch target that no attacker ever
  typed (an indicator from a sensor event pointed at it; the mark stays when the indicator is
  pruned), at depth 1 or more, and EVERY file that links to it (not only the first) names it as
  an asset and is itself web content. An asset is an attribute that the element loads, in a real
  start tag (`<img src>`, `<link href>`, `<form action>`, `<video poster>`, `<object data>`...),
  or a style sheet `url()` or `@import` outside comments and strings; text such as `src=...`, a
  comment, the body of a `<script>` or an attribute the element does not load (`<b src>`) is not. A link in the text of a page, in a
  web script, in JSON, in a shell script or in a binary makes the file attacker content (network
  verification fetches count neither way). A plain web sample is kept and shown, but its
  links are not followed, it gets no hash indicator, and it is left out of the network batch, the
  hash lookups (VirusTotal, abuse.ch and the contact checks), the blocklist candidates and the
  abuse report drafts, whether or not a hash indicator was recorded for it before the update.
  Anything an attacker asked for is attacker content whatever its kind: a file from a typed URL
  (depth 0, or a URL that also has an indicator) or from a link inside a script or a binary has
  its links followed within the existing caps (depth 2, 20 next-stage URLs per file), gets a hash
  indicator and feeds all of the above. So a typed page costs at most 20 fetches for its assets,
  and those stop there. A spared file (a `spared` flag on the sample) is analysed again when an
  attacker later asks for it: a typed URL serves the same bytes, an attacker types the URL that
  served it, or a script or a binary links to that URL, even long after a page queued it first.
  If that new analysis fails or times out, the file is no longer spared and its hash becomes an
  indicator.
- The collector skips, when it claims a queued target, any target that no attacker typed and that
  only plain web samples link to. It is marked `refused` with the error `web_parent`, is never
  fetched and spends no quota, so the targets queued before the update do not drain onto the
  public web. If an attacker later types the same URL, or attacker content links to it, it goes
  back in the queue. Links already recorded from old pages stay in their sample's link list.
  Migration 0033 adds the `typed` and `spared` marks, an index on the links of a target, and the
  one function that lets the analyzer put such a target back in the queue: only when a link that
  is not a web asset points at it, and with the time set by the database.
- The Malware page names plain web content in plain words (Web page, Stylesheet, Script (web),
  Image (SVG), Data (JSON), Data (XML)) instead of "Unknown" and the raw kind, and the "new files
  this week" sentence no longer counts it. Sample items in the API carry a `crawled` flag for
  this.

## [0.11.4] - 2026-11-12

### Fixed

- An update no longer leaves the checkout unreadable by the containers. `scripts/update.sh` keeps
  `umask 077` for its state file, but it ran the checkout (and, in source mode, the image build)
  under it too, so every file git rewrote became `0600` (`0700` for executables). In source mode the
  images are built from those files and the non-root user inside a container could not read them:
  the `migrate` container failed with `Permission denied` on its migrations and the update stopped
  with ingest, api, collector and analyzer down. Scripts such as `scripts/backup-service.sh` also
  became `0700`. The checkout, the pull and the build now run under `umask 022`, whatever umask the
  caller has (`scripts/auto-update.sh` runs under `077`), and `scripts/rollback.sh` does the same.
  After every checkout the update, the rollback, the installer and `scripts/env-migrate.sh` make
  the files of the committed tree readable again (`chmod go+rX`, listed from `HEAD`, not the index).
  The folders that hold those files are opened too (`hub/` becomes `0755`), so `hub/.env` is set to
  `0600` afterwards. Never touched: every `.env*` file (the example files excepted), `hub/.env`,
  `hub/secrets` and `.suckerpot-state`, symlinks, and anything that resolves outside the
  checkout. A node that was already hit is repaired by its next update. How to repair one by hand:
  [docs/updates.md](docs/updates.md#unreadable-files-after-an-update).

## [0.11.3] - 2026-11-12

### Added

- Common reconnaissance now carries a tag instead of leaving most Redis, Docker, web, MySQL, ADB
  and Telnet sessions untagged. Two new informational tags (never red, never a malware family):
  `service-probe` for read-only requests that identify an exposed service (Redis `INFO`, `PING`,
  `GET` and `CONFIG GET`; the Docker API `/_ping`, `/version`, `/info` and listings; MySQL and SQL
  Server version and database-list queries; a GET for the signature path of a web application such
  as WordPress, phpinfo, Jenkins or a VPN portal) and `iot-shell-probe` for the shell-escape and
  BusyBox probe sequence that loaders type first on a Telnet device shell (`enable`, `system`,
  `shell`, `sh`, `/bin/busybox <word>`, `cat /proc/self/exe`). Existing tags cover more too:
  `env-file-probe` now follows the web sensor's dotfile, config-file and backup flags (for example
  `/admin/config.php` or `/.vscode/sftp.json`), `scanner` follows its scanner and fuzzer
  user-agent flag, and `recon` includes the Android `getprop` and `screencap` commands. Both new
  tags are mapped to MITRE ATT&CK, named in campaigns and insights and explained on the Defend
  page. A homepage, `robots.txt` or favicon request stays untagged.

### Changed

- Abuse reports now say why a draft is blocked and what to do. Settings, Reporting checks each text (reply contact, signature, introduction, closing, note, subject template, X-ARF user agent) on its own: a text that would block every draft, for example a reply address on a domain that names the project, is refused with one sentence under the field and nothing is saved. The same sentences show when a text you saved earlier blocks drafts today, because the rules grow over time. The list of drafts gets a Blocked drafts card (how many, one sentence per reason, what to do, and the setting that causes it) and a few words on each blocked row. The report page gives a next step for every reason instead of a bare description. The API adds `fields` to a refused settings save, `field_issues` to `GET /abuse/settings` and `blocked_drafts` to `GET /abuse/status`.

### Fixed

- AbuseIPDB lookups no longer go to the same busy addresses every day while new sources stay
  unscored. The hourly maintenance job deleted every stored answer after 48 hours, so each known
  address looked new again and the daily quota was spent on re-checks. Answers are now kept and
  used until they are refreshed, and the migration rebuilds the lost ones from the sessions. The
  quota goes to addresses never looked up first (busiest first), then to answers older than the
  new `REPUTATION_RECHECK_DAYS` (default 7, from 1 to 30). A fifth of each day's quota (at least
  one lookup, at most half) is kept for those refreshes, so old answers are still renewed when
  new sources arrive all day. Addresses that cannot be looked up no longer hold the first places
  of the queue.
- GreyNoise: a "too many requests" answer now stops lookups until the next UTC day and marks the
  day's counter as full (so the key test in Settings reports "quota exhausted" until then, even
  after a key change), instead of retrying every hour. The free Community tier allows far fewer
  lookups than most configured quotas, so the retries only produced more errors.
- Open drafts are checked again after the reporting settings or the "never in a report" list change. Before, a draft kept the result of its last build for up to an hour (longer for a draft the lookup cap skipped), so a reply contact fixed in Settings left every draft marked blocked. The worker now re-checks the open drafts from their stored evidence, with no lookup and no rebuild, when the settings revision or the deny set changed. The check is the one the build and the send path run (text, X-ARF and `.eml`, with the reply reference), and nothing is ever sent by this pass. It never clears what the build found in the evidence (an internal id, a private or a documentation address): only a rebuild does. The sessions the API and the SMTP sender treat as internal ids now include the attacker sessions behind a payload host, as the build does. A draft whose options the owner edited is re-checked on its own. A draft that carries one of those codes is not rendered, downloaded or exported either, and cannot be marked reviewed, until a rebuild clears it.

- Campaigns of one actor are now merged. The worker only merged two campaigns when a single new
  session carried a key of both, which almost never happens: an actor that does credential
  stuffing, then drops a file, then leaves a ransom note produces three keys in separate
  sessions, so it stayed split into three campaigns by kind (the status showed `"merged": 0`
  for ever). A new pass compares the source addresses of the campaigns that changed: two live
  campaigns on a common sensor merge when they share at least 5 addresses and at least 60 % of
  the smaller campaign's addresses are also in the other one. The oldest campaign keeps its id,
  so shared links keep working; the others show as merged and point to it, and the page of a
  merged campaign links to the combined one. It applies to campaigns that already exist, with
  nothing to run: every campaign is checked once after the update (a few hundred per cycle), then
  only the ones that change. A merged campaign is named after its two main goals ("Malware
  dropper and database ransom over MySQL #12"), keeps the highest severity of its parts and
  counts a shared address once. Credential-only floods (many logins, no commands, few addresses
  in one network) still do not form campaigns; the limits and what it would take are in
  [Architecture](docs/ARCHITECTURE.md#how-the-features-fit-together).
- `update.sh` and `install.sh` no longer report a failed update or install on a healthy node
  whose dashboard is bound to a LAN address while `API_ALLOWED_ORIGINS` is set. Their final
  dashboard check sent the bind address as `Host`, which the API rejects; it now sends
  `localhost`, which the API always accepts.
- An honest node on a network too small for corroboration no longer loses reputation every day.
  The hub's daily volume penalty (a node sending many values that no other node sees) now applies
  only while at least `HUB_VOLUME_MIN_NODES` (default 5) active nodes old enough to count have
  reported in the last 14 days. Before, a lone node was penalised daily and ended up
  soft-suspended after about a week.
- The network status no longer shows "0 sent" for a day whose batch was sent twice (after a
  restart or a lost answer). When the hub reports it already holds the batch, the node now
  records the item counts it sent instead of the hub's zeros.

## [0.11.2] - 2026-11-11

### Changed

- The installer now accepts a machine sold as "2 GB" (about 1.9 GiB, for example `MemTotal: 2009976 kB`): the memory bar is 1.75 GiB (1,835,008 kB) instead of about 1.94 GiB, and the default setup runs there with the low-memory limits. Between 1.75 and 2 GiB it warns and asks when there is less than 512 MiB of swap (not with `--yes`). Below 1.75 GiB, participant mode says what the machine reports and offers the lite setup in one question (default yes; `--yes` takes it and prints a note); accepting it behaves exactly as `--lite`. Full mode and machines below the lite minimum (1 GiB) are still refused, and the message states the reported memory and, in full mode, the exact `--participant --lite` command.

### Fixed

- A fresh install no longer fails with `backup` stuck waiting. The `db` healthcheck now probes over TCP (`pg_isready -h 127.0.0.1`), so the database reports healthy only once it accepts network connections, not while the image still runs its temporary start-up server on the Unix socket. The `backup` service also retries a failed dump after 30 s, 60 s, 120 s and so on (never later than the hourly check) instead of waiting an hour. The hub database healthcheck got the same TCP probe.
- A participant node installed without a VPN can now join the network. The installer leaves the hub address out of `.env` so that the one shipped with the release applies, but the egress gate of `ingest` built its direct-mode scope from `.env` only, found no host, and stayed closed with `direct_allow_mismatch`: the node kept running its sensors and never reached the hub. The scope now uses the same shipped defaults as the network code. A node that already agreed to join at install time keeps its request and retries by itself after the update, with nothing to run. VPN mode is unchanged.
- `./scripts/install.sh --feeds` now really fetches the community lists: the feed worker uses the feed address and key shipped with the release when `NETWORK_FEED_URL` and `NETWORK_FEED_KEY` are both left out, instead of staying unconfigured. Set both to point at another feed.
- `./scripts/status.sh` no longer says `Not joined. Join: ./scripts/participant.sh join` for a node that agreed to join but is not accepted by the hub yet. It says `Joining as <pseudonym>: not accepted by the hub yet`, with the last problem in plain words, and exits with code 1 (warning `join_pending`) while a problem blocks the join.

## [0.11.1] - 2026-11-11

### Added

- `scripts/move-admin-ssh.sh`: moves your own admin SSH from the port it uses to another one in one command on Debian and Ubuntu (`sudo ./scripts/move-admin-ssh.sh [PORT]`, default 22222; run it again with another port to change it; `--undo` goes back to port 22, with SuckerPot stopped), including systemd socket activation. It opens the new port next to the current one, waits until a real login on the new port is seen (not just a connection), and only then closes the current one; on a timeout, Ctrl-C, a failure or a killed earlier run, SSH goes back to the port it started from. It refuses SSH bound to a specific address, several ports it did not set up, and a port held by another program, and it opens ufw or firewalld only where SSH is open to everyone. The installer is unchanged and still never edits the SSH configuration; its messages and `docs/vps.md`, `docs/install.md` and `docs/participate.md` point to the script.

## [0.11.0] - 2026-11-11

### Upgrading

- **Check `NETWORK_ENABLED` before you update.** When it is not set in `.env`, a node is now OFF the collaborative network (the compose default changed from `true` to `false`). A node that takes part must have `NETWORK_ENABLED=true` in `.env`; the installer writes it when you join. Check with `grep '^NETWORK_ENABLED=' .env`. A node that has the line set to `true` is unchanged.
- The database migration `0031` runs with the update (the `migrate` service applies it); it replaces one function in place and rewrites no data. Hub operators get `h0011` (a new, empty table) when they update the hub.
- A broker volume written by Redis 8.10 is handled at start. Valkey cannot read the RDB preamble in the AOF file that Redis 8.10 wrote, so the entrypoint moves the unreadable data aside (`*.unreadable-<UTC time>` in the volume, two copies kept) and starts with an empty buffer. Only the events still waiting in the buffer are lost, a few seconds on a healthy node. To keep them, run the `CONFIG SET aof-use-rdb-preamble no` and `BGREWRITEAOF` commands from `docs/updates.md` ("The stream buffer on update and rollback") on the running Redis before you update. This is optional.
- Two features were removed. You can delete these variables from `.env`: `ABUSECH_SUBMIT_ENABLED`, and `LLM_ENABLED`, `LLM_DAILY_QUOTA`, `LLM_MONTHLY_TOKEN_CAP`, `LLM_MODEL` and `ANTHROPIC_API_KEY`. If they stay, they are ignored and the node starts normally. Stored submission rows stay in the database, unused. A key stored in Settings for the removed explanation provider is deleted when the API starts.
- The default of `GREYNOISE_DAILY_QUOTA` is now 7 (it was 50): the free Community tier allows about 50 lookups a week. A value you set in `.env` is kept, so lower it if it is above 7 and you use the free tier.
- `just restore` now restores into a side database and swaps it in, so it needs room for a second copy of the database until the swap. Check `docker system df` and the size of the `db-data` volume first.
- Sign-in has two new settings, `LOGIN_VERIFY_CONCURRENCY` (default 2) and `LOGIN_VERIFY_WAIT` (default 5). The defaults need no change. Each password check holds about 64 MiB, so keep the value inside the `api` memory limit.
- Updates and rollbacks behave differently: a rollback restores the database only when the schema moved (`--restore-db` and `--keep-db` override it), and an update fails only on a service that was healthy before it. Details in `docs/updates.md`.
- Stored sessions keep the tags they already have: there is no re-tagging. The renamed annotation rules make the scripts worker rebuild the stored script explanations once.

### Added

- Hub: public network observatory (design M34). With `HUB_OBSERVATORY_ENABLED=true` (off by default) the worker publishes `network.json` (schema `selfhostr-network-stats/1`, CC0) on the feed site once a day, independent of `HUB_FEED_MODE`: node counts, the bootstrap state against `HUB_MIN_NODES`, confirmations, reports and takedowns, attack traffic per day and the most targeted services, tags and malware families. Every figure is a network total from consensus-eligible nodes only, at day level, published with a delay, rounded, and coarse (weekly, one significant figure, small figures left out) while fewer than three eligible nodes contribute; outcomes are exact only with production consensus thresholds, and bootstrap figures are counted once a week. No per-node value appears. Caddy allows one browser origin to read it (`HUB_OBSERVATORY_ORIGIN`, default `https://suckerpot.selfhostr.io`, `GET` only).
- Hub migration `h0010`: `observatory_daily`, network-wide aggregates of each final day, counted once (the worker role cannot update them) and kept 400 days.
- CI job `licences`: fails when a Python (`uv.lock`) or web (pnpm) dependency has a licence outside the open-source allow-list (MIT, Apache-2.0, BSD, ISC, MPL-2.0, OFL-1.1, CC0, Unlicense, 0BSD, Zlib, BSL-1.0, LGPL/GPL/AGPL). `pnpm run licences` runs the web half locally.
- `scripts/install.sh --participant --lite` for a 1 GiB VPS or Raspberry Pi: a new `docker-compose.lite.yml` overlay (stacked after the low-memory overlay, recorded in `COMPOSE_FILE` so updates keep it) lowers the database and Redis limits, and the default sensors become SSH, Telnet, web and Redis. Total memory limit of the participant stack: 3,248 MiB by default, 1,936 MiB with the low-memory overlay, 1,424 MiB with `--lite`. No security setting changes; a new guardrail test only allows memory figures in the overlay, and the CLI guardrail renders it.
- `docs/vps.md`: join the network from a cheap VPS (no home address, no router change) with the steps to move admin SSH off port 22 first, including the `ssh.socket` case of Ubuntu 24.04 and newer, and a Raspberry Pi section (64-bit system, arm64 images).
- Dashboard banner when the pipeline is stalled: a severe notice above every page ("Events have not been stored for 42 minutes. Attacks reaching your sensors are being lost.") with the last error and the commands to check the service, and a quiet, dismissible notice when events were set aside. A Pipeline card on Settings shows the same state. Nothing is shown while the pipeline is healthy or when the API cannot say.
- `GET /api/v1/settings/pipeline` returns `ok`, `stalled` or `unknown` from a heartbeat that ingest writes (`PIPELINE_STALL_SECONDS`, default 300, sets the stall limit).
- Settings, retention card: a new "Oldest stored event" field, and `retention.oldest_event_at` in `GET /api/v1/settings/system`. When the size ceiling (`DB_MAX_SIZE_GB`) has already dropped older data, the finding says so instead of promising the full 90 days.
- `scripts/install.sh --join-network`: the only way to join the collaborative network without answering the question. `scripts/restore-db.sh --keep-previous` keeps the replaced database as `<db>_before_restore`.
- `just test-backup-restore` and a `backup-restore` CI job: a restore tested end to end on a throwaway project, including a truncated dump that must be refused. `just broker-test` and a `broker` CI job do the same for the broker volume cases.
- Hub migration `h0011`: the `recheck_assignments` table (see Security).
- `scripts/check-release-ref.sh` and a `check` job in the release workflow (see Security).

### Changed

- The message broker is now Valkey 9.1 (`valkey/valkey:9.1.3-alpine3.24`, BSD-3-Clause) instead of Redis 8.10. It is a drop-in replacement: same protocol, same configuration and ACL file, same volumes and ports. The Streams buffer survives the engine change only when the AOF holds no RDB preamble (see Fixed). The container now runs `valkey-server` and the health check `valkey-cli`.
- The collaborative network is presented as an experimental preview and is off unless you ask for it. The installer question defaults to no (`[y/N]`), `--yes` alone never joins, and `NETWORK_ENABLED` defaults to `false` in compose, `.env.example`, ingest and the API. Participant mode still joins, because running that mode is the request. The consent screens say what is sent, to whom, what comes back today (nothing yet) and how to leave.
- Docs corrected to match the code: `docs/network.md` no longer says the hub cannot learn a node's address (Cloudflare, the reverse proxy and the hub operator see the address a request comes from, and the probe-linking limit is described), the never-listed claims match `never.yaml` and `ranges.yaml`, `feeds.md` uses the shipped feed URL, and the GreyNoise free tier is about 50 lookups a week, not a day. `SECURITY.md` names the latest release tag as the supported version. The README gains a short "How it compares" section.
- Sign-in no longer has a global window that refuses everyone: 30 wrong passwords a minute from anywhere used to lock the owner out. Password checks (argon2) run in a small pool (`LOGIN_VERIFY_CONCURRENCY`, default 2) with a short queue (`LOGIN_VERIFY_WAIT`, default 5 seconds). Over the `LOGIN_RATE_GLOBAL` budget, each refused sign-in is answered one second later, and a correct password is never delayed. A client address can have one sign-in check in flight at a time; a second one at once gets `429`. The per-address limit and the global window of re-authentication are unchanged.
- `GREYNOISE_DAILY_QUOTA` defaults to 7 instead of 50 (see Upgrading).
- Tags that name a malware family, a CVE or a fraud now need specific evidence, and generic traffic gets a probe or recon tag instead. `sip-fraud` needs an INVITE to an international number (plain REGISTER or INVITE is `sip-probe`), `synology-exploit` also needs a DSM web API call, `smb-eternalblue` needs an explicit `eternalblue` or `ms17_010` flag (SMB1-only clients get `smb-v1-probe`), `mirai-busybox`, `adb-mirai` and `adb-mirai-download` need a variant token or a `mirai.<arch>` binary name (`mirai-telnet-loader` is removed), `php2shell` needs PHP code in the upload-progress field or the include of a session file the sensor saw created (plain touches get the new `php-upload-progress-probe`), `db-ransom` needs a ransom note, `persistence` needs a write, a crontab pipe or file, `systemctl enable` or `chattr`, and OpenSSH CVE relevance covers OpenSSH CVEs only. The rules engine gains a `has_all` operator, and the two new probe tags are benign, mapped to ATT&CK T1595.002 and have guidance text. The demo generator still produces PHP2Shell sessions.
- Fake SSH server and shell: the authentication methods are exactly `publickey,password` as on a stock Ubuntu OpenSSH (keyboard-interactive is gone), the key exchange lists match and compression is not offered. The fake image derives its machine identity (machine-id, host key fingerprints, boot time, MAC, binary sizes) per install from a secret, binaries have believable sizes and an ELF header, `/proc/self` and a `/proc/<pid>` entry for every process `ps` lists exist, the shell handles `$(( ))` and `$RANDOM`, `wget`, `curl` and `git clone` print what the real tools print for an unresolvable, loopback or reachable host (nothing is fetched, the sensor still only records the URL), downloads vary per URL, and common tools no longer answer "command not found". Several inputs that crashed a command are handled.
- The other service sensors give each install its own coherent identity from its secret: Docker (2 to 6 containers from real images, consistent across the API), Redis (a keyspace with several usage styles, `TTL`, `PTTL` and the `INFO` keyspace line, install-specific paths), ADB (one build date behind the build id, patch level, fingerprint and kernel), web (site title, tagline and posts), SIP (26 Asterisk versions, FreePBX user agents on about 30% of installs) and Synology (29 models with their platform, 28 host names).
- The static safety test of all 12 sensors and `sensors/common` is stricter: no process spawning, no dynamic import or `getattr` indirection on `os` or `builtins`, no outbound primitive. `common` also checks that nothing writes and that only `publisher.py` imports redis. No violation was found.
- Lookups of a session's events carry a time range taken from the session row, so TimescaleDB opens only the chunks that can hold them instead of every compressed chunk. This covers the session events endpoint, campaign excerpts, the session value filter, the story builder and campaign clustering in ingest (candidates are cut into slices of at most one day or 200 sessions). A new static test fails when a query on `events` by `session_id` has no time bound.
- `just restore` (`scripts/restore-db.sh`) loads the dump into a side database while ingest and the API keep running, checks it, and only then swaps it in (see Upgrading). A failure before the swap leaves the live database and the services untouched. After the swap both databases are kept and the swap-back commands are printed. `scripts/rollback.sh` gets the same protection.

### Removed

- The node-side abuse.ch submission: the ingest worker that sent captured malware URLs to URLhaus and command-and-control addresses to ThreatFox, its review queue, its settings card, the Submissions page and `ABUSECH_SUBMIT_ENABLED`. It was off by default, needed a personal abuse.ch account and made each node speak to a third party in its owner's name; the hub already submits centrally. Kept: abuse.ch lookups for enrichment (`ABUSECH_AUTH_KEY`, `ABUSECH_DAILY_QUOTA`), takedown tracking and its listing checks, the hub and the database schema (no migration: the submissions table stays, unused, and retention still prunes it). Takedown targets are now synced from sent reports only.
- The optional LLM explanation of captured scripts: the ingest worker, `POST /scripts/{id}/explain`, the `ai` and `llm` fields of the script answers, the panel on the script page and the `LLM_*` and `ANTHROPIC_API_KEY` variables. It was off by default, needed a paid key and sent normalised commands to an outside service. The built-in line by line explanation from the local rules base and the whole script library stay. No migration: the two tables stay, unused. A key stored for it in Settings is deleted when the API starts, and the API refuses to store a new one.

### Fixed

- Ingest could stop storing events about a week after install, silently. Once the oldest chunk of `events` was compressed, the `retract_benign` call that clears a research scanner's earlier events decompressed it, hit the 30 second statement timeout and made ingest retry the same batch forever, on every stream, while the sensors' capped streams dropped events. Migration `0031` rewrites the function so it only touches the chunks of the session. Ingest now also runs it in a savepoint (a failure no longer fails the batch), isolates streams from each other, counts timeouts and permission errors as failed attempts, bisects a stuck batch and parks the event the database refuses in the small, capped `events:parked` stream (500 entries, 2 KB of data each), and logs the stream, SQLSTATE and database message. A new `pipeline_state` row and `GET /api/v1/settings/pipeline` report a stalled pipeline (`PIPELINE_STALL_SECONDS`, `INGEST_MAX_BATCH_FAILURES`). The `ingest` Redis user gets `XADD` on `events:parked` only.
- Updates no longer fail, roll back and blacklist a release because a service was already unhealthy before the update: the health of every service is recorded first and only a regression fails (`UPDATE_HEALTH_WAIT_SECONDS`, default 180, bounds the wait for `starting` services). A rollback restores the database only when the Alembic revision changed (`--restore-db` and `--keep-db` override it), and the automatic updater adds a release to `bad-versions` only when the release itself is at fault (or after `AUTO_UPDATE_MAX_ATTEMPTS`, default 3, repeated failures).
- Broker: Valkey 9.1 cannot read the RDB preamble of a Redis 8.10 AOF (`Can't handle RDB format version 15`), so the first start on an existing volume crash-looped. The base file is now plain commands (`aof-use-rdb-preamble no`), and when the server cannot load `/data` the entrypoint moves it aside (`*.unreadable-<UTC time>`, two copies kept) and starts empty. An update from Redis 8.10 therefore works unattended and loses only the events still waiting in the buffer; `docs/updates.md` gives the optional command that keeps them. Tested by `scripts/test-broker.sh`.
- Sign-in: a locked or disabled account no longer answers faster than a wrong password, and a flood of wrong passwords can no longer keep the owner queued out.
- Settings no longer says raw events are kept for 90 days when the size ceiling has already dropped older chunks.
- The guardrails read the admin SSH port from `ADMIN_SSH_PORT`, like `scripts/check-ports.sh`, instead of a constant.

### Security

- The hub counted a takedown vote for any open target id a node sent, so two enrolled nodes could push any open target to `taken_down` on their own. The hub now records which recheck items it hands to which node (`recheck_assignments`, at most 200 per node per day, pruned after 3 days) and a vote counts only against such an assignment, once. The wire protocol and the consensus thresholds are unchanged, and nodes on a previous release keep working.
- A release can only come from main: the release workflow first checks that the tag is exactly `vMAJOR.MINOR.PATCH` and that its commit is an ancestor of `origin/main` (`scripts/check-release-ref.sh`), before anything is built or signed. The jobs that write to the registry, sign or publish run in the GitHub environment `release`, where maintainers can require reviewers. Until that environment is configured, only the new check applies. `docs/updates.md` has a new section "What a release proves".

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

[Unreleased]: https://github.com/selfhostr/suckerpot/compare/v0.11.5...HEAD
[0.11.5]: https://github.com/selfhostr/suckerpot/compare/v0.11.4...v0.11.5
[0.11.4]: https://github.com/selfhostr/suckerpot/compare/v0.11.3...v0.11.4
[0.11.3]: https://github.com/selfhostr/suckerpot/compare/v0.11.2...v0.11.3
[0.11.2]: https://github.com/selfhostr/suckerpot/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/selfhostr/suckerpot/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/selfhostr/suckerpot/compare/v0.10.0...v0.11.0
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
