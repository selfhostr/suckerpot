# SuckerPot network hub: operator guide

The hub is the server of the SuckerPot network. It takes the daily batches from member systems, confirms the targets that enough independent sensors agree on, sends abuse reports for them, and publishes the network's figures. It is a separate deployment. It lives in `hub/`, with its own `docker-compose.yml`, its own database and its own migrations.

This guide is for the person who runs a hub. For what members see and share, read [The SuckerPot network](../docs/network.md). For the wire format, read [Network protocol](../docs/network-protocol.md). The design and its review are in [M29](../docs/design/m29.md).

Every example uses placeholders. The public name is `hub.example.org`, and addresses come from the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Where to run the hub

Run the hub on its own host, not on a member's connection.

- **Never on a home line.** A member's home address must never be the hub's address, and must never be the address that sends abuse reports. A home line also changes IP addresses and goes down often.
- **Not on a sensor host.** Keep the hub off any machine that runs a sensor or a member's dashboard.
- **A machine you can dedicate.** A small virtual server in a data centre is the usual choice.

The host needs:

| Need | Why |
| --- | --- |
| A public IPv4 address (IPv6 if you can) | Members connect to it. Caddy also needs it for the certificate |
| Inbound TCP 80 and 443 | Let's Encrypt validation and the HTTPS API |
| A DNS record for `HUB_DOMAIN` that points at the host | Caddy gets its certificate for this name |
| Outbound access | RDAP (to find abuse contacts), the report mailbox (SMTP over TLS), and the optional lookup sources |
| Docker with Compose | Everything runs in containers |
| 2 GB of RAM or more, and 2 vCPUs | The compose file sets a memory limit on each service |

The hub's address becomes public the first time a member joins. Treat the host as public from day one.

## Architecture

| Service | Networks | What it does |
| --- | --- | --- |
| `caddy` | `hub-edge`, `hub-public` | Terminates TLS for `HUB_DOMAIN`, proxies `/v1/*` only, writes no logs |
| `hub-api` | `hub-edge`, `hub-internal` | The signed API (FastAPI and uvicorn), no access log |
| `hub-worker` | `hub-internal`, `hub-out` | Hourly consensus, takedown votes, reputation, statistics, retention, reports. The only service with outbound traffic |
| `hub-db` | `hub-internal` | PostgreSQL 17, with connection and statement logging off |
| `hub-migrate` | `hub-internal` | One-shot: runs the migrations and sets the three database role passwords |
| `hub-admin` | `hub-internal` | Operator CLI, in the `tools` profile. Run it with `docker compose run --rm hub-admin ...` |
| `hub-backup` | `hub-internal` | Daily `pg_dump`, seven kept |

`hub-edge` and `hub-internal` are internal networks. Only Caddy has a port on the host, and only the worker reaches the outside.

Three database roles keep the parts apart. `hub_api` can write nodes, nonces, challenges and observations. `hub_worker` can do everything except change the schema. The migration owner is used only by `hub-migrate`.

## First deployment

1. Create the two external volumes. Their names are `<HUB_VOLUME_PREFIX>_db-data` and `<HUB_VOLUME_PREFIX>_backups`. For example, with the prefix `hubprod`:

   ```bash
   docker volume create hubprod_db-data
   docker volume create hubprod_backups
   ```

   The volumes are external on purpose. Compose cannot delete them, and `docker compose down -v` does not touch them.

   The backup service runs as uid 999 and the feed writer as uid 10001, so give them their volumes (the feeds volume is `<prefix>_feeds`):

   ```bash
   docker run --rm -v hubprod_backups:/v alpine chown 999:999 /v
   docker run --rm -v hubprod_feeds:/v alpine chown 10001:10001 /v
   ```

2. Create the environment file from the template, and fill in every empty value. Use 24 or more characters for each password, all different, with letters, digits, `-` and `_` only.

   ```bash
   cd hub
   cp .env.example .env
   ```

3. Make the signing key. The key is an Ed25519 seed in a file that only the hub can read. Keep the directory and the file out of Git.

   ```bash
   mkdir -p secrets
   sudo chown 10001 secrets
   sudo chmod 700 secrets
   docker compose run --rm hub-admin gen-signing-key --out /keys/hub_signing_key
   docker compose run --rm hub-admin show-public-key --key-file /keys/hub_signing_key
   ```

   The second command prints `hub_key=...`. This is the public key. Publish it to members as `NETWORK_HUB_KEY`, together with `NETWORK_HUB_URL=https://hub.example.org`, through a channel you control.

4. Start the stack and wait for the health checks:

   ```bash
   docker compose up -d --build
   docker compose ps
   ```

   `hub-migrate` runs first, applies the migrations and sets the role passwords. Then `hub-api`, `hub-worker` and `caddy` start. Caddy gets its certificate on the first request.

5. Check the API from a machine outside the hub:

   ```bash
   curl -s https://hub.example.org/v1/info
   ```

   The answer lists `protocols`, `hub_key`, `pow`, `limits`, `thresholds` and `today`. The `hub_key` must match the key you printed in step 3.

### Upgrades

Pull the new code, then run `docker compose up -d --build` from `hub/`. Migrations run again on their own. The worker runs one copy only. Keep it that way.

## Behind a tunnel

Use this mode when the host already uses ports 80 and 443, or when you do not want to expose the host at all. A Cloudflare Tunnel connector (`cloudflared`, on another machine) sends plain HTTP to one host port and Cloudflare ends TLS. The worker reaches the internet only through an existing authenticated HTTP proxy, such as a VPN gateway.

```bash
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d --build
```

Set these in `.env` (see the end of `.env.example`). The overlay needs Docker Compose 2.24 or newer.

| Variable | Meaning |
| --- | --- |
| `HUB_BIND` | Host address Caddy listens on. Use a private address that only the tunnel machine can reach |
| `HUB_HTTP_PORT` | Host port that maps to Caddy's port 8080 |
| `HUB_TRUSTED_PROXY` | Required. The peer address allowed to name the client (see below) |
| `HUB_PUBLIC_SUBNET` | Subnet of the `hub-public` network, `198.18.77.0/24` by default. Change it if it collides with yours |
| `HUB_EGRESS_NETWORK` | Name of the existing Docker network the proxy is on. It must already exist and be created with `internal: true`, with the proxy as its only uplink |
| `HUB_EGRESS_PROXY` | The proxy URL, for example `http://user:change-me@vpn:8888` |

What the overlay changes:

- **Caddy** loads `Caddyfile.tunnel` instead of `Caddyfile`. It serves plain HTTP on 8080 for both names, needs no capability and no sysctl, and is the only service with a published port. A test keeps `Caddyfile.tunnel` identical to `Caddyfile` apart from the site addresses, the trust settings and the forwarding header.
- **Client addresses.** Caddy trusts the `Cf-Connecting-Ip` header only from `HUB_TRUSTED_PROXY`, and rewrites `X-Forwarded-For` with that address for `hub-api`. The rate limits then work per client and not per tunnel. The main `Caddyfile` has no such trust. When the connector runs on another machine, Docker's iptables rules keep its real source address, so set `HUB_TRUSTED_PROXY` to the connector's address. Only when the connector runs on the hub host itself (or a connection arrives through Docker's userland proxy) does Caddy see the gateway of the `hub-public` bridge instead: then use the first address of `HUB_PUBLIC_SUBNET` (`198.18.77.1` by default). The value accepts several space-separated addresses or ranges. To check which peer Caddy sees, send one request through the tunnel and run `docker compose exec caddy netstat -tn | grep :8080`: the foreign address of the connection is the peer. This only reads the live socket table; nothing is logged. Either way, anyone who can reach the host port can name any client address, so firewall that port to the tunnel connector only, and keep `HUB_BIND` private.
- **The egress network must have no other route.** Create it with `internal: true` and put only the proxy on it as the uplink. The worker checks this at start: when a proxy variable is set and the container has a default route, it logs the code `egress_default_route` and refuses to start.
- **Outbound traffic.** `hub-worker` and `hub-admin` join the proxy's network and get `HTTPS_PROXY` and `HTTP_PROXY`. The `hub-out` network is unused, so no service has a direct route out. RDAP, the corroboration sources, the range lists and the abuse.ch submissions all go through the proxy.

In the Cloudflare dashboard, add two public hostnames to the tunnel, one for `HUB_DOMAIN` and one for `HUB_FEEDS_DOMAIN`. Both point at `http://<host>:<HUB_HTTP_PORT>`, where `<host>` is `HUB_BIND`.

Upgrading an existing tunnel install: the overlay gives `hub-public` a fixed subnet, and Docker cannot change the subnet of a network that already exists. Recreate it with `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml down`, then `up -d` again. The volumes are external, so the data is kept.

Things to know:

- **Cloudflare sees client addresses and request contents.** It ends TLS, so it handles every request. The "no client address is logged" promise covers the hub only. Turn off Cloudflare logging and analytics for these hostnames where you can, and tell members that this mode puts a third party in the path.
- **Report mail goes through the proxy too.** When `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` is set (upper or lower case), the mailer opens an HTTP `CONNECT` tunnel to the SMTP host through the proxy (Basic proxy authentication from the URL, percent-decoded), then uses implicit TLS on port 465 or STARTTLS otherwise, with full certificate and host name checks against `HUB_SMTP_HOST`. In this mode TLS is always required, whatever `HUB_SMTP_STARTTLS` says, and there is never a direct connection or a fallback to one. A literal SMTP address must be public. If the proxy or the VPN is down, refuses the tunnel, or the link breaks before the message is sent, the mailer logs a constant code (`proxy_unreachable`, `proxy_refused`, `smtp_link_down`, ...), never a password, and leaves the reports approved and queued for the next run. Only a definitive SMTP answer from the server marks a report failed.
- **Keep the proxy credentials secret.** They live in `.env`, which is never committed.

## Configuration

Set these in `hub/.env`. The defaults are the values in the code, and in `.env.example` where the template sets them.

### Secrets and identity

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_DOMAIN` | none (required) | Public name of the hub. Members use it as `NETWORK_HUB_URL` |
| `HUB_VOLUME_PREFIX` | none (required) | Prefix of the two external volumes |
| `HUB_DB_PASSWORD` | none (required) | Database owner. Used by `hub-db`, `hub-migrate` and `hub-backup` |
| `HUB_API_DB_PASSWORD` | none (required) | Role `hub_api` |
| `HUB_WORKER_DB_PASSWORD` | none (required) | Role `hub_worker` |
| `HUB_SIGNING_KEY_PATH` | `./secrets/hub_signing_key` | Host path of the signing key file, mounted as a Docker secret |
| `HUB_SIGNING_KEY_DIR` | `./secrets` | Host directory that `hub-admin` writes the key into. It must be the directory of `HUB_SIGNING_KEY_PATH` |

The signing key is never read from the environment. Only its file path is.

### Enrolment and proof of work

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_POW_DIFFICULTY` | `27` | Base difficulty in bits, from 0 to 40 |
| `HUB_ENROL_SOFT_CAP` | `3` | Challenges one address prefix may draw in 10 minutes before the price rises |
| `HUB_ENROL_STEP` | `3` | Further challenges per extra bit above the soft cap |
| `HUB_ENROL_HARD_CAP` | `5000` | Enrolments per UTC day in total. More are refused with `enrolment_closed` |
| `HUB_CHALLENGES_PER_PREFIX` | `20` | Challenges one address prefix may request per 10 minutes |

The price is per address prefix. An IPv4 address is its own prefix. An IPv6 address counts as its /64. A flood from one prefix raises that prefix's price only. See the protocol page for the full rule.

### Consensus

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_MIN_NODES` | `5` | Eligible nodes that must see a value before it is confirmed. Also the number of nodes that must fetch a dropper |
| `HUB_MIN_WEIGHT` | `3.0` | Total reputation of those nodes. A node counts at most 1.0 |
| `HUB_NODE_MIN_AGE_DAYS` | `14` | Days a node must be enrolled before its sightings count |
| `HUB_NODE_MIN_ACTIVE_DAYS` | `7` | Days with data in the last 14 that a node needs to count, from 0 to 14 |
| `HUB_MIN_REPUTATION` | `0.3` | Lowest reputation that counts |
| `HUB_VOLUME_MIN_NODES` | `5` | Active nodes that must have reported in the last 14 days before the daily volume penalty applies, from 2. Below this nobody can corroborate a value, so a lone honest node is not penalised |
| `HUB_WINDOW_DAYS` | `7` | Days of sightings that one consensus run looks at, from 1 to 14 |
| `HUB_COHORT_MAX_SHARE` | `0.5` | Most of the nodes one enrolment week may supply |
| `HUB_OBS_RETENTION_DAYS` | `14` | Days to keep per-node observations, from 1 to 60 |

Lower the thresholds only on a test hub. A smaller `HUB_MIN_NODES` makes the network easier to poison.

### Reports

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_REPORT_MODE` | `review` | `review`: an operator approves each report. `auto`: sent after the hold, when the rules below allow it. `off`: nothing is queued |
| `HUB_REPORT_HOLD_HOURS` | `24` | Hours a queued report waits before an automatic approval (`auto` mode) |
| `HUB_AUTO_MIN_COHORTS` | `5` | Independent enrolment weeks among eligible nodes before `auto` mode may approve anything |
| `HUB_REPORT_DAILY_CAP` | `100` | Reports sent per day, all recipients together |
| `HUB_REPORT_TEMPLATE_FILE` | empty | Path of a file on the hub host with the wording. Empty means facts only |
| `HUB_REPORT_REPLY_TO` | empty | Reply address written into the reports |
| `HUB_SMTP_HOST`, `HUB_SMTP_PORT` | empty, `587` | The project's report mailbox |
| `HUB_SMTP_USER`, `HUB_SMTP_PASSWORD` | empty | Login for that mailbox. The password is never logged |
| `HUB_SMTP_FROM` | empty | Sender address |
| `HUB_SMTP_STARTTLS` | `true` | Upgrade the connection with STARTTLS |

Keep the wording out of Git. Put it in a file on the host and point `HUB_REPORT_TEMPLATE_FILE` at it.

### abuse.ch submissions

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_ABUSECH_MODE` | `off` | `off`: nothing is queued or sent. `review`: an operator approves each submission. `auto`: URLhaus submissions are sent after the report hold. ThreatFox ones always wait for an operator |
| `HUB_ABUSECH_AUTH_KEY` | empty | The abuse.ch Auth-Key. Empty means off, whatever the mode. Sent only as a header, never logged |
| `HUB_ABUSECH_DAILY_CAP` | `50` | Submissions sent per day, both services together |

See [Submitting to abuse.ch](#submitting-to-abusech) for what is sent.

### Corroboration

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_ABUSEIPDB_KEY` | empty | Optional. Lets the hub check an address with AbuseIPDB. About 900 checks a day, cached for 24 hours |
| `HUB_GREYNOISE_KEY` | empty | Optional. Lets the hub check an address with GreyNoise. About 40 checks a day, cached for 24 hours |

Without a key, a source is off. Addresses then need 10 nodes instead of 5. The lookup sends only public attacker addresses to the source. No node data is sent.

### Limits and worker

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_RATE_UNSIGNED_PER_MIN` | `10` | Unsigned requests per address, per minute |
| `HUB_RATE_UNSIGNED_PER_DAY` | `100` | Unsigned requests per address, per day |
| `HUB_RATE_SIGNED_PER_HOUR` | `60` | Signed requests per node, per hour |
| `HUB_REVEALS_PER_DAY` | `2000` | Reveals per node, per day |
| `HUB_NEW_VALUES_PER_DAY` | `20000` | New values per node and day. More are dropped and counted as `cap` |
| `HUB_WORKER_INTERVAL_S` | `3600` | Seconds between worker cycles, at least 5 |

### Link verification (M32)

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_VERIFY_MODE` | `off` | `off`: no task, no early reveal accepted. `review`: an operator approves each link (`verify approve <id>`) before a verifier gets it. `auto`: tasks are released after a random delay |
| `HUB_VERIFY_MIN_REPORTERS` | `2` | Eligible nodes that must have reported a link. Below 2 the hub refuses to start |
| `HUB_VERIFY_DAILY_CAP` | `200` | Tasks per day for the whole network |
| `HUB_VERIFY_HOST_DAILY_CAP` | `5` | Tasks per site per day |
| `HUB_VERIFY_LEASE_HOURS` | `6` | How long a verifier holds a task |
| `HUB_VERIFY_MAX_ATTEMPTS` | `2` | Tries per link |
| `HUB_VERIFY_URL_MAX_AGE_DAYS` | `3` | Only links reported in the last N days |
| `HUB_VERIFY_DELAY_MIN_H`, `HUB_VERIFY_DELAY_MAX_H` | `6`, `30` | Random delay between the reveal and the release of a task in `auto` mode |
| `HUB_SIGNING_KEY_ALT_FILE` | empty | Alternate signing key for a key rollover. Answers then carry both signatures. Make it with `gen-signing-key --alt`, publish it in a release, then promote it |

Grant the role with `node role grant <fingerprint> verifier`. The commands are in the Operator CLI section.

### Test overlay only

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_ALLOW_DOCUMENTATION` | off | Accepts documentation address ranges. Never set it on a real hub |
| `HUB_TRUST_PROXY` | set to `1` by compose on `hub-api` | Reads the client address from the forwarding header that Caddy sets. Used only for the in-memory rate limits |

Every variable `hub/hub/config.py` reads is passed through by `hub/docker-compose.yml` with the same default, except the few that compose sets itself (database URLs, signing key path, proxy trust) or that exist only for tests; `hub/tests/test_compose_env.py` fails if one is missing.

## Privacy: what is and is not logged

The hub is designed so that no client IP address is stored or logged.

| Layer | What it does |
| --- | --- |
| Caddy | Log output is discarded globally, and per site. No access log |
| `hub-api` | uvicorn runs with `--no-access-log --no-server-header`, and the log level is `warning` |
| Application | A logging filter rewrites any record that contains an IPv4 or IPv6 address, a node key or a long hex string |
| Rate limits | Kept in memory only, keyed by an HMAC of the address with a random key that changes every day |
| Database | No IP column in any table. `log_connections`, `log_disconnections` and `log_statement` are off |
| Tests | `hub/tests/test_privacy.py` checks these rules, including the Caddyfile and the uvicorn command |

What the operator must still take care of:

- **The host.** The hub cannot control the host's own logs. SSH logs, firewall logs and the Docker daemon's logs can show addresses. Keep them off, or keep them private and short-lived.
- **Your own changes.** Do not add access logs, request logging or a debug mode to the containers. Do not put a client address in a table, a file or a report. The privacy tests will catch some of this, not all.
- **The reverse proxy in front.** If you put a second proxy or a CDN in front of Caddy, its logs are outside this design. Use Caddy alone, or make sure the front proxy also logs nothing.
- **Backups.** A dump holds node keys and observations, but no client addresses. See [Backups](#backups).

## Reports

### What a report contains

A report covers a group of targets. It goes to one recipient, usually an abuse desk for the address's network, and it contains:

- the day range of the evidence;
- the services and the kind of activity;
- behaviour tags and malware families;
- the number of sensors, as a range (5 to 9, 10 to 24, 25 or more) and the number of countries, shown only from three countries up;
- for a download, the SHA-256 and the link, once the link is confirmed;
- for a command server, the address or domain, the port and the family.

A report never contains a node id, a pseudonym, a fingerprint, a node's address, or an exact count. It is sent as plain text and as X-ARF. Headers are neutral: no project name, and no mailer name.

### What gets reported

- An address with a severe activity (a login that worked, a command, a download or an exploit) from enough nodes, or with 100 or more login attempts from enough nodes.
- A link or a file-hosting domain that at least two nodes fetched, once the link is confirmed. The fetched content must be malware-like: a known malware family or an executable or script file type (ELF, PE, shell, Python, Perl, PHP). An HTML page, plain text, an archive or an unknown type never qualifies, so an ordinary page of a compromised site is not listed or reported.
- A command server that is confirmed. Command servers are always reported by hand.

Scans and connections alone are never reported. A target that has been reported is not reported again. A target that came back after a takedown can be reported again, but only when its earlier report is more than 30 days old.

### The flow

1. Each worker cycle (hourly) queues reports for reportable targets, one per recipient and kind. A recipient gets at most one new report per kind every 7 days. A failed report is retried after a day.
2. In `review` mode (the default), the queued report waits.
3. In `auto` mode, the report is approved once the hold is over. Auto mode stays closed until `HUB_AUTO_MIN_COHORTS` independent enrolment weeks exist. It never approves a command-server report.
4. Approved reports are sent. At most one mail per recipient per day, and at most `HUB_REPORT_DAILY_CAP` in total. A failed send blocks that recipient for a day.

### The operator's review

In `review` mode, review each report before you approve it. The CLI runs in the `hub-admin` container:

```bash
docker compose run --rm hub-admin reports list --state queued
docker compose run --rm hub-admin reports show 42
docker compose run --rm hub-admin reports approve 42
docker compose run --rm hub-admin reports cancel 42
```

Before you approve, check:

- **The targets.** Is each address really an attacker, and not a shared service? A public resolver, a large CDN or a package mirror should be on the never-list (`never add`), not in a report.
- **The timing.** Does the day range make sense? A single odd day can be a probe from a member. Ask whether the evidence would also fit a test from your own network.
- **The recipient.** Is the abuse contact the one for that network? The hub gets it from RDAP.
- **Command servers.** Check the dropper that named the server. A command server that only one file vouches for is a weak case.
- **The wording.** The facts must match the evidence. If the wording is empty, the report states the facts only.

Cancel a report when you are not sure. A cancelled report blocks the same target for 30 days, so cancel only what you are willing to leave alone.

### Reports in auto mode

Use `auto` only after you have run `review` for a while and trust the consensus. Keep the hold at least 24 hours, so that you can cancel. Watch the report count. Switch back to `review` if a bad pattern shows up. Command servers still wait for you.

### Abuse handling

When a desk replies, or a member or someone else reports a mistake:

- `target dispute <id> --note "..."` marks the target disputed, and lowers the reputation of the nodes that supported it. Use it when a report was wrong.
- `never add <value> --kind ip|domain|sha256 --note "..."` puts a value on the never-list. The hub stops confirming it, and recheck disputes any confirmed target that matches.
- `node suspend <fingerprint>` (and `unsuspend`) stops a node's data from counting. The node is not told.

Each CLI action that changes state writes an entry to `hub_audit`, with the actor and the action. The audit holds no node data.

## Submitting to abuse.ch

Confirmed malicious infrastructure goes to abuse.ch first, because hosting providers and security vendors act on URLhaus and ThreatFox. The abuse e-mail of the previous section stays the secondary channel, and it is still reviewed by an operator.

### What qualifies

The same consensus as for reports, with the same strictness:

- **URLhaus:** a confirmed link with a revealed value that at least two eligible nodes fetched, where each of those nodes' own report is malware-like (a known family or an executable file type: ELF, PE or a script). One count decides: HTML fetched twice and a third node claiming an executable queues nothing. The tags come from those nodes' reports only.
- **ThreatFox:** a confirmed command server whose family has a Malpedia name (the table is in `hub/abusech.py`). These submissions are never automatic. They wait for an operator in every mode.

Public hosts only: no private or shorthand numeric addresses (`127.1`), single-label names or local suffixes (`.local`, `.internal`, `.lan`, `.home.arpa`). Anything the feeds would exclude (never-list, allow-list, delisting decisions, reserved space, and for ThreatFox the CDN and Tor ranges) is skipped, both when it is queued and again just before it is sent, and the target must still be confirmed or reported. ThreatFox waits while the CDN or Tor ranges are older than 30 days, like the feeds. `target dispute` and an accepted delisting reject the matching queued and approved submissions. A ThreatFox submission is sent only if an operator approved it with the CLI (`approved_manually`), whatever the mode or the actor name. A target is submitted once: the table `abusech_submissions` has a unique `(kind, indicator)`.

### Path B: a link a verifier fetched

A second route to URLhaus exists when link verification is on (`HUB_VERIFY_MODE`). A submission with `basis = verified` needs both:

- at least two distinct **eligible** nodes reported the link (counted from their observations; the verifier's attestation never counts as one of the two, though a verifier whose own sensor reported the link does count as a reporter), and
- a node that **still holds the `verifier` role** attested malware-like content (a known family or an executable file type) in the last 3 days.

The candidate `url` target may still be a candidate, but never disputed, taken down or expired. Every guard of the first path applies (public host, never-list, allow-list, delisting, CDN and Tor ranges, length), at queue time and again just before sending. Before sending, the task must also still be `attested` (not refused by an operator or deleted by retention) and the attester must still hold the role. A link that already has a submission is not queued again; the earlier row wins.

Approval: in `review` mode every row waits for an operator, as today. In `auto` mode a verified row is approved automatically only if `HUB_VERIFY_MODE=auto`, its reporters (recomputed at approval time) come from at least two enrolment cohorts, the network has `HUB_AUTO_MIN_COHORTS` cohorts and the report hold has passed; otherwise it stays queued for review. `target dispute`, `verify refuse`, an accepted delisting and `node role revoke verifier` withdraw verified rows like the others.

### What is sent

The public indicator, the malware name, at most five tags from a fixed list (the family, `elf`, an architecture, `sh`, `exe`), a fixed confidence for ThreatFox and the anonymous flag. Never a node key, a pseudonym, a count of nodes, a day, a free text or anything about the operator. A test checks the outgoing body. The answer is reduced to a constant code (`inserted`, `already_known`, `invalid`, `blacklisted`, `auth_failed`, `rate_limited`, `http_error`, `unknown_outcome`) and the server text is never stored.

Requests use `httpx` with its default proxy handling, so the tunnel overlay's proxy applies. There is a timeout, no redirect is followed and an answer over 64 KiB is dropped. An unknown outcome is not retried. A refused key, a rate limit or an unreachable service leaves the submissions approved for the next cycle.

### The operator's review

```bash
docker compose run --rm hub-admin abusech list --state queued
docker compose run --rm hub-admin abusech approve 7
docker compose run --rm hub-admin abusech reject 8
```

`reports list` shows `abuse.ch: <n>` on a report whose targets have a submission. Finished submissions are kept 365 days.

## Public feeds

The hub publishes the community blocklists on `HUB_FEEDS_DOMAIN` (for example `feeds.example.org`). They are free and public, and they are built from the same consensus as the reports. The design is in [M30](../docs/design/m30.md). The guide for people who download the lists is [Community blocklist feeds](../docs/feeds.md).

Publishing is **off by default**: `HUB_FEED_MODE=off`. While it is off, the worker reads and writes nothing, and the feed site serves only its README.

### The feed key

The feed has its own minisign key. It is not the hub key. A leak of the feed key cannot impersonate the hub to nodes, and the other way round.

Compose mounts the key file into `hub-admin` and `hub-worker`, so create the file first. Give it to uid 10001, then generate the key into it:

```bash
cd hub
sudo touch secrets/feed_key
sudo chown 10001 secrets/feed_key
docker compose run --rm hub-admin gen-feed-key --out /keys/feed_key --force
```

The command prints `feed_public_key=RW...` and `feed_key_id=...`. The public key goes into `README.txt` on the feed site, and into the project documentation, so that people can check it.

- The file is mode `0600`, owned by uid 10001. Keep an offline copy.
- Set `HUB_FEED_KEY_PATH` (default `./secrets/feed_key`) and `HUB_FEED_SIGNING_KEY_FILE=/run/secrets/hub_feed_key`.
- If the key is lost, every earlier file stops verifying for new users, and you must publish a new key with a notice. There is no silent way to rotate it.

### Modes: `HUB_FEED_MODE`

| Mode | What happens |
| --- | --- |
| `off` | Default. Nothing is read, fetched or written. |
| `review` | Recommended for the first weeks. Any run that adds a value is **held** until you release it. Runs that only remove values are published. |
| `auto` | Runs are published on their own. Only a breaker trip (below) holds a run. |

Start with `review`. Read the held diffs for a few weeks before you move to `auto`.

### The change breaker

A run is held when it would change a list too much:

- it adds more than `HUB_FEED_BREAKER_ADD_PCT` (50 %) of a list, or removes more than `HUB_FEED_BREAKER_REMOVE_PCT` (50 %); and
- the absolute change is at least `HUB_FEED_BREAKER_MIN` (200).

A held run publishes nothing. The previous files stay on the feed site until their `valid_until`. The run is stored as `held`, with its diff, and an audit row is written. The breaker catches poisoning bursts, consensus bugs and data loss.

| Command | What it does |
| --- | --- |
| `feeds status` | Paused or not, the last status, and the last 10 runs with their state |
| `feeds diff <serial>` | Shows what a held run would change |
| `feeds release <serial>` | Lets the held run go out at the next run |
| `feeds discard <serial>` | Drops the held run. Runs with the same change are skipped until the change is different. |
| `feeds pause` / `feeds resume` | Stops or restarts runs. A paused feed writes nothing. |
| `feeds rebuild` | Runs now, ignoring the interval |

```bash
docker compose run --rm hub-admin feeds diff 4813
docker compose run --rm hub-admin feeds release 4813
```

### The allow-list

The allow-list holds values that no list may carry. A value can be an address, a CIDR or a domain (suffix match). Allowing is safe, so CIDRs are fine here. They never go into a list.

| Command | What it does |
| --- | --- |
| `allow add <value> --reason <reason> [--expires <date or days>] [--note "..."]` | Adds a value |
| `allow remove <value>` | Removes it |
| `allow list` | Lists the entries |

Reasons: `owner_request`, `shared_infra`, `remediated`, `policy`, `false_positive`. `remediated` and `owner_request` expire after 90 days unless you give `--expires`. The other reasons do not expire.

### Delisting: the operator side

People ask for removals through the form at `https://feeds.example.org/v1/delist.html`, through the API, or by e-mail to `HUB_DELIST_MAILBOX`. Every request is reviewed by a person. The public target is **72 hours**, and `README.txt` says so.

| Command | What it does |
| --- | --- |
| `delist list [--state received\|suppressed\|accepted\|rejected]` | Lists requests |
| `delist show <id>` | Shows one request, with its evidence and contact |
| `delist accept <id> --as false_positive\|remediated\|policy --note "..." [--list inbound\|outbound\|outbound-domains]` | Accepts it, for the request's scope or the narrower `--list` |
| `delist reject <id> --note "..."` | Rejects it. The entry stays. |

The `--note` is **public**. The requester sees it, so write it for them.

| Outcome | What it does |
| --- | --- |
| `false_positive` | Removes the value, allows it for good, and disputes its target. Contributors still linked to the target lose a little reputation (M29 §8.3). |
| `remediated` | Removes the value and allows it for 90 days. The target is not disputed. |
| `policy` | Removes the value, allows it for good, and adds it to the never-list. Use it for a resolver or a CDN that should never have been listed. |
| `rejected` | The value stays, and the note explains why. |

Interim effect: an inbound value is hidden from the next run until the decision. The number of values hidden per day is capped by `HUB_DELIST_AUTO_SUPPRESS_DAILY`. Outbound values are not hidden. They are the ones attackers most want to escape, so they wait for review. A suppressed inbound value stays hidden past the SLA, because a wrongly hidden bot address costs less than a wrongly listed innocent one. Check the queue with `delist list --state received` at least once a day. `delist list` and `feeds status` print a warning line when an open request is past the 72 h SLA.

Scope: a value is hidden only when `inbound` is the only list that holds it, whatever list the request names, and it is hidden from `inbound` only. An accepted request applies to the list it named, or to `inbound` when that was the only list holding the value. Such a decision, a false positive included, never touches the same address on `outbound`. A request that named no list for a value that is on an outbound list too covers every list: narrow it with `delist accept ... --list inbound` (or another list) unless you mean to take the value off every list. `--list` can only narrow, never widen or move, a request's scope. `allow list` shows the scope of every row.

### Ranges, and failing closed

The hub excludes what no list may carry: reserved space, public resolvers, shared hosting names, the never-list, the allow-list, CDN front-end ranges and Tor exit relays. The CDN and Tor ranges come from fixed sources, listed in `hub/hub/data/ranges.yaml`. The hub contacts only those hosts, over HTTPS, with no redirect.

| Source | Refresh | Notes |
| --- | --- | --- |
| `tor` | every 24 h | Tor exit relays. Always excluded from every list (there is no switch). |
| `cdn:cloudflare`, `cdn:fastly`, `cdn:cloudfront` | every 7 days | Major CDN and cloud front ends |

- A failed refresh keeps the last good copy. It retries after 6 hours.
- A source is refused when it holds a prefix wider than /8 (IPv4) or /16 (IPv6), when it is too small, or when it shrinks by more than half.
- Every source of `ranges.yaml`, and `tor` always, must have a copy younger than 30 days. A source that was never fetched, or whose copy is older, stops every feed run (`ranges_stale`). The hub does not publish without its exclusions.
- `ranges status` shows the copies, and `ranges refresh` fetches now.
- `HUB_EXTERNAL_RANGES_ENABLED=false` keeps every feed off, because the exclusions would be missing.

Plain cloud compute (VPS providers) is not excluded. That is where malware lives. Short expiry and delisting handle address reuse.

### Outside sources

A single report of an address is not enough for the high tier. The hub asks AbuseIPDB and GreyNoise, when `HUB_ABUSEIPDB_KEY` or `HUB_GREYNOISE_KEY` is set, and caches the answer. Without a key there is no outside source. Then the high lists stay empty. URLhaus and ThreatFox are not used for corroboration yet.

### Settings

Set these in `hub/.env`. The defaults are the values in `.env.example`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_FEED_MODE` | `off` | `off`, `review` or `auto` |
| `HUB_FEEDS_DOMAIN` | `feeds.example.org` | Public name of the feed site. A separate Caddy site, separate from `HUB_DOMAIN`. |
| `HUB_FEED_KEY_PATH` | `./secrets/feed_key` | Host path of the feed key |
| `HUB_FEED_SIGNING_KEY_FILE` | `/run/secrets/hub_feed_key` | Where the worker reads the key |
| `HUB_FEED_INTERVAL_MIN` | `60` | Minutes between runs |
| `HUB_FEED_HOLD_HOURS` | `6` | Hours a new value waits before it is listed |
| `HUB_FEED_VALID_DAYS` | `3` | Days a signed index stays valid |
| `HUB_FEED_TTL_INBOUND_DAYS` / `_PAYLOAD_DAYS` / `_C2_DAYS` | `7` / `14` / `30` | Days without a new sighting before an entry leaves |
| `HUB_FEED_MAX_INBOUND` / `_OUTBOUND` / `_DOMAINS` | `50000` / `20000` / `20000` | Size caps per list |
| `HUB_FEED_BREAKER_ADD_PCT` / `_REMOVE_PCT` / `_MIN` | `50` / `50` / `200` | Change breaker |
| `HUB_FEED_NEVER` | empty | Extra addresses or names that no feed may carry (comma separated, for example your own hosts) |
| `HUB_EXTERNAL_RANGES_ENABLED` | `true` | Fetch the CDN and Tor range sources. With `false` the feeds stay off. |
| `HUB_DELIST_POW_DIFFICULTY` | `20` | Proof-of-work bits for a removal request |
| `HUB_DELIST_DAILY_CAP` | `200` | Removal requests accepted per day |
| `HUB_DELIST_AUTO_SUPPRESS_DAILY` | `50` | Inbound values that may be hidden per day before a decision |
| `HUB_DELIST_MAILBOX` | empty | Mailbox named in `README.txt` for removals by e-mail. Empty means the form only. |

### The feed site and its limits

- **No CDN.** Static files are cheap to serve. A 50,000-line list is roughly 750 KiB, and roughly 250 KiB compressed. A CDN would see every download. If you add one, change `README.txt` to say which CDN sees the requests, and record the decision here. The privacy statement changes with it.
- **No logs.** The feed site discards its access log, sets no cookies and honours no query string on files. The one exception is `/v1/lookup`.
- **Connection limits.** Caddy limits the header size, the request body (64 KB on the feed site) and the timeouts for each connection. Limit each source at the host too, with nftables, and do not log it. The example below limits new connections per source address. Test it on your host before you rely on it.

  ```
  table inet feed_guard {
    chain input {
      type filter hook input priority filter; policy accept;
      tcp dport { 80, 443 } ct state new meter feed_rate { ip saddr limit rate over 30/second } drop
    }
  }
  ```

- **Caddy and `NET_BIND_SERVICE`.** Caddy runs as uid 65532 with every capability dropped. It needs one capability back: `NET_BIND_SERVICE`, to bind ports 80 and 443. The Caddy binary carries that capability as a file capability, and the kernel refuses to run a binary with a file capability that it cannot grant. So `cap_add: [NET_BIND_SERVICE]` is the only capability added. The sysctl `net.ipv4.ip_unprivileged_port_start=0` lets the user bind the low ports. Nothing else is granted.

### Feed health

Add these to your checks. A held run or a failed run needs a look.

| Check | Healthy when |
| --- | --- |
| `feeds status` | The last run is `published` or `unchanged`, or it is a `held` run you know about |
| Feed index | `index.json` on the feed site has a `valid_until` in the future |
| Feed key | `feed_public_key` in `README.txt` matches the key in the project documentation |

Feed tests run in `just test`. The end-to-end feed test runs in `just hub-integration`, including a minisign check of the published files.

## Public network observatory

The worker can publish `network.json` on the feed site: anonymised figures about the network for the project site (node counts, the bootstrap state, confirmations, reports, takedowns and the attack traffic the network sees). The design, the schema and every anonymity rule are in [M34](../docs/design/m34.md); the public description is in [The SuckerPot network](../docs/network.md#public-network-figures).

It is **off by default**. It does not depend on `HUB_FEED_MODE`: the lists can stay off while the observatory publishes.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_OBSERVATORY_ENABLED` | `false` | Build `network.json` into `HUB_FEED_DIR` once a day. `false` reads and writes nothing |
| `HUB_OBSERVATORY_ORIGIN` | `https://suckerpot.selfhostr.io` | The one browser origin Caddy allows to read the file (CORS, `GET` only). Read by `caddy`, not by the worker |

To turn it on, set `HUB_OBSERVATORY_ENABLED=true` in `hub/.env` and run `docker compose up -d hub-worker caddy`. The file appears after the next worker cycle at `https://<HUB_FEEDS_DOMAIN>/v1/network.json`. To unpublish, turn it off and delete `network.json` and `network.json.gz` from the feeds volume.

Things to know:

- Each final day (four days back, when no batch for it can arrive) is counted once into `observatory_daily` and never recounted. Only days still covered by the observations (`HUB_OBS_RETENTION_DAYS`) can be counted, so a newly enabled observatory starts with about ten days of history and builds up from there.
- Only nodes eligible for consensus count. `min_nodes` in the file is `HUB_MIN_NODES`.
- Relaxed thresholds are handled in code: with any eligibility setting below its default, the activity figures stay coarse; with relaxed consensus (`HUB_MIN_NODES`, `HUB_MIN_WEIGHT`, `HUB_COHORT_MAX_SHARE`) the outcomes are weekly and rounded to tens, and with `HUB_MIN_NODES` below 3 no outcome number is published.
- The bootstrap figures are counted once per ISO week and kept in `worker_state`.
- The file is not signed and not listed in the feed index. It is informational.

## Operator CLI

```bash
docker compose run --rm hub-admin <command>
```

| Command | What it does |
| --- | --- |
| `gen-signing-key --out /keys/hub_signing_key` | Makes the signing key. Refuses to overwrite unless `--force` is given. The file is mode 0400 |
| `show-public-key --key-file /keys/hub_signing_key [--all]` | Prints `hub_key=...`; `--all` also prints `hub_key_alt=...` from `--alt-key-file` (default `HUB_SIGNING_KEY_ALT_FILE`) |
| `gen-signing-key --alt --out <file>` | Makes the alternate key for a rollover. Never overwrites, even with `--force`. Mode 0400 |
| `reports list [--state queued\|approved\|sent\|failed\|cancelled]` | Lists reports |
| `reports show <id>` | Shows a report's text and targets |
| `reports approve <id>` | Approves a queued report. It is sent by the next worker cycle |
| `reports cancel <id>` | Cancels a report |
| `abusech list [--state queued\|approved\|sent\|failed\|rejected]` | Lists abuse.ch submissions |
| `abusech approve <id>` / `abusech reject <id>` | Approves a queued submission, or rejects a queued or approved one |
| `abusech cancel <id>` / `abusech cancel --all-verified` | Withdraws one unsent submission, or every unsent verified one (use it if you stop trusting a verifier) |
| `node role grant <fingerprint> verifier` / `node role revoke <fingerprint> verifier` | Gives or removes the verifier role. A revoke returns the node's open leases to the queue and withdraws verified submissions that no remaining verifier vouches for |
| `node roles` | Lists the nodes that hold a role (fingerprint, role, day granted) |
| `verify status` | Task counts per state, the mode and how many links were admitted today against the caps |
| `verify list [--state ...]` | Lists tasks (id, state, site, reporters/cohorts, last report day, release time). Never prints a link |
| `verify show <id>` | One task and its attestations. The link is printed only while the task is `pending_review`, `queued` or `leased` |
| `verify approve <id>` | Moves a `pending_review` task to `queued`. A verifier can lease it at once (no release delay) |
| `verify refuse <id> --note "..." [--abuse]` | Ends a task as `refused` (`operator`) and withdraws its submissions. `--abuse` also disputes the `url` candidate (lowers its contributors' reputation). `reject` is an alias |
| `target dispute <id> --note "..."` | Disputes a target |
| `never add <value> [--kind ip\|domain\|sha256] [--note "..."]` | Adds a value to the never-list |
| `never remove <value>` | Removes a value from the never-list |
| `never list` | Lists the never-list |
| `node suspend <fingerprint>` / `node unsuspend <fingerprint>` | Suspends or restores a node |
| `stats` | Prints the figures |

There is no web admin. The CLI keeps the attack surface small. Every change above writes a `hub_audit` row with the action and counts only: no link, no fingerprint, no node id.

There is no `verify pause`. The API (`hub_api`) cannot read worker markers, and a pause that only the worker honoured would let verifiers keep leasing. To stop verification, set `HUB_VERIFY_MODE=off` and restart the hub, or `review` to hold new tasks for approval. To stop one verifier, `node role revoke`. To stop sending, `abusech cancel --all-verified` or `HUB_ABUSECH_MODE=off`.

## What the worker does

Each cycle runs these steps. A failing step is logged by type and does not stop the others.

1. Seeds the built-in never-list (public resolvers, large CDN and SaaS domains, update servers, package registries).
2. Runs consensus over the window, confirming or keeping candidates.
3. Reads the takedown votes.
4. Re-checks the never-list against confirmed targets.
5. Expires targets that nobody has seen for 30 days.
6. Once a day: reputation, weekly member statistics and the network summary.
7. With `HUB_OBSERVATORY_ENABLED=true`: counts the newly final days and, once a day, publishes `network.json`.
8. Runs retention.
9. Queues, approves and sends reports, if the mode allows it.
10. Queues, approves and sends abuse.ch submissions, if a mode and an Auth-Key are set.
11. Writes a heartbeat. The container health check fails when the heartbeat is older than three cycles.

Takedown votes come from members' local re-checks. A vote counts only for a target the hub asked that node to re-check that day, once (the `recheck_assignments` table, pruned after 3 days). Members do not send those yet in this release, so no target moves to `taken_down` for now. See [Takedown checks](../docs/network.md#takedown-checks).

## Retention

| Data | Kept for |
| --- | --- |
| Per-node observations | `HUB_OBS_RETENTION_DAYS` (14) |
| Batch markers | 14 days |
| Nonces and enrolment challenges | Until they expire (10 minutes) |
| Contributor links | Until the target is resolved, or 30 days |
| Takedown votes | 30 days |
| Weekly member statistics | 8 weeks |
| Candidate targets that nobody saw again | 14 days |
| Expired targets | 180 days after their last update |
| Recipient log (report counts per day) | 90 days |
| Reports sent, failed or cancelled | 365 days |
| abuse.ch submissions sent, failed or rejected | 365 days |
| Observatory daily aggregates (network-wide, no node reference) | 400 days |
| Nodes with no request for 30 days | Deleted, with everything linked to them |
| Delisting requests | 180 days once decided (an open request is kept until its decision); evidence and contact 30 days after the decision, or 180 days after the request while it is still open |

## Backups

The `hub-backup` service runs `pg_dump` once a day, in custom format. It keeps the seven newest dumps in the `<HUB_VOLUME_PREFIX>_backups` volume. The health check is healthy while a dump is less than 26 hours old.

A dump holds the node public keys, pseudonyms, countries that members showed, enrolment days, the last 14 days of observations, the report texts and the audit log. Treat the volume as sensitive:

- keep it on a private disk, and do not copy it to shared storage unless it is encrypted;
- do not put dumps in a bug report or a chat;
- delete old dumps when you no longer need them.

### Restoring

The repository has no restore script for the hub yet. A restore is manual:

1. Stop the services that write: `docker compose stop hub-api hub-worker`.
2. Restore the dump into `hub-db`, with `pg_restore --clean --if-exists` into the `hub` database, as the database owner.
3. Run `docker compose run --rm hub-migrate` to check the schema and the role passwords.
4. Start the stopped services again.

Be aware of two things. First, a dump older than a node's leave brings that node back into the database. Its key can no longer sign anything, because the node wiped its key, and the node is removed after 30 days of silence. Second, a restore loses everything written after the dump was taken.

### The signing key

Back up the signing key file separately, in a private and encrypted place. Do not store it in the same volume as the dumps. Without it, the hub cannot sign answers under the published key.

If the key is lost, make a new one with `gen-signing-key`, publish the new `hub_key`, and tell members to update `NETWORK_HUB_KEY`. Their node keys stay valid, so they do not need to join again.

If the key leaks, an attacker can sign fake answers that members would accept. Make a new key at once, publish it through a channel you trust, and ask members to update. Treat every answer signed in the time between as suspect.

## Health and monitoring

| Check | Healthy when |
| --- | --- |
| `hub-api` | `GET /healthz` on `127.0.0.1:8080` returns 200 |
| `hub-worker` | `python -m hub.worker --health`: the last heartbeat is less than three cycles old |
| `hub-db` | `pg_isready` answers |
| `hub-backup` | A dump is less than 26 hours old |
| `caddy` | Port 443 accepts connections |

Watch the queued reports and the figures from `stats`. A growing queue that nobody reviews is a risk: it stops the reports, or it leaves a target unreported for a long time.

## Tests

| Command | What it runs |
| --- | --- |
| `just test` | The unit tests of the hub (`-m 'not integration'`), with the other Python packages |
| `just hub-integration` | The integration tests against a throwaway PostgreSQL (`hub/docker-compose.test.yml`), with documentation ranges allowed, and an end-to-end flow: synthetic nodes enrolled with a low difficulty, aged, a worker run, reveals, rechecks, and a leave |

The integration run uses its own project name and its own volumes, and removes them at the end.

## Limits of this release

- No web admin. Everything is done through the CLI.
- No restore script yet (see [Restoring](#restoring)).
- Takedown votes are not sent by members yet, so no target becomes `taken_down`.
- Command-server reports are always reviewed by hand. The hub never connects to a target itself. A confirmed target is a judgement by consensus, not a proof.
- The community feeds are off until the project identity is set (the feed domain, the feed key and the delisting mailbox), and until a short legal review is done. `HUB_FEED_MODE` stays `off` until then.
- The feeds corroborate with AbuseIPDB and GreyNoise only. URLhaus and ThreatFox are not used yet: the abuse.ch corroboration path of the selection code exists but is never fed, so an outbound entry always needs the sample evidence of two nodes.
- Delisting requests share one global daily cap (`HUB_DELIST_DAILY_CAP`). Someone who solves the proof of work many times can use it up for a day, and real requests then wait for the next day or go to the project mailbox. Nothing is listed or unlisted by this.
- The feed signing key cannot be rotated yet. A node keeps refusing lists signed with any other key, so a lost or replaced key stops updates (the nodes keep their last verified copy until it expires). It never makes them accept forged lists.
- A C2 report does not say how sure the node was. Nodes only send C2 addresses they hold with high confidence; the hub cannot check that, and relies on its own rule instead (two droppers, each named by two nodes).
