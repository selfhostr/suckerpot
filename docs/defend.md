# Defend with blocklists, rules and your exposure

The Defend pages turn what the honeypot saw into things you can use at work: lists to load into a firewall, rules to load into a SIEM or an intrusion detection system, and a short checklist per attack type. Everything here is built from data already in the database. Nothing is scanned, resolved or contacted, and nothing is reported to anyone.

## Blocklists

```{warning}
**Experimental preview.** The SuckerPot network has very few nodes today. Its shared feed may be empty, and a participant gets nothing back yet. Thresholds and the protocol may change without notice. Known limits: identity is free, so the consensus does not yet resist a determined attacker who creates several nodes, and the hub run by the project maintainers is the single root of trust. The local blocklists on this page do not depend on the network. Only the community lists do. See [The SuckerPot network](network.md) and [Community blocklist feeds](feeds.md).
```


Ingest scores every source address, host name, download URL and file hash seen in the last `BLOCKLIST_WINDOW_DAYS` days (default 30) and stores the result in `blocklist_entries`. It runs every 15 minutes and is off by default: set `BLOCKLIST_ENABLED=true`.

A score runs from 0 to 100. Each point has a reason, shown in plain English on the page: brute-forcing, a login that worked, commands run, malware dropped, an exploit attempt, a bad AbuseIPDB score, several sensors hit, part of a campaign, and so on. Addresses that malware dropped on your decoys is said to contact (probable C2) are scored too: 75 when ThreatFox lists them as a botnet C2, 40 when only a VirusTotal sandbox saw the contact (below the default feed threshold of 50). See {ref}`Security <probable-c2-addresses>`. Mass scanners that did no harm are capped at 35. Entries below 10 are not listed. At most `BLOCKLIST_MAX_ROWS` entries are kept (default 20,000), best score first.

An indicator typed into a command can be planted by a single attacker, so indicators are scored by distinct source networks (/24 for IPv4, /48 for IPv6), never by how often they appear. Without a threat-intel match, a hash recorded by a sensor, or three independent source networks, an indicator scores at most 45, below the default feed threshold of 50.

Never listed, whatever the score:

- public DNS resolvers (such as 8.8.8.8 and 1.1.1.1) and a built-in list of large SaaS, cloud and CDN domains;
- anything in your own never-list: `BLOCKLIST_NEVER` (addresses, networks, names, comma separated), plus `AUTH_TRUSTED_PROXIES`, `API_ALLOWED_HOSTS` and `INDICATORS_IGNORE`, which are read automatically;
- private, loopback, link-local, multicast and other reserved addresses (so your own network cannot end up on a list);
- a short built-in list of shared hosting names such as `github.com` or `pastebin.com` (attackers download tools from them, and so do you). Other hosting providers are not excluded;
- research scanners, unless you ask for them.

### Overrides

An administrator can always allow or always block a value, with a note and an optional expiry. While feeds are enabled this asks for the account password again, because it changes what firewalls receive. Allowed values leave every list at once; blocked values join at score 100. Overrides are audited.

### Exports

Download from the Blocklists page, or `GET /api/v1/defend/export` while signed in:

| Format | Content | Use it for |
| --- | --- | --- |
| `alias` | IP addresses, one per line, nothing else | OPNsense and pfSense "URL Table (IPs)" aliases |
| `txt` | One value per line (any kind) | Proxies, DNS filters, EDR import lists |
| `csv` | Every column, with a header | Spreadsheets and reports |

Every value is validated again when it is written out. In CSV, a cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe, and control characters are removed, so opening a file in a spreadsheet cannot run a formula. Demo entries are left out unless you ask for them.

### The subscription feed (optional)

A firewall cannot sign in to the dashboard, so there is an optional feed. It is **off by default**: set `FEEDS_ENABLED=true` and restart the API. It is the only part of the app that works without the dashboard login.

- Create a token in Settings, Feeds (administrators, password asked again). The token has 256 random bits and is shown once; only its hash is stored. It can carry limits (kinds, minimum score, research scanners or not) and an expiry, and it can be revoked at any time.
- Fetch `https://<dashboard>/feeds/<token>/ip.txt` (also `domain`, `url`, `hash`, and `.csv`). This form exists for tools that can only fetch a URL, so treat the URL like a password. Tools that can send a header should use `GET /feeds/ip.txt` with `Authorization: Bearer <token>`.
- Requests are rate limited per client address and per token. Wrong tokens count against the client address. Every refusal is a plain `404`, so a probe learns nothing. The API keeps no access log.
- Set `AUTH_TRUSTED_PROXIES` when the dashboard is behind a tunnel or proxy. Without it every client looks like the proxy, so the rate limits and the failure lockout are shared by everyone (the API logs a warning at start-up).
- If the dashboard is behind Cloudflare Access, the firewall will be turned away. Prefer a Cloudflare Access service-token policy for `/feeds/*` (the header form), or a bypass limited to your firewall's source address. An open bypass leaves only the token between the internet and the list. Cloudflare and any proxy in between can log the request path, so a path token ends up in their logs: use the header form where the tool allows it.

## Community lists (Network tab)

The Blocklists page has two tabs. **This sensor** is the list built from your own sensor, described above. **Network** shows the community lists of the SuckerPot network (`/defend/blocklists?tab=network`).

Start with the sentence at the top of the tab. It says how many entries each list holds, and how many of them your sensor also saw. Then one card per list:

- **Outbound** is marked "Start here". It blocks traffic leaving your network: malware hosts and command servers. A device that reaches one is probably infected.
- **Inbound** blocks traffic coming in from attack sources.
- **Outbound domains** holds the same kind of hosts by name, for DNS filters.

Each card has a **Copy URL** menu with the file formats (plain text, IPv4 only, IPv6 only, nftables, ipset, MikroTik, CSV, JSON, STIX). The URLs point at the public feed, so a firewall can fetch them without this dashboard. A **How to use** drawer gives short steps for OPNsense and pfSense, and links to [Community blocklist feeds](feeds.md).

The entries table lists the values. Filters are in the URL (`list`, `tier`, `seen_here`, `q`), so you can share a view. A value that your sensor also saw links to its attacker page.

If the feed is off, the tab explains what the lists are, and shows the public URLs. Turn the fetch on with `NETWORK_FEED_ENABLED`, see [Configuration](configuration.md#community-lists-m30). Until then, nothing contacts the feed host.

Once the feed is on, the card "Why join the network?" says it plainly. The lists are free and public. Every firewall gets the same lists, whether or not you join. Joining adds your sensor to the ones that confirm entries. You then see which entries your sensor helped confirm. No extra lists or perks are promised.

## Detections

The Detections page writes Sigma rules (for log search) and Suricata rules (for network inspection) from what the honeypot recorded: request paths that attackers used, shell commands typed in tagged sessions, and the hosts, download URLs and file hashes with a high score.

**Every rule says "review before deploying", and so does every export.** The rules come from decoy traffic, not from your network. They can match harmless activity. Run them as searches or in alert-only mode first.

Captured strings are untrusted. A string must be printable ASCII to be used at all, it is cut to a fixed length, and it only ever appears inside one quoted value: single-quoted in Sigma, and in Suricata every character outside a short safe set is written as `|hex|` bytes, so it cannot end the option or add one. Titles and messages are built from fixed text, never from captures. Suricata ids are in the local range 4100000 to 4999999.

Below the rules, "Check this at your company" lists, for each behaviour the honeypot actually saw, what the attackers do, where to look in your own logs and what to change.

## Your exposure

Type in the services you run (name, kind of service, product, version, whether it is reachable from the internet). The page puts each one next to what the honeypot recorded for the same kind of service: attacks, sources, how many went as far as running commands, the trend against the previous period, and the known exploited vulnerabilities the CVE watch matched. Services that are attacked here but are not in your inventory are listed too, as a prompt to check.

The inventory is free text that is stored and shown. It is only compared with our own data.

## API

| Route | Who | What |
| --- | --- | --- |
| `GET /api/v1/defend/summary` | both roles | Totals per kind, top reasons, feed status |
| `GET /api/v1/defend/blocklist` | both roles | Scored entries, paginated |
| `GET /api/v1/defend/export` | both roles | Download a list |
| `GET /api/v1/defend/overrides` | both roles | Overrides, paginated |
| `POST /api/v1/defend/overrides`, `DELETE .../{id}` | admin | Allow or block a value |
| `GET /api/v1/defend/feed-tokens` | admin | Tokens (hint only, never the token) |
| `POST /api/v1/defend/feed-tokens` | admin, password again | Create a token |
| `POST /api/v1/defend/feed-tokens/{id}/revoke` | admin | Revoke a token |
| `GET /api/v1/defend/detections` and `/export` | both roles | Generated rules |
| `GET /api/v1/defend/guidance` | both roles | What to check at your company |
| `GET /api/v1/defend/inventory` | both roles | The inventory, paginated |
| `POST`, `PATCH`, `DELETE /api/v1/defend/inventory` | admin | Change the inventory |
| `GET /api/v1/defend/exposure` | both roles | Inventory against attacks |
| `GET /api/v1/network/feed/status`, `GET /api/v1/network/feed/entries` | both roles | Community lists: state and entries ([API](api.md#community-lists-m30)) |
| `GET /feeds/{token}/{kind}.{txt,csv}`, `GET /feeds/{kind}.{txt,csv}` | token | The subscription feed (opt in) |

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLOCKLIST_ENABLED` | `false` | Score indicators into blocklists (ingest) |
| `BLOCKLIST_WINDOW_DAYS` | `30` | How far back to look |
| `BLOCKLIST_MAX_ROWS` | `20000` | Most entries kept |
| `FEEDS_ENABLED` | `false` | Serve the token-protected feed (API) |
| `BLOCKLIST_NEVER` | empty | Extra addresses, networks and names that are never listed |
