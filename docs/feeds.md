# Community blocklist feeds

The SuckerPot network publishes free blocklists. Any firewall can load them. This page is for the person who loads them: what the lists hold, how to fetch them, how to check them, and how to ask for a removal.

The examples use the placeholder host `feeds.example.org`. The public address of the feed is written there until the project sets its real one. Use the address from the project documentation once it is live.

The lists are built only from what many sensors saw. Each entry needs observations from at least five independent sensors. The network explains how that works in [The SuckerPot network](network.md).

## The five lists

| List | Direction | What it holds | Start here when |
| --- | --- | --- | --- |
| `outbound` | Blocks traffic **leaving** your network | Hosts that served malware (payload hosts) and command servers (C2) | You want the safest first list. Use it on your firewall. |
| `outbound-high` | Blocks traffic leaving your network | The stricter part of `outbound` | You want fewer false positives and accept fewer hits |
| `outbound-domains` | Blocks names your devices look up | Exact host names of the same kind of hosts | You run a DNS filter (Pi-hole, AdGuard Home, pfBlockerNG DNSBL, Unbound) |
| `inbound` | Blocks traffic **coming in** | Addresses that attacked sensors (scans, brute force, exploit attempts) | You publish services on the internet and want them shielded |
| `inbound-high` | Blocks traffic coming in | The stricter part of `inbound` | You want the low-risk default for automatic blocking |

### Why outbound first

Most firewalls start with inbound blocking. The outbound lists are the better start for most networks.

- **They work after a compromise.** An infected camera, NAS or laptop fetches its second-stage file or calls its command server. An outbound block stops that call. The infection stays harmless. An inbound block does nothing once the device is already inside.
- **False positives cost little.** No device on your network needs to reach a host that served malware. An inbound address, on the other hand, can be a customer's home connection that changed hands last week.
- **The list is small and stable.** A few hundred to a few thousand hosts that stay for days or weeks. Attack sources are tens of thousands of home devices that change address often.
- **A hit is a signal.** When a device hits an outbound rule, that device is probably infected. Log the hits and look at them.

### Tiers

Each entry has a tier: `standard` or `high`. The `-high` files hold only the high tier. The base file holds both.

An entry reaches the high tier when:

- at least 10 eligible nodes saw it;
- on at least 3 different days, each with at least 5 nodes that saw it;
- from at least 3 different enrolment weeks, each with at least 2 of those nodes;
- and an outside service also flags it. The hub uses AbuseIPDB or GreyNoise for this.

The high tier is empty when the hub has no outside source configured. `outbound-domains` has only the standard tier for now.

## What gets listed, and why

### The rules

| Rule | What it means |
| --- | --- |
| Several independent sensors | An entry needs observations from at least 5 eligible nodes, the "k" in k-support. One sensor's sighting never changes a list. |
| TCP evidence for inbound | An address is listed only when the evidence came over TCP. Scans, plain connects and web-only probes never list an address. Evidence seen on SIP (UDP) never lists one either, because UDP source addresses can be faked. A node sends one summary per address and day, so when an address shows up on SIP and on a TCP service the same day, that node's summary for the day is not counted at all. |
| Payload hosts | A host is listed only when a file was fetched from it by at least 2 nodes, and that file has a known malware family. A URL that was merely typed into a command never lists its host. |
| Command servers (C2) | A command server is listed only when the hub's analysis rates it with high confidence, and at least two different samples from at least two nodes point to it. |
| Names | A host name is listed only when it was revealed by the same evidence as the address. Shared hosting and big cloud names are never listed. |
| Hold | A new value waits 6 hours after it was first confirmed before it appears. |
| Expiry | A value leaves the list when it has no new sighting for a set time (see the table below). |
| Size caps | Each list has a maximum number of entries. Over the cap, the high tier stays and the newest entries stay. |

### Expiry

| List | An entry leaves the list after |
| --- | --- |
| `inbound`, `inbound-high` | 7 days without a new sighting |
| `outbound`, `outbound-high`, `outbound-domains` (payload hosts) | 14 days without a new sighting, or at once when the hosted file was taken down |
| Command servers (C2) | 30 days without new evidence, or when the hub sees them go down |

Attack sources change address often, so inbound entries expire fast. That also limits the damage when an address moves to an innocent holder.

### What is never listed

| Never listed | Why |
| --- | --- |
| Private, loopback, link-local, multicast and other reserved addresses | Your own network must never end up on a list |
| Public DNS resolvers and root servers (the big public resolver addresses, for example) | Attackers type them into commands. Blocking them breaks networks. |
| Shared hosting and big SaaS names (for example `github.com`) | Blocking them breaks work |
| Large CDN and cloud front-end address ranges | One address serves thousands of sites |
| Tor exit relays | An exit relays many users. The attacker is not the exit. If you want to block Tor, use the Tor Project's own exit list. |
| Research scanners | They announce themselves and do no harm by our definition |
| Values the operators removed by policy | Allow-list decisions |

Commercial VPN exits and residential proxies cannot be excluded reliably. Short expiry and delisting handle them. Expect some false positives on inbound lists.

### What is published about each entry

The plain text files hold only the value. The detail files (`.csv`, `.json`) add:

| Field | Meaning |
| --- | --- |
| `family` | `4`, `6` or `dns` |
| `tier` | `standard` or `high` |
| `categories` | `brute-force`, `login-success`, `command-exec`, `malware-drop`, `exploit`, `payload-host`, `c2` |
| `services`, `tags`, `families` | Only for values that many sensors agree on |
| `ports` | Command server ports, for C2 entries |
| `first_seen`, `last_seen`, `expires` | UTC dates (`YYYY-MM-DD`) |
| `reported` | `true` when the hub has sent an abuse report for the value |

Nothing else is published. No node ids, no countries, no node counts, no sample hashes, no URLs and no free text. A list cannot tell you which sensor saw what, or when.

## Formats and URLs

Base address: `https://feeds.example.org/v1/`

The `v1` is the format version. Each file has a `.minisig` signature next to it. Each file has a `.gz` copy for clients that ask for compression.

### Files

| File | Format | Lists |
| --- | --- | --- |
| `outbound.txt` | One address per line, IPv4 then IPv6, sorted | All five lists (`<list>.txt`) |
| `outbound.v4.txt`, `outbound.v6.txt` | One address family per file | Lists with addresses |
| `outbound.nft` | nftables file for `nft -f` | Address lists |
| `outbound.ipset` | `ipset restore` file with an atomic swap | Address lists |
| `outbound.rsc` | MikroTik RouterOS v7 script | Address lists |
| `outbound.csv` | CSV with details (RFC 4180, CRLF, spreadsheet-safe cells) | All lists |
| `outbound.json` | JSON with details | All lists |
| `outbound.stix.json` | STIX 2.1 bundle, `TLP:CLEAR` | `outbound`, `outbound-high` |
| `outbound-domains.txt`, `.csv`, `.json` | One exact name per line | `outbound-domains` only |
| `index.json`, `index.json.minisig` | The signed manifest | Always |
| `stats.json` | Public statistics | Always |
| `removed.json` | Values that expired or were taken down in the last 30 days | Always |
| `README.txt` | Policy, accuracy statement, delisting and licence | Always |
| `delist.html` | The delisting form | Always |

A list file uses its list name, so `inbound-high.txt` and `outbound-domains.txt` work the same way.

The domain list has no `.v4`, `.v6`, `.nft`, `.ipset`, `.rsc` or `.stix.json` files.

### The manifest: `index.json`

Fetch `index.json` first. It lists every file with its size and its sha256, plus the serial and the validity:

```text
{"schema":"selfhostr-feeds/1","serial":4812,"generated_at":"2026-11-01T13:00:00Z",
 "valid_until":"2026-11-04T13:00:00Z","licence":"CC0-1.0","key_id":"8C1D2E3F4A5B6C7D",
 "next_key_id":null,"lists":[{"id":"outbound", ...,"files":[{"name":"outbound.txt",
 "format":"txt","bytes":12034,"sha256":"<64 hex characters>","modified":"2026-11-01T13:00:00Z"}]}],
 "other":[{"name":"stats.json","bytes":4210,"sha256":"<64 hex characters>"}]}
```

- `serial` goes up each time a list changes. Never accept a lower serial than the one you have.
- `valid_until` is three days after generation by default. After it, stop using the files and fetch again.
- `next_key_id` is reserved for a future key change. It is `null` today.

### Structured files

`outbound.json` has a `schema` field (`selfhostr-feed/1`), the list name, the serial, `valid_until`, the licence and the entries. Read only the fields you know. New fields can appear in `/v1/`, and your parser should ignore them.

### HTTP behaviour

| Behaviour | Detail |
| --- | --- |
| Methods | `GET` and `HEAD` only |
| Query strings | Ignored on files. The only exception is `/v1/lookup`. |
| Caching | `ETag` and `Last-Modified` on every file. Send `If-None-Match` to get `304 Not Modified`. |
| Compression | `Accept-Encoding: gzip` returns the `.gz` copy |
| Cache time | 15 minutes |
| Content type | `text/plain; charset=utf-8` for the text formats |
| Cross-origin | `stats.json` and `index.json` allow any origin (for project pages) |

### How often to fetch

Poll once every 1 to 6 hours. Polling more often than once an hour does not help. The lists change at most once an hour.

## Step by step: OPNsense

Menu names follow OPNsense 25.x. Your version may name things a little differently.

1. Go to **Firewall → Aliases** and click **+**.
2. Fill in:
   - **Name:** `selfhostr_outbound`
   - **Type:** **URL Table (IPs)**
   - **Refresh Frequency:** `0` days `6` hours
   - **Content:** `https://feeds.example.org/v1/outbound.txt`
   - **Description:** `SuckerPot outbound (CC0)`
3. Save, then **Apply**.
4. Repeat for `selfhostr_inbound` with `https://feeds.example.org/v1/inbound-high.txt`. Start with the high tier.
5. Go to **Firewall → Settings → Advanced** and check **Firewall Maximum Table Entries**. It must be larger than the sum of all your tables. Each list holds up to 50,000 entries.
6. Create the outbound block rule. Go to **Firewall → Rules → LAN** (or use a floating rule for all interfaces) and add:
   - **Action:** Block (Reject ends connections faster)
   - **Direction:** in
   - **TCP/IP Version:** IPv4+IPv6, **Protocol:** any
   - **Source:** LAN net
   - **Destination:** the alias `selfhostr_outbound`
   - **Log:** on. A hit means an infected device.
   - Move the rule **above** your default allow rule. Save, then **Apply**.
7. Add the inbound rule only if you publish services. Go to **Firewall → Rules → WAN**, add a block rule with source `selfhostr_inbound` and destination any. Place it **above** the rules that come from your port forwards.
8. Check the alias. Go to **Firewall → Diagnostics → Aliases**, select `selfhostr_outbound`, and compare the entry count with `outbound` in `index.json`.
9. Put pass rules for your own critical hosts (backup target, VPN peers) **above** the block rules.

## Step by step: pfSense

Menu names follow pfSense CE 2.7 and pfSense Plus 24.x.

### Plain URL table

1. Go to **Firewall → Aliases → URLs** and click **Add**.
2. Fill in:
   - **Type:** **URL Table (IPs)**
   - **Name:** `selfhostr_outbound`
   - **URL:** `https://feeds.example.org/v1/outbound.txt`
   - **Update Frequency:** `1` day
3. Save, then **Apply Changes**.
4. Go to **System → Advanced → Firewall & NAT** and make sure **Firewall Maximum Table Entries** is large enough.
5. Go to **Firewall → Rules → LAN** and add a rule **at the top**:
   - **Action:** Block
   - **Address Family:** IPv4+IPv6, **Protocol:** any
   - **Source:** LAN subnets
   - **Destination:** Single host or alias, `selfhostr_outbound`
   - **Log:** on
   - Save, then **Apply Changes**.
6. For inbound, add a WAN rule with source `selfhostr_inbound`. Place it above the rules that port forwards create.

### Faster refresh with pfBlockerNG

pfBlockerNG refreshes on its own schedule and handles IPv4 and IPv6 separately. Install the package first.

1. Go to **Firewall → pfBlockerNG → IP → IPv4** and click **Add**.
   - **Name:** `Selfhostr_outbound`
   - **Source Definitions:** format **Auto**, state **ON**, source `https://feeds.example.org/v1/outbound.v4.txt`, header `selfhostr_outbound`
   - **Action:** **Deny Outbound**
   - **Update Frequency:** **Every 1 hour**
   - Save.
2. Do the same on the **IPv6** tab with `outbound.v6.txt`.
3. For inbound lists use the action **Deny Inbound**.
4. For names, go to **DNSBL → DNSBL Groups** and add a group with source `https://feeds.example.org/v1/outbound-domains.txt`.
5. Go to **Firewall → pfBlockerNG → Update** and run **Force Update**.

## Step by step: nftables

The `.nft` file creates its own table, `inet selfhostr`, with one set per family. Your chain goes in the same table. Sets are scoped to their table, so a rule in another table cannot use them.

Example chain, in a file you own, for example `/etc/nftables.d/selfhostr-chain.nft`:

```
table inet selfhostr {
  chain fwd {
    type filter hook forward priority -5;
    ip daddr @outbound_v4 counter reject
    ip6 daddr @outbound_v6 counter reject
  }
}
```

Load the list, then the chain. Each `nft -f` applies the whole file in one transaction.

```sh
#!/bin/sh
# Refresh the outbound list. Run it from a systemd timer every 6 hours.
set -eu
export FEED_PUBKEY=RW...   # the feed's public key, from README.txt
/usr/local/share/selfhostr/fetch-verify.sh -d /etc/nftables.d outbound.nft
nft -f /etc/nftables.d/outbound.nft
```

The script is in [`scripts/feeds/fetch-verify.sh`](../scripts/feeds/fetch-verify.sh). It checks the signature before it replaces the file. See [Verify before you load](#verify-before-you-load).

Set names are the list name with `_` for `-`, plus `_v4` or `_v6`: `outbound_v4`, `outbound_v6`, `inbound_high_v4`.

## Step by step: ipset and iptables

The `.ipset` file swaps in a new set in one step, so there is never an empty list in between.

```sh
# Refresh (run every 6 hours after a verified download):
ipset restore -f /etc/selfhostr/outbound.ipset

# Add the rules once:
iptables -I FORWARD -m set --match-set selfhostr-outbound-v4 dst -j REJECT
ip6tables -I FORWARD -m set --match-set selfhostr-outbound-v6 dst -j REJECT
```

The sets are named `selfhostr-<list>-v4` and `selfhostr-<list>-v6`. The sets are `hash:net`, so a later CIDR format needs no change on your side. The file names no prefixes today.

## Step by step: MikroTik (RouterOS v7)

The `.rsc` file adds each address with a timeout of 1 day 6 hours. Addresses that leave the list expire on their own, so there is never a gap with no entries. Import every 6 hours.

1. Create a script that downloads and imports the list:

   ```
   /system script add name=selfhostr-update source={
     /tool fetch url="https://feeds.example.org/v1/outbound.rsc" dst-path=selfhostr.rsc check-certificate=yes
     /import file-name=selfhostr.rsc
   }
   ```

   The router must trust the certificate chain of the feed host. Import the CA certificate if your router does not have it.

2. Schedule it:

   ```
   /system scheduler add name=selfhostr-update interval=6h on-event=selfhostr-update
   ```

3. Add the block rules, above your general forward accept rule:

   ```
   /ip firewall filter add chain=forward action=drop dst-address-list=selfhostr-outbound log=yes log-prefix=selfhostr comment="SuckerPot outbound" place-before=<number>
   /ipv6 firewall filter add chain=forward action=drop dst-address-list=selfhostr-outbound comment="SuckerPot outbound" place-before=<number>
   ```

   `place-before` sets the position. Use the number of your first forward accept rule, which you can read with `/ip firewall filter print`. Use the IPv6 number for the IPv6 rule.

MikroTik does not check the signature. Load the outbound list (the high tier if the router is small). A list with 50,000 lines is slow to import on small routers.

## Step by step: MISP

Use the feed as a MISP feed to get the indicators into your events.

1. Go to **Sync Actions → Feeds → Add feed**.
2. Pick one of these:
   - **Format:** **Freetext**, **URL:** `https://feeds.example.org/v1/outbound.txt`
   - **Format:** **Simple CSV**, **URL:** `https://feeds.example.org/v1/outbound.csv`, value in column 1
   - or import `https://feeds.example.org/v1/outbound.stix.json` as a STIX 2.1 file (**Event → Import**).
3. Enable the feed, fetch it, and check the event count against `outbound` in `index.json`.

MISP does not check the signature for you. Run `fetch-verify.sh` first and point MISP at a copy you have verified, if you need that guarantee.

## Step by step: DNS filters (outbound-domains)

Use `outbound-domains.txt`. It holds one exact name per line.

| Tool | Where | What to enter |
| --- | --- | --- |
| Pi-hole | **Group Management → Adlists → Add** | `https://feeds.example.org/v1/outbound-domains.txt`, then **Tools → Update Gravity** |
| AdGuard Home | **Filters → DNS blocklists → Add blocklist → Add a custom list** | `https://feeds.example.org/v1/outbound-domains.txt` |
| pfBlockerNG DNSBL | See the pfSense section above | Source `https://feeds.example.org/v1/outbound-domains.txt` |

A DNS block stops the lookup. It does not stop a device that connects by address. Use it together with the address lists.

## Verify before you load

Every file is signed with minisign. The signature proves that the file came from the feed key and has not changed since it was made. A mirror or a proxy cannot change the file without breaking the signature.

### The feed key

The public key is printed in `README.txt` on the feed site. It starts with `RW`. Compare it with the key in the project documentation. If the two differ, do not use the feed, and report it.

The key is a single line, for example:

```
RW...                 (the feed's public key, from README.txt)
```

### Check a file by hand

Install `minisign` from your package manager, then:

```sh
curl -fsS -O https://feeds.example.org/v1/outbound.txt
curl -fsS -O https://feeds.example.org/v1/outbound.txt.minisig
minisign -Vm outbound.txt -P RW...
```

A good file prints `Signature and comment signature verified`. The signature also names the file and the serial in its trusted comment:

```
trusted comment: timestamp:1793538000 file:outbound.txt serial:4812
```

Check that the file name is the one you asked for, and that the serial is the one in `index.json`. Then check the sha256 in `index.json`:

```sh
sha256sum outbound.txt
grep -o '"name":"outbound.txt"[^}]*"sha256":"[0-9a-f]*"' index.json
```

### The script: fetch and verify

[`scripts/feeds/fetch-verify.sh`](../scripts/feeds/fetch-verify.sh) does all of this in one step. It is a short POSIX shell script with no `eval`. It:

1. downloads `index.json` and its signature, and verifies them;
2. refuses an index past its `valid_until`, and an index with a lower serial than the one it stored (rollback);
3. for each file, downloads the file and its signature, verifies both, and checks the sha256 against `index.json`;
4. replaces the local file only when every check passed, in one rename.

```sh
FEED_PUBKEY=RW... ./scripts/feeds/fetch-verify.sh -d /var/lib/lists outbound.txt outbound-domains.txt
```

| Option | Meaning |
| --- | --- |
| `-b BASE_URL` | Feed address. Default `https://feeds.example.org/v1`. Only `https` is accepted. |
| `-d DEST_DIR` | Where the verified files go. Default: the current directory. |
| `-P PUBKEY` | The public key. You can also set `FEED_PUBKEY`. |

The script needs `curl`, `minisign`, `sha256sum`, `mktemp`, `date`, `sort`, `grep`, `sed`, `cut` and `head`. A failed check stops the run with exit status 1 and names the check. The old file stays in place.

### Key changes

The index has a `next_key_id` field, reserved for a future key change. It is `null` now. If it ever holds a value, read the project's notice before you change keys. Do not accept a new key from the feed itself.

## Licence: CC0 1.0

The lists and the files are released under **CC0 1.0 Universal**, the public-domain dedication. You may copy, change, mix and redistribute them, for any purpose, with no permission and no attribution. The full text is at <https://creativecommons.org/publicdomain/zero/1.0/legalcode>.

- The project asks, without any condition, that you credit "the SuckerPot network" if it is convenient.
- The data comes with no warranty. The operators are not liable for blocking decisions you make with it.
- The licence of the project's code is separate and unchanged.

We chose CC0 because a firewall vendor or a list aggregator can use the data without legal conditions. An attribution licence is hard to comply with in a firewall.

## Accuracy

Each entry means: "observed by at least five independent sensors". It does not say that the holder of the address is guilty of anything. Many listed devices are themselves compromised. Addresses change hands, and hosts get cleaned up.

Use the lists as one input among others. Do not block a critical service only because it is listed. Put allow rules for your own critical hosts above the block rules.

## Removal (delisting)

If an entry is wrong, or the problem is fixed, ask for removal. A person reviews every request. The project aims to decide within **72 hours**.

### The form

Open `https://feeds.example.org/v1/delist.html`. Enter the value, choose a category, and add evidence or a contact address if you want. The form solves a small proof-of-work puzzle in your browser first. It takes about a second.

| Field | Values |
| --- | --- |
| `value` | An address or an exact host name |
| `list` | Optional. The list it appears on. Tier names (`-high`) are accepted and mean the base list. |
| `category` | `i_operate_this`, `shared_infrastructure`, `cleaned_up`, `address_reassigned` or `other` |
| `evidence` | Free text, up to 2,000 characters. It is stored as plain text, never shown as HTML. |
| `contact` | Optional e-mail address, used only to answer. Deleted 30 days after the decision. |

When you send the request, you get a request id and a status token. **The token is shown once.** Keep it. It is the only way to check the request later.

### Through curl

The same steps work from a script:

| Step | Request | Answer |
| --- | --- | --- |
| 1 | `POST /v1/delist/challenge` with body `{}` | `{"challenge": "...", "difficulty": 20, "expires_in": 600}` |
| 2 | Solve the puzzle (see below) | A nonce |
| 3 | `POST /v1/delist` with `{"challenge", "pow_nonce", "value", "category", "evidence"?, "contact"?}` | `{"id", "status_token", "state", "listed", "sla_hours": 72}` |
| 4 | `GET /v1/delist/<id>` with `Authorization: Bearer <status_token>` | `{"id", "state", "outcome", "public_note", "created_day", "decided_day"}` |

The puzzle: take the 32 challenge bytes (base64url-decoded). Add your nonce (1 to 16 bytes, base64url-encoded in the request). The SHA-256 of the two must start with `difficulty` zero bits. At difficulty 20, about a million tries are needed. The form does this in a Web Worker.

If the value is not on any list, step 3 answers `"listed": false`, and nothing is stored. A second request for a value that already has an open one answers `{"listed": true, "state": "already_open", "sla_hours": 72}`. Nothing is stored and no token is issued: use the number and code of the first request. Requests are rate limited. A `429` answer carries the wait time.

### What happens while the request is open

| Where the value is listed | Effect at once |
| --- | --- |
| `inbound`, `inbound-high` | Hidden from the next run until the decision. Only a small number of values per day can be hidden this way. |
| `outbound`, `outbound-high`, `outbound-domains` | Nothing. These are reviewed first, because attackers most want to escape them. |

### Outcomes

| Outcome | Effect on the list |
| --- | --- |
| `false_positive` | Removed for good. The value is allowed from then on. |
| `remediated` | Removed. The value is allowed for 90 days, because the problem is fixed. |
| `policy` | Removed for good. The value is added to the never-list (for example, a resolver or a CDN that should never have been listed). |
| `rejected` | Stays on the list. The `public_note` explains why. |

## Look up one value

```sh
curl -fsS 'https://feeds.example.org/v1/lookup?value=192.0.2.1'
```

The answer is one word:

```json
{"value":"192.0.2.1","status":"not_listed"}
```

| `status` | Meaning |
| --- | --- |
| `listed` | The value is on a list now |
| `removed` | It left a list in the last 30 days, because it expired or was taken down |
| `not_listed` | Neither. A delisted or excluded value also answers `not_listed`. |

The lookup gives no dates, no categories, no list names and no node counts. It is rate limited per client address.

## Removed values: `removed.json`

`removed.json` lists the values that left a list in the last 30 days, with the list, the date and the reason (`expired` or `taken_down`). Delisted and excluded values are counted in `stats.json`. They are never listed, so an innocent address is not published twice.

## Public statistics: `stats.json`

`stats.json` holds the totals per list, 90 days of daily counts, the median time from listing to takedown, the delisting figures and the number of excluded ranges. No value appears in it.

## Network figures: `network.json`

`network.json` holds anonymised figures about the network itself: node counts, how close the network is to its first collective report, confirmations, reports, takedowns and the attack traffic the network sees. When the hub operator turns it on, it is published even while the lists are off. The rules are in [The SuckerPot network](network.md#public-network-figures) and the schema in [M34](design/m34.md). Browsers may read it from the project site only.

## Privacy

| Question | Answer |
| --- | --- |
| Does the feed site log who downloads a file? | No. The web server writes no access log, and it sets no cookies. |
| Is there an account, a token or an API key? | No. The lists are the same for everyone. |
| Are per-user URLs used? | No. Files take no query string. |
| Is there analytics or a script on the list pages? | No. The delisting page runs one inline script and talks only to the feed host. |
| Is there a CDN? | Not at launch. If that changes, `README.txt` will say which CDN sees requests. |
| What does the delisting form keep? | The value, the category, the day, and the decision. It never stores your address. Evidence and contact are deleted 30 days after the decision. Requests are deleted after 180 days. |
| What about your firewall and your proxy? | Your own network can log what it fetches. The feed cannot see that. |

## The local mirror on your own SuckerPot

If you run a SuckerPot sensor, its dashboard can serve the community lists to your firewall. The mirror holds only what your node verified. This helps when the firewall should not reach the internet, or when it can only fetch from one address.

What the mirror does:

- It serves the entries that your node verified. It never fetches anything for the firewall.
- It is empty when the lists are stale (past `valid_until`), not fetched yet, or switched off. It fails toward not blocking.
- It applies your always-allow overrides. Your own hosts stay off the lists.
- It serves `txt` and `csv` only. It has no `.minisig` files. Check the status on the dashboard instead: it shows the serial, `valid_until` and "signature verified".

### Set it up

1. Turn on the mirror and the fetch in `.env`. The mirror needs the dashboard feed switch (`FEEDS_ENABLED`), and the node needs the feed address and key:

   ```
   FEEDS_ENABLED=true
   NETWORK_FEED_ENABLED=true
   NETWORK_FEED_URL=https://feeds.example.org/v1
   NETWORK_FEED_KEY=RW...
   ```

   `NETWORK_FEED_URL` and `NETWORK_FEED_KEY` are not in the `just set` list. Set them in `.env` by hand, then restart the stack. Turn the switches on with `just set FEEDS_ENABLED=true NETWORK_FEED_ENABLED=true`.
2. Create a token of kind `network`. Use the API (`POST /api/v1/defend/feed-tokens` with `"kinds": ["network"]` and your password), or the Settings, Feeds tab if your version offers the kind. Store the token like a password.
3. Point the firewall at the mirror:

   ```
   https://dashboard.example.org/feeds/<token>/network/outbound.txt
   ```

   The lists are `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`. The `.csv` form works too.
4. Or send the token as a header, `Authorization: Bearer <token>`, to `/feeds/network/outbound.txt`. The header form keeps the token out of logs.

The path form puts the token in the URL. Treat that URL like a password, and revoke the token if it leaks.

## See also

- [The SuckerPot network](network.md): how the lists are built and what members share
- [Defend](defend.md): the Network tab on the Blocklists page
- [Configuration](configuration.md#community-lists-m30): the `NETWORK_FEED_*` settings
- [API](api.md#community-lists-m30): the node endpoints and the mirror routes
- [Network protocol](network-protocol.md): the feed format, in the "Feeds" part
