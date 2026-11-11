# Network protocol `spn/1`

This is the wire protocol between a SuckerPot node and a network hub. It is normative. The reference implementation is the `suckerpot_netproto` package (`netproto/`). Its golden test vectors (`netproto/tests/vectors.json`) are the contract for any other implementation: a client that reproduces every vector byte for byte speaks `spn/1`.

For the design and the threat model, read [M29](design/m29.md). For the user view, read [The SuckerPot network](network.md). For the hub, read `hub/README.md`.

Every address and name below is a placeholder. The examples use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.org`.

## Transport

- HTTPS to the hub URL, for example `https://hub.example.org`. Every path is under `/v1`.
- JSON, UTF-8, `Content-Type: application/json`. Bodies are compact ASCII JSON (`separators=(",", ":")`, non-ASCII escaped).
- Request bodies are at most 1 MiB for `POST /v1/observations` and 64 KiB for every other request. Oversize bodies get `too_large` before they are parsed.
- Every JSON object rejects unknown fields. The nesting depth is at most 6.
- Client `User-Agent: spn-node/1`. No cookies. Redirects are not followed. Requests go only to the host of the configured hub URL.
- Every request body is padded: a `"pad"` field holds spaces so that the body length is a multiple of 4096 bytes. An empty body (a `GET` or a `DELETE`) is not padded.

## Keys and signatures

- **Node identity.** Each node makes an Ed25519 key pair. `node_key` is the base64url encoding (no padding) of the 32-byte public key. The fingerprint is the first 8 hex characters of `sha256(public key)`, shown as `Node 3f9a1c07`.
- **Hub identity.** The hub has its own Ed25519 key pair. Its public key is `hub_key`, published by `GET /v1/info`. A node pins it in `NETWORK_HUB_KEY` and refuses any answer that the pinned key did not sign.

### Request headers

| Header | Content |
| --- | --- |
| `X-SPN-Key` | `node_key` of the sender |
| `X-SPN-Timestamp` | Unix time in seconds, integer, 1 to 12 digits |
| `X-SPN-Nonce` | base64url of 16 random bytes (22 characters) |
| `X-SPN-Signature` | base64url of the 64-byte Ed25519 signature of the canonical request string |

Unsigned endpoints (`GET /v1/info`, `POST /v1/enrol/challenge`) take no key and no signature. A client should still send `X-SPN-Nonce` on them, so that the answer can be checked (see [Answer signatures](#answer-signatures)).

### Canonical request string

The signed string is these lines joined with `\n`, with no trailing newline:

```
SPN1-REQ
<METHOD in uppercase>
<path with query exactly as sent, for example /v1/targets?since=c_12&limit=1000>
<X-SPN-Timestamp>
<X-SPN-Nonce>
<lowercase hex sha256 of the raw body bytes; of the empty string for GET and DELETE>
```

The path is exactly what the client sent, so a query that the hub re-orders would fail. The body hash covers the padded body, so the padding is signed too.

### Hub checks on a signed request

The hub runs these checks in this order. The body is not parsed before step 6.

| Step | Check | Error code if it fails |
| --- | --- | --- |
| 1 | Size of the body | `too_large` |
| 2 | The four headers are present and well formed | `invalid_payload` |
| 3 | `abs(now - timestamp) <= 300` seconds | `stale_timestamp` |
| 4 | The signature checks out with the key named in `X-SPN-Key` | `bad_signature` |
| 5 | The key belongs to an enrolled node | `unknown_node` (signed, see below) |
| 6 | The nonce is new for this node (kept for 10 minutes) | `replayed_nonce` |
| 7 | The per-node rate limit | `rate_limited` |

A failed request also counts against the address that sent it (see [Rate limits](#rate-limits)).

### Replay rules

- A signed request is valid for 300 seconds of clock difference, and only once. The hub stores each nonce for 10 minutes, per node. A repeat within that time gets `replayed_nonce`.
- A request signature covers the method, the path with query, the timestamp, the nonce and the body hash. Changing any of them breaks the signature.
- Enrolment is protected differently. The enrolment request is signed by the key being enrolled, and it must use a challenge that the hub issued. The challenge is single use and expires after 600 seconds.
- A node that gets `replayed_nonce` or `stale_timestamp` should build a new request with a new nonce and the current time. It must not resend the same bytes.

### Answer signatures

Every answer to a request that passed authentication carries `X-SPN-Hub-Signature`. It is the Ed25519 signature by the hub key of this string:

```
SPN1-RESP
<METHOD in uppercase>
<path with query exactly as sent>
<X-SPN-Key of the request, or "-" for an unsigned request>
<X-SPN-Nonce of the request>
<signed request: lowercase hex sha256 of the request X-SPN-Signature string;
 unsigned request: lowercase hex sha256 of the request body>
<HTTP status code>
<lowercase hex sha256 of the response body>
```

The node checks the signature against the pinned hub key. If the check fails, the node refuses the answer and records `hub_signature`.

During a key rollover the hub also signs the same string with an alternate key and sends it in `X-SPN-Hub-Signature-Alt`. A node pins a set of 1 to 3 public keys and accepts an answer when either header verifies under any pinned key. A node that pins one key and reads only `X-SPN-Hub-Signature` keeps working until the hub swaps the primary key. `hub_key` of `GET /v1/info` is always the primary key, and a node checks that it belongs to its pinned set. See [Hub key set](#hub-key-set).

The answer is bound to the whole request, not only to its nonce. A man in the middle cannot send its own request to the hub, keep the signed answer and replay it to a victim's nonce, because the answer also names the method, the path and the request signature.

Which answers are signed:

- Answers to a request that passed authentication are always signed. This includes `unknown_node`: a node that sends `DELETE /v1/node` and gets a signed `unknown_node` knows that the hub holds nothing of its own.
- Answers to a request whose authentication failed (`too_large`, `stale_timestamp`, `bad_signature`, malformed headers, an unknown route) are not signed. A node treats an unsigned error as "not authenticated", never as a statement by the hub. It retries later.
- An unsigned endpoint answer is signed only when the request carried a well-formed `X-SPN-Nonce`.

The hub never stores or logs the client address. It keeps only a keyed hash of the address, in memory, to rate limit unsigned requests and repeated failures.

## Errors

Every error is a status code with the body `{"error": "<code>"}`.

| Code | Status | Meaning |
| --- | --- | --- |
| `too_large` | 413 | The body is over the size cap |
| `invalid_payload` | 400 | Schema or value validation failed, or a malformed header or query |
| `unsupported_protocol` | 400 | The `protocol` value is not `spn/1` |
| `stale_timestamp`, `replayed_nonce`, `bad_signature`, `unknown_node` | 401 | Signature checks, see above |
| `pow_invalid`, `challenge_expired` | 400 | The enrolment proof failed or the challenge is gone |
| `pseudonym_invalid` | 400 | The pseudonym breaks the rules in [Pseudonyms](#pseudonyms) |
| `pseudonym_taken` | 409 | Another node has the pseudonym |
| `enrolment_closed` | 503 | The daily enrolment cap is reached. Temporary |
| `not_verifier` | 403 | The node does not hold the verifier role (`/v1/verify/tasks`, `/v1/verify/results`). Signed |
| `rate_limited` | 429 | Too many requests. The `Retry-After` header gives seconds |
| `day_not_closed` | 400 | The batch day has not ended in UTC yet |
| `day_too_old` | 400 | The batch day is more than 3 days old |
| `server_error` | 500 | Anything else |

A soft-suspended node is never told. Its requests succeed, and its data is ignored.

### Node-side codes

The node records these codes itself. The hub never sends them.

| Code | Meaning |
| --- | --- |
| `hub_signature` | The answer's signature does not match the pinned hub key |
| `hub_unreachable` | No answer (timeout, refused connection, unreadable answer) |
| `egress_closed` | The VPN gate is closed, so nothing was sent |
| `pow_timeout` | The proof-of-work search ran out of its time budget. Treated as temporary |
| `waiting_enrolment` | Enrolment is temporarily closed or too hard. The node retries with backoff |
| `waiting_self_address` | The node has no confirmed own address, so it sends nothing |
| `guard_failed` | The whole batch failed the identity check, so nothing was sent |
| `no_settings_key` | The settings encryption key is not usable, so no key can be stored |
| `leave_unconfirmed` | The leave could not be confirmed at the hub, so the node wiped its data anyway |

## Endpoints

| Method | Path | Signed | Body and answer |
| --- | --- | --- | --- |
| GET | `/v1/info` | no | `{protocols, hub_key, pow: {algorithm, difficulty}, limits, thresholds: {min_nodes, min_age_days}, today}` |
| POST | `/v1/enrol/challenge` | no | `{protocol, node_key}` returns `{challenge, difficulty, expires_in}` |
| POST | `/v1/enrol` | by the new key | `{protocol, challenge, pow_nonce, pseudonym?, country?, show_country}` returns `{node_id, fingerprint, enrolled_day, eligible_from_day}` |
| GET | `/v1/node` | yes | returns `{node_id, fingerprint, pseudonym, country, show_country, enrolled_day, eligible_from_day, standing, active_days_14}` |
| PATCH | `/v1/node` | yes | `{protocol, pseudonym?, country?, show_country?}` returns the node |
| DELETE | `/v1/node` | yes | returns `{deleted: true}`. Removes the node and everything linked to it |
| POST | `/v1/observations` | yes | one batch per node and day (see below). Returns `{accepted, rejected, duplicate}` |
| GET | `/v1/targets?since=<cursor>&limit=<1..1000>` | yes | returns `{cursor, targets, reveal, recheck}`. `limit` defaults to 200 |
| POST | `/v1/reveals` | yes | `{protocol, items: [{kind, value_b, value}]}` (at most 200) returns `{accepted, rejected}` |
| POST | `/v1/rechecks` | yes | `{protocol, day, items: [{id, state}]}` (at most 500) returns `{accepted}` |
| GET | `/v1/network` | yes | returns the network summary |
| GET | `/v1/verify/reveals` | yes | returns `{items: [{kind: "url", value_b}]}` (at most 200): links this node reported recently that wait for their clear value |
| GET | `/v1/verify/tasks?limit=<1..20>` | yes, verifier | returns `{tasks: [{id, url, lease_until}]}`. Leases queued tasks. Others get `not_verifier` |
| POST | `/v1/verify/results` | yes, verifier | `{protocol, items: [Result]}` (at most 50) returns `{accepted, rejected}` |

`standing` is coarse: `new`, `good` or `low`. The reputation number is never sent.

### Target

```json
{"id": "t_8c1d2e0a11bb", "kind": "ip", "value": "198.51.100.23", "value_b": null,
 "state": "confirmed", "nodes": 1, "countries": 4,
 "first_day": "2026-10-26", "last_day": "2026-10-30",
 "services": ["ssh", "telnet"], "activity": ["login", "command", "download"],
 "tags": ["mirai"], "families": ["mirai"],
 "reported_day": null, "taken_down_day": null}
```

- `kind` is `ip`, `url`, `domain`, `sha256`, `c2_ip` or `c2_domain`.
- `value` is null for a blinded kind (`url`, `domain`) that is not revealed yet. `value_b` then holds the blinded value.
- `nodes` is a bucket: `0` is 5 to 9 nodes, `1` is 10 to 24, `2` is 25 or more.
- `countries` is null below 3.
- `state` is `confirmed`, `reported`, `taken_down`, `disputed` or `expired`.
- The cursor is opaque. `recheck` lists confirmed or reported targets that the node is asked to check, at most 50 per pull. The hub records each of them as an assignment for that node and that UTC day (at most 200 a day per node). A `/v1/rechecks` answer counts only for a target assigned to the sender, with the `day` it was assigned on, and only once. Any other answer is dropped silently, and `accepted` counts the answers that were taken.
- A target never carries a node id, a fingerprint or a pseudonym.

### Observation batch

```json
{
  "protocol": "spn/1",
  "batch_id": "AAECAwQFBgcICQoLDA0ODw",
  "day": "2026-10-30",
  "sources": [
    {"ip": "198.51.100.23", "services": ["ssh"], "activity": ["login", "command", "download"],
     "tags": ["mirai"], "sessions": 1, "attempts": 3}
  ],
  "payloads": [
    {"url_b": "<64 hex>", "host_ip": "198.51.100.9", "host_b": null,
     "sha256": "<64 hex>", "family": "mirai", "file_type": "elf-arm", "fetched": true}
  ],
  "c2": [
    {"ip": "198.51.100.50", "domain_b": null, "port": 23, "family": "mirai", "via_sha256": "<64 hex>"}
  ],
  "files": [
    {"sha256": "<64 hex>", "family": "mirai", "file_type": "elf-arm"}
  ],
  "pad": "    "
}
```

- **Caps.** At most 5000 sources, 1000 payloads, 1000 C2 entries and 1000 files. A batch holds at most 20 000 new values in total, and the hub rejects the rest with reason `cap`.
- **Day.** `day` is a UTC day that has ended, and at most 3 days old by the hub's clock.
- **Idempotency.** `batch_id` is 16 random bytes in base64url. A second batch with the same `batch_id` for the same node and day answers `duplicate: true` and changes nothing. A different `batch_id` for a day that was already submitted is `invalid_payload`. One batch per node and day.
- **Buckets.** `sessions` and `attempts` are buckets: `0` is 0 or 1, `1` is 2 to 9, `2` is 10 to 99, `3` is 100 to 999, `4` is 1000 or more.
- **Shape.** A payload has exactly one of `host_ip` and `host_b`. A fetched payload has its `sha256`. A C2 entry has exactly one of `ip` and `domain_b`. A C2 entry names the file it came from with `via_sha256`.
- **Malware-like fetches.** The hub counts a `fetched` payload towards a report or a feed entry only when its `family` is known or its `file_type` is an executable or script type (`elf-*`, `pe`, `script-*`). `archive`, `other` and a missing type never count.
- **Lists.** Every list holds distinct entries. Duplicates are refused.
- **Addresses.** IPv4 or IPv6 global unicast only. Private, reserved and documentation ranges are refused. Documentation ranges are accepted only by a hub test overlay (`HUB_ALLOW_DOCUMENTATION=1`). IPv4-mapped addresses and addresses that embed an IPv4 address (NAT64, Teredo, 6to4) are refused.
- **Tags.** Tags outside the allow-list are dropped, not refused. The allow-list is `TAGS_V1` in `netproto/suckerpot_netproto/enums.py`, plus `cve-YYYY-NNNN` to `cve-YYYY-NNNNNNN`.
- **Families and file types.** Values outside `FAMILIES_V1` and `FILE_TYPES_V1` are refused.
- **Reserved field.** `credentials` is reserved and refused in version 1.

Activity values are `connect`, `scan`, `login`, `login_success`, `command`, `download`, `exploit` and `http`. Services are `ssh`, `telnet`, `web`, `rdp`, `redis`, `docker`, `mysql`, `adb`, `mssql`, `smb`, `sip` and `synology`. Ports are never sent. A node sends `sip` sessions (UDP, spoofable) as presence only: they add the service and the session count, never activity, tags or attempts; an address seen only on `sip` has the activity `connect`.

### Pseudonyms

A pseudonym is optional. When it is set, the hub checks:

- 3 to 24 characters, matching `^[A-Za-z0-9][A-Za-z0-9 _.-]{1,22}[A-Za-z0-9]$`;
- no `://` and no `@`, and no two spaces in a row;
- no run of four digits;
- not a reserved word (`admin`, `administrator`, `root`, `hub`, `official`, `moderator`, `staff`, `support`, `system`, `network`, `node`) and not containing `suckerpot`, `selfhostr` or `honeypot`, ignoring case, spaces, `_`, `.` and `-`.

Uniqueness is checked on the normalised form: lowercase, with separators collapsed to one space. A node may change its pseudonym once every 7 days.

### Rate limits

These are the defaults. The operator can change them (see `hub/README.md`).

| Limit | Default | Key |
| --- | --- | --- |
| Unsigned requests | 10 per minute and 100 per day | Address (IPv6: its /64) |
| Failed authentications | 30 per minute | Address |
| Enrolment challenges | 20 per 10 minutes | Address (IPv6: its /64) |
| Signed requests | 60 per hour | Node |
| Reveals | 2000 per day | Node |
| New values in a batch | 20 000 per day | Node |
| Enrolments | 5000 per day in total | Network |

## Enrolment and proof of work

Enrolment is a three-step exchange.

1. `POST /v1/enrol/challenge` with the new `node_key`. The hub returns a 32-byte `challenge` (base64url), the `difficulty` for this request and `expires_in`, which is 600 seconds.
2. The node finds a `pow_nonce` such that `sha256(challenge || pubkey || pow_nonce)` starts with at least `difficulty` zero bits. `challenge` and `pubkey` are the raw 32-byte values. The nonce is 1 to 16 bytes, sent as base64url. The reference solver counts from zero with an 8-byte big-endian nonce.
3. `POST /v1/enrol`, signed by the new key, with `challenge`, `pow_nonce`, the optional pseudonym and country, and `show_country`.

### How the difficulty is set

The base difficulty is 27 bits. It is priced per address prefix, not for the whole network:

- The prefix is the full IPv4 address, or the /64 of an IPv6 address.
- Up to 3 challenges (`HUB_ENROL_SOFT_CAP`) per prefix in a 10-minute window cost the base difficulty.
- Above that, each prefix pays one more bit. Then one more bit for every 3 further challenges (`HUB_ENROL_STEP`). The increase is at most 10 bits, and the difficulty never goes above 48.

A flood from one prefix therefore prices out that prefix alone. A global counter would let one attacker make enrolment expensive for everyone. Enrolment also stops for the whole network once 5000 enrolments happen on one UTC day (`enrolment_closed`).

The node solves the puzzle in a child process at low priority (`os.nice` 15), with a 15-minute limit, so ingest keeps running.

Proof of work is a speed bump. Age, cohort, reputation and corroboration are the real defences (see [The SuckerPot network](network.md#how-consensus-protects-against-poisoning)).

## Blinding

A link or a domain name is sent only as a blinded value:

```
value_b = lowercase hex sha256("spn/1|" + kind + "|" + canonical(value))
```

`kind` is `url` or `domain`.

- **url.** The scheme and the host are lowercased. The host is converted with the IDNA codec of the Python standard library. The default port (80 for `http`, 443 for `https`, 21 for `ftp`) is removed. The fragment is removed. The path and the query are kept byte for byte, and an empty path stays empty. User information, spaces and control characters make the URL invalid. IPv4 and IPv6 literals are normalised.
- **domain.** Lowercase IDNA, with no trailing dot. Labels hold letters, digits, `-` and `_`. An address is not a domain.

Examples from the vectors:

| Input | Canonical | `value_b` (first 16 hex) |
| --- | --- | --- |
| `HTTP://Example.ORG:80/a/B?x=1&y=%2F#frag` | `http://example.org/a/B?x=1&y=%2F` | `bd0e11a8735313cb` |
| `https://example.org:443/` | `https://example.org/` | `0ae7d77bca7d18c6` |
| `http://bücher.example.org/p` | `http://xn--bcher-kva.example.org/p` | `fded646d1d81a3bf` |
| `Example.ORG.` (domain) | `example.org` | `8c64aeadd9d489f1` |

### What blinding does and does not do

The hash is fast and unsalted. It hides a high-entropy value, such as a link with a random token, from anyone who reads the hub database. It does not hide a guessable value. Anyone with a list of likely links or domains can test each candidate against `value_b`.

Version 1 accepts this. A slow key derivation with a fixed public salt would cost every node one derivation per link per day, and it would change every `value_b`. It is a candidate for version 2.

The hub counts nodes per `value_b`. A blinded value that gets confirmed is listed in `reveal`. A node that has the clear value sends it to `POST /v1/reveals`. The hub checks that the value blinds to `value_b`, and then validates it: it must parse as a URL or a domain, and it must not be on the never-list.

A node reveals only hashes that the hub asked for, only values it holds, and only after the identity check.

## Versioning

- `protocol` is in every body where a body has one, and the path starts with `/v1`.
- The hub rejects unknown fields. So an additive field goes into the hub first, then into the nodes.
- A breaking change becomes `spn/2` under `/v2`. The hub serves both for at least six months, and `GET /v1/info` lists them in `protocols`.

## Verification (added in M32, additive)

The protocol string stays `spn/1`. No existing request or answer changes, so nodes from before M32 keep working. A hub that predates M32 answers `404` (unsigned) on the new paths, and a node treats that as "no verification" and retries once a day.

### Early reveal

`GET /v1/verify/reveals` lists the blinded links that this node reported in the last few days and that wait for a clear value. The node answers with the existing `POST /v1/reveals`, only for values it holds and only after the identity check. The hub validates the value exactly as for a confirmed target, and keeps it only for the verification task.

### Tasks and results

A node with the verifier role leases tasks with `GET /v1/verify/tasks` (lease of a few hours, `limit` 1 to 20) and later reports one `Result` per task in `POST /v1/verify/results`:

```json
{"id": "v_0123456789ab", "outcome": "fetched",
 "sha256": "<64 hex>", "size": 48213, "file_type": "elf-arm", "family": "mirai"}
```

| Field | Rule |
| --- | --- |
| `id` | `^v_[0-9a-f]{12}$`. A task leased to the caller. Unique in a request |
| `outcome` | `fetched`, `unreachable`, `http_error`, `too_large`, `timeout`, `refused` (the node's own guards said no) or `skipped` (a local cap) |
| `sha256`, `size`, `file_type` | Required with `fetched`, refused otherwise. `size` is 1 to 67,108,864. `file_type` comes from the closed file type list |
| `family` | Only with `fetched`, optional (null allowed). From the closed family list |

Bodies are padded, unknown fields are refused, depth is at most 6 and the size cap is 64 KiB, as for every `spn/1` request. A request holds at most 50 results, and an answer at most 20 tasks. A participant adds about 4 signed requests an hour (`/v1/verify/reveals` every 15 minutes) and a verifier about 8.

### Hub key set

A node pins 1 to 3 hub public keys (`NETWORK_HUB_KEY` takes a comma-separated list). The hub signs with its primary key in `X-SPN-Hub-Signature` and, while it rolls its key over, with the alternate key in `X-SPN-Hub-Signature-Alt`. The roll-over has four phases: one key; both keys sent and a release that pins both; the hub swaps primary and alternate at least 30 days later; the old key is dropped from the release at least 90 days later. A node that still pins only the old key fails closed (`hub_signature`) after the swap. The feed key set works the same way.

### Committed defaults

Each release ships `suckerpot_netproto/data/network_defaults.env`, mirrored byte for byte at `config/network-defaults.env`. It holds the hub URL, the hub key set, the feed URL and the feed key set. An explicit value in `.env` wins, and an empty one counts as unset. A value written `<LIKE_THIS>` is a placeholder and means "not configured": the network cannot be joined, and the release workflow refuses to publish a release that still holds one.

## Golden test vectors

`netproto/tests/vectors.json` holds the vectors. They use fixed test keys, which are never used anywhere else. The vector file has these sections:

| Section | What it checks |
| --- | --- |
| `requests` | The canonical request string and the Ed25519 signature for a set of requests |
| `responses` | The canonical answer string and the hub signature, for a signed and an unsigned answer |
| `blind_urls`, `blind_domains` | Blinding, including IDNA, default ports, fragments and IPv6 |
| `pow` | A proof-of-work check: the digest, the difficulty and the nonce |

Ed25519 signatures are deterministic, so another implementation must reproduce every signature byte for byte.

The test keys and values used in the examples below:

```
node seed (hex)  000102...1f          node_key  A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
hub seed  (hex)  202122...3f          hub_key   Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc
timestamp        1790000000           nonce     AAECAwQFBgcICQoLDA0ODw
```

A signed `GET /v1/info` with an empty body:

```
SPN1-REQ
GET
/v1/info
1790000000
AAECAwQFBgcICQoLDA0ODw
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Its signature is `6SmwSsSm-sIfEpE7-Wrhp7An2EATs7mFefPStH8OO6Nicc6x3CSiIYUX-aG9EzbpvMEd7bmvPjwXxcRx2VFlBg`.

The unsigned `POST /v1/enrol/challenge` answer with status 429 is bound to the request by the body hash of the request. Its canonical string has `-` where a signed request has the node key.

To regenerate the file, run `python tests/gen_vectors.py` in `netproto/`. Regenerate only when the spec changes, and review the diff. The test module is `netproto/tests/test_vectors.py`.

## Feeds

The public blocklist feeds are not part of `spn/1`: they are files the hub publishes over plain HTTPS, and anyone can read them. The library is `suckerpot_netproto.feeds` (`models`, `render`, `minisign`, `parse`); the hub renders and signs with it, a node verifies and parses with it. The design is `docs/design/m30.md`.

### Lists and URLs

Base URL `https://<feeds domain>/v1/`. `/v1/` is the format version; a breaking change is `/v2/`, served next to it for at least 6 months. The lists are `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`. `*-high` holds the high tier only; the base file holds both tiers.

| File | Content |
| --- | --- |
| `index.json`, `index.json.minisig` | Signed manifest |
| `<list>.txt` | One value per line, IPv4 then IPv6, sorted numerically, `\n` line ends, no comments, no blank lines |
| `<list>.v4.txt`, `<list>.v6.txt` | The same, one address family |
| `<list>.nft`, `<list>.ipset`, `<list>.rsc` | nftables, `ipset restore`, MikroTik RouterOS v7 |
| `<list>.csv`, `<list>.json` | Metadata |
| `outbound.stix.json`, `outbound-high.stix.json` | STIX 2.1 bundle, outbound lists only |
| `<file>.minisig` | minisign signature of that file |

`outbound-domains` has `.txt`, `.csv` and `.json` only. Every IP list has all the other formats, and the STIX files exist for `outbound` and `outbound-high`.

### What may be listed

- An address: a single, global unicast, canonical text (IPv4 dotted, IPv6 compressed and lower case). No prefix, no range, no scope id, no IPv4-mapped or embedded form. Documentation ranges are accepted only when a test flag is set.
- A name: an exact host in lower case ASCII (IDNA), at least two labels, not a private top-level name (`local`, `internal`, `lan`, ...). No wildcard, no leading or trailing dot.
- Every renderer re-validates each entry from scratch. A value that fails is dropped and counted (`Rendered.dropped`), so no newline, quote, space or script character can reach firewall syntax. More than the list cap (50,000 inbound, 20,000 outbound and domains) raises `too_large`, and so does a file over 8 MiB.

### Firewall shapes

The three files start with `# selfhostr <list> serial <n> generated <UTC> licence CC0-1.0`; the MikroTik file has `# selfhostr <list> serial <n>`.

- **nft**: a `table inet selfhostr` with sets `<list>_v4` and `<list>_v6` (dashes become underscores; `flags interval; auto-merge`), a `flush set` for each, then one `add element` line per non-empty set. `nft -f` applies the file as one transaction.
- **ipset**: for each family `create` the live set and a `-new` twin with `-exist`, `flush` the twin, `add` the elements, `swap`, `destroy` the twin. The type is `hash:net`. `maxelem` is the list cap rounded up to a power of two (65536 for the inbound lists, 32768 for the outbound lists) and never depends on the content, because `create -exist` fails when an existing set has other parameters. `hashsize` is 4096 for IPv4 and 1024 for IPv6.
- **rsc**: `:local t 1d6h`, then one `:do { add ... timeout=$t } on-error={ set [find ...] timeout=$t }` per address under `/ip firewall address-list` or `/ipv6 firewall address-list` (IPv6 as `/128`). A section with no address is omitted. Entries lapse on their own, so removed values leave the router.
- **csv**: RFC 4180, CRLF, one header row, columns `value, family, list, tier, categories, services, tags, families, ports, first_seen, last_seen, expires, reported`. Lists are joined with `;`. A cell that starts with `=`, `+`, `-`, `@`, tab or CR gets a leading `'`; control characters are removed.
- **json**: `selfhostr-feed/1` as in the design (section 6.3). The entry keys are fixed: inbound entries have `services` and `tags`; outbound entries have `tags`, `families` and `ports`. Consumers ignore unknown fields. The bytes are compact ASCII JSON with one trailing newline.
- **stix**: a bundle with the core TLP marking definition (the 2.1 standard calls TLP:CLEAR `TLP:WHITE`), and one `indicator` per entry with a `[ipv4-addr:value = '...']`, `[ipv6-addr:...]` or `[domain-name:...]` pattern. No identity, no `created_by_ref`. Ids are UUIDv5 of list and value, and `created` / `modified` / `valid_from` / `valid_until` come from `first_seen` / `last_seen` / `expires`, so an unchanged list renders to identical bytes.

All output is deterministic: sorted, with no clock read. The only moving parts are the `serial` and `generated_at` of the headers.

### `index.json`

`selfhostr-feeds/1` with `serial` (monotonic), `generated_at`, `valid_until`, `licence`, `key_id`, `next_key_id`, `lists[]` (id, direction, tier, entries, v4, v6, files with name, format, bytes, sha256, modified) and `other[]` (name, bytes, sha256). `format` is one of `txt`, `txt-v4`, `txt-v6`, `nft`, `ipset`, `rsc`, `csv`, `json`, `stix`. File names match `^[a-z0-9][a-z0-9._-]{0,63}$`, so a name can never be a path. `render_index` writes the exact bytes that are signed.

### Signatures

minisign, algorithm `ED` (Ed25519 over BLAKE2b-512 of the file), implemented with `cryptography` and `hashlib.blake2b`, no shell-out.

```
untrusted comment: signature from minisign secret key
base64( "ED" || key_id[8] || ed25519(blake2b512(file))[64] )
trusted comment: timestamp:<unix> file:<name> serial:<serial>
base64( ed25519( signature[64] || trusted_comment ) )
```

- The public key is the `RW...` string: `base64("Ed" || key_id[8] || public[32])`. The key id prints as upper case hex of its 8 bytes in reverse order (the form used in `index.json`). `parse_public_key` takes the bare string or the two-line file.
- The legacy `Ed` algorithm (whole-file signature) is refused. `Ed` is only the public-key marker.
- The trusted comment is signed, so a verifier checks that `file` is the name it fetched and `serial` is the index serial. A valid signature of another file or an older serial is refused.
- Secret keys are read and written unencrypted (the file is a Docker secret); an encrypted key file is refused.
- During a rotation `signature_key_id` tells which key made a `.minisig`, and a file has two signatures (`<file>.minisig`, `<file>.next.minisig`).

The upstream example public key `RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3` parses to key id `E7620F1842B4E81F`, which is how the key-id byte order was checked. The structure was re-derived in the tests with plain `cryptography` calls. A cross-check with the upstream `minisign` binary belongs to the hub integration job.

### Parsers and the node check

Parsers are size capped (default 16 MiB per file, 256 KiB for the index), refuse malformed input and never raise anything but `FeedError` (`code` is one of `bad_format`, `bad_value`, `too_large`, `too_many_invalid`, `bad_signature`, `wrong_key`, `wrong_file`, `wrong_serial`, `hash_mismatch`, `expired`, `rollback`).

1. `verify_index(index_bytes, sig_text, public_key, now=, last_serial=)`: signature, signed file name is `index.json`, signed serial equals the index serial, `key_id` equals the key used, `valid_until` is in the future, serial is not lower than the last accepted one.
2. `verify_file_against_index(index, name, data, sig_text, public_key)`: the file is listed, size and sha256 match, signature names this file and this serial.
3. `parse_txt` / `parse_list_json`: every value is re-validated (prefix, private, wildcard, non-canonical, duplicate and wrong-kind values are invalid). Invalid entries are dropped and counted; more than 1 % invalid rejects the file. JSON nesting is limited and `NaN` is refused.

### Golden vectors

`netproto/tests/feed_vectors/` holds `keys.json` (a fixed test key, never used anywhere else) and `golden/`: every file of three lists (`outbound`, `inbound`, `outbound-domains`), `index.json` with its signature, and signatures of three files. Ed25519 is deterministic, so another implementation must reproduce every byte. To regenerate, run `python -m tests.test_feeds_common` in `netproto/` and review the diff; only do it when the spec changes.
