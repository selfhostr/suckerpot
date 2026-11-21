# Trap packs

A trap pack teaches the web sensor a new trap without a code change. One pack is written per flaw, usually per CVE. It is data only: byte strings to look for in a request, flags to add to the event, and, if you want, a fake answer built from a fixed template.

```{admonition} Status
:class: note

Phases 1 and 2 of M37. Packs are bundled in the web sensor image, and signed packs reach every node between releases (see [Signed distribution](#signed-distribution)). The dashboard view and the banner sensor for non-HTTP flaws come in later phases. The design is in the [M37 design note](dev/design/m37.md).
```

## What a pack can and cannot do

A pack **can**:

- Match a request on its method, its path, the names of its query keys and headers, and byte strings in the path, query, body, headers or the whole request.
- Add up to four flags to the event. Flags of an `exploit` trap get the guaranteed event quota, like the built-in exploit flags.
- Add the pack's CVE ids to the event's `cve` list, for an `exploit` trap with specific evidence (see [Evidence rule](#evidence-rule)).
- Answer like the vulnerable product, with a fixed status, an allow-listed set of headers and one of up to four bodies.

A pack **cannot**:

- Run anything. There is no code, no regular expression, no wildcard and no repetition. The engine only searches bytes with `in` and fills fixed templates.
- Read or name a file, open a connection, fetch a URL or open a port. URLs in a request are still found by the built-in extraction, which only reports them.
- Remove or change a flag the sensor's own code sets, or set one of those flags. The flags of the bundled packs (`phpunit_rce`, `phpunit_probe`, `log4shell`, `router_exploit`) belong to their pack: ingest rules give them a meaning, so no other pack may set them.
- Keep state across requests, compute anything on the payload, or delay an answer.
- Serve a link, a script, a frame or a download for another host (see [Content rules](#content-rules)).
- Replace a page the built-in site serves, such as the login page (see [How packs compose with the site](#how-packs-compose-with-the-site)).

## Files and workflow

| Path | What |
| --- | --- |
| `traps/packs/<id>.yaml` | The pack source. The file name is the pack id |
| `traps/fixtures/<id>/` | Raw requests (`exploit-*.http`, `probe-*.http`, `benign-*.http`) and `expect.json`, the trap hits and flags each one must give |
| `traps/fixtures/benign/` | Requests from browsers, crawlers, monitoring and the site's own pages. No pack may give an `exploit` hit or a CVE on them |
| `sensors/web/web_sensor/data/traps-bundled.json` | The compiled bundle that ships in the image. Generated, never edited by hand |

1. `just trap-new CVE-2026-55501 acme-edgegate-cve-2026-55501` creates the pack and its fixture folder from a template. The second argument (the pack id) is optional.
2. Write the requests from the advisory and public analyses. Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `example.net` only.
3. Edit the pack and `expect.json`. Every `TODO` must go: the check refuses a pack that still has one.
4. `just trap-build` compiles every pack into the bundle. Commit the YAML, the fixtures and the bundle. The reviewer reads the bundle diff, not only the YAML.
5. `just trap-check` validates every pack with the same code the sensor uses, checks that the bundle is up to date, runs the fixtures, the benign corpus, the differential test and the cost and memory tests.

Sensors read JSON only. The YAML is compiled by `ingest/tools/trap_packs.py`, and the validator, `suckerpot_common.traps`, is shared by the sensor, ingest and the checks, so they all agree on what is valid.

## Format

An example, for a fictional product and CVE:

```yaml
schema: suckerpot-trap/1
id: acme-edgegate-cve-2026-55501
version: 1
engine: 1
sensor: web
title: Acme EdgeGate pre-auth command injection
cve: [CVE-2026-55501]
disclosed: 2026-11-18
product: {vendor: Acme, name: EdgeGate}
group: vpn-appliance
tag: acme-edgegate-rce
attack: [T1190]
traps:
  - id: version-probe
    level: probe
    match:
      method: [GET, HEAD]
      path: {exact: /api/v1/version}
    outcome: {flags: [edgegate_probe]}
    respond:
      kind: php
      status: 200
      content_type: application/json
      variants:
        - '{"product":"EdgeGate","version":"7.2.{rand_int:1-4}","build":"{rand_hex:8}"}'
        - '{"product":"EdgeGate","version":"7.1.{rand_int:6-9}","build":"{rand_hex:8}"}'
  - id: diag-rce
    level: exploit
    match:
      method: [POST]
      path: {exact: /api/v1/diag/ping}
      needles:
        - {in: body, any: ["host="]}
        - {in: body, any: [";w", ";c", "|s", "$("]}
    outcome: {flags: [edgegate_rce]}
    respond:
      kind: php
      status: 200
      content_type: application/json
      variants:
        - '{"status":"ok","target":"{echo:query:host}","rtt_ms":{rand_int:9-40}}'
```

Unknown fields are refused, everywhere.

### Top level

| Field | Type and bounds | Meaning |
| --- | --- | --- |
| `schema` | `suckerpot-trap/1` | Format id |
| `id` | 3 to 48 of `a-z 0-9 -`, not starting with `-` | Stable pack id, also the file name |
| `version` | 1 to 65535 | Raise it on every change. The higher version wins |
| `engine` | 1 to 255 | Lowest engine that understands the pack. This release is engine 1. An older engine skips the pack (`engine_too_new`) |
| `sensor` | `web` | Which sensor loads it |
| `title` | 1 to 120 printable characters | Shown to the operator |
| `cve` | 0 to 8 ids, `CVE-YYYY-NNNN` to `CVE-YYYY-NNNNNNN` | The flaws the pack is about |
| `disclosed` | `YYYY-MM-DD` | Public disclosure day. Newer packs load first |
| `product` | `{vendor, name}`, 1 to 40 characters each | What the trap pretends to be |
| `group` | slug, optional | Persona group: an install answers as at most one product per group |
| `presence` | 0.05 to 1.0, default 1.0 | Share of installs that answer as this product. Detection is always on |
| `tag` | slug, 3 to 40 characters | Tag for exploit hits (used by later phases) |
| `attack` | 0 to 4, `T####` or `T####.###` | ATT&CK technique ids |
| `traps` | 1 to 16 traps | The traps |

### A trap

| Field | Bounds | Meaning |
| --- | --- | --- |
| `id` | 1 to 32 of `a-z 0-9 -`, unique in the pack | |
| `level` | `probe` or `exploit` | Probe: the client checks whether the product is there. Exploit: the request carries the exploit shape |
| `match.method` | subset of `GET HEAD POST PUT DELETE PATCH OPTIONS`; empty means any | Methods are case-sensitive, as in HTTP |
| `match.path` | exactly one of `exact`, `prefix`, `suffix`, `contains`; 1 to 256 printable ASCII bytes (`suffix` and `contains`: 4 or more) | On the path, percent-decoded twice and lowercased. `exact` and `prefix` start with `/` |
| `match.query_keys` | 0 to 8 names | All must be present (decoded, lowercased) |
| `match.header_names` | 0 to 8 names | All must be present (any case) |
| `match.needles` | 0 to 6 conditions, all must hold | Each is `{in, any}`. `in` is `path`, `query`, `body`, `headers` or `blob`. `any` is 1 to 16 needles; the condition holds when one is found |
| `match.case` | `insensitive` (default) or `exact` | `exact` compares the decoded bytes without lowercasing |
| `outcome.flags` | 1 to 4, `a-z 0-9 _`, 3 to 32 characters, starting with a letter | Flags added to the event. A flag the sensor's code sets, or a flag owned by another pack, is refused |
| `outcome.claim_cve` | `true` or `false`; default `true` for `exploit`, not allowed on `probe` | Adds the pack's CVE ids to the event's `cve` list |
| `respond` | optional | The fake answer. Without it the trap only observes and the site answers as before |

A trap needs at least one of `path`, `query_keys`, `header_names` or `needles`.

**Needles** are printable ASCII strings of 2 to 256 bytes, or `hex:` followed by 4 to 512 hex digits for raw bytes. With `case: insensitive` they are lowercased when the pack is compiled.

**Anchors.** A needle is searched exactly as written. The `query` and `body` areas start with `&` and the `headers` area starts with a newline, so an author can anchor a needle explicitly:

- `&key=value` in `query` or `body` matches only at the start of a parameter: `&allow_url_include=1` matches `?allow_url_include=1` and `?a=b&allow_url_include=1`, but not `-d allow_url_include=1` (PHP-CGI) nor `xallow_url_include=1`. Without the `&`, `allow_url_include=1` matches anywhere, also in `-d allow_url_include=1`, JSON, XML or text bodies.
- `"\nname: value"` in `headers` (a YAML double-quoted string with a leading `\n`) matches only at the start of a header line: `"\nx-api-version: ${jndi"` matches the `X-Api-Version` header only. Without it, `-agent: mozilla` also matches inside `User-Agent: Mozilla`. A newline is allowed only as the first character of a `headers` needle.

Only explicitly anchored needles can be specific (see the [evidence rule](#evidence-rule)); unanchored ones always count as weak.

**Percent escapes.** The path, query, body and blob are percent-decoded (twice) before matching, so `match.path` and a needle there must hold the decoded bytes: a value with `%` followed by two hex digits (`%2e`, also in `hex:` form) is refused (`schema`).

**Search areas** are the ones the detector already builds, with the same caps:

| Area | Content |
| --- | --- |
| `path` | The path, percent-decoded twice, first 4 KiB |
| `query` | The query string, percent-decoded twice, first 4 KiB |
| `body` | The first 16 KiB of the body, percent-decoded twice |
| `headers` | `name: value` lines, values cut at 1 KiB, 32 KiB in total |
| `blob` | Path, `?`, query, a newline and body, first 24 KiB |

### Evidence rule

A trap that claims a CVE must hold specific evidence, one of:

- a **specific needle condition**: in `query`, `body` or `headers` (never `path` or `blob`), and every needle of the condition (any one of them may match) has 6 bytes or more and does not occur in the trap's path. Each needle is explicitly anchored. In `headers` it is `"\nname: value"` with a value of 6 bytes or more (`"\nx-api-version: ${jndi"`), so a generic value such as `mozilla` never counts. In `query` and `body` it is a whole `&key=value` with a non-empty value (`&allow_url_include=1`); a needle without a key, such as `admin&pw` or `=admin&wp-subm`, never counts. A needle on a header every client sends never counts either: `user-agent`, `accept` and `accept-*`, `connection`, `host`, `cache-control`, `pragma`, `upgrade-insecure-requests`, `sec-*`, `dnt`, `referer`, `cookie`, `content-type`, `content-length` and the other `content-*`, `te`, `priority`, `origin`, `x-requested-with`, `x-forwarded-*`, `x-real-ip`, `keep-alive`, `range`, `authorization`, `via`, `forwarded`, `upgrade`, `transfer-encoding`, `expect`, `from` and `if-*`. In `query` and `body`, a needle on a tracking key (checked on every `key=value` part of the needle) (`utm_*`, `fbclid`, `gclid`, `msclkid`, `yclid`, `dclid`, `igshid`, `mc_cid`, `mc_eid`, `_ga`, `_gl`, `ref`, `source`, and the WordPress login form keys `log`, `pwd`, `wp-submit`, `redirect_to`, `testcookie`, `rememberme`) never counts, also as one `key=value` part of a longer needle (`a=1&pwd=x`), nor one on a common key, whatever its value (`&page=123456` is a page number): `page`, `paged`, `lang`, `s`, `p`, `q`, `id`, `search`, `query`, `sort`, `order`, `orderby`, `sortby`, `dir`, `format`, `callback`, `v`, `ver`, `cat`, `category`, `tag`, `author`, `feed`, `preview`, `replytocom`, `offset`, `limit`, `start`, `per_page`, `count`, `size`, `num`, `n`, `t`, `ts`, `_`, `cb`, `year`, `month`, `day`, `hl`, `locale`, `type`, `keyword`, `keywords`, `filter`, `view`, `amp`, `nocache`, `rand`, `random`, `timestamp`, `time`, `date`;
- an `exact` or `prefix` path of 12 bytes or more on a path the built-in site does not serve.

The validator refuses a claiming trap without it (`evidence`). A pack can never turn `GET /` into an exploit.

### The fake answer

| Field | Bounds | Meaning |
| --- | --- | --- |
| `kind` | `php`, `static` or `error` | Header order and framing from the sensor's Apache model, so the answer looks like the rest of the site |
| `status` | 200 201 204 301 302 400 401 403 404 405 500 503 | 204 has an empty body (every variant is `""`). 301 and 302 need a `Location` header; `Location` is allowed only with 201, 301 and 302 |
| `content_type` | `text/html; charset=UTF-8`, `text/plain`, `application/json`, `text/xml`, `application/xml` | |
| `headers` | 0 to 6 `[name, value]` pairs | Names: `Cache-Control`, `Set-Cookie`, `WWW-Authenticate`, `X-Frame-Options`, `Location`, `Pragma`, `Expires`. Values: printable ASCII, 512 bytes at most. `Location` is a path or starts with `{base_url}`. Only `Set-Cookie` may repeat |
| `variants` | 1 to 4 bodies, 16 KiB each at most | One is chosen per install and pack |

Templates have placeholders and no logic:

| Placeholder | Value |
| --- | --- |
| `{hostname}` | The sensor's host name |
| `{server_ip}` | The install's fake private address |
| `{site_title}` | The fake WordPress site title |
| `{base_url}` | `http://` or `https://` and the request's Host, as the rest of the site uses it |
| `{server_token}`, `{php_version}` | The Apache token and PHP version |
| `{date_http}`, `{year}`, `{install_date}` | The current date (HTTP format), the year, the fake install day |
| `{rand_hex:N}` | N hex digits (1 to 64), stable per install and pack |
| `{rand_int:A-B}` | An integer from A to B (at most 1,000,000,000), stable per install and pack |
| `{echo:query:KEY}` | The decoded value of one query key, filtered to `A-Za-z0-9._-` and cut to 64 bytes. Allowed in bodies only, never in headers |

Braces that are not a placeholder stay as text, so JSON bodies need no escaping.

### Content rules

The validator refuses (`content`) a body or header that contains, in any case, as written or once every space, tab and line break is removed (browsers drop them inside URLs):

- a URL scheme: `http:`, `https:`, `ftp:`, `javascript:`, `vbscript:`;
- `{base_url}` followed by anything but `/`, `?`, `#`, a quote, a space or the end of the text (so `{base_url}@evil.example` or `{base_url}.evil.example` cannot name another host);
- a URL value that leaves the site: `//`, `/\`, `\/`, `\\` or `data:` at the start of the text or right after `"`, `'`, `=`, `(` or `,` (so `src= //host`, `srcset="/a 1x, //host 2x"` and `url= //host` are refused);
- a character reference other than `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;` and `&nbsp;` (no `&#...;`, no `&sol;`), so nothing can be spelled with entities;
- an event handler attribute: `on` and letters, optional spaces, then `=` (`onload=`, `onerror =`), when it starts an attribute name;
- `<script`, `<iframe`, `<frame`, `<object`, `<embed`, `<applet`, `<base`, `<svg`, `<math`, `<meta`, `<link`, `<style`, `url(`, `@import` or `expression(`;
- a form `action` that is not a path on this site or `{base_url}`;
- an `{echo:...}` next to a letter, digit, `:`, `/`, or another placeholder, or right after `<`, so an echoed value can never complete a tag name, a URL scheme or a word;
- `suckerpot`, `selfhostr` or `honeypot`.

`Location` is a path (not `//` or `/\`) or starts with `{base_url}`, and `{echo:...}` is never allowed in a header.

A rendered body is at most 16 KiB. A pack can make a node answer like a vulnerable product. It cannot make it host a link, a script or a download for someone else.

## How packs compose with the site

1. The built-in detector runs first, unchanged. Pack flags are added; a pack never removes one.
2. Every loaded trap is matched on every request. Detection never depends on persona or presence.
3. If matching traps have `respond` and are active on this install, the most specific one answers instead of the site: `exact` path, then `prefix` (longest first), then `suffix`, then `contains`, then no path; then the most conditions; then pack id order. Otherwise the site answers as before.
4. On a path the built-in site serves (`/`, `/index.php`, `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/`, `/wp-json/`, `/wp-content/`, `/wp-includes/`, `/phpmyadmin/`, `/pma/`, `/robots.txt`, `/favicon.ico`, `/info.php`, `/phpinfo.php`, the static files and listed directories), a trap may answer only if it also has a `query_keys` condition or a specific needle condition (as in the [evidence rule](#evidence-rule): `query`, `body` or `headers`, every needle 6 bytes or more, header needles naming their header). A needle on the path or the blob, or a generic one such as `": "`, never lets a pack replace a built-in page. The validator also refuses a responding trap whose `exact` or `prefix` path only covers such pages without that condition.
5. The check refuses two responding traps with the same path condition, methods and number of conditions.

**Per-install variation.** The install's private profile secret picks the variant (one per pack, so the probe and exploit answers agree), fills `{rand_hex}` and `{rand_int}`, decides `presence`, and picks one product per `group`. Two installs answer differently; one install always answers the same way.

## Limits

| Item | Limit |
| --- | --- |
| Bundle file | 1 MiB of JSON, 64 packs loaded |
| One pack | 64 KiB of canonical JSON, 16 traps |
| Traps loaded | 512, of which at most 32 without a path condition |
| Traps without a path | At most 64 distinct needles, and the bytes they can search (the size of each needle's area: path 4 KiB, query 4 KiB, body 16 KiB, headers 33 KiB, blob 24 KiB) at most 512 KiB, so they always run within their budget |
| Packs that own reserved flags | They run first and outside the per-request budget; what they can search is capped at 256 KiB at load |
| Needles | 16 per condition, 6 conditions per trap, 2 to 256 bytes each |
| Compiled memory | 4 MiB per trap set (an estimate that a test checks is an upper bound) |
| Work per request | Traps run most specific path first, after the packs that own reserved flags. Traps with a path share 96 distinct needle searches and 512 KiB of searched bytes; the traps this budget skips are counted in the event as `data.trap_budget`. Traps without a path have their own 64 searches and 512 KiB, which the load limit above guarantees is enough. At most about 1.25 MiB is searched per request, whatever the packs and the request |
| Cost | p99 under 2 ms added per request with the limits filled (tested) |
| Worst case | A request crafted against needles chosen to be slow (`aaa...b` over `aaa...`) adds at most 5 ms (tested; about 1 ms measured) |

**Room for new flaws.** Packs load newest `disclosed` first. Packs disclosed more than 90 days ago may use only three quarters of each limit, so a new pack always has room. A pack that does not fit is rejected as `over_limit`.

## Loading and errors

The web sensor loads its bundled packs at start, then the downloaded bundle whenever it changes (see [Signed distribution](#signed-distribution)). Each pack is validated on its own. An invalid pack is skipped with one log line that carries its id and a reason, and the other packs load:

```text
trap pack rejected: id=acme-edgegate-cve-2026-55501 reason=evidence source=traps-bundled.json
```

| Reason | Meaning |
| --- | --- |
| `schema` | A field is missing, unknown, of the wrong type, or sets a built-in flag |
| `limits` | A size or count bound is exceeded |
| `evidence` | A trap claims a CVE without specific evidence |
| `content` | A fake answer breaks a content rule or a placeholder is malformed |
| `engine_too_new` | The pack needs a newer engine |
| `over_limit` | The pack is valid but the load limits are full |

An unreadable or invalid bundle file loads no pack at all, and the sensor runs with its built-in detection only.

## Signed distribution

A pack merged on `main` reaches every online node within about an hour, without a release. Nodes keep the packs bundled in their image and add the downloaded ones.

1. **Sign.** The workflow `.github/workflows/trap-packs.yml` runs on a push to `main` that touches `traps/`, or by hand on `main`. It never runs on a pull request. A first job, without any secret, checks every pack and writes `traps.json`: every pack, the kill list `traps/disabled.yaml`, and a new `seq` (the current Unix time, refused unless it is above the published one). A second job runs in the protected GitHub environment `trap-packs`, whose required reviewer is the owner. Only that job sees the pack secret key (the environment secret `TRAP_PACK_SECRET_KEY`). It first rebuilds `traps.json` from the checked-out commit and refuses to sign a file that differs (anything but `issued_at`). It then signs the file with minisign, checks the signature against the public key in `config/network-defaults.env`, and attaches `traps.json` and `traps.json.minisig` to the fixed GitHub release `trap-packs`. Set the environment to allow deployments from the `main` branch only.
2. **Relay.** The hub worker reads that release every 10 minutes, verifies the signature and the `seq`, and copies the bytes unchanged to the feed site, `https://<feed host>/v1/traps/`. The hub holds no private key: it cannot sign.
3. **Fetch.** `ingest` fetches `traps.json` and its signature every 30 minutes (plus up to 5 minutes of jitter, and once at start), with a conditional `GET`, from the host of `NETWORK_FEED_URL` only. In full mode it goes through the VPN egress gate; in participant direct mode through `hubproxy`, which already allows the feed host. The sensors never fetch anything.
4. **Verify and hand over.** `ingest` checks the signature with the pack public key (`TRAP_PACK_KEY`), refuses a `seq` lower than the last one it accepted, runs the same validator as the sensor, and writes `active.json` and `active.json.minisig` to the `trap-packs` volume (temporary file, `fsync`, rename).
5. **Load.** The web sensor mounts that volume read-only. Every 30 seconds it looks at the files; when they change, it checks the signature itself, validates and compiles a new set of traps and swaps it in. Requests in flight finish with the old set, and no connection is dropped.

The sensor and `ingest` each refuse a bundle with a forged signature, a signature from another key, or a `seq` lower than the one they have. A compromised `ingest` or hub can withhold a bundle or delete it (the sensor then falls back to its bundled packs), but cannot add a trap. Packs never expire: a node that is offline keeps its last bundle and fetches the newest when it is back.

A bad pack inside a good bundle is rejected alone, with its id and reason in the log; the other packs load. Per pack id, the higher `version` wins, whether it is bundled or downloaded. A downloaded bundle older than the image's bundled packs is ignored.

**Every event** of the web sensor carries `data.trap_seq`, the `seq` of the bundle the sensor runs (`0` for the bundled packs alone).

### Gate G: 48 hours before a CVE counts as an exploit

For 48 hours after a pack version first loads on a node, the CVE tags its hits produce are shared with the network as usual, but they do not make the source's activity `exploit`. So a new pack cannot make anyone reportable before it has run for 48 hours, the same delay as the release floor. Detection and the dashboard are immediate. If `ingest` cannot read the trap state, no CVE tag counts as an exploit (fail closed).

### Turning a pack off

| Scope | How | Delay |
| --- | --- | --- |
| Every node | Add `{id: <pack id>, reason: <short reason>}` to `traps/disabled.yaml` and merge. Bundled packs are turned off too | Within the hour |
| This node | `TRAP_PACKS_DISABLED=id,id` in `.env`, then restart the web sensor | At once |
| This node, every downloaded pack | `TRAP_PACKS_REMOTE=false` in `.env`. Ingest stops fetching and removes the downloaded bundle; the bundled packs keep running | At once |
| A stolen pack key | A release that changes `TRAP_PACK_KEY` | A release |

### Settings

| Setting | Default | Where | Meaning |
| --- | --- | --- | --- |
| `TRAP_PACKS_REMOTE` | `true` | `ingest` | Fetch the signed bundle. Nothing is fetched without a route (VPN egress, or `hubproxy` in participant direct mode) |
| `TRAP_PACK_KEY` | the release's key | `ingest`, `sensor-web` | The pack public key (`RW...`). Empty in `.env` and in `config/network-defaults.env`: downloaded packs stay off |
| `TRAP_PACKS_DISABLED` | empty | `sensor-web` | Pack ids to turn off on this node, comma-separated |

### No route out: import a bundle by hand

A full install without the `egress` profile has the bundled packs only. Download `traps.json` and `traps.json.minisig` elsewhere (from the `trap-packs` release) and load them:

```bash
just trap-import traps.json traps.json.minisig
```

The same checks apply: signature, `seq` and every pack. An imported bundle stays when `TRAP_PACKS_REMOTE=false`.

### The pack key (owner)

`ingest/tools/trap_packs.py keygen --out <file>` creates a key pair: it prints the `TRAP_PACK_KEY=RW...` line for `config/network-defaults.env` and writes the secret key file (mode 0600). Put the content of that file into the secret `TRAP_PACK_SECRET_KEY` of the GitHub environment `trap-packs`, and nowhere else. The public key reaches nodes with the next release, which the release manifest covers. Until then, `TRAP_PACK_KEY` is empty and the workflow refuses to sign.

## What the events show

A request that hits a pack trap carries `data.traps`: up to four entries `{pack, v, trap, level}`. The flags and `cve` are in the usual `flags` and `cve` keys, and the tagging rules in `ingest/rules/web.yaml` turn the flags into tags as for any other flag. When a trap answered, `app` is `trap` and `route` is `trap:<pack>/<trap>`.

## Bundled packs

| Pack | Traps | Flags |
| --- | --- | --- |
| `phpunit-eval-stdin` | `eval-stdin` (exploit), `vendor-dir` (probe) | `phpunit_rce`, `phpunit_probe` |
| `log4j-log4shell` | `jndi-header`, `jndi-request` (exploit) | `log4shell` |
| `router-boaform-gponform` | `boaform`, `gponform` (exploit) | `router_exploit` |

These three were rules in the sensor's code before. They were converted with the same behaviour: they observe only, claim no CVE and do not answer. A differential test proves that every request in the golden, demo and test-suite corpus gives the same flags, CVEs, severity and response bytes as the old code. The extraction of a Log4Shell callback URL stays in the sensor's code.
