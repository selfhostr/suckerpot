# Trap packs

A trap pack teaches the web sensor a new trap without a code change. One pack is written per flaw, usually per CVE. It is data only: byte strings to look for in a request, flags to add to the event, and, if you want, a fake answer built from a fixed template.

```{admonition} Status
:class: note

Phase 1 of M37. Packs are bundled in the web sensor image and change with a release. Signed packs that reach every node without a release, the dashboard view and the banner sensor for non-HTTP flaws come in later phases. The design is in the [M37 design note](dev/design/m37.md).
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
- Remove or change a flag the sensor's own code sets, or set one of those flags.
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
| `match.path` | exactly one of `exact`, `prefix`, `suffix`, `contains`; 1 to 256 printable ASCII bytes | On the path, percent-decoded twice and lowercased. `exact` and `prefix` start with `/` |
| `match.query_keys` | 0 to 8 names | All must be present (decoded, lowercased) |
| `match.header_names` | 0 to 8 names | All must be present (any case) |
| `match.needles` | 0 to 6 conditions, all must hold | Each is `{in, any}`. `in` is `path`, `query`, `body`, `headers` or `blob`. `any` is 1 to 16 needles; the condition holds when one is found |
| `match.case` | `insensitive` (default) or `exact` | `exact` compares the decoded bytes without lowercasing |
| `outcome.flags` | 1 to 4, `a-z 0-9 _`, 3 to 32 characters, starting with a letter | Flags added to the event. A flag the sensor's code sets is refused |
| `outcome.claim_cve` | `true` or `false`; default `true` for `exploit`, not allowed on `probe` | Adds the pack's CVE ids to the event's `cve` list |
| `respond` | optional | The fake answer. Without it the trap only observes and the site answers as before |

A trap needs at least one of `path`, `query_keys`, `header_names` or `needles`.

**Needles** are printable ASCII strings of 2 to 256 bytes, or `hex:` followed by 4 to 512 hex digits for raw bytes. With `case: insensitive` they are lowercased when the pack is compiled.

**Search areas** are the ones the detector already builds, with the same caps:

| Area | Content |
| --- | --- |
| `path` | The path, percent-decoded twice, first 4 KiB |
| `query` | The query string, percent-decoded twice, first 4 KiB |
| `body` | The first 16 KiB of the body, percent-decoded twice |
| `headers` | `name: value` lines, values cut at 1 KiB, 32 KiB in total |
| `blob` | Path, `?`, query, a newline and body, first 24 KiB |

### Evidence rule

A trap that claims a CVE must hold specific evidence: a needle of 6 bytes or more in `query`, `body`, `headers` or `blob`, or an `exact` or `prefix` path of 12 bytes or more on a path the built-in site does not serve. The validator refuses a claiming trap without it (`evidence`). A pack can never turn `GET /` into an exploit.

### The fake answer

| Field | Bounds | Meaning |
| --- | --- | --- |
| `kind` | `php`, `static` or `error` | Header order and framing from the sensor's Apache model, so the answer looks like the rest of the site |
| `status` | 200 201 204 301 302 400 401 403 404 405 500 503 | |
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

The validator refuses (`content`) a body or header that contains, in any case:

- a URL scheme: `http:`, `https:`, `ftp:`, `javascript:`, `vbscript:`, or a link to another host (`"//`, `'//`, `=//`, `(//`, `\\`);
- `<script`, `<iframe`, `<frame`, `<object`, `<embed`, `<applet` or `<base`;
- a form `action` that is not a path on this site or `{base_url}`;
- an `{echo:...}` next to a letter, digit, `:`, `/`, or another placeholder, or right after `<`, so an echoed value can never complete a tag name, a URL scheme or a word;
- `suckerpot`, `selfhostr` or `honeypot`.

A rendered body is at most 16 KiB. A pack can make a node answer like a vulnerable product. It cannot make it host a link, a script or a download for someone else.

## How packs compose with the site

1. The built-in detector runs first, unchanged. Pack flags are added; a pack never removes one.
2. Every loaded trap is matched on every request. Detection never depends on persona or presence.
3. If matching traps have `respond` and are active on this install, the most specific one answers instead of the site: `exact` path, then `prefix` (longest first), then `suffix`, then `contains`, then no path; then the most conditions; then pack id order. Otherwise the site answers as before.
4. On a path the built-in site serves (`/`, `/index.php`, `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/`, `/wp-json/`, `/wp-content/`, `/wp-includes/`, `/phpmyadmin/`, `/pma/`, `/robots.txt`, `/favicon.ico`, `/info.php`, `/phpinfo.php`, the static files and listed directories), a trap may answer only if it also has a `query_keys` or `needles` condition.
5. The check refuses two responding traps with the same path condition, methods and number of conditions.

**Per-install variation.** The install's private profile secret picks the variant (one per pack, so the probe and exploit answers agree), fills `{rand_hex}` and `{rand_int}`, decides `presence`, and picks one product per `group`. Two installs answer differently; one install always answers the same way.

## Limits

| Item | Limit |
| --- | --- |
| Bundle file | 1 MiB of JSON, 64 packs loaded |
| One pack | 64 KiB of canonical JSON, 16 traps |
| Traps loaded | 512, of which at most 32 without a path condition |
| Distinct needles of traps without a path | 128 (they are searched on every request) |
| Needles | 16 per condition, 6 conditions per trap, 2 to 256 bytes each |
| Compiled memory | 4 MiB per trap set (an estimate that a test checks is an upper bound) |
| Work per request | 160 distinct needle searches; past that, matching stops for this request and a counter goes up |
| Cost | p99 under 2 ms added per request with the limits filled (tested) |

**Room for new flaws.** Packs load newest `disclosed` first. Packs disclosed more than 90 days ago may use only three quarters of each limit, so a new pack always has room. A pack that does not fit is rejected as `over_limit`.

## Loading and errors

The web sensor loads the bundle once at start. Each pack is validated on its own. An invalid pack is skipped with one log line that carries its id and a reason, and the other packs load:

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

## What the events show

A request that hits a pack trap carries `data.traps`: up to four entries `{pack, v, trap, level}`. The flags and `cve` are in the usual `flags` and `cve` keys, and the tagging rules in `ingest/rules/web.yaml` turn the flags into tags as for any other flag. When a trap answered, `app` is `trap` and `route` is `trap:<pack>/<trap>`.

## Bundled packs

| Pack | Traps | Flags |
| --- | --- | --- |
| `phpunit-eval-stdin` | `eval-stdin` (exploit), `vendor-dir` (probe) | `phpunit_rce`, `phpunit_probe` |
| `log4j-log4shell` | `jndi-header`, `jndi-request` (exploit) | `log4shell` |
| `router-boaform-gponform` | `boaform`, `gponform` (exploit) | `router_exploit` |

These three were rules in the sensor's code before. They were converted with the same behaviour: they observe only, claim no CVE and do not answer. A differential test proves that every request in the golden, demo and test-suite corpus gives the same flags, CVEs, severity and response bytes as the old code. The extraction of a Log4Shell callback URL stays in the sensor's code.
