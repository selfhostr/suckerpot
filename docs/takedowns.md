# Track takedowns

SuckerPot follows what happens to the targets in your reports. Is the malware file still served? Is the attacking address still active? How long did the takedown take, and which providers act?

Takedown tracking is optional and off by default. It needs `TAKEDOWN_ENABLED=true`. Re-checks of payload URLs also need `COLLECTOR_ENABLED=true`.

This page covers:

- what is re-checked, and what is never contacted;
- the states a target can have;
- the statistics, including the 48-hour rule;

Related pages: [Replies to reports](replies.md) (the answers from providers), [Configuration](configuration.md#takedown-tracking-m27), and the design in [docs/design/m27.md](design/m27.md).

## What is never contacted

SuckerPot is a honeypot. It does not hunt back. Takedown tracking follows the same rule:

| Target | Contacted? |
| --- | --- |
| A malware URL that served a sample to the collector | Yes, one bounded GET (see below). |
| Other paths on the same host, such as a directory listing | Never. |
| A command-and-control (C2) server | Never. No connection, no ping, no banner grab. |
| An attacking IP address | Never. No connection, no ping, no traceroute. |
| A URL hosted on an address that attacked you in the last 30 days | Never. Passive signals only. |
| Any host for port scans, DNS brute force or reverse lookups | Never. |
| An abuse report to AbuseIPDB | Never. SuckerPot only reads AbuseIPDB. |

The fixed intel services are asked about a value. These are URLhaus, ThreatFox and AbuseIPDB. They are not the target. Their answers come from their own databases.

Why:

- A connection to a C2 server or an attacker is a probe of their infrastructure. That is a counter-scan.
- A payload host is public by nature: it serves a file to anyone who asks. Asking once, the same way the collector asked the first time, is the same request.
- An address that attacks you is not a host that serves you. SuckerPot keeps out of it.

### The re-check of a payload URL

The collector re-checks a URL only when all of these are true:

1. The collector fetched the URL before and stored a sample from it.
2. The URL is not on a C2 address, and not on an address that attacked you in the last 30 days.
3. The target is still being tracked.

The re-check is one GET with the same identity and limits as the original fetch:

- the same user agent, headers and timeouts;
- redirects followed by hand, at most `COLLECTOR_MAX_REDIRECTS`, and each hop is checked against the same URL rules;
- the body is capped at `COLLECTOR_MAX_BYTES`;
- every request goes through the VPN. With the tunnel down, nothing is sent and no quota is used.

SuckerPot stores nothing unless the file changed. The body is hashed while it streams. If the hash matches the last one, the bytes are thrown away. If the file is different, it is kept as a new sample, if there is room in quarantine. A file that is never stored is never run.

The schedule of re-checks per URL:

| When after the report | Check |
| --- | --- |
| 0 h, 1 h, 6 h, 24 h, 48 h | Each once. |
| Every 24 h after that | Until tracking stops (`TAKEDOWN_TRACK_DAYS`, 30 by default). |
| Every 72 h while the URL is down | To catch a host that comes back. |

That is about 35 requests per URL in 30 days. The daily cap is `TAKEDOWN_HTTP_DAILY_QUOTA` (200 by default).

### Passive checks

Some signals need no request at all:

| Check | Looks at | Used for |
| --- | --- | --- |
| Sightings | Your own sensors. Did an attacking address connect again after the report? | Attack sources: Active or Quiet. |
| Samples | Did a new sample that you collected point to a reported C2 address? | C2 servers: Active or Unknown. |
| Listings | URLhaus, ThreatFox and AbuseIPDB answers, asked at 0 h, 24 h, 7 days and 30 days. | Extra evidence for every kind. |

Listing lookups have their own daily caps, `TAKEDOWN_INTEL_DAILY_QUOTA` (100) and `TAKEDOWN_ABUSEIPDB_DAILY_QUOTA` (50). Each one also uses the provider's normal quota, so tracking can never take the whole intel budget. When a cap is used up, no more lookups run until the next day. A closed tunnel means no lookup and no quota used.

## Targets

A target is one thing you reported. SuckerPot creates targets from:

| Source | Target kind | Role |
| --- | --- | --- |
| The subject of an attack-source report | IP address | Attack source |
| The subject of a payload-host report | IP address or domain | Payload host |
| A URL that served a sample from that host | URL | Payload URL (a child of its host) |
| The subject of a C2 report | IP address or domain | C2 |

A target reported in several places keeps the earliest report date. Demo reports never create tracked targets unless `ABUSE_REPORTS_INCLUDE_DEMO=true` (for screenshots).

Each target is tracked for `TAKEDOWN_TRACK_DAYS` days after it was reported. You can stop tracking early: a target page has a **Stop tracking** button for administrators.

Each host with URLs keeps at most 20 child URLs, the latest first.

## States

Each target has one state. The dashboard shows the state as an icon and a word. Red is used only for a payload that is still served or replaced, never for an address or a C2.

| Target | State in the data | Shown as | Meaning |
| --- | --- | --- | --- |
| Payload URL | `up` | Still serving | The last check found the same file, or a file that could not be compared. |
| Payload URL | `changed` | Serving a new file | The URL answers with a different file. It may be a new sample. |
| Payload URL | `down` | Down | Two checks in a row found it gone (see below). |
| Payload URL | `unknown` | Unknown | Not checked yet. |
| Payload host | `up`, `changed`, `down`, `unknown` | Same words | Taken from its URLs: up while any URL is up, down when every URL is down. |
| Attack source (IP) | `up` | Active | Our sensors saw it attack in the last 72 hours, or a listing reported it again. |
| Attack source (IP) | `down` | Quiet | Not seen for 7 days (`TAKEDOWN_QUIET_DAYS`) after the report. |
| C2 server | `up` | Active | New malware points to it, or a listing was refreshed after the report. |
| C2 server | `unknown` | Unknown | No passive signal yet. |

### When a URL counts as down

A single failed check never means down. A URL is down when its last two checks are down answers, and they are far enough apart:

| Kind of answer | Examples | Gap between the two checks |
| --- | --- | --- |
| Strong | Not found (404), Gone (410), other client error, suspended-account page, empty answer | At least 1 hour |
| Weak | Not reachable, no answer in time, server error (5xx) | At least 6 hours |

The dashboard shows "Not answering since" for a URL that has failed once and is not yet confirmed down.

For a C2 server the state is never **down**. SuckerPot does not contact C2 servers, so it cannot see them go away. The page says so: it shows whether new malware still points to the address.

### Time to takedown

Time to takedown is the first confirmed down time minus the report time. It is an upper bound. The takedown happened between the last check that was up and the first check that was down. The target page shows that window, for example "down between 14:00 and 20:00, 19 hours after the report".

A target that was already down at its first check (`down_before_report`) has no time to takedown. It is left out of the statistics.

## Statistics

The Results page counts takedowns from the targets. It leaves out demo targets and targets that were already down at the first check.

Attack sources and C2 servers are not takedowns. They have their own "quiet" and "active" counts. Only payload URLs and payload hosts count as takedowns.

### The 48-hour rule

"Taken down within 48 hours" is counted over the targets that can be judged. A target can be judged only when it was observed for the whole 48 hours, or when it went down within them.

Example. You reported 31 malware URLs. Nine of them were reported less than 48 hours ago and have not gone down yet. Those nine are not judged yet, so they are left out of the count. The other 22 can be judged. Twelve of the 22 went down within 48 hours. The Results page reads: "12 of 22 reported malware URLs went down within 48 hours."

The same rule applies to 7 days and 30 days. This is called right-censoring. It stops young reports from making the numbers look worse than they are.

Other rules:

- **Median time to takedown** needs at least five values. Below that the page says "not enough data yet".
- **Still up after 30 days** counts the targets that were tracked to the end and never went down.
- **Channels** are shown as mail only, URLhaus only, or both. URLhaus notifies hosting providers itself. The page does not claim that your report caused a takedown that URLhaus also reported.

### Per provider

Each provider gets a row with its targets, the share down within 48 hours and 30 days, its median time to takedown, the number still up, and, from [Replies to reports](replies.md), the reports sent, the share answered and the median first reply.

A provider is:

- the network (AS number) of the address, when it is known;
- otherwise the abuse mailbox of the registrar you wrote to, for domains.

The Results page can group by provider, mailbox, country or report kind. Filters live in the URL, so a view can be shared.

### Monthly history

A monthly roll-up keeps the counts per provider, kind and channel. It holds numbers only: no values, no URLs, no addresses. It is kept after the reports are deleted by retention, so the history stays on the Results page.

## Retention

| Data | Kept for |
| --- | --- |
| Individual checks | `TAKEDOWN_CHECK_RETENTION_DAYS` (400 by default). |
| Targets | 400 days after tracking stops. |
| Old abuse.ch submission rows (from before v0.11.0) | 730 days. |
| Monthly roll-up | Forever. |

## Related

- [Replies to reports](replies.md): what the providers answered.
- [Configuration](configuration.md#takedown-tracking-m27): every variable.
- [Dashboard](ui.md#results-m26-m27): the Results and Target pages.
- [Design M27](design/m27.md): the full design, with the invariants and the tests.
