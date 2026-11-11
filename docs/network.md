# The SuckerPot network

The SuckerPot network is a pool you can join and leave at any time. Many SuckerPot systems share what their sensors saw, in aggregate and without identities. The network confirms a target only when several independent sensors agree. It then sends one strong abuse report instead of many weak ones, and it follows the takedown.

This page is for members and for people who want to know what joining means. The hub operator reads `hub/README.md`. The exact wire format is in [Network protocol](network-protocol.md). The design and its review are in [M29](design/m29.md).

```{warning}
**Experimental preview.** The SuckerPot network has very few nodes today. Its shared feed may be empty, and a participant gets nothing back yet. Thresholds and the protocol may change without notice. Known limits: identity is free, so the consensus does not yet resist a determined attacker who creates several nodes, and the hub run by the project maintainers is the single root of trust. The network is off unless you choose to join.
```

```{warning}
Joining is a choice you are always asked about, and the default answer is no. The installer asks "Join the SuckerPot network? [y/N]" and shows what would be shared first. `--yes` never joins: joining without a question needs `--join-network`. `--no-network` skips the question. An existing install that never answered is never joined by an update. In a full install you can also join or leave in the dashboard at any time. In a participant install, choosing that mode in the installer is the join.
```

## What joining means

Joining turns your sensors into one voter in a shared network. Your system then:

- sends one daily batch of attacker addresses and a few related facts (see [What is shared](#what-is-shared-and-what-never-is));
- receives the list of targets the network has confirmed, and shows it to you (today this list is usually empty, see the note above);
- can see the network's totals and which members take part.

You do not get a share of anything, and you do not get better detection. The benefit is for the internet: an address that many sensors agree on is more likely to be removed, and the people who run it are more likely to be told.

Your system stays on your own machine. Nothing is installed on the hub side for you, and no account or e-mail address is created.

## Joining is always an explicit choice

The network feature is off by default (`NETWORK_ENABLED=false`). To use it, set `NETWORK_ENABLED=true` and join. Nothing goes to the hub until this system has joined, and a join needs an explicit agreement:

| Way to join | Who | Default |
| --- | --- | --- |
| The installer question "Join the SuckerPot network? [y/N]" (full mode), after the consent screen, or the flag `--join-network` | The person installing | No. An empty answer is a no. `--yes` alone does not join. `--no-network` skips the question |
| The participant install (`--participant`) | The person installing | The mode is the join |
| Settings, Network: join, after being shown the five items and confirming with the password | An administrator | Not joined |

A yes in the installer (or `--join-network`) writes a consent record (`NETWORK_CONSENT`) and a random pseudonym to `.env`. Ingest then joins by itself, once. In a full install the traffic only ever leaves through the VPN, so the join waits until a VPN is configured. Enrolment and every network read go through the VPN once a VPN exists, and with none nothing leaves at all. Nothing about your sensors is submitted until your own public address is confirmed (it is learned from traffic, or you set it in Settings), so your own address cannot leak into a batch.

The record is consumed at the first start: ingest uses it only within 7 days of the day written in it. Later it is ignored, so restoring an old database cannot undo a leave. To re-agree, use the dashboard or, in a participant install, `./scripts/participant.sh join` (it writes a fresh record).

With `NETWORK_ENABLED=false` (the default), the whole feature is off: the Network pages explain it and the worker never contacts the hub.

Other rules:

- Leaving takes one click and the password. See [How to leave](#how-to-leave). A leave is final for restarts and updates: a stored record never joins you again by itself.
- Joining again after you leave is a new decision. Do it in the dashboard (Settings, Network), after being shown the five items and confirming with the password.
- An upgrade never joins an install that has no consent record.
- Viewers can read the Network pages but cannot join or leave. Only an administrator can.

## What is shared and what never is

When you join, you are shown five items. Each item is one kind of data. The API refuses a join unless you confirm all five.

| Item | What is sent | Form |
| --- | --- | --- |
| Attacker addresses | The addresses that attacked your sensors | Clear IP address, with the kind of service (for example `ssh`, `web`), a coarse activity (`connect`, `scan`, `login`, `login_success`, `command`, `download`, `exploit`, `http`), behaviour tags and rounded counts |
| Download links | Links that attackers tried to fetch malware from | Blinded: a SHA-256 hash of the normalised link. The clear link is revealed only after the network confirms the hash and a member holds the clear link |
| Malware file fingerprints | SHA-256 of a captured file, its family and its file type | Hash only. The file is never sent |
| Command servers | Address or domain and port of a command-and-control server | Only high-confidence links, and only when a dropper that several sensors fetched backs them |
| Takedown checks | Whether a reported target still answers | `up` or `down`. Nothing is sent yet, see [Takedown checks](#takedown-checks) |

### What is never shared

These things never leave your system, whatever you tick:

- usernames and passwords that attackers tried;
- commands typed in a shell, and web requests;
- source and destination ports, and exact times (only the UTC day is sent);
- anything from research scanners or from harmless visitors;
- your own address, domain, host name or dashboard address, in any spelling;
- private, reserved and documentation addresses;
- anything on your never-block list.

Your private key never leaves your system. It is stored encrypted and used only to sign requests. Your public key goes with every signed request, because the hub needs it to check the signature.

### What the hub can see about you

The hub sees what a batch contains, and the requests that carry it. It does not see:

- your name, mailbox, payment or account (there is none);
- your domain or host name (every item is checked for them before it leaves).

If you choose a pseudonym, the hub sees it. If you choose a country and show it, the hub sees that too.

The address your request comes from is not hidden by the protocol, see [What the hub can and cannot learn](#what-the-hub-can-and-cannot-learn).

### Identity controls on your side

Before a batch leaves, every item passes the same identity check that protects your abuse reports. The check drops an item that contains your own address, a domain you use, or any term you have listed as yours. A batch that fails the check as a whole is not sent.

Nothing is sent until you confirm your own address in Settings, Reporting. Without a confirmed address, the node shows that it is waiting for your address and sends nothing. This is on purpose. It stops your own address from leaving in a batch by mistake.

```{note}
Test traffic counts. If you test your sensors from an outside address that is not in your address terms, that address is submitted like any attacker's. Add your test address to your terms, or expect it to appear in a batch.
```

## What you get back

| Item | What it is |
| --- | --- |
| Totals | Members, members active this week, countries with at least three members, confirmed, reported and taken-down targets over 30 days, median days to takedown |
| Weekly figures | Confirmed, reported and taken-down targets per week |
| Recently taken down | Targets, with the number of sensors (as a range) and a "You helped" mark when your system contributed |
| Members | Pseudonym or node number, country (only if the member showed it), member since (a month), active days in the last full week, and a tier |

Nothing in the public figures can point to a single system. There is no ranking, and the member list is shuffled by the hub on every day.

## The community lists

The network also publishes free blocklists. They are built from the same consensus as the hub's reports. Any firewall can load them, and they cost nothing to use.

| List | Blocks | Built from |
| --- | --- | --- |
| `outbound` | Traffic leaving your network to malware hosts and command servers | Payload hosts fetched by at least 2 nodes, with a known malware family or an executable or script file type. Command servers with high-confidence analysis and at least 2 samples from 2 nodes. |
| `inbound` | Traffic coming in from attack sources | Addresses with login success, commands, downloads, exploits or repeated login attempts, seen over TCP by at least 5 nodes |
| `outbound-domains` | DNS lookups of the same hosts, by name | The names behind the `outbound` evidence |

The `-high` variants hold the stricter subset. The full rules, the formats and the steps for each firewall are in [Community blocklist feeds](feeds.md).

The lists are published by the hub, from its own server. A member's home connection is never the source of a list. Nothing in a list names a member, a country, a sensor or a day of sighting. An entry needs at least five independent sensors before it can appear at all, and no single sensor's sighting changes a list.

### Why join, and what it changes

The lists are free and public. Anyone can use them, member or not. Joining does not unlock a better list.

What joining does change:

- Your sensor's sightings become one of the votes that confirm an entry. More sensors, faster and more accurate lists.
- The Network tab tells you which entries your sensor also saw, and which ones it helped confirm. You can see the effect of your own sensor.

Joining does not give you a private list or an early copy. Members get the same files as everyone else.

## Public network figures

The hub can publish one more public file, `network.json`, next to the lists on the feed site. The project site reads it to show how the network is doing. Anyone can download it. It is CC0, like the lists, and the same rules apply: no access log, no cookies, no query string. The design and the exact schema are in [M34](design/m34.md).

| Section | What it says |
| --- | --- |
| Nodes | Members, nodes that sent a batch last week, and countries shown by at least three members |
| Bootstrap | How many eligible nodes consensus needs (`HUB_MIN_NODES`) and how many are still missing, counted once a week once that week's late batches are in |
| Outcomes | Targets confirmed, reported and taken down per day over 90 days, reports and abuse.ch submissions sent in 30 days, the median time to takedown. Exact only when the hub runs the production consensus thresholds; otherwise weekly and rounded to tens (totals over the last four complete weeks), or nothing at all when a confirmation could rest on fewer than three nodes |
| Activity | Attacking addresses per day and how many logged in, ran commands, downloaded or sent exploits; download links, files and command servers seen; the most targeted services, the most frequent tags and malware families over 30 days |

How the file protects members:

- **Nothing per node.** No node id, fingerprint, pseudonym, address, reputation or tier.
- **Days only, and late.** Outcomes stop two days back. Activity stops four days back, when no batch for that day can arrive any more. A day is counted once and never recounted, so a node that joins or leaves cannot change a published figure.
- **Rounded.** Activity counts have two significant figures and are never finer than tens. Lists give shares, not counts.
- **Only eligible nodes count.** A node counts only once it is eligible for consensus (old enough, active enough, good reputation). Freshly enrolled nodes cannot unlock finer figures or test what another node saw.
- **Coarse while the network is small.** A day with fewer than three eligible nodes is never shown alone: its week is one average of attacking addresses, logins and commands, with one significant figure, and the smaller figures (downloads, exploits, links, files, command servers) stay empty. A single node's day off or exact volume does not show. A service, tag or family needs enough support, over several weeks, before it is named; a CVE tag needs two nodes.
- **Countries.** A member country appears only when at least three members chose to show it.

The activity figures describe attackers, not members. They show the traffic the network received, never where a sensor is or who runs it. With very few nodes, the list of services also shows which sensors those nodes run.

## How consensus protects against poisoning

Poisoning means that someone sends false sightings to get an innocent address or site listed. The network makes this expensive. A single node can never publish anything.

A value becomes a **confirmed target** only when all of these hold. The numbers below are the defaults. The hub operator can change them, and the live values are published at `https://suckerpot-hub.selfhostr.io/v1/info`.

1. **Enough nodes.** At least 5 eligible nodes saw it.
2. **Enough weight.** The reputation of those nodes adds up to at least 3.0. A node counts at most 1.0. A new node starts at 0.6, so five new nodes make exactly 3.0.
3. **Enough days.** The sightings come from at least two different days, or from 10 nodes.
4. **No single cohort.** No single enrolment week supplies more than half of the nodes. A farm that signs up in one go cannot confirm alone.
5. **Corroboration for addresses.** An address seen by 5 to 9 nodes also needs a known-bad signal from the hub's optional lookup sources (AbuseIPDB or GreyNoise, if the operator has keys), or else 10 nodes. A hub without lookup keys always needs 10. Links, domains and command domains always need 10 nodes.
6. **Dropper for command servers.** A command server counts only with a file that at least two eligible nodes fetched, and with at least five of its own nodes that fetched the same file.
7. **Never-list.** Public resolvers, large CDN and SaaS domains, update servers, package registries, reserved ranges and the operator's own entries never confirm.

By default, an **eligible node** must:

- be at least 14 days old;
- have sent data on at least 7 of the last 14 days (an empty batch does not count);
- have a reputation of at least 0.3;
- not be suspended.

### Reputation

Each node has a hidden reputation number. It rises a little when its sightings confirm a target, and more when a confirmed target is taken down. It falls when a sighting is disputed, and when a node sends a large volume that nobody else ever sees. Below 0.2 a node is soft-suspended. Its batches are accepted and then ignored, and it is not told. The number itself is never sent. Members only see `new`, `good` or `low`.

### Published values only change with consensus

The first and last day, the services, the activity, the tags and the families of a listed target change only when at least five eligible nodes support the change. One sighting from one node can never change what members see about a listed target. This stops an attacker from using a listed address to test whether one particular address is a sensor.

### Reports

Scans and connections alone are never reportable. The hub reports only:

- addresses with a severe activity (a login that worked, a command, a download or an exploit) seen by enough nodes, or with 100 or more login attempts from enough nodes;
- links and files that at least two nodes fetched;
- command servers that are confirmed.

Reports are grouped: at most one report per abuse desk and kind in a week. In the first release an operator reviews each report before it goes out. Command-server reports are never sent automatically. See `hub/README.md`.

### What consensus does not stop

A patient operator with at least five aged, well-behaved nodes can get a false target through. The reputation rules slow this down, and human review of reports is the last barrier. Consensus is a strong filter, not a proof.

## Participants and verifiers

There are two ways to join. Both mean the same thing for the data that is shared.

- **Full install.** You join from the dashboard, as described in [How to join](#how-to-join).
- **Participant install.** You run `./scripts/install.sh --participant`, which is the consent, and the node joins by itself. There is no dashboard. See [Join the network in three commands](participate.md).

### The no-VPN trade-off

A participant can run without a VPN. The node then reaches the hub through `hubproxy`, a small allow-list proxy that accepts connections to the hub host only. The cost is that the hub and the Cloudflare tunnel in front of it see the participant's own address when it connects. The hub application does not store it, but the reverse proxy and Cloudflare can log it. This is stated in the consent text and in `./scripts/status.sh`. A VPN can be added at any time with `./scripts/participant.sh vpn <file>`. Without a VPN the collector and enrichment are off, so the node reports links but never downloads anything.

The hub and feeds host names (`suckerpot-hub.selfhostr.io`, `suckerpot-feeds.selfhostr.io`) contain the product name. Anyone who sees a node's DNS queries or the TLS server name (SNI) of its connections, such as the participant's internet provider without a VPN or the VPN provider with one, can tell that the machine runs SuckerPot. Attackers who only reach the sensors cannot see this traffic.

### The early reveal of a link

Normally a download link is shared as a hash. When at least two nodes report the same link, the node reveals the clear link to the hub so that a verifier can fetch it. The clear link is kept apart from the blinded target. This adds a residual risk: a seized hub would show the links revealed for verification. Nodes keep a record of what they revealed (`./scripts/status.sh`).

### Verifier nodes

A verifier is a node that has a VPN and the collector, and that the hub operator has granted the `verifier` role. It fetches a revealed link through its VPN and sends back an attestation: sha256, size, file type and family. An attestation never counts as a sighting. A link becomes eligible for URLhaus only when at least two eligible nodes reported it and a verifier attested malware-like content. The role is opt-in on the node (`--verifier`) and granted by the operator, who can revoke it at any time. A wrong or hostile verifier is the main new risk. The operator's controls are in `hub/README.md`.

## How to join

Before you start, make sure these hold:

- `NETWORK_HUB_URL` and `NETWORK_HUB_KEY` are set in `.env`. Each release ships the public hub address and key in `config/network-defaults.env`, so you do not need to set them. A value in `.env` always wins.
- `SETTINGS_ENCRYPTION_KEY` is set. The node key is stored encrypted, and without this key the network refuses to store it.
- Your own address is confirmed in Settings, Reporting.

Then:

1. On the host, run `just set NETWORK_ENABLED=true`. It writes `.env` and restarts `ingest` and `api` so they read it. Only if you run your own hub, set its address and key the same way: `just set NETWORK_HUB_URL=https://hub.example.org NETWORK_HUB_KEY=<key>`. A full install also needs a working VPN, because every call to the hub goes through it.
2. Open **Settings, Network** and read the page. It lists what is shared and what is never shared.
3. Press **Join the network**. The dialog asks for:
   - the five items, shown for you to confirm;
   - an optional pseudonym. Do not use a name that you use anywhere else;
   - an optional country. It is never detected for you. It is shown only if you tick "Show my country" and at least three members share it;
   - your dashboard password again.
4. The sensor creates its key and solves a proof-of-work puzzle. This can take a few minutes on a small machine. It runs at low priority, so ingest keeps working. The hub can raise the puzzle's price when many systems sign up at once. While the hub is closed or the puzzle is too hard, the page says that enrolment is waiting, and the sensor retries by itself.
5. Your sensor is now a member. Its standing shows `new`. It sends its first batch after the next day ends, plus a random wait of 2 to 20 hours. By default, your sensor counts toward confirmations after 14 days of regular batches. The standing then changes to `good`.

### Pseudonyms

| Rule | Detail |
| --- | --- |
| Length | 3 to 24 characters |
| Characters | Letters, digits, space, `_`, `.` and `-`. Starts and ends with a letter or digit |
| Forbidden | `://`, `@`, four digits in a row, reserved words (for example `admin`, `hub`, `network`, `node`, `official`) and the names of this project |
| Owner check | The identity check refuses a name that contains your own names or domains |
| Changes | At most one change per 7 days, at the hub |

Empty means the network shows you as `Node` followed by your fingerprint, for example `Node 3f9a1c07`.

## How to leave

Open **Settings, Network** and press **Leave the network**. The dialog says what will be deleted, and asks for your password again. Then:

1. The worker asks the hub to delete your node. The hub deletes the node record and everything linked to it: its observations, its links to targets, its takedown votes, its weekly statistics and its request nonces.
2. Your system deletes its local key, its membership record, the list of targets it kept and its history of batches, including the exact JSON you could read.
3. The Network pages show you as not a member.

If the hub cannot be reached, the worker retries each cycle for up to seven days. After that it deletes everything locally and records `leave_unconfirmed`. The hub removes a node that stays silent for 30 days, so nothing stays active.

A leave is final. To remove the installer's consent record from `.env` as well, run `just set NETWORK_CONSENT=` (an empty value is the only value `just set` accepts for this key).

Two things are not deleted, and you should know why:

- **Published figures.** Totals that include your help stay. They are sums over many systems and carry no link to your node.
- **Hub backups.** The hub keeps daily database dumps for seven days. A deleted node can still be in an older dump until that dump is rotated out. See `hub/README.md`.

## The Network pages

The pages are in the **Defend** space. The **Network** entry has two tabs: **Overview** (`/network`) and **Members** (`/network/members`). Settings has a **Network** tab too.

### Overview

- **Not a member.** The page shows the join card and the explanation: what the network does, what is shared, what is never shared and the one residual risk. It shows no network figures, and it does not ask the hub for anything.
- **A member.** The first line says what the network did in the last 30 days, and what your sensor helped confirm. Under it:
  - a row of figures (active members this week, confirmed, reported, taken down, median time to takedown);
  - a weekly chart of confirmed, reported and taken-down targets;
  - a list of recently taken down targets, filtered in the URL by state, kind and "mine";
  - the **Your node** card: fingerprint, pseudonym (you can edit it), country, date you joined, eligibility, standing, last batch, and **See exactly what was sent**, which shows the stored JSON of your last batch with a copy button;
  - the **Leave the network** button.

### Members

A list of members with their pseudonym (or node number), country flag or a dash, date of joining, seven dots for the active days of last week, and a tier from 0 to 4. The tier is a count range, not a score. The list is sorted by pseudonym. There is no ranking by activity. The country filter is in the URL.

### Settings, Network

The same join and leave controls as on the Overview, with the node card. The "What is shared" and "What is never shared" lists are always here.

### Setup checklist

The setup checklist has a Network item. It is off when this system is not a member, green when it is a member and sent a batch in the last two days, and a warning with the reason when batches are waiting. The first-run setup has an optional Network step after Alerts. Its own "Skip for now" moves on and shares nothing. When `NETWORK_ENABLED` is false and no hub is configured, the step only says that the network is off.

## Takedown checks

The network can follow what happens after a report. Members check their own targets locally, and the hub counts the answers. A target is taken down after at least two nodes say `down` on three different days, with no `up` on the last of them.

Two parts exist, and only one is active.

- **Local takedown tracking works.** In a full install with a VPN, your own system re-checks the targets in your reports (M27) and shows their state in the dashboard.
- **Network-wide confirmation is not active yet.** Nodes do not send their re-check results to the hub yet. Until they do:
  - every re-check a node would share answers `unknown`;
  - the node sends a re-check only for `up` or `down`, so it sends nothing for this box;
  - no target moves to `taken_down` because of a member.

The box stays in the join form so that the consent list does not change later. Ticking it now sends nothing.

## Threat model

This section answers one question for each party: what can they learn, and what can they do? The full analysis is in [M29, section 3](design/m29.md#3-threat-model).

### Who we worry about

| Party | What they have |
| --- | --- |
| **A1. Attacker** | Source addresses and download links they control. They know which addresses they hit and when. They can be a member. |
| **A2. Malicious member or a farm of fake members** | Many enrolled systems and forged sightings. |
| **A3. Curious hub operator** | The hub database and the hub's traffic. |
| **A4. Hub seized or compromised** | A full copy of the database at one moment. |
| **A5. Network observer** | Sees traffic between your system and the VPN, and between the VPN and the hub. |
| **A6. Abuse desk** | Receives a report, and may pass it on to the customer who runs the address. |
| **A7. Fake hub** | Tries to impersonate the hub to your system. |

### What a malicious member can learn

| Can learn | Cannot learn |
| --- | --- |
| Public figures, the target list and their states | Any other node's batches |
| Pseudonyms, fingerprints, countries that members chose to show, and a member's tier | Which address belongs to which member. A fingerprint is a hash of a public key, not an address |
| Whether an address they probed is listed, once it is confirmed | Which member saw an attacker, or when, at a finer level than a day |
| Whether their own sightings contributed to a listed target (they know their own data) | The sightings of a member they probed |

A member can send many forged sightings. They are weighted by reputation, age, enrolment week and corroboration, so a few members cannot make a target. A large patient farm can. The hub can then refuse, report only with human review, or dispute the target.

### What the hub can and cannot learn

The hub is run by the project maintainers and is reached through a Cloudflare tunnel. That has consequences.

| Who | What they see |
| --- | --- |
| Cloudflare | The source address of every request, the hub host name, and the size and timing of requests. Cloudflare ends the TLS connection, so it can also read the content of the requests. The signatures protect them from change, not from being read. |
| The hub's reverse proxy and the hub operator | The same source address, in the proxy's logs if logging is on. The hub application itself keeps no client address in its code or tables. |
| The hub operator, from stored data | Per node: public key, pseudonym, country (if shown), enrolment day, last active day, reputation, standing. For 14 days, the addresses, services and activity each node submitted, by day. |

Without a VPN, the source address is the node's own public address. With a VPN it is the VPN exit address. In both cases it is visible to Cloudflare and to the hub's proxy, so it cannot be called hidden.

What the hub cannot learn from a batch: exact times, ports, usernames, passwords, commands, and the clear value of a link that is not confirmed (links are blinded).

A hub operator can also link a node key to its sensors without any log. The operator sends probe traffic from distinctive source addresses to a sensor address, then watches which node key reports those addresses the next day. The design does not prevent this.

A hub operator who turns on logging could also link a VPN exit or a home address to a pseudonym. The design accepts these risks for version 1.

### What a hub compromise or seizure gives away

- The node public keys, pseudonyms and enrolment days of all members.
- Fourteen days of observations by node, at the day level.
- Blinded links. A link with a random token is hard to guess. A guessable link can be checked against a list of candidates, because the hash is fast and not salted. This is a known limit of protocol version 1 ([network-protocol.md](network-protocol.md#blinding)).
- The report texts and their recipients.

It does not give away the node keys' private halves, which never leave the nodes, or the hub's signing key, which is kept in a separate secret file. The hub's signing key is the one key an attacker must not get. If it leaks, see `hub/README.md`.

### What a network observer can learn

- That your system talks to the VPN, and how much.
- Requests to the hub are padded to a multiple of 4 KiB, so their size says little. The timing of one daily batch is visible.
- Nothing about the content, as long as the observer is not Cloudflare. TLS protects the path up to Cloudflare, and the hub is behind Cloudflare's tunnel.

### What an attacker can learn about your sensors

An attacker that probes many addresses can learn that a set of addresses runs a SuckerPot sensor. Many probe addresses over weeks make this more likely. The attacker cannot learn which member runs them. This risk exists because your sensors answer connections, and it is the same with or without the network. The Overview says so before you join.

### What the community lists reveal

The lists are public, so they are visible to everyone, attackers included.

- **Member data:** none. Entries carry no node data. Every attribute that is published (services, tags, families, dates) needs at least five nodes behind it. One node's sighting of an address changes nothing public, not even its expiry.
- **Timing:** the lists are regenerated on a fixed hourly schedule, and new entries wait 6 hours after confirmation. The publication time says nothing about one member.
- **Downloads:** the feed site is behind Cloudflare, which sees who fetches the lists. The feed site itself keeps no access log and sets no cookies.
- **Poisoning:** an attacker who controls many sensors could try to list a third party. Only the hub's own confirmed targets can enter a list, after stricter rules than reports. A text typed into a honeypot command never lists an address by itself. The hub excludes a fixed list of public resolvers and large CDN, cloud and software-hosting names (`hub/hub/data/never.yaml`), the address ranges of three large CDNs, and Tor exit relays (`hub/hub/data/ranges.yaml`). Other shared hosting and ordinary VPS providers are not excluded, because that is where malware lives.
- **Forgery:** each file is signed with a feed key that is separate from the hub's key. Your node checks the signature, the serial and the expiry before it stores anything.

### What the public figures reveal

`network.json` follows the same idea as the lists: nothing in it names a member. Figures are network totals from eligible nodes only, at day level, published days later, rounded, and coarse below three nodes ([Public network figures](#public-network-figures)). Someone who sends a lot of traffic (several hundred addresses a day for a week) to an address they suspect is a sensor could look for a jump in the weekly average. That only tells them what they could already learn by probing the address, that it runs a sensor, not who runs it.

### What is not protected

- The consensus does not yet resist a determined attacker. Identity is free, so one person can create several nodes. Today the network has few nodes, and the hub operator is the single root of trust.
- A sensor that is reachable from the internet is already visible to every attacker who scans it.
- The hub operator can see the attacker addresses that nodes submit, and the address each request comes from. These addresses belong to the attackers, not to members.
- The system's own logs (SSH, the host firewall, the Docker daemon on the host) are outside this design. Keep them private.

## Where to go next

| Read | When |
| --- | --- |
| [Network protocol](network-protocol.md) | You build a client or want to check a signature |
| [Join the network in three commands](participate.md) | You want to help the network with a small install |
| `hub/README.md` | You run a hub |
| [Configuration](configuration.md#suckerpot-network-m29) | You want every `NETWORK_*` variable |
| [M29 design](design/m29.md) | You want the full analysis and the decisions |
