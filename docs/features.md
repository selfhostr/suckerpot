# What SuckerPot does

By the end of this page you will know what each part of SuckerPot does and which page covers it. SuckerPot has four parts: **Observe**, **Defend**, **Report** and **Share**. Everything here is off or optional unless the text says otherwise.

```{warning}
SuckerPot is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Attacker input is never executed. SuckerPot never touches an attacker: no scan, no counter-scan, no hack back, no connection to an attacking host. Abuse reports are mails to the abuse contact that the attacking network publishes, off by default, and sent the way you choose (see [Reporting attacks](reporting.md)).
```

## Observe

Sensors take the attacks. One dashboard tells each attack as a short story.

### Sensors

Twelve sensors in four families. Six are on by default (SSH, Telnet, Web, Redis, Docker and ADB); `--sensors all` turns on all twelve. Each family has its own colour in the dashboard, and each sensor has its own icon and name. The full list is on the [Sensors](sensors/index.md) page.

| Family | Sensors | What they fake |
| --- | --- | --- |
| Remote shells | SSH, Telnet, ADB | An OpenSSH 9.6 server, a BusyBox login, an Android TV box with `adbd` and no authentication |
| Web and APIs | Web, Docker, Synology | Apache 2.4 with unpatched PHP 8.3, WordPress and phpMyAdmin; an exposed Docker Engine API; a Synology NAS with unpatched DSM 7.2.1 (login page and Web API) |
| Databases | Redis, MySQL, MSSQL | Redis 7.2 with no password; MySQL 8.0 and SQL Server with weak logins |
| Windows and VoIP | RDP, SMB, SIP | A Windows Server with NLA; a Windows file service (observation only); an Asterisk-style PBX on UDP and TCP |

Each sensor records what the attacker does and never runs it. A few examples:

- **SSH.** The fingerprint of OpenSSH 9.6 on Ubuntu, a configurable set of weak logins, and a pure-emulation shell over an in-memory fake filesystem. It records every login attempt and command, records `wget` / `curl` / `tftp` downloads as URLs only, and keeps timed terminal I/O for replay (see [the SSH sensor page](sensors/ssh.md)).
- **Web.** A byte-identical fake Apache 2.4.58 with PHP 8.3 (unpatched mod_php), WordPress and phpMyAdmin pages, and detection of PHP2Shell (upload-progress) exploit attempts, tagged `php2shell`.
- **RDP.** A Windows Server look-alike with NLA. It records NTLM logins, checks decoy passwords, identifies the client tool, and can optionally capture cleartext passwords from clients that skip NLA (owner opt-in).
- **SIP.** Answers are capped so that the sensor cannot be used to amplify a flood.

### The dashboard

Pages are grouped in three spaces plus Settings, so you always know where you are:

- **Observe:** Today, Live (a flat world map of the last 15 minutes) and Attacks (sessions, attackers and networks).
- **Understand:** Campaigns and Techniques; Tools (scripts, malware and infrastructure); Trends (activity and patterns).
- **Defend:** Protection (blocklists and detections), Exposure (your exposure and CVE watch), Alerts, Abuse reports (reports and results) and Network (overview and members). The pages of the Report and Share parts live here too.
- **Settings:** sensor health, API keys, quotas, retention, storage, users, reporting and the network.

Each page opens with a plain-English finding. Every IP, country, tag or URL links to a filtered view, and every filter lives in the URL. A session page has a terminal replay at real speed. `Ctrl+K` opens a search box that finds an IP, hash, domain, CVE or campaign. Security words have a glossary tooltip. Known research scanners are labelled and hidden from lists unless you ask for them. Dark and light, desktop and mobile. An owner login plus optional administrator and read-only viewer accounts (argon2, CSRF protection, lockout, audit log) guard it, and a screenshot mode (`?mask=1`) masks addresses. See [The dashboard](ui.md).

### Understanding attacks

- **Enrichment and tags.** GeoIP and ASN from DB-IP Lite (no key needed) or MaxMind GeoLite2, optional AbuseIPDB and GreyNoise Community reputation with a 24 h cache and enforced daily quotas (every key is optional, see [Provider API keys](api-keys.md)), and a declarative YAML rules engine (no regular expressions) for tags such as `recon`, `mirai`, `crypto-miner`, `malware-drop` and `php2shell`.
- **Campaigns.** Sessions that share a script, a payload host, a file hash, a malware family, an exploit or a credential list are grouped into one campaign, with a plain-English story. A campaign needs at least two sources, and research scanners are never grouped. Campaigns that turn out to come from the same addresses are merged into the oldest one.
- **Techniques.** Each session is labelled with the MITRE ATT&CK techniques it used, shown as a heatmap per day.
- **Scripts.** The command sequences that attackers type are fingerprinted into a library, each with a plain-English explanation from a rules base.
- **Payloads.** Optional, off by default: the collector fetches a download link through the VPN only, and the analyzer reads the file statically. Nothing is ever run.
- **Today.** A home page that says what changed in the last 24 hours.
- **Alerts and reports.** Discord, Microsoft Teams and e-mail alerts for new campaigns, new download hosts, malware drops and watched CVEs. Every rule is off until you switch it on. A weekly report has a one-page printable view.
- **Retention and backups.** Raw events kept 90 days, aggregates forever, compression after 7 days, a disk guard, and `just backup` / `just restore` (see [Data retention](retention.md)).

## Defend

Turn what the sensors saw into protection for your own machines.

- **Scored blocklists** with a reason for every point, and overrides.
- **Exports** for OPNsense and pfSense aliases, plain text and CSV, and an opt-in token feed for firewalls.
- **Sigma and Suricata rules**, marked "review before deploying".
- **Your exposure** compares your own service inventory with what was recorded.

See [Defend](defend.md).

## Report

Tell the network that hosts an attacking machine what it did, so the machine gets cleaned up.

- **Abuse reports** to the abuse contact of the attacking network, found through RDAP behind the VPN. Off by default. You send them by hand, with one click, or automatically, with pacing rules that keep your mailbox from looking like spam.
- **An identity guard** that blocks any report that could point back to you. The wording around the facts is yours and optional.
- **Replies** read from your report mailbox and matched to their reports.
- **Takedown tracking**: is the file still served, is the address still attacking, how long did it take.
- **CERT exports** in STIX 2.1 and MISP, and password-protected sample bundles.

See [Reporting attacks](reporting.md), [Replies to reports](replies.md) and [Track takedowns](takedowns.md).

## Share

The SuckerPot network is opt-in and off until you join. Nodes share aggregate attacker data, without identities.

- **Consensus.** A target is confirmed only when several independent, aged nodes agree. A single node can never publish anything.
- **Network reports.** The hub sends one strong abuse report per confirmed target instead of many weak ones, and the nodes leave those targets to it.
- **Community blocklist.** Free, signed lists for any firewall, built from the same consensus.
- **Public observatory.** Anonymised figures about the network on the project site.

The network is an experimental preview with very few nodes today. See [The SuckerPot network](network.md), [Community blocklist feeds](feeds.md) and [Join the network](participate.md).

## Hardened by default

Non-root, read-only containers with all capabilities dropped and `no-new-privileges`; isolated networks with an internal backend; one Redis ACL user per sensor, limited to `XADD` on its own stream; least-privilege database roles; no outbound route for the API; and an nftables [host firewall template](../scripts/host/firewall.nft). See [Security](SECURITY.md).

## Live demo

See every page with synthetic data in the [live demo](https://suckerpot.selfhostr.io/demo/).
