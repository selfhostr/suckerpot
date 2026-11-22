<div align="center">
<a href="https://suckerpot.selfhostr.io"><img src=".github/assets/banner.svg" alt="suckerpot: a honeypot you can actually read" width="100%"></a>

**A self-hosted honeypot with one dashboard that tells each attack as a short story.**

[Site](https://suckerpot.selfhostr.io) · [Docs](https://suckerpot.selfhostr.io/docs/) · [Demo](https://suckerpot.selfhostr.io/demo/) · [Changelog](CHANGELOG.md)

[![CI](https://img.shields.io/github/actions/workflow/status/selfhostr/suckerpot/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/selfhostr/suckerpot/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

## Overview

**See attacks, block them, and get them cleaned up at the source.**

`suckerpot` runs fake services that take attacks and records what the attacker does, without ever running it. It is one product in four parts:

- **Observe.** Sensors take the attacks, and one dashboard tells each attack as a short story.
- **Defend.** Scored blocklists, firewall exports, Sigma and Suricata rules, and a view of your own exposure.
- **Report.** Abuse reports to the abuse contact of the attacking network, sent by hand, with one click or automatically, with replies and takedowns tracked. The goal: get compromised machines cleaned up.
- **Share.** An opt-in network of independent nodes that confirm targets together, publish a community blocklist, report at network level and feed a public observatory.

`suckerpot` never probes an attacker: no scan, no counter-scan, no hack back, no connection to an attacking host. The optional collector is the one exception, and it is off by default: it downloads, once and through the VPN only, the file an attacker told the honeypot to fetch, as the victim would. A report is a mail to the abuse contact the network publishes; reporting is off by default and you choose how it is sent. Free, for good: MIT licence, no paid edition.

> **`suckerpot` is meant to be attacked.** Deploy it only on an isolated host or VM that you are ready to lose.

## How it compares

- [T-Pot](https://github.com/telekom-security/tpotce) bundles many honeypots with Kibana. It covers more protocols, and it is heavy: plan for 8 to 16 GB of RAM.
- [Cowrie](https://github.com/cowrie/cowrie) is an excellent SSH and Telnet honeypot. It writes logs; it is not a dashboard.
- [CrowdSec](https://www.crowdsec.net/) protects your own servers from a shared blocklist. That is a different job from watching attacks.
- `suckerpot` has a different angle: six recommended sensors by default (up to twelve), a small footprint (2 GiB of memory is the minimum, see the [install guide](docs/install.md)), and one dashboard that tells each attack as a readable story, with a terminal replay for SSH and Telnet sessions.

## Quick start

```bash
git clone https://github.com/selfhostr/suckerpot.git && cd suckerpot
git switch --detach "$(git describe --tags --abbrev=0)"
./scripts/install.sh --full
```

Needs Docker with the compose plugin (the installer offers to install it from Docker's package repository), or Podman 5.4+ (experimental, see the [install guide](docs/install.md#podman-experimental)). The installer asks at most two questions, creates the secrets, starts the stack and prints the dashboard address; the six recommended sensors are on by default (`--sensors all` turns on all twelve). Back up with `just backup`. Before you expose anything, follow the [go-live checklist](https://suckerpot.selfhostr.io/docs/deployment/).

The optional SuckerPot network is an experimental preview, off unless you ask for it: very few nodes exist, its shared feed may be empty, and a participant gets nothing back yet ([details](docs/network.md)). Only want to try it? `./scripts/install.sh --participant` installs sensors without a dashboard (see [Join the network](https://suckerpot.selfhostr.io/docs/participate/)); a 1 GiB VPS works with `--lite` ([VPS guide](https://suckerpot.selfhostr.io/docs/vps/)).

## Features

- **Observe.** Twelve sensors (SSH, Telnet, ADB, Web, Docker, Synology, Redis, MySQL, MSSQL, RDP, SMB and SIP), six of them on by default. A dashboard where every IP, country, tag or URL links to a filtered view, with campaigns, MITRE ATT&CK techniques, a script library and a terminal replay for SSH and Telnet. Alerts to Discord, Microsoft Teams and e-mail, every rule off until you switch it on.
- **Defend.** Scored blocklists with a reason for every point, OPNsense and pfSense exports, Sigma and Suricata rules.
- **Report.** Abuse reports behind your VPN, an identity guard that blocks anything pointing back to you, paced automatic sending that only sends fresh evidence, reply matching and takedown tracking ([Reporting attacks](docs/reporting.md)).
- **Share.** The opt-in network, a free community blocklist and public network figures ([The network](docs/network.md)).
- **Hardened by default.** Non-root, read-only containers, isolated networks, one Redis ACL user per sensor.

Details: [What suckerpot does](docs/features.md).

## Architecture

Sensors feed Redis Streams, ingest enriches and stores the events in PostgreSQL with TimescaleDB, and a FastAPI service serves the React dashboard. Sensors are the only services published to the internet and can reach Redis and nothing else. Optional workers in ingest build and send abuse reports through the VPN only, and exchange daily batches with the network hub. See [Architecture](docs/ARCHITECTURE.md).

## Limits

- It is a honeypot: it will be scanned and attacked within minutes of going online.
- Sensors imitate services, so a patient attacker can tell they are fake.
- Alpha: before 1.0 the API, the database schema and the installer can change between minor versions.
- The web and Synology sensors are still under security review.
- Delivery from sensors to the database is at least once, so a crash can count a batch twice.
- Abuse reports only help when the network operator acts. Many never answer, and automatic sending needs a mail provider that accepts abuse reports ([details](docs/reporting.md#sending-without-getting-blocked)).

## Contributing

Issues and pull requests are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Provided "as is", without warranty of any kind.

## Support

`suckerpot` is free and has no company behind it. If it saves you time: [sponsor us on GitHub](https://github.com/sponsors/selfhostr).
