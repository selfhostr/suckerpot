<div align="center">
<a href="https://suckerpot.selfhostr.io"><img src=".github/assets/banner.svg" alt="suckerpot: a honeypot you can actually read" width="100%"></a>

**A self-hosted honeypot with one dashboard that tells each attack as a short story.**

[Site](https://suckerpot.selfhostr.io) · [Docs](https://suckerpot.selfhostr.io/docs/) · [Demo](https://suckerpot.selfhostr.io/demo/) · [Changelog](CHANGELOG.md)

[![CI](https://img.shields.io/github/actions/workflow/status/selfhostr/suckerpot/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/selfhostr/suckerpot/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
</div>

## Overview

`suckerpot` runs fake services that take attacks and records what the attacker does, without ever running it. A single dashboard opens each page with a plain-English finding. It is passive and opt-in: no counter-scans, no hacking back, no automatic reporting. Free, for good: MIT licence, no paid edition.

> **`suckerpot` is meant to be attacked.** Deploy it only on an isolated host or VM that you are ready to lose.

## How it compares

- [T-Pot](https://github.com/telekom-security/tpotce) bundles many honeypots with Kibana. It covers more protocols, and it is heavy: plan for 8 to 16 GB of RAM.
- [Cowrie](https://github.com/cowrie/cowrie) is an excellent SSH and Telnet honeypot. It writes logs; it is not a dashboard.
- [CrowdSec](https://www.crowdsec.net/) protects your own servers from a shared blocklist. That is a different job from watching attacks.
- `suckerpot` has a different angle: six recommended sensors by default (up to twelve), a small footprint (2 GiB of memory is the minimum, see the [install guide](docs/install.md)), and one dashboard that tells each attack as a readable story, with a terminal replay for SSH and Telnet sessions.

## Quick start

```bash
git clone --depth 1 --branch v0.11.0 https://github.com/selfhostr/suckerpot.git
cd suckerpot
./scripts/install.sh
```

Needs Docker with the compose plugin. The installer creates the secrets, starts the stack and prints the dashboard address; the six recommended sensors are on by default (`--sensors all` turns on all twelve). Back up with `just backup`. Before you expose anything, follow the [go-live checklist](https://suckerpot.selfhostr.io/docs/deployment/).

The optional SuckerPot network is an experimental preview, off unless you ask for it: very few nodes exist, its shared feed may be empty, and a participant gets nothing back yet ([details](docs/network.md)). Only want to try it? `./scripts/install.sh --participant` installs sensors without a dashboard (see [Join the network](https://suckerpot.selfhostr.io/docs/participate/)); a 1 GiB VPS works with `--lite` ([VPS guide](https://suckerpot.selfhostr.io/docs/vps/)).

## Features

- **Twelve sensors.** SSH, Telnet, ADB, Web, Docker, Synology, Redis, MySQL, MSSQL, RDP, SMB and SIP.
- **Readable dashboard.** Every IP, country, tag or URL links to a filtered view, and every filter lives in the URL.
- **Enrichment and tags.** GeoIP and ASN, optional reputation lookups, and a YAML rules engine.
- **Campaigns and MITRE ATT&CK.** Techniques and a script library, each with a plain-English story.
- **Defend.** Scored blocklists, OPNsense and pfSense exports, Sigma and Suricata rules.
- **Alerts and a weekly report.** Discord, Microsoft Teams and e-mail, every rule off until you switch it on.
- **Hardened by default.** Non-root, read-only containers, isolated networks, one Redis ACL user per sensor.

Details: [What suckerpot does](docs/features.md).

## Architecture

Sensors feed Redis Streams, ingest enriches and stores the events in PostgreSQL with TimescaleDB, and a FastAPI service serves the React dashboard. Sensors are the only services published to the internet and can reach Redis and nothing else. See [Architecture](docs/ARCHITECTURE.md).

## Limits

- It is a honeypot: it will be scanned and attacked within minutes of going online.
- Sensors imitate services, so a patient attacker can tell they are fake.
- Alpha: before 1.0 the API, the database schema and the installer can change between minor versions.
- The web and Synology sensors are still under security review.
- Delivery from sensors to the database is at least once, so a crash can count a batch twice.

## Contributing

Issues and pull requests are welcome: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Provided "as is", without warranty of any kind.

## Support

`suckerpot` is free and has no company behind it. If it saves you time: [sponsor us on GitHub](https://github.com/sponsors/selfhostr).
