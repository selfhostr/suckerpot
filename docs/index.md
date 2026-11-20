# SuckerPot

**See attacks, block them, and get them cleaned up at the source.**

SuckerPot is a self-hosted honeypot. Fake services (sensors) take the attacks, and one dashboard tells each attack as a short story you can click through. From what it sees, SuckerPot builds blocklists for your firewall, writes abuse reports to the networks that host the attacking machines, and, if you choose, shares what it saw with other nodes. Everything runs in Docker Compose on one host. It is free, under the MIT licence, with no paid edition.

```{warning}
SuckerPot is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Read [Getting started](getting-started.md) before you install it.
```

## Four parts, one product

| Part | What it does | Start with |
| --- | --- | --- |
| **Observe** | Sensors take attacks. One dashboard tells each attack as a short story: who, what they tried, what they wanted. | [What SuckerPot does](features.md), [The dashboard](ui.md), [Sensors](sensors/index.md) |
| **Defend** | Scored blocklists, firewall exports, Sigma and Suricata rules, and a view of your own exposure. | [Defend](defend.md) |
| **Report** | Abuse reports to the abuse contact of the attacking network, sent by hand, with one click or automatically. Replies and takedowns are tracked. The goal is to get compromised machines cleaned up. | [Reporting attacks](reporting.md) |
| **Share** | The opt-in network: independent nodes confirm targets together, publish a free community blocklist, send network-level reports, and feed a public observatory. | [The SuckerPot network](network.md) |

## The one rule

SuckerPot never probes an attacker. It does not scan, counter-scan or hack back, and it never opens a connection to an attacking host to probe or answer it. The optional collector is the one exception, and it is off by default: it downloads, once and through the VPN only, the file an attacker told the honeypot to fetch, as the victim would. Attacker input is recorded, never executed.

A report is a mail to the abuse contact that the attacking network publishes in RDAP. Reporting is off by default, and you choose how reports leave: by hand, with one click, or automatically. SuckerPot never reports to AbuseIPDB; it only reads it. The details are in [Reporting attacks](reporting.md#the-rule-report-never-touch).

## Start here

- **Install it.** [Install SuckerPot](install.md) runs one command and starts the stack.
- **Take the first steps.** [Getting started](getting-started.md) covers the warnings, the requirements and the first login.
- **Only want to help the network?** [Join the network](participate.md) installs sensors without a dashboard.

## Words used in these docs

| Word | Meaning |
| --- | --- |
| **Sensor** | One fake service, such as the SSH or the web sensor. SuckerPot has twelve. |
| **Full install** | SuckerPot with its dashboard, installed with `./scripts/install.sh`. |
| **Participant install** | Sensors and a network node without a dashboard, installed with `./scripts/install.sh --participant`. Choosing it is the choice to join the network. |
| **Node** | One SuckerPot install, full or participant, that takes part in the network. The dashboard lists nodes under Network, Members. |
| **Hub** | The server of the network. It takes the daily batches from nodes, confirms targets, sends network-level abuse reports and publishes the community lists. |
| **Abuse report** | A mail to the abuse contact of the network that hosts an attacking machine. Your node can send one, and so can the hub. |
| **Target** | An address, link or domain that the network confirmed as hostile. |

## Defaults

- The network is off (`NETWORK_ENABLED=false`) until you join. A participant install joins, because that is its purpose.
- Abuse reports are off (`ABUSE_REPORTS_ENABLED=false`), and so is sending them (mode `off`).
- Automatic updates are on in a participant install and off in a full install (see [Updates](updates.md#automatic-updates)).
- Alerts, feeds, payload collection and takedown tracking are off until you turn them on.

SuckerPot is made by selfhostr, an organisation that builds self-hosted tools. Technical names (packages, volumes, environment variables) use the `suckerpot` prefix. The current version and every change are in the [changelog](https://github.com/selfhostr/suckerpot/blob/main/CHANGELOG.md).

```{toctree}
:maxdepth: 1
:caption: Get started

getting-started
install
vps
participate
deployment
updates
```

```{toctree}
:maxdepth: 2
:caption: Observe

features
ui
sensors/index
trap-packs
event-schema
retention
```

```{toctree}
:maxdepth: 1
:caption: Defend

defend
```

```{toctree}
:maxdepth: 1
:caption: Report

reporting
replies
takedowns
```

```{toctree}
:maxdepth: 1
:caption: Share

network
feeds
network-protocol
```

```{toctree}
:maxdepth: 1
:caption: Reference

configuration
api
api-keys
ARCHITECTURE
SECURITY
```

```{toctree}
:maxdepth: 1
:caption: Development

roadmap
dev/development
demo-data
dev/roadmap-history
dev/progress
dev/design/index
```
