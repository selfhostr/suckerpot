# SuckerPot

SuckerPot is a self-hosted honeypot with one readable dashboard. A few fake services (sensors) take the attacks. Each attack becomes an event. The events are enriched, tagged and stored, and the dashboard tells what happened as a short story you can click through. Everything runs in Docker Compose on one host.

Most honeypot stacks are a pile of separate tools and dashboards that are hard to read. SuckerPot goes the other way: few sensors, built well, and one dashboard that is the product. Each page opens with a plain-English finding, every IP, country, tag or URL is a link to a filtered view, and every filter lives in the URL so you can share it.

```{warning}
SuckerPot is built to be attacked. Deploy it only on a dedicated, isolated machine that you are ready to lose. Read [Getting started](getting-started.md) before you install it.
```

Start here:

- **Install it.** [Install SuckerPot](install.md) runs one command and starts the stack.
- **Take the first steps.** [Getting started](getting-started.md) covers the warnings, the requirements and the first login.
- **Understand the main idea.** [What SuckerPot does](features.md) lists the sensors, the dashboard and the analysis features. [The SuckerPot network](network.md) explains the opt-in sharing.

SuckerPot is made by selfhostr, an organisation that builds self-hosted tools. Technical names (packages, volumes, environment variables) use the `suckerpot` prefix. The current version and every change are in the [changelog](https://github.com/selfhostr/suckerpot/blob/main/CHANGELOG.md). The new analysis features are off until you turn them on.

```{toctree}
:maxdepth: 1
:caption: Get started

getting-started
install
participate
vps
deployment
```

```{toctree}
:maxdepth: 1
:caption: Using it

features
ui
defend
replies
takedowns
network
feeds
api-keys
demo-data
```

```{toctree}
:maxdepth: 2
:caption: Reference

sensors/index
configuration
ARCHITECTURE
event-schema
api
retention
network-protocol
```

```{toctree}
:maxdepth: 1
:caption: Security

SECURITY
```

```{toctree}
:maxdepth: 1
:caption: Operations

updates
```

```{toctree}
:maxdepth: 1
:caption: Development

development
```
