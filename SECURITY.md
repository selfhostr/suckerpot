# Security Policy

## Supported versions

SuckerPot is in alpha and has tagged releases. The supported version is the latest release tag (see the [releases](https://github.com/selfhostr/suckerpot/releases)); fixes land on `main` and ship in the next tag. Older tags are not patched. Before 1.0 the API, the database schema and the installer can change between minor versions.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting: on the repository, go to Security, then "Report a vulnerability". Include steps to reproduce and the impact.

## Scope

In scope, because they break the design in [docs/SECURITY.md](docs/SECURITY.md):

- Anything that lets attacker input run code in a sensor or in ingest (the fake shell must stay pure emulation).
- A way out of a sensor container, or from a sensor to anything except its own Redis stream.
- A way to read or change data through the sensors, the API or the dashboard without the intended access.
- A flaw in the API or dashboard: injection, XSS (for example through attacker-controlled strings shown in the UI), CSRF, authentication bypass, or unbounded resource use.
- A way to make the stack exhaust disk, memory or the queue from the outside despite the caps.
- A secret, private address or captured data committed to the repository.
- A fake service that reveals what it is to a client.

Not a vulnerability:

- Being scanned, brute-forced or exploited. That is the point of a honeypot.
- A fake service accepting weak credentials or looking vulnerable on purpose.
- Findings that need an operator to ignore the [deployment guide](docs/deployment.md), for example exposing the dashboard port to the internet.

## Notes

- Never commit `.env`, API keys or captured data. If you find any in the history, report it privately.
- Use the documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in reports and examples.
