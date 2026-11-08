# Contributing

Issues and pull requests are welcome on [GitHub](https://github.com/selfhostr/suckerpot). For the architecture and the project rules, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/development.md](docs/development.md). The sensors never execute attacker input, the repository is public (no secrets, real addresses or captured data), and container hardening is not weakened without a stated reason.

## Setup

Everything runs in containers. The host only needs Docker with the compose plugin and [`just`](https://github.com/casey/just).

```bash
git clone https://github.com/selfhostr/suckerpot.git && cd suckerpot
cp .env.example .env          # replace every change-me (openssl rand -base64 32)
scripts/install-hooks.sh      # gitleaks pre-commit hook
just up                       # build and start the stack
just demo                     # synthetic attack data
```

## Checks

A change must pass these (CI runs the same):

```bash
just check        # lint, typecheck, unit tests and web build
just --list       # integration tests and more
```

Add tests for any behaviour you change. Sensor tests use a real client where possible.

## Pull requests

- Keep them focused, one change each, and update the docs when behaviour or configuration changes.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), for example `feat(ssh): ...` or `fix(web): ...`.
- Everything is in English: code, comments, docs, commit messages and every UI string.
- Sensors never execute attacker input. No `subprocess`, `os.system`, `eval` or `exec` in sensor code.
- UI work uses the design system in [web/DESIGN.md](web/DESIGN.md). Do not add one-off styles.

## Public repo hygiene

The repository is public and history is forever. Never commit:

- `.env`, API keys, tokens, passwords or password hashes;
- captured data: attacker IPs, credentials, sessions, payloads or database dumps;
- GeoLite2 `.mmdb` files or SSH host keys;
- real hostnames, IP addresses or details of your own network.

In examples, tests and docs use only the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.

To report a vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
