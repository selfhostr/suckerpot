# Roadmap

This page says what SuckerPot works on now, what comes next and what may come later. Plans change. The [changelog](https://github.com/selfhostr/suckerpot/blob/main/CHANGELOG.md) says what shipped. The full history of past milestones is in [Roadmap history](dev/roadmap-history.md).

## Now: v0.12

- **One product.** The documentation describes SuckerPot as one product in four parts: Observe, Defend, Report and Share (see [What SuckerPot does](features.md)), with one reporting page and one vocabulary.
- **Groundwork for trap packs.** A trap pack is a small, reviewed set of fake responses and detection rules for one new vulnerability. Work starts on its format and on how a pack is reviewed and shipped.
- **Security review of the web and Synology sensors.** Both run today and are still under review (see [Sensors](sensors/index.md)).

## Next

- **Trap packs for new CVEs.** When a new vulnerability is exploited in the wild, a trap pack is released and deployed to every node through the normal signed updates. The network figures on the public observatory then show how many nodes saw it being exploited.
- **"Your contribution".** A view for participants: what your node helped confirm, report and get taken down.
- **Zero-touch participant installs.** Join the network with one command and no questions on a fresh machine, with safe defaults.

## Later

- Idempotent replay after a crash, so a batch replayed between the database commit and the acknowledgement is never counted twice.
- A per-network daily cap on new campaigns, and campaigns for credential-only floods.
- Provider keys that the API can store but never read back.
- More realistic shells and logon screens, within the rule that attacker input is never executed.
