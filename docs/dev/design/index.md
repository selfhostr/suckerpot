# Design notes

These are the design documents written before the larger milestones were built. Each one records the problem, the options, the decision and the threat model at that time. They are history: where a note and the user documentation disagree, the user documentation and the code are right.

| Note | Subject |
| --- | --- |
| [M21](m21.md) | Anonymous egress, payload collection and static analysis |
| [M22](m22.md) | Anonymous abuse reporting |
| [M23](m23.md) | Upload the VPN configuration from the dashboard |
| [M24](m24.md) | Guided tour, setup checklist and tunnel controls |
| [M25](m25.md) | Sending abuse reports: a send queue, and optional SMTP |
| [M26](m26.md) | Report outcomes: did anyone answer? |
| [M27](m27.md) | Takedown tracking (and the node-side abuse.ch submission, since removed) |
| [M28](m28.md) | Installable by anyone |
| [M29](m29.md) | The SuckerPot network |
| [M30](m30.md) | Community blocklist feeds |
| [M32](m32.md) | Participant installs, verifiers and automatic updates |
| [M33](m33.md) | The network on by default (since reverted: the network is off unless you join) |
| [M34](m34.md) | Public network observatory |
| [M36](m36.md) | Useful from the first node |
| [M37](m37.md) | Trap packs for new CVEs |
| [M38](m38.md) | Better abuse reports: measuring their effect, X-ARF v4, one mail per provider per day, a form queue (approved, not implemented yet) |
| [Podman](podman.md) | Podman as a second container engine (approved, not implemented yet) |
| [Installer UX](installer-ux.md) | A shorter, clearer installer: fewer questions, a progress display, a plain mode (approved, not implemented yet) |

```{toctree}
:maxdepth: 1
:hidden:

m21
m22
m23
m24
m25
m26
m27
m28
m29
m30
m32
m33
m34
m36
m37
m38
podman
installer-ux
```
