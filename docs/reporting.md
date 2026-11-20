# Reporting attacks

Report is the third part of SuckerPot, after Observe and Defend. A blocklist protects your own machines. An abuse report goes further: it tells the network that hosts an attacking machine what that machine did, so that its owner can clean it up. Most attacking machines are compromised servers, routers and cameras whose owners do not know.

By the end of this page you will know what can be reported, who sends the report, how sending works, and how to send without getting your mailbox blocked.

```{note}
Reporting is off by default. Nothing is sent until you turn it on and choose how reports leave.
```

## The rule: report, never touch

SuckerPot never touches an attacker. It does not scan, counter-scan or hack back, and it never opens a connection to an attacking host to probe or answer it.

A report is a mail to the abuse contact that the attacking network publishes in RDAP, the public registry of address and domain owners. The network operator decides what to do with it. The mail says what was seen, with times and evidence, and nothing about you.

- Reporting is off by default. You choose how reports leave: by hand, assisted (one click per report) or automatic.
- SuckerPot never reports to AbuseIPDB. It only reads AbuseIPDB, as one of the optional reputation sources.
- The optional collector can download a file from a link that an attacker typed, through the VPN only, and [takedown tracking](takedowns.md) can fetch that same link again. Neither is a probe of the attacker: see [What is never contacted](takedowns.md#what-is-never-contacted).

## Two levels: your node and the network

Reports are made at two levels.

| Level | Who sends | From which mailbox | Evidence |
| --- | --- | --- | --- |
| Your node | You, or your node on your behalf | Your own anonymous mailbox, through your VPN | What your own sensors recorded |
| The network | The hub | The project's report mailbox | What many independent nodes agreed on |

Both levels follow the same rule: they report, they never touch. When your node is part of the network, it leaves to the hub the targets the hub already handled, so one network operator does not get two reports about the same machine (see [How your node defers to the network](#how-your-node-defers-to-the-network)).

## Reports from your node

The abuse worker in `ingest` builds the drafts. It is off until you set `ABUSE_REPORTS_ENABLED=true`. Every hour (`ABUSE_BUILD_INTERVAL_S`) it selects what deserves a report, looks up the abuse contact over RDAP through the VPN, and writes one draft per recipient and kind. You find the drafts at Defend > Abuse reports in the dashboard.

### What your node reports

A draft covers one of three kinds of subject.

**Attack sources.** An address that attacked your sensors. Only sessions from the last 7 days count (`ABUSE_LOOKBACK_DAYS`), and only once the address has been quiet for 30 minutes (`ABUSE_SETTLE_MIN`). An address is selected when at least one of these is true:

- it made 50 or more login attempts in that window (`ABUSE_MIN_LOGIN_ATTEMPTS`);
- it logged in and then ran commands;
- it tried to download a file;
- one of its sessions has a severe tag: `malware-drop`, `mirai`, `crypto-miner`, `php2shell`, `exploit` or any `cve-*` tag (`ABUSE_SEVERE_TAGS`).

**Payload hosts.** A host that an attacker's download command pointed to, from the same 7 days.

**Command servers.** A command-and-control address that the static analysis found in a sample with high confidence.

Some things are never selected, before any lookup is made:

- known research scanners and sessions marked benign;
- private, reserved and documentation addresses (documentation addresses only appear in demo drafts, which can never be sent);
- the never-block list (public resolvers and the entries in `BLOCKLIST_NEVER`) and every term in "Never in a report", such as your own addresses and names.

The same source is not reported again to the same recipient for 14 days (`ABUSE_RESEND_DAYS`). Every variable is in [Configuration](configuration.md#anonymous-reporting-m22).

### How your node defers to the network

When your node has joined the network, the worker drops every address and domain that the network reported, or saw taken down, in the last 30 days. The window counts from the report or takedown date, not from the last sighting. The hub has already sent one strong report about that machine, and a second, weaker one from you would only add noise for the same abuse desk.

A target that the network merely confirmed is not dropped. The hub may never report it (see [What makes an address reportable for the network](#what-makes-an-address-reportable-for-the-network)), so your own report still counts. A node that has not joined reports everything it selects.

### Set it up

1. **Turn the VPN on.** RDAP lookups and mail leave only through the [anonymous egress](deployment.md#anonymous-egress-vpn). With the tunnel down, nothing leaves.
2. **Turn the worker on.** Set `ABUSE_REPORTS_ENABLED=true` in `.env` and restart `ingest`. Reports stay locked (`no_self_address`) until the stack knows which address it protects.
3. **Fill Settings > Reporting (admin).** Add a reply contact: an alias that is not on one of your own domains. It is the only required setting. Until it is set, rendering answers `settings_incomplete`, and a report cannot be marked reviewed. The introduction, closing text, note, signature, subject template and X-ARF user agent are optional. The project ships no wording, because shipped text lives in a public repo and could be searched. Leave them empty to send only the facts: an empty part is left out, an empty subject becomes `Abuse report for <address>` and an empty X-ARF user agent becomes `Mozilla/5.0`. If you write your own, make it yours.
4. **Confirm the self terms.** The worker learns the address and names of the monitored machine from traffic (an address is stored only when two or more distinct /24 or /48 networks used it, and counts only while seen in the last 72 hours). Learned terms start inactive. Open the "Never in a report" list in Settings > Reporting, check each one and confirm it. If your address just changed, add it by hand: manual terms are active at once.
5. **Check it.**

   ```bash
   just abuse-guard-check
   ```

   It renders every open report in every format and the last 7 days of STIX and MISP, and prints PASS or FAIL per format with reason codes only. A non-zero exit means something would leak, or no address is confirmed yet. Run it after you change the settings or the self terms, and before the first real report.

### The identity guard

Abuse desks often forward a report to their customer, who may be the attacker. A report must not lead back to you. Every report, in every format, passes the identity guard right before it is shown, downloaded or sent. The guard blocks a report that contains your address, one of your names or domains, the VPN exit, the project name, a private address, a dashboard path or an internal id. When the stack does not know your own address yet, the guard fails closed and nothing can be sent.

A blocked report says why on its page, in one sentence per reason. The full list of checks is in [Security](SECURITY.md#the-identity-guard).

### Three ways to send

Pick the mode in Settings > Reporting > Sending.

| Mode | Name in Settings | What happens |
| --- | --- | --- |
| By hand | `off` (default) | SuckerPot sends nothing. You copy each report and send it from your own mailbox. |
| Assisted | `click` | A "Send now" button sends a ready report, after a confirmation. |
| Automatic | `auto` | Ready reports are sent after a hold time (default 60 minutes, 10 to 1440). While a report waits, the page shows the time it will go, with a Cancel button. |

**By hand.** Open Defend > Abuse reports and choose To send. It walks through the ready reports one at a time. For each report it shows the recipient, the subject and the body, with copy buttons. "Open in mail app" opens a `mailto:` link with the recipient and the subject. The full plain-text body is copied to the clipboard on every click, so a long report is one paste away. "Sent, next" marks the report as sent and opens the next one. Check the sender address in your mail app before you send, and connect that mailbox through your VPN. You can also download `report.txt` and `evidence.csv` from a report page and attach them.

**Assisted and automatic** need an SMTP profile (see [Set up SMTP](#set-up-smtp)).

These rules hold in every mode:

- Demo reports are never sent.
- A report that fails the identity guard, or that has no reply contact, is never sent.
- Before each send, ingest rebuilds the complete message, headers included, and runs the identity guard on it again.
- Mail leaves only through the VPN. The API has no route out and never connects to a mail server. While the VPN gate is closed, a send waits and nothing is attempted.
- "Send a test" sends a short neutral message to the sender address itself, so you can check the profile first.

### Automatic sending and pacing

Automatic sending is built to look like what it is: a person sending a few reports a day, not a bulk mailer.

- **Fresh reports only.** A report whose last activity is more than 7 days old is never sent automatically. One that ages past 7 days while it waits is cancelled (`too_old`). You can still send it by hand.
- **Newest first.** The freshest evidence is scheduled and sent first. A report you send by hand goes before the automatic ones.
- **Spacing.** At most one automatic send every 3 minutes.
- **Daily cap.** Automatic sends stop for the day once `daily_cap` reports went out through SMTP that UTC day (default 20, 1 to 200). Sends with the "Send now" button count too. A report over the cap waits for the next UTC day.
- **Deferrals.** If the mail server answers "try later" (an SMTP 4xx reply, often a limit on mails per minute or per hour), the send is marked `deferred`, every automatic send waits one hour, and the report is scheduled again by itself, at most 3 times in all.
- **Refusals.** A refusal (5xx) is never retried by itself. Neither is a send whose outcome is unknown, because a second mail would be worse. Both show the server's reply code, for example `refused:550` or `deferred:451`.
- **Switching off.** When you leave `auto`, the queued automatic sends are not sent: they end as `mode_changed`, or `mode_off` when you turn sending off.

### Set up SMTP

You need an SMTP server that accepts your login with STARTTLS (usually port 587) or with SMTPS (usually port 465). Enter the server's DNS name, not an IP address, with the port, the security, the login name, the sender address and the password. Saving the profile asks for your dashboard password again. The SMTP password is stored encrypted, and the dashboard never shows it again. The API reference is in [Sending abuse reports](api.md#sending-abuse-reports-m25).

Some mail services give SMTP access only on a paid plan, sometimes only with a custom domain and an app token instead of your password. Without SMTP access, keep the mode at `off` and use the To send queue. Settings has a preset that fills in the server and the port for one such service.

## Sending without getting blocked

A mailbox that sends abuse reports can look like a spam source to its own provider. If the provider blocks it, your reports stop and you may lose the account. These steps keep it working.

- **Read your provider's terms first.** Many providers forbid unsolicited or bulk mail unless you have their written agreement. Abuse reports are unsolicited by nature. Ask your provider whether they accept them, or pick a provider that does.
- **Set the cap to half the provider's quota.** Provider quotas often count a rolling 24-hour window. SuckerPot's daily cap counts per UTC day, so the end of one day and the start of the next can fit twice the cap into 24 hours. Set `daily_cap` to at most half of your provider's daily quota.
- **Start with `click`, then move to `auto`.** Send a few reports with one click each first. Watch for bounces and warnings from your provider. Switch to `auto` once that has gone well for a while.
- **Keep replies readable.** Abuse desks answer, and some ask questions. Use a mailbox that SuckerPot can read over IMAP, so that the answers are matched to their reports (see [Replies to reports](replies.md)).
- **Send fresh reports only.** This is why `auto` only sends reports with activity in the last 7 days. A provider checks the reported host when the report arrives. Weeks later the machine is often cleaned or given to someone else, and the report is closed as "cannot be substantiated". Older reports can still go by hand, one at a time, when you know they are worth it.

## Reports from the network

When enough independent nodes see the same attacker, the hub sends one report for all of them, from the project's report mailbox. A node sends nothing to abuse desks on the network's behalf. The hub operator's guide is in [hub/README.md](../hub/README.md#reports).

### What makes an address reportable for the network

A target is reported only after the network has confirmed it. Confirmation already needs several independent, aged, well-behaved nodes. With the defaults: 5 or more eligible nodes, sightings on two days or more, and for an address either 10 nodes or a known-bad signal from an outside source (see [How consensus protects against poisoning](network.md#how-consensus-protects-against-poisoning)).

On top of that, only observations from eligible nodes in the last 7 days (`HUB_WINDOW_DAYS`) count, and a confirmed target must pass one of these rules:

| Kind | Reportable when |
| --- | --- |
| Attacking address | At least 5 eligible nodes (`HUB_MIN_NODES`) saw a severe activity from it (a login that worked, a command, a download or an exploit), and the network's record of the target lists that activity. Or: at least 5 eligible nodes each saw 100 or more login attempts from it in one day. |
| Download link or file-hosting domain | At least two eligible nodes fetched a malware-like file from it (a known malware family, or an executable or script file type), and the clear value was revealed to the hub. |
| Payload host given as an address | A malware-like file fetched from it by at least two eligible nodes, and the address seen by at least 5 eligible nodes in all. |
| Command server | Confirmed. The confirmation itself needs a dropper fetched by two nodes. |

Scans and connections alone are never reportable. Login attempts travel to the hub as a bucket per node and per day (0 or 1, 2 to 9, 10 to 99, 100 to 999, 1000 or more), so "100 or more in one day" is the bucket that the rule checks. The never-list (public resolvers, large CDNs, the operator's own entries) is applied again before a report is queued.

### How the hub sends

- **Grouped.** One report per abuse desk and kind. A desk gets at most one new report per kind in 7 days. A failed report blocks that desk for a day.
- **Reviewed.** In the default `review` mode, the hub operator reads and approves each report.
- **Automatic, with limits.** In `auto` mode a queued report is approved after a 24-hour hold (`HUB_REPORT_HOLD_HOURS`), and only once the network has eligible nodes from 5 different enrolment weeks (`HUB_AUTO_MIN_COHORTS`). A report about a command server is never approved automatically.
- **Paced.** At most one mail per desk per day, and at most 100 a day in all (`HUB_REPORT_DAILY_CAP`).
- **Once.** A reported target is not reported again. One that comes back after a takedown can be reported again when its earlier report is more than 30 days old. A cancelled report blocks its targets for 30 days.
- **Anonymous.** A network report never names a node: no node id, pseudonym, address or exact count. The number of sensors is given as a range (5 to 9, 10 to 24, 25 or more).
- **abuse.ch.** The hub can also submit confirmed malware links to URLhaus and command servers to ThreatFox. This is off by default (`HUB_ABUSECH_MODE`), and a ThreatFox submission always waits for the operator. A node never submits anything to abuse.ch itself.

## After the report

- **Replies.** SuckerPot can read the answers from your report mailbox over IMAP, match each one to its report and show the outcome: a receipt, a ticket, a resolution, a rejection or a bounce. See [Replies to reports](replies.md).
- **Takedowns.** SuckerPot follows what happens to each reported target: is the file still served, is the address still attacking, how long did it take, and which providers act. See [Track takedowns](takedowns.md).
- **CERT exports.** A report page and a campaign page export STIX 2.1 or MISP JSON for a CERT. Administrators can also download a password-protected bundle of samples to upload by hand to a malware repository. Both pass the identity guard.

## Related pages

- [Security: anonymous reporting](SECURITY.md#anonymous-reporting-m22): what a report never contains, and how leaks are prevented.
- [Configuration](configuration.md#anonymous-reporting-m22): every `ABUSE_*` variable.
- [The dashboard: abuse reports](ui.md#abuse-reports-m22): the pages, tab by tab.
- [The SuckerPot network](network.md): consensus, and what a node shares.
