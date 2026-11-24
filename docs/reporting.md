# Reporting attacks

Report is the third part of SuckerPot, after Observe and Defend. A blocklist protects your own machines. An abuse report goes further: it tells the network that hosts an attacking machine what that machine did, so that its owner can clean it up. Most attacking machines are compromised servers, routers and cameras whose owners do not know.

By the end of this page you will know what can be reported, who sends the report, how sending works, and how to send without getting your mailbox blocked.

```{note}
Reporting is off by default. Nothing is sent until you turn it on and choose how reports leave.
```

## The rule: report, never touch

SuckerPot never probes an attacker. It does not scan, counter-scan or hack back, and it never opens a connection to an attacking host to probe or answer it.

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

The abuse worker in `ingest` builds the drafts. It is off until you set `ABUSE_REPORTS_ENABLED=true`. Every hour (`ABUSE_BUILD_INTERVAL_S`) it selects what deserves a report, looks up the abuse contact over RDAP through the VPN, and writes one draft per recipient: a daily digest that holds every source of every kind for that abuse address (see [One mail per provider per day](#one-mail-per-provider-per-day)). You find the drafts at Defend > Abuse reports in the dashboard.

### What your node reports

A digest holds sources of three kinds, each in its own section.

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
- the never-block list and every term in "Never in a report", such as your own addresses and names. The never-block list holds the public resolvers, the entries in `BLOCKLIST_NEVER`, and shared services that attackers type into commands but that are not the attacker: video and social sites, URL shorteners, and file, paste and code hosts (for example a video site, a link shortener or a public paste site). A domain on the list covers every name below it. It applies to all three kinds of report, so a registrar never gets a report about a whole shared service.

The same source is not reported again to the same recipient for 14 days (`ABUSE_RESEND_DAYS`). Every variable is in [Configuration](configuration.md#anonymous-reporting-m22).

### How your node defers to the network

When your node has joined the network, the worker drops every address and domain that the network reported, or saw taken down, in the last 30 days. The window counts from the report or takedown date, not from the last sighting. The hub has already sent one strong report about that machine, and a second, weaker one from you would only add noise for the same abuse desk.

A target that the network merely confirmed is not dropped. The hub may never report it (see [What makes an address reportable for the network](#what-makes-an-address-reportable-for-the-network)), so your own report still counts. A node that has not joined reports everything it selects.

### Set it up

1. **Turn the VPN on.** RDAP lookups and mail leave only through the [anonymous egress](deployment.md#anonymous-egress-vpn). With the tunnel down, nothing leaves.
2. **Turn the worker on.** Set `ABUSE_REPORTS_ENABLED=true` in `.env` and restart `ingest`. Reports stay locked (`no_self_address`) until the stack knows which address it protects.
3. **Fill Settings > Reporting (admin).** Add a reply contact: an alias that is not on one of your own domains. It is the only required setting, and it must contain a mail address (the X-ARF part names it; without one the draft is blocked with `reply_contact_not_email`). Until it is set, rendering answers `settings_incomplete`, and a report cannot be marked reviewed. The introduction, closing text, note, signature, subject template, X-ARF user agent and X-ARF organisation are optional. The project ships no wording, because shipped text lives in a public repo and could be searched. Leave them empty to send only the facts: an empty part is left out, an empty subject becomes `Abuse report for <address>`, an empty X-ARF user agent becomes `Mozilla/5.0` and an empty X-ARF organisation becomes the domain of the reply contact. If you write your own, make it yours.
4. **Confirm the self terms.** The worker learns the address and names of the monitored machine from traffic (an address is stored only when two or more distinct /24 or /48 networks used it, and counts only while seen in the last 72 hours). Learned terms start inactive. Open the "Never in a report" list in Settings > Reporting, check each one and confirm it. If your address just changed, add it by hand: manual terms are active at once.
5. **Check it.**

   ```bash
   just abuse-guard-check
   ```

   It renders every open report in every format and the last 7 days of STIX and MISP, and prints PASS or FAIL per format with reason codes only. A non-zero exit means something would leak, or no address is confirmed yet. Run it after you change the settings or the self terms, and before the first real report.

### The identity guard

Abuse desks often forward a report to their customer, who may be the attacker. A report must not lead back to you. Every report, in every format, passes the identity guard right before it is shown, downloaded or sent. The guard blocks a report that contains your address, one of your names or domains, the VPN exit, the project name, a private address, a dashboard path or an internal id. It reads every part of the mail decoded: base64 MIME parts, every value of the X-ARF JSON, and any base64 inside those values (such as the evidence lines), so base64 cannot hide a leak from it. When the stack does not know your own address yet, the guard fails closed and nothing can be sent. Your network pseudonym, if you have one, is never allowed in a report either.

A blocked report says why on its page, in one sentence per reason. The full list of checks is in [Security](SECURITY.md#the-identity-guard).

### The machine-readable part (X-ARF v4)

Every mail carries one machine-readable report per source, in the current X-ARF format: XARF v4 (version 4.2.0), JSON. Many abuse desks parse it automatically. Each report is checked against the official XARF 4.2.0 schema, which ships with SuckerPot, right before the mail leaves. A report that does not validate stops the send with `xarf_invalid`: that is a bug, and nothing is sent instead.

- **One source:** the mail has the shape the XARF specification describes, an RFC 6522 report: the text, a `message/feedback-report` part, `xarf.json`, and `evidence.csv`.
- **Several sources (a digest):** the text, `evidence.csv`, and one JSON file per source, `xarf-001.json`, `xarf-002.json` and so on. Each file is a complete report. The text names the file under each source. The XARF specification describes one report per mail only, so a desk whose parser takes only that shape may skip the files; its staff still have the text and the CSV. For such a desk, switch on **One mail per source (strict X-ARF)** on the recipient. Each source then goes in its own spec-shaped mail, and every mail counts against the daily cap.

What a report carries is the same set of facts as the text and the CSV: the source address or host, its source port, the times, the attacked port and service, the counts, the redacted log lines (base64, with their hash), hashes and malware families, and your reply contact with its domain. The type follows what the source did: `connection/login_attack` for logins and commands, `connection/vulnerability_scan` for exploit attempts (with the CVE ids probed), `connection/sql_injection`, `content/malware` for a payload host, `infrastructure/botnet` for a command server.

What a report never carries: your address (`destination_ip` is never set), `evidence_source` (it would say `honeypot`), `confidence`, host or sensor names, trap pack ids or any local tag. Tags come from three fixed lists only: services (`service:ssh`), CVE ids (`cve:cve-2023-1389`, only those named by a trap pack loaded more than 48 hours ago) and malware families (`malware:mirai`). Each report has a random `report_id`, kept on the source so a reply that quotes it is matched (see [Replies to reports](replies.md#the-x-arf-report-id)). It is unrelated to every other id.

The report page has an X-ARF tab that shows each JSON file exactly as the mail carries it, with copy and download buttons. The `.eml` download holds the same parts. For a sent report, the files are the ones that left: ingest stores them when it marks the report sent, and the page lists only the sources that went. A report sent before X-ARF v4 says so; no JSON is made up for it. A viewer (not an administrator) sees random report ids instead of the real ones, because a reply that quotes one is matched to its report, like the reply reference.

### Three ways to send

Pick the mode in Settings > Reporting > Sending.

| Mode | Name in Settings | What happens |
| --- | --- | --- |
| By hand | `off` (default) | SuckerPot sends nothing. You copy each report and send it from your own mailbox. |
| Assisted | `click` | A "Send now" button sends a ready report, after a confirmation. |
| Automatic | `auto` | Ready reports are sent after a hold time (default 60 minutes, 10 to 1440). While a report waits, the page shows the time it will go, with a Cancel button. |

**By hand.** Open Defend > Abuse reports and choose To send. It walks through the ready reports one at a time, one item per digest. For each report it shows the recipient, the subject and the body, with copy buttons. "Open in mail app" opens a `mailto:` link with the recipient and the subject. The full plain-text body is copied to the clipboard on every click, so a long report is one paste away. "Sent, next" marks the report as sent and opens the next one. Check the sender address in your mail app before you send, and connect that mailbox through your VPN. You can also download `report.txt`, `evidence.csv` and the X-ARF files from a report page and attach them, or download the whole `.eml`.

**Assisted and automatic** need an SMTP profile (see [Set up SMTP](#set-up-smtp)).

These rules hold in every mode:

- Demo reports are never sent.
- A report that fails the identity guard, or that has no reply contact, is never sent.
- Before each send, ingest rebuilds the complete message, headers included, and runs the identity guard on it again.
- Mail leaves only through the VPN. The API has no route out and never connects to a mail server. While the VPN gate is closed, a send waits and nothing is attempted.
- "Send a test" sends a short neutral message to the sender address itself, so you can check the profile first.

### One mail per provider per day

A busy provider used to get several mails a day, one per kind of report, each sent about an hour after the previous one. Now all the sources that share an abuse address go into one daily digest.

- **One digest per recipient.** The draft gains new sources every hour until it is due. It has a section per kind: attack sources, payload hosts, command servers.
- **The digest hour.** A digest goes once a day at your node's digest hour. A new install picks a random minute between 06:00 and 09:00 UTC, so that nodes do not all send at the same minute. Change it in Settings > Reporting > Sending (shown in your local time). A draft started after today's digest hour waits for tomorrow's. The hold stays as a minimum delay after the last rebuild, so you can still look and cancel: once its automatic send is queued and it is due within the hold, a digest is no longer rebuilt (new sources wait for the next one), and it goes no sooner than the hold time after its last rebuild. A digest that missed its time (its send was cancelled, or sending is not automatic) keeps collecting sources and is due at the next digest hour.
- **Parts.** A digest holds at most 100 sources (`ABUSE_MAX_SUBJECTS`), newest first. When one goes out full, the rest becomes part 2, sent at least 2 hours later, and part 3 after that. At most 3 parts a day; the rest waits for the next day.
- **One automatic mail per address per day.** Whatever the parts, an abuse address gets one automatic digest a UTC day. A mail you send by hand ("Send now" or "Sent, next") counts as that recipient's digest for the day: new sources wait for the next digest hour. A second send by hand to the same provider on the same day asks you to confirm ("This provider already got a report today").
- **Freshness, per source.** An automatic digest carries only the sources with activity in the last 7 days. The older ones stay on the draft, marked "older than 7 days", and go only with a send you start yourself; they are not counted as sent. A digest with no fresh source left is cancelled `too_old`.
- **Reviewed digests are frozen.** New sources go into the next draft, so a recipient can have one reviewed digest and one draft.
- **Form-only and dead recipients** get no automatic digest, as before.
- **Strict recipients.** With "One mail per source (strict X-ARF)" on, each draft holds one source and goes as a spec-shaped mail. The one-a-day rule does not apply; the daily cap, the spacing and the hold do.
- **After a cancel.** An automatic send cancelled because the desk takes only its web form or the address is dead is scheduled again once you clear the flag. One stopped by a change of sending mode is armed again when you switch back to automatic. One cancelled as `too_old` or `shared_host`, or failed as `xarf_invalid` or by the identity check, is scheduled again once the draft changes (new activity, the shared service left out, the check passing). A refusal (5xx), an unknown outcome and your own cancel are never retried by themselves. The report page says why a send stopped.
- **Switching it back on.** An automatic send queued while digests were off is cancelled with `digest_enabled`; the next build gives the draft its digest hour and the send is scheduled again then.
- **Turning it off.** Settings > Reporting > Sending has the switch "One mail per provider per day" (on by default). Off, a draft is sent after the hold, as before; sources of all kinds still share one draft per recipient.

When you upgrade, the open drafts of each recipient are merged into one digest on the first build, and the old drafts are marked superseded. Automatic sends that were waiting for those drafts are cancelled with `digest_migration`, so nothing leaves during the upgrade. An automatic send queued for a draft that a later build merges or retires is cancelled with `superseded`. Reviewed reports are not changed: they are sent as they are, with their X-ARF parts. Sent and closed reports keep their history.

### Automatic sending and pacing

Automatic sending is built to look like what it is: a person sending a few reports a day, not a bulk mailer.

- **Fresh reports only.** A source whose last activity is more than 7 days old is never sent automatically (see [freshness per source](#one-mail-per-provider-per-day)). A report with no fresh source left is cancelled (`too_old`). You can still send it by hand.
- **Never list, again.** Before any send, by hand or automatic, the subjects of the report are checked against the never-block list. A draft made before an entry was added is cancelled with `shared_host` and never sent.
- **Desks that take a web form only.** No mail goes to a desk that only takes its web form (cancel code `form_only`). Its reports wait in **To submit by form** instead: see [Desks that take only a web form](#desks-that-take-only-a-web-form). A send you start yourself still goes out.
- **Dead addresses.** A hard bounce (a 5.x.x failure) from a report sent to an address is remembered too. One bounce of the "user unknown" kind (5.1.1, "550 user not found") marks the address `undeliverable`. Any other permanent failure needs two. Automatic sending then skips it (cancel code `undeliverable`) and the report page says so. Type another address for the recipient, which starts a clean record, or clear the flag. A delayed notice ("still being retried") is not a bounce and is ignored.
- **Newest first.** The freshest evidence is scheduled and sent first. A report you send by hand goes before the automatic ones.
- **Spacing.** At most one automatic send every 3 minutes.
- **Daily cap.** Automatic sends stop for the day once `daily_cap` mails went out through SMTP that UTC day (default 20, 1 to 200). A digest is one mail, whatever its number of sources. Sends with the "Send now" button count too. A report over the cap waits for the next UTC day.
- **Deferrals.** If the mail server answers "try later" (an SMTP 4xx reply, often a limit on mails per minute or per hour), the send is marked `deferred`, every automatic send waits one hour, and the report is scheduled again by itself, at most 3 times in all.
- **Refusals.** A refusal (5xx) is never retried by itself. Neither is a send whose outcome is unknown, because a second mail would be worse. Both show the server's reply code, for example `refused:550` or `deferred:451`.
- **Switching off.** When you leave `auto`, the queued automatic sends are not sent: they end as `mode_changed`, or `mode_off` when you turn sending off.

### Desks that take only a web form

Some abuse desks ignore mail and take reports only through a form on their website. SuckerPot never submits a form by itself: forms have captchas and terms of use, and a report a person submitted is more credible. It prepares everything, and you paste it in.

**Which desks.** A recipient goes to the form queue when:

- a reply that matched one of its reports (or that you linked to one) says it refuses mail or only accepts its web form (for example "we no longer accept reports by email", "this inbox is not monitored" or "we require you to submit all tickets via our portal"). The first `https` link of a verified reply on the provider's own domain is kept as a hint;
- the **shared directory of abuse forms** has an entry for it that says the desk does not read mail (`accepts_mail: false` or `ignored`). An entry matches a desk by its exact mailbox domain, or by ASN only when the mailbox is on one of the provider's own domains: an ASN alone never routes a desk. The node then sends no mail there at all, not even a first one;
- you chose it: **This desk takes only a web form** on a report page.

**Clear this flag** on the report page when the desk takes mail again. The shared directory then leaves that desk alone; only a new verified reply from the desk can mark it again.

**Form preferred is not form only.** A desk that writes "while we accept email reports, we encourage you to use our form" still reads mail. Its reply is an automatic receipt, mail keeps going, and the report page only says "This provider also has a web form; mail still works", with the form link when there is a safe one. See [What a reply teaches about the desk](replies.md#what-a-reply-teaches-about-the-desk). Before this was fixed, such a reply could mark the desk form only: press **Clear this flag** on its report page to send it mail again.

**One report per provider and week.** The sources of a form-only desk go into one form report per ISO week (Monday 00:00 UTC), which fills during the week like a digest. It is in the queue as soon as it holds a source, so you can submit early while the evidence is fresh. Sources older than 7 days are marked. A report you have not submitted moves into the next week with its sources.

**The copy kit.** Open **Abuse reports, To submit by form** and open a provider's kit. It holds, each with its own copy button:

| Field | Content |
| --- | --- |
| Form | The form link, with its host in text next to it. A link from the shared directory says when maintainers last checked it; a link from a reply says to check the address first. When both exist and differ, both are shown with a warning |
| Your email | Your reply contact |
| Your name | The optional **Your name for web forms** setting (Settings, Reporting), empty by default |
| Abuse type | The form's own option when the directory knows it, else "Login attack", "Exploit attempt", "Malware download" or "Command server" |
| Addresses | One per line, or one block per address when the form takes one address at a time |
| First seen, last seen | UTC, with the report's precision |
| Description | A short text built from the same labels as the mail (your introduction is left out), within the form's limit (1,000 characters by default). Its last line is `ref <token>`, so a reply that quotes it finds the report |
| Log excerpt | The first 20 evidence lines of each source |
| Evidence file | `evidence.csv`, or `evidence.txt` for a form that takes text files only |

Every field, the evidence file and the form links pass the identity guard, one by one and together. A blocked kit shows the reasons and has no copy button.

**Open the form through your VPN.** A warning at the top of every kit says it: the provider sees the address of the browser that submits the form. Mail always leaves through the VPN; a form you submit from your own browser does not, unless you open it through your VPN or the Tor Browser. Form links open in a new tab with no referrer, so the provider never learns your dashboard address. A link is clickable only when it is `https` on the provider's own domain; anything else is shown as text.

**Submitted.** Press **Submitted** once the form is sent. The report then counts as sent everywhere: the 14-day resend rule, takedown tracking, Results (channel "Form"), [the effect measure](#do-reports-make-a-difference) and the one-mail-per-day rule for that provider. It does not count against the SMTP daily cap. Each address has a check box: only the ticked ones are recorded as sent, and the others wait for the next form report. For a form that takes one address at a time, nothing is ticked at first; tick each address as you submit it.

**The shared directory of abuse forms.** The file `reporting/forms/abuse-forms.yaml` lists known abuse forms. It is data only, ships with each release, and only changes through a reviewed pull request. CI refuses a form link that is not `https`, whose host is not under the provider's own domains, that is an IP address, holds a user name, a port or a fragment, or carries a query string other than `lang` (so no token or session can hide in it). Maintainers check every entry on the provider's own website, never from a link in a reply, and the kit says so when an entry was last checked more than a year ago.

When a verified reply taught your node a form link, the report page offers **Suggest for the shared directory**: a short text with the provider's name, mailbox domain, ASN and the form link, to post as an issue on the public repository (template "Abuse form"). It never holds an address you reported, a ticket number, the reply text or anything about your node. When the link has a query string, a port or anything else outside the kit's rule, only the provider's site (`https://<host>/`) goes into the text, because a path or a query could hold a ticket number, a token or your address; the page asks you to find the form page on the provider's own site. The report page shows a reply's link as a link only under the same rule as the kit; otherwise as text. Posting from your personal account links that account to reporting this provider.

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
- **Do reports make a difference?** The Results page compares reported attacking addresses with similar ones that were not reported. See [Do reports make a difference?](#do-reports-make-a-difference) below.
- **CERT exports.** A report page and a campaign page export STIX 2.1 or MISP JSON for a CERT. Administrators can also download a password-protected bundle of samples to upload by hand to a malware repository. Both pass the identity guard.

## Do reports make a difference?

The question: when your node reports an attacking address, is it less often still attacking a week later than a similar address that was not reported? The **Do reports make a difference?** card on the Results page and one line of `just status` answer it. They show nothing but progress until there is enough data.

This compares two groups. It does not prove that a report made an address stop: an address that was not reported may differ in ways the comparison cannot see. The page says so, and its wording never claims a cause.

### How it is measured

- **Who is compared.** Each attacking address named in a sent report (sent by SMTP, or marked sent by hand) is paired with one address that passed the same report rules in the same days (within 3 days) but was not reported. On a node that reports everything, such addresses exist only where something stopped the report: no contact found, a muted or form-only desk, the daily cap, or a draft you discarded. Demo reports, the never list, your own addresses and private ranges never count.
- **Same kind of attacker.** Both addresses must match exactly, over the 7 UTC days that end on the day of the first report: the kind of activity (exploit, download, a login with commands, logins only), the number of events (1 to 9, 10 to 99, 100 to 999, 1,000 or more), and the last sighting (that day, 1 to 2 days before, 3 to 6 days before).
- **Closest provider.** Among those, the closest provider wins: the same network (ASN) first, then the same provider size and country, then the same provider size. The size is built from the RDAP block of the address and how many addresses of its ASN your sensors saw in 30 days. A reported address with no match is counted as unmatched and never used. Each control is used once.
- **Still seen.** An address is still seen at 7 days when any of your sensors saw a session from it in the 7 days from day 7 to day 13 after the report (scans count too). A second horizon, 30 days, uses days 30 to 36.
- **Only when your sensors were up.** A week counts only when at least 6 of its 7 days had sessions from at least 10 different addresses. Otherwise the pair is left out ("sensors down"), so a week offline never looks like a week without attackers.
- **Left out.** A pair is also left out when the control was reported later (before the end of its week), or when the SuckerPot network reported either address.
- **Frozen.** Each outcome is recorded once and never changes. The two addresses of a pair are deleted 30 days after its 30-day outcome; the counts stay.

### When a number is shown

Nothing but progress ("12 of 30 comparable pairs") until there are at least **30 pairs** with a result and at least **10 pairs where only one of the two was seen**. Above that, the card shows the share of each group still seen, with whole percentages and the number of pairs, and a 95 % interval of the difference in points (Newcombe's method for paired data). The verdict comes from the interval only:

| Verdict | When | Example |
| --- | --- | --- |
| Not enough data | Below the minimum | "Not enough data yet to tell whether reports help: 12 of 30 comparable pairs." |
| Less often seen | The whole interval is below 0 | "Reported sources were less often seen attacking a week later: 38 % against 61 % for similar sources that were not reported (84 pairs; the difference is between 9 and 37 points). This compares two groups; it does not prove that the reports made the difference." |
| No clear difference | The interval contains 0 | "No clear difference yet: 52 % of reported sources and 55 % of similar unreported sources were still seen a week later (84 pairs). The gap could be chance." |
| More often seen | The whole interval is above 0 | "Reported sources were more often seen attacking a week later: 64 % against 41 % (84 pairs). This compares two groups; it does not say why." |

The interval is wide at first: about 25 points either way with 30 pairs, 14 with 100, 8 with 300. A small node will at best see a clear difference for a large effect. That is the honest answer.

`just status` adds a **Reports** section once an attack-source report was sent, for example `Report effect: not enough data yet (12 of 30 pairs)`. It is information, never a warning. `just status --json` has the same numbers under `report_effect`.

### The random holdout (optional)

Without randomness, an address that was not reported was left out for a reason, and that reason may also explain its future (a provider with no abuse contact may also never clean anything). A fair test needs chance to decide. With `ABUSE_EFFECT_HOLDOUT_PCT` (0 by default, at most 10), that share of new attack candidates is chosen at random and not reported for 21 days. After that it is reported as usual if it still attacks. Held-back addresses become the preferred controls (shown as "random holdout"). Turn it on knowingly: it delays some reports. Turning it off releases every held-back address at once. It never sends a report that would not have been sent.

### Where it runs

The measure runs in `ingest` whenever abuse reporting is on (`ABUSE_REPORTS_ENABLED=true`), at most once an hour, with a bounded amount of work per run. It does not need takedown tracking. On its first runs it pairs the reports sent in the last 45 days. It reads only your own reports and sessions: no lookup, no network access, and no address leaves the node. The dashboard reads counts only, never an address.

## Related pages

- [Security: anonymous reporting](SECURITY.md#anonymous-reporting-m22): what a report never contains, and how leaks are prevented.
- [Configuration](configuration.md#anonymous-reporting-m22): every `ABUSE_*` variable.
- [The dashboard: abuse reports](ui.md#abuse-reports-m22): the pages, tab by tab.
- [The SuckerPot network](network.md): consensus, and what a node shares.
