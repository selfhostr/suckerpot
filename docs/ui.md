# Use the dashboard

The dashboard is a single-page web app in `web/`. The API serves the built files, so there is one port to publish and one thing to put behind the tunnel. The design rules are in `web/DESIGN.md`. Colour tokens, the type scale and every component are shown on the `/styleguide` page of a running dashboard.

## Navigation

The sidebar (the drawer on a phone) has ten entries in three spaces, plus Settings at the bottom. Related pages are grouped in **hubs**: one sidebar entry, and a row of tabs at the top of each page of the hub. The tabs are plain links between ordinary pages, so every address and filter in the URL keeps working. The entry stays highlighted on detail pages too (a session, an attacker, a campaign, a script).

| Space | Entry | Tabs | Question it answers |
| --- | --- | --- | --- |
| Observe | Today | | What is happening now? |
| Observe | Live | | What is happening now? |
| Observe | Attacks | Sessions, Attackers, Networks | Who is attacking, and from where? |
| Understand | Campaigns | Campaigns, Techniques | Who is behind it? |
| Understand | Tools | Scripts, Malware, Infrastructure | What do they drop, and from where? |
| Understand | Trends | Activity, Patterns | How does it change over time? |
| Defend | Protection | Blocklists, Detections | What should I block or watch? |
| Defend | Exposure | Your exposure, CVE watch | What of mine is at risk? |
| Defend | Alerts | | What was I told, and what did the weekly report say? |
| System | Settings | | How is the system set up? |

The Styleguide page is routable everywhere but listed in the sidebar only in development builds. The whole table lives in `web/src/app/nav.ts`.

`Ctrl+K` opens search from anywhere. The pages read the endpoints described in [API](api.md).

## Principles

- **A sentence before a chart.** Every card opens with a plain-English finding, then shows the evidence.
- **Colour means something.** One hue per sensor family (remote shells blue, web and APIs purple, databases green, Windows and VoIP ochre), always paired with an icon and a label. The Synology sensor belongs to the web and APIs family, so it adds no new colour. Each sensor has its own icon and name. Red is reserved for severe events: a download attempt, or an exploit or malware tag.
- **Everything is clickable.** An address, a tag or a sensor count opens the matching filtered view. Filters live in the URL, so every view can be shared.
- **Calm real-time.** New events slide in softly, numbers tween, nothing flashes. With "reduce motion" set in the system, all animation is off.
- **Times** are stored in UTC and shown in the browser's time zone, relative ("5 min. ago") with the exact time on hover.
- **Dark by default**, with a light theme. The theme follows the stored choice, then the system setting.

## Pages

| Page | Path | What it shows |
| --- | --- | --- |
| Sign in | `/login` | The login form. Any other page sends you here when there is no session. `/set-password` asks for a new password on first sign-in. |
| **Observe** | | |
| Today | `/` | The home page: the last 24 hours as a visual story. A plain headline and five big numbers, a flow diagram (country, door, how far they got), an hour-by-hour strip, a few "stories of the day", then what to do about it. See [Today, search and the glossary](#today-search-and-the-glossary). |
| Live | `/live` | A flat world map of the last 15 minutes of attacks, with arcs landing at the home point, a stats strip, a ticker of the newest events and rankings of addresses, countries and networks. See [The Live page](#the-live-page). |
| Attacks | `/attacks` | Sessions, newest first, one line each, as a short story. Filters: sensor, source address, period, tag, country and network. Pages of 50, virtualised. |
| Session detail | `/attacks/<session id>` | The attack timeline, with long runs of the same event folded, a terminal replay for shell sessions, and a source panel. |
| Attackers | `/attackers`, `/attackers/<ip>` | Profiles by address: first and last seen, sensors targeted, reputation. |
| Networks | `/networks` | The hosting providers and networks (ASNs) the attacks come from. The old `/attackers?view=asns` address redirects here. |
| Activity | `/overview` | KPIs for the last 24 hours, activity per sensor, the sensor mix, the latest events and up to three insights (see [Insights](#insights)). |
| **Understand** | | |
| Campaigns | `/campaigns`, `/campaigns/<id>` | Sessions that share a script, payload host, file hash, malware family, exploit or credential list, grouped into one campaign with a plain-English story. Campaigns from the same addresses are merged into the oldest one; the old address shows a note with a link to the combined campaign. |
| Techniques | `/techniques` | The MITRE ATT&CK techniques seen, as a heatmap per day. |
| Scripts | `/scripts`, `/scripts/<id>` | The library of command scripts that attackers typed, each with an explanation and the sessions that used it. |
| Malware | `/malware` | Download URLs, defanged, with how often, from how many addresses and with which tool. File hashes and VirusTotal links appear when payload fetching is on. |
| Infrastructure | `/infrastructure` | A finding first ("40 scanning IPs fetched payloads from 2 shared hosts this week"), a flow diagram from source addresses through indicators to malware families (a list on narrow screens), a filterable indicator table, a detail panel with threat-intelligence answers, and CSV or STIX 2.1 export buttons. Indicators are defanged text, never links. |
| Trends | `/trends` | Top usernames, passwords, commands and URLs, tags over time, a day by hour heatmap, and "new this week" (values never seen in the 90 days before). |
| CVE watch | `/cves` | New and known-exploited vulnerabilities ranked by how much they matter to the services you emulate, with "seen in our traffic" counts. |
| **Defend** | | |
| Blocklists | `/defend/blocklists` | Scored blocklists with a reason for every point, overrides, and exports for firewalls. A Network tab shows the community lists. See [Defend](defend.md) and [Community blocklist feeds](feeds.md). |
| Detections | `/defend/detections` | Sigma and Suricata rules marked "review before deploying". |
| Your exposure | `/defend/exposure` | Your own service inventory compared with what was recorded. |
| Abuse reports | `/defend/abuse`, `/defend/abuse/<id>` | Drafts of anonymous abuse reports to review, copy and mark sent. See [Abuse reports](#abuse-reports-m22). |
| Abuse reports: Results | `/defend/results`, `/defend/results/targets/<id>` | Did anyone answer, how fast did targets go down, and which providers act. See [Results](#results-m26-m27). |
| Alerts and reports | `/defend/alerts`, `/reports/<week>` | Alert rules and channels (all off until you switch them on), and the weekly report with a printable view. |
| **System** | | |
| Settings | `/settings` | Sensor status, enrichment quotas, retention, the disk guard and the database size. The provider API keys can be set, replaced, removed and tested here: write-only, with a password prompt for every change (see [Provider API keys](api-keys.md)). Administrators also see **Users** and the **Audit log**; viewers see neither, and no control that changes anything (see [Users and roles](#users-and-roles)). |
| Styleguide | `/styleguide` | Every token and component, in every state. |

Any other address shows a "page not found" screen.

## Sign in

When the API answers `401`, the app shows the sign-in page. After a successful login the session lasts `SESSION_TTL_HOURS` (12 by default). The cookies are set by the server; the app never stores the password or a token in the browser's storage. The app reads the CSRF cookie and sends it on every write. Too many attempts show "Wait a minute, then try again". If login keeps failing behind a tunnel (the API answers `403` to a cross-origin login), add the public origin to `API_ALLOWED_ORIGINS` (see [Deployment](deployment.md#behind-a-tls-terminating-tunnel)).

## Users and roles

Two kinds of people can use the dashboard besides the owner: **administrators** and **viewers** (see [Users and roles](configuration.md#users-and-roles) for what each may do).

- **Add a user** (Settings > Users > Add user): username, name, role and your own password. The app then shows a temporary password **once**, in a dialog that does not close by accident, with a Copy button and a warning. The person signs in with it and is taken to **Set your password** before anything else.
- **Row actions** (the three dots): change role, disable or enable, unlock (only while locked), reset password (shows a new temporary password once), sign out everywhere, delete. Each asks for your own password. You cannot do the destructive ones to your own account.
- **Status** is one word with an icon: Active, Waiting for first sign-in, Locked, Disabled. The owner row says "Set in .env" and has no actions.
- **Audit log**: newest first, one sentence per entry ("sam reset the password of riley"), filterable by kind (Sign-ins, Users, Keys) and by name; the filters are in the URL (`?audit_action=user.&audit_actor=sam`). Click a name to filter by it.
- **Viewers** get the same pages, with a small "Read-only access" mark in the sidebar footer (and in the mobile header), no key buttons, and no Users or Audit cards.
- **Account menu** (sidebar footer): your name, role, last sign-in, **Change password** and **Sign out**. The owner's password is changed in `.env`, so that entry is disabled for the owner.

In the demo and mock builds, add `?as=viewer` to any address to preview the read-only interface and `?as=first-login` for the Set your password screen (`?as=admin` goes back). The choice lasts for the browser tab.

## Insights

The Overview page opens with up to three insights, each one a plain sentence with the numbers behind it, for example "PHP2Shell exploit attempts tripled since Tuesday (312 vs 104)." They come from fixed rules, not from a language model, and each rule has a minimum volume so a quiet host stays quiet. Each insight links to the filtered view that shows its evidence. The rules and thresholds are in [API](api.md#get-apiv1insights). Days in the wording are UTC days.

## Trends and malware

- **A sentence before a chart.** Every Trends card states what the chart shows ("Most attacks arrive between 02:00 and 05:00") before the chart.
- **Local time.** The heatmap is stored by UTC hour and shown in the browser's time zone.
- **Defanged URLs.** On the Malware page a URL is shown as `hxxp://example[.]com/x.sh`, as plain text and never as a link, so it cannot be opened by mistake. The copy button copies the defanged form. Do the same wherever you paste these URLs.
- **Nothing is fetched.** The page lists URLs that attackers tried to download. SuckerPot does not download them.

## Samples and egress (M21)

- **Samples tab.** The Malware page has a Samples tab for files the collector fetched. It opens with a sentence ("12 new binaries this week, 9 of them Mirai builds for ARM and MIPS"), then one row per sample: family (or "Unknown"), kind and architecture, size, number of sources, last seen. Filters live in the URL. Each URL row on the Malware page also shows a fetch status chip with a word and an icon (Fetched, Pending, Failed, Refused, or "TFTP: recorded, not fetched"). A fetched URL links to its sample by short hash.
- **Sample page** (`/malware/samples/<sha256>`). A header with family, kind and architecture, severity and the hashes with copy buttons, plus a VirusTotal link. Then: **Where it came from** (URLs, sessions, address chips, sensors), **The chain** (session, script, binary, C2) as a vertical step list, **What it matched** (YARA hits as tags), the **deobfuscated script** as plain text with a summary of the steps, and the **strings** in a virtualised list. Red is used only for a sample with a malware-family YARA hit or an executable dropped by a session.
- **Download as archive.** Administrators only. A dialog explains that the zip uses the password `infected`, and asks for the dashboard password again. Viewers do not see the button. The file is never shown or served raw.
- **Settings, Egress card.** One sentence first: "Outbound traffic leaves through the VPN" or "Outbound traffic is paused: the VPN tunnel is down". Then the time of the last check, the reason when the gate is closed, a meter for the collector quota and a meter for the quarantine against its cap. The VPN exit address is hidden until you click to reveal it.

## Abuse reports (M22)

Nothing here sends mail. You read, copy and send from your own mailbox.

- **Abuse reports page** (`/defend/abuse`). A finding first ("4 reports are ready for review, covering 23 addresses in 3 networks"). When nothing can be built (worker off, egress closed, no confirmed self address) an empty state says why and links to Settings. Tabs by status (Drafts, Reviewed, Sent, Closed, Discarded) with counts, and a "No contact found" list where you can type a mailbox. Rows are grouped by provider: name and mailbox, network chips, the kind (Attack source, Payload host, C2 server), number of subjects, the period and the identity check as an icon plus a word.
- **Report page** (`/defend/abuse/<id>`). A status stepper (Draft, Reviewed, Sent, Closed). The **Identity check** card comes first: it says what was masked, or why the report is blocked, using reason codes in plain English. Then the **Message** card with Plain text, X-ARF and .eml, read-only To, Subject and Body fields with copy buttons and downloads. Then the subjects (the only place with links back into the dashboard), notes and actions: Mark reviewed, Mark sent (with a date and time), Close, Discard, Regenerate. A stale revision reloads the page. Viewers see everything and no buttons. Demo reports carry a "Demo data, do not send" banner and cannot be marked sent. Red is used only for a blocked identity check.
- **Export for CERT.** A menu on the report page and on the campaign page: STIX 2.1 or MISP JSON, with a TLP choice (default TLP:GREEN).
- **Sample bundle.** Administrators select up to 10 stored samples (from the Samples tab or a sample page) and download one password-protected zip. The dialog explains the `infected` password, asks for your dashboard password again and says how many samples were excluded by the identity check.
- **Settings > Reporting** (administrators). The reply contact, signature, introduction, closing text, note, subject template, X-ARF user agent and default options. Only the reply contact is required; the other texts are marked Optional and are left out of the report when empty. Below it, the **Never in a report** list: learned and manual terms, masked with a reveal button, a button to confirm a learned term, and add and delete for manual ones.

## Results (M26, M27)

The **Abuse reports** entry is a hub with two tabs: **Reports** and **Results**. The rules of the reports themselves are in [Abuse reports](#abuse-reports-m22). The answers and their matching are in [Replies to reports](replies.md), and the tracking of the targets in [Takedowns](takedowns.md).

- **Results page** (`/defend/results`). Every card opens with one plain sentence, then the chart or table that proves it. Filters (period, report kind, channel, provider, grouping) live in the URL, so a view can be shared. From the top:
  1. Stat tiles: reports sent, answered (%), median first reply and resolved. With takedown tracking on, also taken down within 48 hours and median time to takedown.
  2. **Reports over time.** Stacked weekly bars by report kind.
  3. **Did anyone answer?** One bar per outcome. Rejected and bounced use the warning tone, never red.
  4. **How fast they answer.** A delay histogram: under 1 hour, under 6 hours, under 24 hours, under 7 days, later.
  5. **How fast do things go down?** (tracking on) A step chart of the share of targets that went down, by hours since the report, one line for URLs and one for hosts. The legend has words, not only colours.
  6. **Providers.** One row per provider: name (an ASN chip, which opens the networks page), country, targets, down within 48 hours, median time to takedown, still up after 30 days, reports sent, answered, median first reply. Sortable. A row opens the Reports tab filtered by that recipient.
  7. **Targets** (tracking on). Tracked targets with a kind, a channel, a state and a time to takedown. Rows open the target page. A target is shown as defanged text and is never a link.

  Without any report, the page says "No report sent yet. Results appear here once you send one." With takedown tracking off, the page says so and names the variable. Viewers see everything, read-only.

- **Target page** (`/defend/results/targets/<id>`). A header with the defanged value, the provider, the report time and the state with its time-to-takedown bounds. One sentence says what the last check found, for example "Still serving the same file 3 days after the report." For C2 servers the sentence says that only passive signals exist. Below it a **Timeline**: the report, the replies, and each check with its method, its result in words and its HTTP status. A changed file links to its new sample. Hosts list their URLs. Administrators have **Check now** (at most once an hour per target) and **Stop tracking**.

- **Replies to check.** On the Reports page, administrators see a **Replies to check** tab with a count, when there are replies that are unmatched or unverified. Each reply can be linked to a report, confirmed, or its domain trusted.

- **Report page: Outcome card.** Under the stepper, for sent and closed reports. One sentence, for example "The provider opened ticket 48213 2 hours after you sent this report." or "No answer after 16 days." An outcome badge with an icon and a word. Administrators can set the outcome by hand, or go back to automatic. The **Replies** list shows each reply's date, sender domain, class, and a **Verified** or **Check it** mark. Excerpts are text only, with no links and no HTML. Viewers see the sender domain, not the address or the excerpt. Administrators can add a reply by pasting it or uploading an `.eml` file.

- **Settings > Reporting.** One card is added. **Replies** sets up the mailbox, with **Test connection** and **Check now**, and shows the last check or the last error.

Colour follows the same rules as the rest of the dashboard. Red is used only for a payload that is still served or was replaced. Addresses and C2 servers are never red.

## Blocklists: the Network tab (M30)

The Blocklists page (`/defend/blocklists`) has two tabs, set in the URL with `?tab=`. **This sensor** is the page as before. **Network** (`?tab=network`) shows the community lists. The page works the same way with the feed off, and with the feed on.

- **Feed off.** An empty state says what the lists are. It shows the public URLs with copy buttons, because a firewall can fetch them without this dashboard. It also says how to turn the fetch on (`NETWORK_FEED_ENABLED`). Nothing contacts the feed host until the flag is on.
- **Feed on.** The first line is a sentence: how many entries each list holds, and how many also reached this sensor. A status line says when the lists were last updated and whether the signature was verified. Problems show as a chip with text: out of date, last fetch failed, or waiting for the first fetch. The state is never shown by colour alone.
- **One card per list.** The outbound card says "Start here". Each card has a one-line purpose, the entry and high-tier counts, a **Copy URL** menu grouped by tier, and a link to the verified copy on this dashboard when the local mirror is on.
- **Entries table.** Virtualised, paginated on the server. Filters live in the URL: `list`, `tier`, `seen_here` and `q`. A value that this sensor also saw has a badge, and its address opens the attacker page. Members see a "You helped" badge.
- **How to use drawer.** Short steps for OPNsense and pfSense, with a link to [Community blocklist feeds](feeds.md).
- **Why join the network? card.** It says the lists are free and public, and that every firewall gets the same lists. It says what joining adds, and links to the Network pages. It promises no extra lists.

The tab adds no new colour. Red is kept for severe events, as in the rest of the dashboard (`web/DESIGN.md`). The tab works with the keyboard, and its text meets WCAG AA contrast.

## Sessions as stories

A session row reads like a sentence, for example: "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file". The text is written by one pure function in the app and covered by unit tests. The same words are used on the Attacks list, the Live feed and the Session page.

A session is marked severe when it downloaded something or carries a payload tag (such as `php2shell`, `crypto-miner`, `mirai` or `malware-drop`). A single event gets the red icon only when the event itself is severe.

## The Live page

The Live page is the screen to leave running on a wall or a second monitor. The map is the main element. There is no 3D globe: a flat map is easier to read at a glance, and it shows every source in its real place.

From top to bottom:

- **Map.** A flat world map (Equal Earth projection) with land and borders. It shows the last 15 minutes of traffic: one arc per source country, landing at the home point (Switzerland by default). An arc takes the colour of the sensor family that sends most traffic from that country, and gets thicker with more events. Presets are "World" (the default) and "Europe"; the last choice is remembered. Drag, scroll, pinch or use the arrow keys, `+`, `-`, `E` and `0` to pan and zoom.
- **Stats strip.** Events per minute, in total and per sensor family, in the top-left corner of the map (or under it on phones). The family colour is also the arc colour, so the strip is the legend. Click a family to filter the page. Click it again to clear the filter.
- **Ticker.** The newest events, as one row of chips under the map. Hover or focus the ticker to hold it still. New events then wait behind an "N new events" pill. Click the pill to catch up.
- **Rankings.** Three cards show the top addresses, the top countries and the top networks over the same 15 minutes. Each card opens with a sentence, such as "France leads with 21% of events, from 10 addresses." Each row opens the filtered Attacks view.

Hovering a ranking row, a ticker chip or a map dot highlights that country everywhere. Its arc becomes fully opaque, and the other arcs fade. **Pause** freezes the map, the rankings and the ticker at the newest event.

The home point comes from `GET /api/v1/settings/site`. Its position is set with `SITE_HOME_LAT` and `SITE_HOME_LON` (see [Configuration](configuration.md#site-live-map-home)).

With "reduce motion" set in the system, the arcs do not animate, the ticker does not glide and the numbers do not tween. The picture stays the same.

## The live feed

The Live page and the status dot in the header share one connection per browser tab.

- **WebSocket.** The app connects to `/api/v1/live`. It receives the 50 newest events first, then each new event, and statistics every 5 seconds.
- **Reconnects.** When the socket closes, the app retries with exponential backoff and jitter (1 s, 2 s, 4 s, up to 30 s). The dot shows "Reconnecting".
- **Polling fallback.** After 3 failed attempts in a row, or when the server refuses the socket (full, or origin not allowed), the app reads `/api/v1/events/recent` every 10 seconds while it keeps trying to reconnect. The dot then reads "Live" with a "Polling" note.
- **Refusals.** If the server is full (close code 1013), the app waits a minute before it tries again. If the origin is rejected (1008), it waits five minutes, because only a configuration change fixes it. See [Behind a TLS-terminating tunnel](deployment.md#behind-a-tls-terminating-tunnel).
- **Heartbeat.** The app sends a `ping` every 25 seconds.
- **Hidden tabs.** After five minutes in the background, the app disconnects. It reconnects when the tab is visible again.
- **Hold to read.** When you scroll away from the top of the feed, hover it, or press pause, new events wait in a counter ("N new events, jump to latest") instead of moving the list. The buffer keeps the newest 500 events.
- **Slow clients.** If the server had to skip messages for this tab, the app is told how many (`dropped`), and it can say so.

## Today, search and the glossary

**Today** is the page you land on. It tells the last 24 hours in plain words first, and keeps the technical detail one click away.

- **Headline and numbers.** One sentence, then visits, machines, countries, how many got in and how many tried to install something.
- **The flow.** A diagram from the country, to the door (the sensor), to how far the visitor got: only looked, guessed passwords, got in, ran commands, tried to install something, sent an exploit. Hover for the plain label and the count. Click a block or ribbon to open the Attacks list filtered the same way (`/attacks?stage=…`). A legend explains each stage in one sentence. On a phone it becomes one bar per door.
- **Hour by hour.** Drag, click or use the arrow keys to pick an hour; one sentence says what happened in it.
- **Stories of the day.** Three to five notable visits, each with a plain title, a step-by-step path that plays once, a severity badge, the country and address, and a **Technical details** button (raw lines, tags, ATT&CK techniques, campaign and a link to the full session).
- **What you can do about it.** The cards from `GET /api/v1/today`: new campaigns, what to block, what is new this week, your exposure.

The story comes from `GET /api/v1/story`. Underlined words (brute force, malware, exploit, scanner and more) show a one-sentence definition. A card with nothing to report keeps its place and says so.

**Search** is the box at the top of every page on a computer, and the magnifier in the top bar on a phone. `Ctrl+K` (`Cmd+K` on a Mac) opens the same search from anywhere. Type an address, the start of an address ending in a dot such as `203.0.113.`, a CVE id, a file hash, a domain or a URL, or the start of a campaign name. Results are grouped, at most five per group, and Enter opens the first one: an attacker profile, a campaign, the CVE watch, or the Infrastructure page. Indicators are shown defanged and never as links.

**Glossary.** Security words in the interface (ASN, KEV, campaign, indicator, and more) have a dotted underline. Hover, tap or press Enter on one to read what it means in a sentence or two.

**Research scanners.** Known, harmless crawlers such as Censys and Shodan are labelled when they connect and hidden by default, so they do not drown the real attacks. The **Hide research scanners** switch in the header (the navigation drawer on a phone) shows them again, with the number of sessions the last 24 hours hid. The list lives in `ingest/rules/scanners.yaml`. A scanner is recognised by the network that owns its address, never by what it says about itself (a user-agent can be forged). Even then a session stays labelled only while it just looks around: it may connect, probe and send GET, HEAD or OPTIONS requests. A login attempt, a command, a download, a POST, an exploit flag or an attack tag makes it a normal session for good, and its earlier events too. Charts that cover more than a few days come from pre-computed totals that do not separate scanners, so they include scanner traffic.

**Motion.** Cards and pages fade in softly. With `prefers-reduced-motion`, or `?motion=off`, nothing moves.

## Screenshot mode

Real attack data contains attacker addresses. To take a screenshot, turn on **Mask IPs** in the sidebar footer, or open any page with `?mask=1`. Use `?mask=0` to turn it off. The choice is remembered per browser.

- An IPv4 address is masked to its first two parts: `203.0.113.42` becomes `203.0.x.x`.
- The masking also applies to addresses inside free text: URLs, commands, live summaries, the IP filter chip and page headlines.
- Copy buttons are hidden while masking is on.

README and documentation screenshots must use demo data only, even with the mask on. See [Demo data](demo-data.md).

## Keyboard and accessibility

- Every control is a real link or button. Tab moves through the page in reading order, and the focus ring is always visible.
- Whole rows in the Attacks list and the Live feed are links: Tab to a row and press Enter to open the session. The tag badges and address chips inside a row stay separately focusable.
- Colour is never the only signal. Sensors have an icon and a name, severity has an icon and a label.
- Text colours are checked for WCAG AA contrast in both themes by an automated test.
- There are no custom keyboard shortcuts yet.

## Terminal replay safety

```{admonition} Status
:class: warning

The contract below applies to the terminal replay on the Session detail page.
```

SSH sessions are recorded with the bytes the attacker typed and the bytes the server sent back. An attacker controls those bytes, and a terminal emulator interprets escape sequences. The replay must therefore be built under the rules in [Security](SECURITY.md#terminal-replay-safety-contract).

## Pipeline banner

- **Stalled pipeline.** When the ingest service has stopped storing events, a red alert appears above the content of every page: "Events have not been stored for 42 minutes. They are waiting in a queue for now, but once it fills up, the oldest attacks are lost.", with the last error and the commands to check the service. It disappears by itself once events are stored again.
- **Events set aside.** When some events could not be stored and were set aside, a quiet notice says how many and links to Settings, where the Pipeline card shows the status and the last healthy check. You can dismiss it; it returns only if the count grows. An older API without this status shows nothing.

## Run it locally

```bash
just web-dev
```

The Vite dev server starts on `http://127.0.0.1:5173` with mock data, so you do not need the stack. See [Development](development.md).
