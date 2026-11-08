# SuckerPot design system

The UI is the product. The bar is a calm, precise SaaS dashboard (Linear, Vercel, Stripe). The anti-reference is T-Pot and Kibana: many panels, many colours, no story. Every decision below serves one goal: **someone glancing at the screen understands what attackers did, in plain English, in a few seconds.**

The source of truth is code: tokens in `src/styles/tokens.css`, Tailwind mapping in `src/styles/index.css`, components in `src/components/`. The `/styleguide` route shows all of it, in every state.

## Mood

Quiet, dark and precise, like an observatory at night. Neutral surfaces, hairline borders, generous space, and colour only where it means something. Motion is slow to start and fast to settle. Nothing blinks.

## Typography

| Role                                   | Font                                          | Notes                   |
| -------------------------------------- | --------------------------------------------- | ----------------------- |
| UI and text                            | Inter Variable (`@fontsource-variable/inter`) | Features `cv11`, `ss03` |
| Addresses, commands, hashes, URLs, IDs | JetBrains Mono Variable                       | Never for prose         |

- Self-hosted through `@fontsource`. No external font requests.
- `font-variant-numeric: tabular-nums` is set on `body`, so every number lines up and counters never jitter. Numbers use thousands separators (`formatNumber`, en-US).
- Scale (size / line height): `2xs` 11/16, `xs` 12/16, `sm` **13/20 (default UI)**, `base` 14/22 (card findings, page intros), `md` 16/24, `lg` 18/26, `xl` 22/28 (page titles), `2xl` 28/34 (KPI values), `3xl` 36/42.
- Weights: 400 body, 500 labels and findings, 600 titles and KPI values. Titles use `tracking-tight`.

## Colour

All colours are CSS variables on `:root` (dark, the default) and `[data-theme="light"]`. They are plain hex so `src/styles/contrast.test.ts` can check WCAG ratios for every pair. The theme follows the stored choice, else `prefers-color-scheme`, else dark. An inline script in `index.html` applies it before first paint.

### Neutrals

| Token                          | Dark                  | Light                 | Use                                    |
| ------------------------------ | --------------------- | --------------------- | -------------------------------------- |
| `--bg`                         | `#0b0c0e`             | `#f7f7f8`             | Page, sidebar                          |
| `--surface`                    | `#111215`             | `#ffffff`             | Cards                                  |
| `--surface-raised`             | `#17181c`             | `#ffffff`             | Popovers, selected segments            |
| `--surface-hover`              | `#1c1d22`             | `#f2f2f4`             | Hover, active nav                      |
| `--border` / `--border-strong` | `#23252a` / `#34373e` | `#e4e4e8` / `#d1d2d8` | Hairlines                              |
| `--fg`                         | `#ecedef`             | `#0f1013`             | Primary text                           |
| `--fg-muted`                   | `#a1a4ac`             | `#4f525a`             | Secondary text                         |
| `--fg-subtle`                  | `#858892`             | `#6a6d76`             | Labels, timestamps (still AA, ≥ 4.5:1) |

The primary action is neutral (`--primary` is the text colour, inverted). There is no brand hue: a hue always means a sensor or a severity.

### Sensors: one hue per family, one icon per sensor

Twelve sensors cannot each get a hue and stay calm, colour-blind safe and AA. So colour scales by **family** (four hues from the Okabe–Ito set), and each sensor is told apart by its **icon and its name, which are always shown**. Everything comes from one registry, `src/lib/sensors.ts` (name, label, family, icon, default port, story noun): lists, filters, charts, legends and colours are derived from it, never hand-written.

| Family (`--family-*`)    | Hue            | Dark      | Light     | Sensors (icon, port)                                                     |
| ------------------------ | -------------- | --------- | --------- | ------------------------------------------------------------------------ |
| Remote shells `shell`    | sky blue       | `#5ea6f7` | `#1c6bc9` | SSH (square terminal, 22), Telnet (router, 23), ADB (smartphone, 5555)   |
| Web & APIs `web`         | reddish purple | `#d98bcb` | `#a6458f` | Web (globe, 80), Docker (container, 2375), Synology (hard drive, 5000)   |
| Databases `data`         | bluish green   | `#3cc6a4` | `#0a7a62` | Redis (database zap, 6379), MySQL (database, 3306), MSSQL (server, 1433) |
| Windows & VoIP `windows` | ochre          | `#e0b341` | `#8a6100` | RDP (monitor, 3389), SMB (folder, 445), SIP (phone, 5060/udp)            |

- **No fifth hue.** A new sensor joins the family whose attacks it resembles; it never gets a new hue. Okabe–Ito has no free hue left (vermillion and orange belong to severity), and every candidate tried collapses onto an existing family for deuteranopes and protanopes (a violet such as `#a78bfa` lands on sky blue at ΔE2000 < 1), and the globe arcs carry no icon or name to tell them apart. The Synology NAS is attacked through its DSM web portal, so it is a Web & APIs sensor.
- Badges, dots, tiles, map arcs and the default charts use the **family** hue. Each family hue is AA (≥ 4.5:1) as text on `--bg`, `--surface` and its own tint (`tint-family-*`: 14 % in dark, 10 % in light).
- `--sensor-*` are **per-sensor shades** of the family hue (base, lighter, deeper), used only as fills in the "Sensors" chart split. Never text; ≥ 3:1 on `--surface` and `--bg`, and distinct inside a family (tested in `contrast.test.ts`).
- Stacks always run in registry order, so one family is one contiguous block of its hue.
- The sensor filter is a multi-select popover (`SensorFilter`), grouped by family, typed to narrow, a family row toggles all its sensors. It writes `?sensor=ssh,telnet` (comma list; no param = every sensor). The API receives repeated `sensor=` params.

### Severity

| Level   | Meaning                                        | Icon          | Dark      | Light     |
| ------- | ---------------------------------------------- | ------------- | --------- | --------- |
| info    | Connected or probed                            | info          | `#a1a4ac` | `#4f525a` |
| notice  | Tried credentials or sent requests             | dot in circle | `#ecedef` | `#0f1013` |
| warning | Got a shell or ran commands                    | triangle      | `#f0883e` | `#b54708` |
| severe  | Download attempt, malware tag, exploit payload | octagon       | `#f2555a` | `#c8242b` |

**Red is reserved for severe.** Tags that mean a payload or exploit (`php2shell`, `crypto-miner`, `mirai`, `malware-drop`, `container-escape`, `sql-rce`, `eternalblue`, `synology-exploit`, `c3rb3r`) get a small red diamond. Tags that mean harm short of a payload (`db-ransom`, `redis-rogue-master`, `sip-fraud`, `persistence`) get a small orange triangle and make the session a warning. All other tags are neutral. Each marker has an sr-only word ("severe", "warning"). Deltas on KPIs are never green or red: for a honeypot, "more" is neither good nor bad, so they use an arrow and words.

No decorative gradients. The only fills under lines are flat, 8 % opacity.

## Space, shape, elevation

- 4 px grid. Page gutters: 16 px on mobile, 24 px on tablet, 40 px on desktop. Content max width 1200 px. Cards pad 16 px (mobile) / 20 px. Sections are separated by 24 px or more.
- Radius: 4 px chips, 6 px controls, 8 px small cards and nav items, 12 px cards. Pills are fully rounded only for the sensor share bar.
- Elevation: in dark, a border plus a faint top highlight (`--shadow-sm`); shadows only for overlays. In light, a soft 1–2 px shadow.

## Motion

- 150 ms (hover), 200 ms (fades), 250 ms (slide-in), all `cubic-bezier(0.22, 1, 0.36, 1)` (ease-out).
- **Entrance (M19).** Tokens in `tokens.css`: `--motion-card-duration` 320 ms, `--motion-card-distance` 8 px, `--motion-stagger` 60 ms (capped after `--motion-stagger-max` = 5 cards, so the delay never passes 300 ms), `--motion-page-duration` 200 ms, `--motion-page-distance` 4 px. A card uses `animate-card-in motion-stagger` with `--motion-i` set to its position, so a row of cards settles one after another. The app shell wraps every route in `animate-page-in`, a short fade with 4 px of travel. Both are removed (not shortened) under `prefers-reduced-motion`, with `?motion=off`, and when a test sets `window.__SUCKERPOT_MOTION__ = { freeze: true }` (screenshots do), via `data-motion="off"` on the root element (`src/lib/motion.ts`).
- New feed items slide in 6 px from above (`animate-slide-in`). Numbers tween over 600 ms (`AnimatedNumber`). The live dot pulses slowly (2.4 s).
- `prefers-reduced-motion: reduce` turns every animation and transition off; tweens jump to the final value.

## Content rules

- **A sentence before a chart.** `FindingCard` has a mandatory `finding` prop: the plain-English claim the chart proves. Page headers carry one sentence too ("380 sessions from 265 addresses in the last 24 hours.").
- **Stories, not rows.** A session reads as `describeSession()` writes it: "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file". The function is pure and unit-tested (`src/lib/describe-session.test.ts`).
- **Everything clickable.** IPs, tags and sensor counts link to the filtered Attacks view. Filters live in the URL (`?sensor=ssh&src_ip=…`).
- **Times** are stored in UTC, shown relative ("5 min. ago") with the absolute time and the browser time zone on hover.
- **Long runs fold.** Repeated login attempts or HTTP requests in a timeline collapse into "Show 89 more login attempts · 2 min 9 s". Commands never fold: they are the story.
- **Empty and loading states** keep the final layout (skeletons have the same footprint) and say what is missing and what to do.

## Screenshot mode

"Mask IPs" in the sidebar footer, or `?mask=1` / `?mask=0` on any URL (persisted per browser), masks every address: `203.0.113.42` becomes `203.0.x.x`, and IPv4 addresses inside free text (URLs, commands, live summaries, the IP filter chip and page headlines) are masked the same way. Copy buttons are hidden while masked. Use it for any screenshot of real data.

## Which red, where

- A session is severe when it downloaded something or carries a payload tag (`sessionSeverity`).
- A single event gets the red icon only when the event itself is severe (`isSevereEvent`): a download attempt, or the event that carries a tagged exploit: an HTTP request for `php2shell` or `container-escape`, an SMB probe (`scan`) for `eternalblue`, a SQL command for `sql-rce`. A failed login in a session tagged `malware-drop` stays neutral; the red-marked tag badge already says it.

## Terminal replay

The replay terminal is always dark, in both themes, with its own muted ANSI palette (`src/components/replay/terminal-theme.ts`). Attacker-controlled colours never reuse a sensor hue or the "severe" red: an attacker printing red text must not look like a SuckerPot alert. Every ANSI colour is AA on the terminal background (tested). Replays keep at least 80 columns; on narrow screens the terminal scrolls sideways instead of re-wrapping the output. In screenshot mode the terminal masks addresses while keeping their length (`198.51.xxx.xx`), so columns stay aligned.

## KPI tiles

Every tile has the same structure: label, value, one footer line pinned to the bottom. The footer shows a neutral delta when a previous window exists, otherwise a plain hint. No sparkline in the Overview KPIs: the activity chart right below already shows the series.

## Bars and shares

Bars that stand for a sensor use that sensor's colour (the stacked activity chart, the sensor share bar). Every other bar is neutral: the share bars in top lists, an attacker's activity per day (an attacker spans sensors). Tinted backgrounds use the `tint-*` utilities only.

## Tags over time

Only one tag is red: the leading payload tag, which is what the card's finding sentence is about. Every other tag, payload or not, is a neutral lightness step, and payload tags keep a red-outlined diamond in the legend and tooltip. This keeps red rare even when most tagged traffic is malicious.

## Heatmap

Day × hour uses a five-step neutral scale (color-mix of `--fg` into `--surface`), a "Fewer … More" key, and a readout line for the hovered or tapped cell. Hours are shown in the browser time zone.

## Live page

Live is the screen left running on a wall or a second monitor, so the map is the hero and everything else stays out of its way. There is no 3D globe: a flat map is easier to read at a glance and puts every source in its real place at once.

**Layout, top to bottom.** The page header (title, one sentence, sensor filter, Pause), then one card: the map, full content width (the Live page lifts the 1200 px cap, up to 2400 px), about `100dvh - 19.5rem` tall on desktop (26rem to 72rem), 26rem on tablets, 11:8 on phones; the live ticker is the card's footer. Below the card, three ranking cards. On a 1440 × 900 screen the map, the ticker and the ranking titles are above the fold.

**The picture** (`components/map/activity.ts`): the last **15 minutes** of sources, aggregated **per country**, one arc per country to home, coloured by the country's dominant sensor family, thicker for more events (log scale) and fading with age (never below 22 % inside the window). A new event sends one short dash along its arc; active sources (last minute) pulse softly. Nothing flashes, and a quiet minute still shows where traffic came from.

- **Map** (`map/world-map.tsx`): Equal Earth, land and borders from Natural Earth 110m pre-projected into SVG paths (`scripts/gen-map-data.mjs`), country centres from `scripts/gen-centroids.mjs`. Presets "World" (the default, on every width: the first visit and the 0 key) and "Europe" (one click, or E), the choice remembered per browser. Presets fit the card edge to edge (no empty bands): "World" crops to the inhabited band, Alaska to New Zealand, and on near-square cards to the Americas through South-East Asia; on phones the map takes that box's own shape (11:8), so it fills with no empty band. Presets keep the 48 px overlay band clear. Wheel, drag, pinch and the keyboard (arrows, + / -, E, 0) pan and zoom; strokes, dots and labels keep their screen size.
- **Home** is a solid dot, a fixed ring, a slow pulse and a "⌂ Switzerland" label (from `GET /settings/site`), always on top and never covered by source labels.
- **Labels**: "FR 37" next to the 12 busiest visible sources, busiest first. Each label tries the right of its dot, then the left, above, below and the four diagonals, and never covers home, its label or a busier source's dot or label (a quieter dot may sit under it, still clickable); it is dropped only when every spot collides (the tight cluster around home at World scale), so the busiest neighbours keep theirs. Every source dot is a button (tooltip: country, events, addresses, sensors) that opens the country's Attacks view. The tooltip opens on the side away from home, so the lit arc stays visible.
- **Stats strip** (`FamilyStrip`): events per minute in total and per family, on the map's top-left corner on cards 896 px or wider, under the map otherwise. The family swatch is the arc colour, so the strip is also the legend. A family button filters the whole page (`?sensor=`), a second press clears it.
- **Ticker** (`LiveTicker`): the newest events as one row of fixed-width chips (sensor icon, flag, address, summary; red outline and icon for a severe event). A new chip fades in on the left while the others glide right (500 ms); the row is clipped with a short fade on the right. Hovering or focusing the ticker holds it; held events show as an "N new events" pill that resumes. Phones get the latest five as stacked `LiveEventRow`s instead. "All attacks" links to the full list.
- **Rankings** (`LiveLeaders`): Top addresses, Top countries, Top networks over the same 15 minutes, six rows each, each card opening with its finding ("France leads with 21% of events, from 10 addresses."). Rows show flag, name, up to three sensor icons, count and share, with a neutral share bar. Each row opens the filtered Attacks view (`src_ip`, `country`, `asn`).
- **Linked highlight**: hovering or focusing a ranking row, a ticker chip or a map dot lights that country everywhere: its arc goes full opacity and one pixel thicker, other arcs, dots and labels step back to 28 %, its tooltip opens on the map, and matching rows and chips get the hover background.
- **Pause** freezes the whole picture (map, rankings, ticker) at the newest event; Resume or the pill catches up.
- **Reduced motion**: no dashes, pulses, glides or tweens; the picture is the same. Screenshots set `window.__SUCKERPOT_MAP__ = { freeze: true }` for the same effect.
- **Weight**: the map paths are about 30 kB gzip, Live only. No WebGL, no three.js.

## Today

The home page at `/` (first item of Observe). Three to five cards in a two-column grid, each one the same shape: a small heading with an icon, one plain-English sentence written by `GET /today`, at most three items (each opens a filtered view), and one outlined action at the bottom. Cards are, in order: what happened in 24 h, new campaigns, act now (download servers worth blocking), new this week (first-seen networks, URLs, commands) and your exposure (only once a service inventory exists). An odd last card spans both columns. A card with nothing to report keeps its place, its sentence turns muted, and the action stays. Cards enter with the staggered `animate-card-in`.

- **One meta line** under the title: "Updated 17:22" (minutes, not seconds: the page refreshes every two minutes), then, if research scanners are hidden, how many sessions are left out and "Show them".
- **Numbers say what they count**: "82 sessions", "14 sightings", "41 times" (`countUnit`), the unit in the subtle colour. A campaign row has no number: its detail line already says "37 sessions from 9 sources".
- **Item icons carry meaning**: the sensor icon, the country flag, a tag; first-seen items get the icon of what they are (network, URL, command, username), so a card never repeats one glyph three times.
- **Act now is the only red** on the page: its heading icon turns `sev-severe` when it lists servers handing out malware. The word "Act now" carries the meaning; the colour only reinforces it.
- Glossary terms go in the sentence, never in the small card heading (one dotted underline per idea).
- Big changes read as a ratio: "15 times as many as the day before", not "1,415% more".

## Search and the glossary

- **Header.** Desktop has a slim sticky header above the content: the search box on the left (it looks like an input and opens the palette), and on the right what applies to every page: the research-scanner switch with its count (the count shows from `xl`), a hairline divider, and the live status. Phones get the search icon and live dot in the top bar, and the switch in the navigation drawer. The sidebar is one scroll area (Observe, Understand, Defend, System) above a short footer (theme, Mask IPs, account), so all of Defend fits a 1440 × 900 screen.
- **Palette.** The placeholder is short enough for a phone ("Search addresses, CVEs, hashes, domains"). Before typing it lists recent searches and three "Try" examples (an address start, a CVE, a campaign word) that fill the box. On phones it opens just under the top bar. `Ctrl+K` (`Cmd+K` on a Mac) opens the palette from anywhere. It searches addresses, campaigns, CVEs, file hashes and domains or URLs (`GET /search`: indexed prefix lookups, at most five hits per group, groups in a fixed order). Typing an address start such as `203.0.113.` lists the addresses under it. Results open the matching page (`/attackers/:ip`, `/campaigns/:id`, `/cves?cve=`, `/infrastructure?indicator=`); indicators are shown defanged and never as links. Recent searches show while the box is empty. A hit from a research scanner says so.
- **Glossary.** `lib/glossary.ts` holds one or two plain sentences per security term; the `Term` component draws the word with a dotted underline and opens the definition on hover, tap, or Enter (a real button, so keyboard and screen readers get it; it adds a visually hidden ", definition"). `TermText` wraps the first mention of each known word inside a sentence written elsewhere. Do not put a `Term` inside another button or link.

## Research scanners

Ingest labels sessions from known, harmless crawlers (Censys, Shodan...; the list is `ingest/rules/scanners.yaml`) `benign`. They are hidden everywhere by default: the desktop header (the phone navigation drawer) has a "Hide research scanners" switch (on by default; `?scanners=show` or `?scanners=hide` sets it, and the choice is kept per browser) with a line under it that always says how many sessions the last 24 hours hid, or how many it now shows. The flag lives in the API client (`setIncludeBenign`), which adds `include_benign=1` to every list, chart and summary request, so no page passes it around; flipping the switch refetches everything and reconnects the live feed. When scanners are shown, their sessions carry a neutral dashed "Research scanner" badge (never red: they are not a threat), the same `ScannerBadge` in lists and in the palette; the rules engine's `scanner` tag is not repeated beside it. Looking at one address by name (`?src_ip=`) always shows its sessions. The continuous aggregates behind long-window charts are not split by scanner.

## Settings

Read-only by design: a dashed note says settings live in `.env`. Four cards, each with a finding sentence: Sensors (Active / Quiet / Silent with icon and label; silent is a warning, never red), Enrichment (GeoIP provider, age, the required attribution text, quota meters), Data retention, Storage (database against its ceiling; red only when the disk guard is critical).

Tabs whose forms save to the server (Reporting) say so in the note instead. Each section with its own Save button shows `UnsavedHint` next to it while its fields differ from what was last saved, so a long tab never loses an edit silently.

## First-run setup

The audience is someone installing SuckerPot for the first time, so every step answers three questions in the same places:

- **What it is for**: the step title (`h2`) is one plain sentence (`WIZARD_STEPS[].sentence`).
- **Can I skip it?** and **What happens next**: a two-column `StepGuide` (`dl`, subtle labels, muted answers) sits right above the sticky action bar. The skip answer is `WIZARD_STEPS[].skip` (null hides it, as on the last step); "what happens next" is the next step's `teaser`, or `AFTER_SETUP` on the last step, so it stays right when the M29 network step appears.
- **Action bar**: Back on the left; "Finish later" and Next (or "Skip for now" while an optional step is not satisfied) on the right. The last step puts its own actions there instead ("Take the tour", "Go to Today"), never a second row of buttons in the body.
- **Never forward** (`NeverForward` in `setup/ports-table.tsx`): the one rule that must not be missed sits above the ports table, in both the setup step and Settings: a `role="note"` box with a `border-sev-warning/40` outline, a `ShieldAlert` icon in `sev-warning` and the dashboard port in mono. It covers the dashboard port, the admin SSH port and the DMZ. Never red: nothing has gone wrong.
- **VPN idle**: with the gate closed and nothing to trust, the step says "No VPN yet, so nothing leaves this machine.", shows a neutral `CircleDashed` "Idle" (not a warning: it is the expected first-run state), three numbered steps, and the upload card in its `first` mode ("Set up the tunnel"). `?vpn=none` in the mocks shows it.

## CVE watch

A ranked list of vulnerabilities under one plain-English finding ("3 new critical CVEs this week affect services we emulate"). Severity is a word plus a number: a filled orange triangle and a stronger word for critical, an outlined orange triangle for high, a neutral dot for medium and low (never red: red is for severe events). Feed prose (titles, descriptions, dates) uses `normal-nums`, because Inter's tabular figures also widen the hyphen ("pre - auth"). KEV is a small outlined badge with a tooltip, relevance is three dots plus a word, and matched services are neutral chips. The detail panel shows the description, the CISA entry, the sessions of ours that match (links to the filtered Attacks view) and a "Propose a trap" button that copies a plain-text sheet: nothing is built from it. Feed status and the optional NVD and GitHub keys sit under the list. Everything fetched from the feeds is rendered as text.

## Defend

Pages for people who act at their company: block, detect, check exposure. Each opens with a sentence that says what is ready ("44 addresses … are ready for your firewall").

- **Minimum score** is always one of three presets, from `SCORE_PRESETS` in `lib/defend.ts`: **High confidence 70+**, **Balanced 50+** (the default, no `min_score` in the URL) and **Everything 20+**, each with a one-line hint. The list filter, the export and the feed-token dialog use the same control; any other `min_score` in a URL falls back to Balanced.
- **Act before evidence.** On Blocklists the export and your overrides sit above the entries, because the entries load more as you scroll and anything under them would drift out of reach.
- **Scores**: a neutral meter, orange from 70 (a warning, never red), always with the number and a word (High, Listed, Seen).
- **Exposure cards** show their numbers as label-left, value-right rows, then one muted line (trend and last attack), so cards line up whatever the label length.
- Kinds have a title (`label`, "IP addresses"), a singular (`singular`, "IP address") and an in-sentence form (`phrase`, "IP addresses and domains"). Never derive one from the other with string tricks.
- The feeds-off state keeps the tab: the finding says feeds are off, a dashed note says how to turn them on, and "Create token" is disabled.

## Campaigns and techniques

A campaign is told as up to six **stages**, always in story order: Looking around, Getting in, Running code, Staying in, Bringing tools, The goal. Stages are neutral: each has one icon (`components/campaigns/stage-icons.ts`) shown next to its name, and never a hue (a hue means a sensor family or a severity). Seen and not seen differ by shape and words, not colour.

- **List** (`CampaignRow`): severity icon, name, scale in words with flags, a compact `StageTrail` (six slots in story order: an icon in a box where the stage was seen, a dot where it was not, and "3 stages, up to bringing tools" under it), sensor badges, status and last seen.
- **Detail**, top to bottom: header (severity, status, sensors, malware family, one sentence), the counters strip, then "How the attack unfolded": the six-step stepper (`StageTrail variant="steps"`, solid ring seen, dashed ring not seen) and the numbered `StoryStages` (a plain question, one sentence, ATT&CK chips that open this campaign's matching sessions plus an external link). On phones and tablets **What to do** comes right after the story; on desktop it heads the side column above the clues. Then a real excerpt (repeated lines folded into "× 4"), activity per day, and the latest sessions full width so each row keeps its one-line story.
- **Techniques**: the heatmap groups rows by stage (icon and name in each group heading), uses the neutral five-step scale, and the full technique name gets 19 rem on desktop.

## Alerts and reports

- **Rules read as sentences** ("Malware is dropped"), each with a switch. Switched on, a row reveals where it sends (`ChannelPicker`: a check when a channel is on, a dashed "+" when off, so the state never rests on a border shade) and, for event rules, the minimum severity ("Any", "Warning and up", "Severe only"). Both have a small visible label.
- **Delivery states** are an icon plus a word: Sent (status green), Waiting, Not sent (neutral), Failed (orange). Red stays for severe events.
- **The weekly report page** is drawn with the design system from the stored summary: four KPI tiles, "What to do next" as a numbered list, then one finding card per section (services, countries, behaviours, watched CVEs, campaigns, defanged download hosts as plain text, never links). "Print or save as PDF" opens the server's HTML page.
- **The printable report** (`ingest/ingest/reports/render.py`) is made to be forwarded as is: one A4 page, black and white, no colour carrying meaning, every value escaped, no script. Tables are capped at seven rows with an "N more" line and long values are cut with an ellipsis in print, so the worst case still fits one page.
- Prose with hyphenated words or IDs ("E-mail", "CVE-2026-…") uses `normal-nums`.

## Scripts

The library answers "what do attackers run here, and what does it do?" in one read. A row is the plain-English summary first, then the first three commands (mono, muted, cut at 90 characters), then one meta row: severity, "New this week", sensors, steps, campaign. Counts sit in fixed right-hand columns on desktop and on one line under the row on phones.

Script detail, top to bottom: the sentence (what it does, how often, which campaign), the badges, **Line by line**, the AI second opinion, techniques, facts, sessions.

- **Line by line** (`ExplainedLines`): a line-number gutter (mono, subtle, not selectable), the command on a `bg-surface-hover` code band, the explanation in prose (at most `max-w-3xl`), then a meta row with the severity first and the ATT&CK technique link. Long commands wrap inside their band, so a wrapped line never reads as the next command. Only notice, warning and severe get a badge: "info" on every line is noise. A line with no rule is italic and subtle. Rows fade in one after another (40 ms apart).
- **AI second opinion** (`AiExplanationCard`): a dashed `border-strong` card with no shadow, the "AI-generated, may be wrong" label (`AiLabel`) always in its header, muted text only and the same gutter as the rule lines. It must never read louder than the rule-based explanation, which is the source of truth. "Explain now" is admin-only; others read "Only an administrator can ask for this."
- Prose on these pages uses `normal-nums` ("4-step", "built-in"), as on CVE watch. Counts, line numbers and facts keep tabular figures.

## Loading

Heavy pages (Overview, Live, Attackers, attacker profile, session detail, styleguide) load on demand behind a `PageSkeleton` in the final layout. Recharts and xterm get their own chunks, so the first load stays small.

## Scrolling

Lists scroll with the window. The desktop sidebar scrolls as one block when the window is too short (nav items are 28 px tall from `lg`, so every group fits at 1440 × 900), never one group cut in half. A tab strip that scrolls sideways starts at the left and keeps the open tab in view. A box that scrolls (tab strips, segmented controls, a capped message body) takes `scroll-fade-x` or `scroll-fade-y`: its content fades out over 2 rem (2.5 rem vertically) at the edge that hides more, only while there is more, driven by its own scroll timeline (no JavaScript; browsers without scroll timelines show the plain box). The mask also fades borders and fills, so a framed box puts the class on the scrolling element inside the frame, never on the frame. The Live page has no scrolling list: its ticker and rankings are bounded (ten chips, six rows), and the full history is the Attacks list.

## Components

| Component                  | File                                     | Notes                                                                                                                                           |
| -------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| FindingCard ("Card")       | `finding-card.tsx`                       | eyebrow + finding sentence + optional detail, action, footer                                                                                    |
| StatTile                   | `stat-tile.tsx`                          | label, tweened value, neutral delta or hint, sparkline slot, loading                                                                            |
| Sparkline                  | `sparkline.tsx`                          | tiny line, flat 8 % area, accessible label                                                                                                      |
| SensorShare                | `sensor-share.tsx`                       | stacked bar + labelled legend, links to filtered list                                                                                           |
| SensorBadge                | `sensor-badge.tsx`                       | `badge` (family tint + sensor icon + label) or `dot`                                                                                            |
| SensorFilter               | `sensor-filter.tsx`                      | multi-select popover grouped by family, `?sensor=a,b`, keyboard: type, arrows, Enter                                                            |
| FamilyTile                 | `family-tile.tsx`                        | KPI per family: total in its hue, one line per sensor (icon, name, count), each a filtered link                                                 |
| LiveMap, WorldMap          | `map/live-map.tsx`, `map/world-map.tsx`  | Live hero card: flat map, stats strip, ticker footer; linked highlight                                                                          |
| FamilyStrip                | `family-strip.tsx`                       | events / min in total and per family; family toggles filter the page; doubles as the arc legend                                                 |
| LiveTicker                 | `live-ticker.tsx`                        | newest events as gliding chips (stacked rows on phones), hold on hover, "N new events" pill                                                     |
| LiveLeaders                | `live-leaders.tsx`                       | top addresses, countries and networks of the last 15 minutes, finding first, rows link to filtered Attacks                                      |
| SeverityBadge              | `severity-badge.tsx`                     | icon + label, or icon only with an accessible name                                                                                              |
| TagBadge                   | `tag-badge.tsx`                          | mono, neutral; red diamond for payload tags                                                                                                     |
| IPChip                     | `ip-chip.tsx`                            | mono, copy button, links to `?src_ip=`, `masked`, `chip` or `ghost`                                                                             |
| CountryFlag                | `country-flag.tsx`                       | SVG flag (`country-flag-icons`, one small asset each) + name tooltip, `?` for unknown                                                           |
| RelativeTime               | `relative-time.tsx`                      | shared 30 s clock, absolute time tooltip                                                                                                        |
| EventRow                   | `event-row.tsx`                          | icon per event type, mono details, red only for downloads, optional sensor accent                                                               |
| EventTimeline              | `event-timeline.tsx`                     | EventRows with folded runs                                                                                                                      |
| SessionStory               | `session-story.tsx`                      | IP chip + flag + origin + predicate, `inline` or `block`                                                                                        |
| SessionRow                 | `session-row.tsx`                        | one line on desktop, two on mobile, stretched link                                                                                              |
| FilterBar, SensorFilter    | `filter-bar.tsx`                         | URL-synced segmented control and removable chips                                                                                                |
| PageHeader                 | `page-header.tsx`                        | title (text, or a node such as a mono address that wraps) + one sentence + actions                                                              |
| MetaLine                   | `meta-line.tsx`                          | facts joined by middle dots that wrap cleanly: no dot ever ends or starts a line (phone rows of tables)                                         |
| UnsavedHint                | `form-parts.tsx`                         | "Unsaved changes" with a neutral dot next to a section's Save button; pair with `useUnsaved(value)`                                             |
| EmptyState                 | `empty-state.tsx`                        | icon, optional "Coming in Mx" badge, text, action                                                                                               |
| Skeletons                  | `skeletons.tsx`                          | text, row, list, tile, card                                                                                                                     |
| LiveEventRow               | `live-event-row.tsx`                     | one live event: sensor badge, summary (text only), tags, IP, flag, time; whole row opens the session                                            |
| LiveSensorTile             | `live-sensor-tile.tsx`                   | events in the last minute for one sensor, in its hue, links to filtered Attacks                                                                 |
| LatestEventsCard           | `latest-events-card.tsx`                 | FindingCard with the newest live events (Overview)                                                                                              |
| SensorActivityChart        | `charts/sensor-activity-chart.tsx`       | Recharts stacked bars (events per hour, fixed sensor order, sensor hues), legend with icons + totals linking to filtered Attacks, sr-only table |
| DayBars                    | `charts/day-bars.tsx`                    | 30 neutral daily bars for one attacker, sr-only table                                                                                           |
| TopList                    | `top-list.tsx`                           | ranked rows with printed count + share (bar is decoration), each row a filtered link                                                            |
| AttackerRow                | `attacker-row.tsx`                       | one-line attacker profile story; row opens the profile, chips/flags/tags open filtered lists                                                    |
| StageTrail                 | `campaigns/stage-trail.tsx`              | the playbook in story order: `compact` (lists, icon or dot plus words) or `steps` (detail, stepper with names); never a hue                     |
| StoryStages                | `campaigns/story-stages.tsx`             | numbered steps: icon, plain question, one sentence, ATT&CK chips (campaign sessions + external link)                                            |
| ExcerptBlock               | `campaigns/excerpt-block.tsx`            | real lines from one session, text only, back-to-back repeats folded with a count                                                                |
| CampaignRow, CampaignChip  | `campaigns/campaign-row.tsx`, `-chip`    | one campaign as one story line; "Part of campaign" on the session page                                                                          |
| TechniqueHeatmap           | `techniques/technique-heatmap.tsx`       | techniques by day, grouped by stage, neutral scale, readout line, sr-only table                                                                 |
| LiveIndicator, ThemeToggle | `live-indicator.tsx`, `theme-toggle.tsx` | shell chrome                                                                                                                                    |

Primitives (button, card, badge, tooltip, dropdown-menu, sheet, separator, skeleton, scroll-area, tabs, toggle, toggle-group, command, dialog, popover, input) come from shadcn/ui via the CLI and live in `src/components/ui/`. They read our tokens through the shadcn variable contract mapped in `index.css`. Do not edit them for one page: add a variant here instead.

## Structure for feature work

- **Navigation**: `src/app/nav.ts` lists every item with its `space` (Observe, Understand, Defend, footer) and an optional `badge`. The old Overview is shown as "Activity"; its route is still `/overview`.
- **Pages**: one file per page in `src/pages/`. Unbuilt pages are a "Coming soon" `EmptyState`; replace the file, the route already exists in `src/app/router.tsx`.
- **API clients**: one `src/lib/<feature>-api.ts` per feature, exporting its own `<feature>QueryKeys`. Do not extend `api.ts` or its `queryKeys`.
- **Mocks**: one `src/mocks/<feature>.ts` per feature (campaigns, defend, scripts, alerts, search, today), already imported by `handlers.ts`.
- **Styleguide**: add `src/pages/styleguide/<feature>.tsx` exporting `section: FeatureSection` (see `registry.ts`); it is picked up automatically, listed in the table of contents and cropped by the screenshot run.
- **E2E specs**: new specs go in `e2e/<feature>.spec.ts` and import `settle`, `shoot`, `shootTall`, `h1` from `e2e/helpers.ts`.
- **Settings** is a tab layout driven by `?tab=` (general, keys, users, audit, alerts, feeds). Add content to a tab, not a new section above it.
