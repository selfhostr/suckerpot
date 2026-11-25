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
- Scale (size / line height): `2xs` 11/16, `xs` 12/18, `sm` **13/20 (default UI)**, `base` 14/22, `md` 16/24, `lg` 18/26, `xl` 22/28, `2xl` 28/34, `3xl` 36/42. Running text keeps a line height of 1.5 or more (selfhostr guidelines, 6); `2xs` is for one-line labels only.
- Weights: 400 body, 500 labels and findings, 600 titles and KPI values. Titles and figures track at -0.02em.

### Type roles

Every title, label and figure uses a **role** (`@utility type-*` in `index.css`), never a raw size, so a card title or a KPI value is the same size on every page. Roles set size, line height, weight and tracking; the colour stays with the component. `src/styles/scale.test.ts` fails on a role that does not exist, on an `h1` without `type-page-title`, and on one-off sizes such as `text-[13px]`.

| Role                 | Size / weight               | Where                                                            |
| -------------------- | --------------------------- | ---------------------------------------------------------------- |
| `type-page-title`    | 22/28 · 600                 | the page `h1` where it is drawn (detail pages, setup, login)     |
| `type-section-title` | 18/26 · 600                 | a section between card groups ("Entries"), dialog titles         |
| `type-card-title`    | 14/22 · 500                 | a card's finding sentence, its title, sheet titles, empty states |
| `type-lede`          | 14/22 · 400                 | the sentence under a page or section title                       |
| `type-subtitle`      | 13/20 · 500                 | a heading inside a card ("API keys", "Recent sessions")          |
| body (`text-sm`)     | 13/20 · 400                 | text, table cells, md and lg controls                            |
| `type-eyebrow`       | 12/18 · 500                 | the label above a card title or a KPI value                      |
| meta (`text-xs`)     | 12/18 · 400                 | hints, timestamps, chips, sm controls                            |
| `type-column`        | 11/16 · 500 · caps, +0.04em | column labels over a list or table                               |
| `type-kpi`           | 28/34 · 600                 | the value of a KPI tile (StatTile, FamilyTile, KindTiles)        |
| `type-figure`        | 28/34, 36/42 from `sm`      | the headline figures that open Results                           |

The finding sentence is 500, not the 600 of other headings: it is a whole sentence, often two lines, and the eyebrow above it already names the card.

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

The focus outline is the text colour (`--ring` = `--fg`), 2 px with a 2 px offset, on every control (the selfhostr focus rule); inside a box that clips (a scrolling tab strip) it is drawn inset. The primary action is neutral (`--primary` is the text colour, inverted). There is no brand hue: a hue always means a sensor or a severity. The one exception is the product mark (`src/app/logo.tsx`, the same drawing as `public/favicon.svg`): its violet drop and dark tile are fixed colours inside the logo, never a token, and they do not change with the theme.

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

- 4 px grid. Page gutters: 16 px on mobile, 24 px on tablet, 40 px on desktop, the same on every page. Cards pad 16 px (mobile) / 20 px. Sections are separated by 24 px or more.
- **Page width: fluid.** Every page fills the content column beside the sidebar, with the gutters above, and grows when the sidebar folds (1680 px of frame on a 1920 px screen, 1864 px folded). The only cap on the frame is a safety one, 2560 px gutters included (`--container-page-wide`), so rows do not stretch across an ultra-wide screen. A route may declare `handle: { width: "prose" }` (`src/app/page-width.ts`): the frame stays the same, but the page's own column stops at 1152 px (`--container-page-prose`), left-aligned under the breadcrumb. Only the first-run setup, a text-heavy form, does. Lists, hubs, dashboards and detail pages never cap their frame: their text blocks cap themselves (`max-w-2xl` for a lede, `max-w-3xl` for an explanation), so lines stay readable while tables, charts and grids take the room.
- Pages use the room from `2xl` (1536 px), and only where it shortens the read: a third column (Results: three cards to a row, and seven figures on its band when takedowns are tracked; Patterns: the top values beside the tags), side by side panels (Hosts & URLs: the indicator summary beside the control servers), extra table columns (Attackers: network and events), and wider table cells so a place and a network fit on one line. Breakpoints are viewport widths, and the unfolded sidebar takes 240 px of it: a layout that needs more than about 1100 px of content waits for `2xl`, not `xl`.
- Cards of uneven height flow in CSS columns, not grid rows, so a short card never sits next to a hole.
- Radius, as in the selfhostr guidelines: 6 px chips (`rounded-sm`, the "plate"), 8 px controls, small panels and nav items (`rounded-md`, the button), 12 px cards (`rounded-lg`). 4 px (`rounded-xs`) only for marks inside a chip or a control (a copy button inside an address chip, a checkbox). Pills are fully rounded only for the sensor share bar and meters.
- Cards side by side in a grid row share one height (grid rows stretch); a card whose title sits outside its box is a bug, the title goes inside like `FindingCard`. Uneven stacks are two column stacks (Settings, Reporting, VPN), never a grid with holes.

### Sizes

One set of heights, as tokens in `tokens.css` and used by every control primitive (`h-(--control-sm)`):

| Token          | Height | Text                   | Where                                                                                     |
| -------------- | ------ | ---------------------- | ----------------------------------------------------------------------------------------- |
| `--control-sm` | 32 px  | 12 px                  | dense rows: filter bars, card header actions, table rows, toolbars, copy buttons          |
| `--control-md` | 36 px  | 13 px                  | forms: inputs, selects, the form `SegmentedControl` (`size="form"`), Save, dialog buttons |
| `--control-lg` | 40 px  | 13 px                  | the one action of a full-page flow (sign in, set a password), the selfhostr `.btn`        |
| `--chip`       | 22 px  | 12 px sans, 11 px mono | every badge and chip: sensor, severity, tag, scanner, flood, address, KEV, counts         |

- **One row, one height.** Every control in a filter bar is `sm` (button, input, select, segmented control, filter chip, switch box); every control beside a form field is `md`. A Save button next to a field is never smaller than the field.
- **Touch.** Under `(pointer: coarse)` `--control-sm` and `--control-md` become 40 px, so every control is a 40 px target on a phone or tablet (selfhostr 3.8). There is no `xs` button: an icon button is at least `icon-sm`.
- **Icons**: 16 px in every control and next to 13 to 14 px text, 14 px in chips and next to 12 px text, 20 px in an empty state's 40 px box. Lucide, stroke 2 (1.85 to 2.25 for small marks).
- **Cards** pad 16 px on phones and 20 px from `sm` (header, body and footer alike), 16 px between cards, KPI tiles the same with a 12 px gap between label, value and footer.
- **Tables** (CSS-grid lists): column labels in `type-column`, cells in `text-sm`, counts right-aligned with tabular figures, the header row padded like the rows under it.
- Elevation: in dark, a border plus a faint top highlight (`--shadow-sm`); shadows only for overlays. In light, a soft 1–2 px shadow.

## Motion

Motion explains a change; it never decorates. Calm and precise: slow to start, fast to settle, and nothing blinks. One authored motion per page (Today's live map); everything else is a short answer to what the reader just did.

- **Tokens** (`tokens.css`, mirrored in `@theme` so `transition`, `duration-*` and `ease-*` follow them): `--motion-instant` 100 ms, `--motion-fast` 140 ms (hover, colour, exits), `--motion-base` 220 ms (fades, enters, overlays), `--motion-slow` 320 ms (cards, disclosures, morphs, sheets), `--motion-tween` 600 ms (numbers, bars). Easings: `--ease-out` `cubic-bezier(0.22, 1, 0.36, 1)` for anything arriving, `--ease-in` for anything leaving, `--ease-move` `cubic-bezier(0.4, 0, 0.2, 1)` for something going from A to B. **An exit is shorter than its enter**: overlays (tw-animate-css `animate-in` / `animate-out`, every dialog, menu, popover and tooltip) enter on `--motion-enter` and leave on `--motion-exit`, whatever `duration-*` a primitive says; a sheet slides in on slow and out on base.
- **Only transform and opacity move.** The one exception is a disclosure's height. No `transition-[width]`, no animated `top`/`left`, no layout read in a loop.
- **Page changes** use the View Transitions API through React Router (`src/app/view-transitions.ts` turns its `viewTransition` option on for every navigation that changes the page; a filter or a `?tab=` that only rewrites the query string never animates the page). One transition for every page change: the sidebar and the top bars are named and stay put; the page under them fades out on `--motion-route-out` (100 ms) and rises in 6 px on `--motion-route-in` (220 ms). The overlay is painted in `--bg`, so a cross-fade dips to the page background, never to white or black. Back replays the transition. Browsers without view transitions fade the route in (`animate-page-in`).
- **Shared element.** The row that was clicked becomes the page it opens, and turns back on Back: an attacker's address becomes the profile's title, a campaign's name the campaign's title, a session's sensor badge the badge on the session page. Only one element ever carries the name (`subjectName()`), so the browser never drops the transition for a duplicate. Not on phones.
- **Entrance (M19).** `--motion-card-duration` 320 ms, `--motion-card-distance` 8 px, `--motion-stagger` 60 ms (capped after `--motion-stagger-max` = 5 cards, so the delay never passes 300 ms). A card uses `animate-card-in motion-stagger` with `--motion-i` set to its position.
- **Live rows.** New feed items slide in 6 px from above (`animate-slide-in`). The Attacks list checks for new sessions every 30 s: with its top in view they slide in and the rows below glide down; once the reader has scrolled down they wait behind an "N new sessions" pill (`NewRowsPill`) instead of pushing the list. Short ranked lists (top lists, Live's leaders, the latest events card) glide to their new order (`useReorderMotion`, FLIP with the Web Animations API).
- **Filter changes.** Numbers count to their new value (`AnimatedNumber`, 600 ms ease-out, written straight into the text node, no React render per frame). Bars are scaled, not resized (`BarFill`, `transform: scaleX` from the left), so they glide on the compositor.
- **Disclosures** open with a height animation: a native `<details>` where the browser interpolates to `auto` (`interpolate-size`, `::details-content`), a React disclosure with `Collapse` (grid rows 0fr to 1fr). Opening takes slow with an ease-out, closing base with an ease-in.
- **Skeletons** keep the final footprint and carry a faint highlight sweeping across them (`.skeleton`, transform only), not a pulse. `LiveIndicator` pulses slowly (2.4 s) where a page shows it; the shell's dot beside "Today" in the sidebar never moves.
- **Calm mode, phones** (below 640 px): no stagger, no travel (route and card distances are 0, so changes are plain fades), no count-ups, no reorders, no shared element (`calmMotion()` in `src/lib/motion.ts` for what script drives).
- **Reduced motion** (`prefers-reduced-motion: reduce`): entrances are removed, not shortened (a staggered card would sit invisible during its delay); every other animation and transition ends at once, delays included; view transitions are not started. Two loops slow down instead of freezing, because a frozen one reads as broken: a spinner turns once every 2.4 s and a skeleton breathes (opacity only). Numbers jump to their value. `?motion=off` and `window.__SUCKERPOT_MOTION__ = { freeze: true }` (screenshots) set `data-motion="off"` on the root and freeze everything, the two loops included.

## Content rules

- **A sentence before a chart.** `FindingCard` has a mandatory `finding` prop: the plain-English claim the chart proves. Page headers carry one sentence too ("380 sessions from 265 addresses in the last 24 hours.").
- **Stories, not rows.** A session reads as `describeSession()` writes it: "203.0.113.9 tried 37 SSH passwords, then ran 5 commands and tried to download 1 file". The function is pure and unit-tested (`src/lib/describe-session.test.ts`).
- **Everything clickable.** IPs, tags and sensor counts link to the filtered Attacks view. Filters live in the URL (`?sensor=ssh&src_ip=…`).
- **Times** are stored in UTC, shown relative ("5 min. ago") with the absolute time and the browser time zone on hover.
- **Long runs fold.** Repeated login attempts or HTTP requests in a timeline collapse into "Show 89 more login attempts · 2 min 9 s". Commands never fold: they are the story.
- **One rule for page titles.** The header and, in a group, the tab already say where you are, so a page does not repeat its name as a big title: `PageHeader` keeps an `sr-only` `h1` (screen readers and tests still find it) and draws only the one-sentence intro, with the page's "?" and its actions. A detail page (it has a back link) draws its title, because the title is the thing being looked at: an address, a script, a week. Setup has no breadcrumb and draws its own (`showTitle`). With no intro, no actions and the help in the switch row, the header takes no space.
- **Help where there may be doubt.** Every page has a "?" (`PageHelp`, texts in `HELP`): at the end of the page switch row when the page has a switch, after the intro sentence otherwise. A card, section or column whose meaning is not obvious has a smaller "?" beside its label (`CardHelp`, or the `help` prop of `FindingCard`; texts in `CARD_HELP`): what it shows, where the figures come from, what to do with it, in two or three plain sentences. Never describe what the page does not have. A test checks the sentence count and that every text is used.
- **Empty and loading states** keep the final layout (skeletons have the same footprint) and say what is missing and what to do.

## Language (i18n)

- **Nine locales**, one flat string file each in `src/i18n/locales/` (`en`, `fr`, `de`, `es`, `it`, `pt`, `pt-BR`, `ru`, `zh-Hans`). `en.json` is the source: a missing key falls back to English, and a test fails when a locale has a key that `en.json` lacks, when a key used in the code is not in `en.json`, or when a translation changes the `{placeholders}` of the English message.
- **i18next with ICU messages** (`i18next-icu`): `t("today_header_sessions", { count })` with `{count, plural, one {# session} other {# sessions}}`. Keys are snake_case, `<area>_<component>_<meaning>`, always a string literal at the call site. Data tables hold `tk("key")` and render with `t()`. Never call `t()` at module scope: the routed tree is remounted when the language changes.
- **One key is one whole sentence.** Never join translated fragments, never put markup in a message. A sentence with a link or a `<code>` takes a `{placeholder}` and `tNodes()` fills it with the node.
- **Not translated**: product and sensor names, commands, ports, file names, code, MITRE ids, and anything that comes from the server or the traffic. The charter rules apply in every language: plain words, no em dash, no emoji, warnings at full strength.
- **Numbers and dates** go through `lib/format.ts` (`formatNumber`, `formatRelative`, `formatAbsolute`...), which use the active locale (`pt` is formatted as pt-PT); tabular figures stay on. Use `intlLocale()` when an `Intl` formatter is built elsewhere.
- **Text grows.** German and Russian run about 40 percent longer than English. No fixed widths on buttons, tabs, badges or table headers that hold text; flex children that carry text get `min-w-0` and wrap or truncate. Check a change in `de` and `ru` at 1920 and 390 px.
- **Choosing**: the first visit reads `navigator.languages`, an explicit choice is kept in `localStorage`, and the selector is a card on Settings, General (`components/language-card.tsx`) that lists the nine languages by their own names; it is not in the profile menu. `<html lang>` follows.

## Screenshot mode

"Mask IP addresses" in the account menu (the profile block at the foot of the sidebar), or `?mask=1` / `?mask=0` on any URL (persisted per browser), masks every address: `203.0.113.42` becomes `203.0.x.x`, and IPv4 addresses inside free text (URLs, commands, live summaries, the IP filter chip and page headlines) are masked the same way. Copy buttons are hidden while masked. Use it for any screenshot of real data.

## Which red, where

- A session is severe when it downloaded something or carries a payload tag (`sessionSeverity`).
- A single event gets the red icon only when the event itself is severe (`isSevereEvent`): a download attempt, or the event that carries a tagged exploit: an HTTP request for `php2shell` or `container-escape`, an SMB probe (`scan`) for `eternalblue`, a SQL command for `sql-rce`. A failed login in a session tagged `malware-drop` stays neutral; the red-marked tag badge already says it.

## Terminal replay

The replay terminal is always dark, in both themes, with its own muted ANSI palette (`src/components/replay/terminal-theme.ts`). Attacker-controlled colours never reuse a sensor hue or the "severe" red: an attacker printing red text must not look like a SuckerPot alert. Every ANSI colour is AA on the terminal background (tested). Replays keep at least 80 columns; on narrow screens the terminal scrolls sideways instead of re-wrapping the output. In screenshot mode the terminal masks addresses while keeping their length (`198.51.xxx.xx`), so columns stay aligned.

## KPI tiles

Every tile has the same structure: label, value, one footer line pinned to the bottom. The footer shows a neutral delta when a previous window exists, otherwise a plain hint. No sparkline in a KPI row that sits above its own chart (Today's numbers and the hour strip): the chart already shows the series.

**Headline figures** (`StatTile variant="figure"`): the numbers that open Results are not cards. They keep the same three parts, drop the border and fill, take the `3xl` size from `sm`, and sit on one band between two hairlines. A page whose every block is the same bordered card has no first thing to read; the figures are it. Use them once per page, for the page's key numbers only; other KPI rows stay tiles.

## Bars and shares

Bars that stand for a sensor use that sensor's colour (the hour strip on Today, the sensor share bar). Every other bar is neutral: the share bars in top lists, an attacker's activity per day (an attacker spans sensors). Tinted backgrounds use the `tint-*` utilities only.

## Charts

A chart earns its place only when a picture answers the question faster than a number. Most of what the dashboard once drew as charts is a table or a figure now:

- **Over a period, a list with a sparkline** (`Sparkline`, `components/sparkline.tsx`): one row per thing (a tag, a technique), a count, a line of its days, and a change column. The line has no axes and is neutral; the number carries the value. Rows are sorted, so the order is the ranking. No heatmaps and no stacked bars with a legend of ten greys: they ask the reader to decode colour, and a sorted table with a line does not.
- **This against that, a figure** (Results: reports this month against last month): two numbers and a sentence, not two bars.
- **Change** is words and an arrow or a sign, never green and red (`+120%`, `New`, `No change`). It compares the second half of the period with the first.
- **Time of day** is not charted outside Today's hour strip: bots keep no office hours, so a day by hour map shows nothing to act on.
- **Diagrams that need room** (the flow diagram on Hosts & URLs) are off until asked for ("Show diagram", `?diagram=1`); the table beside it has the same facts.
- **Red** is for the one thing the sentence above is about: on Tags, the leading payload tag (a red square and a red line), while other payload tags keep a red-outlined diamond. Every other mark is neutral.
- Every chart and sparkline has an accessible name, and the numbers behind it are in the text beside it.

## Today

The home page at `/` (first item of Observe), and the screen left running on a wall or a second monitor. `/live` and `/overview` open it (with their query string), so old links keep their filters; it also holds what Overview had (the day's numbers, the activity per hour with a per-sensor split, the latest events). It answers three questions at a glance: is something happening now, how was the day, does anything need me. Everything else is one click away: every number, row, hour and item opens its filtered list.

**One screen, no scroll.** From `lg` the page is a CSS grid the height of the window (`100dvh` minus the header, the shell's padding and the version line, at least 40 rem), on the fluid page width, so it grows when the sidebar folds. Under the page header, two rows and two columns: **now** (the map card, and who is behind it) over **the day** (five numbers and the hour strip, and what to do). The right column is one width in both rows (`clamp(20rem, 26%, 26rem)`) and the day row is `clamp(16.5rem, 30dvh, 20rem)`, so the four cards line up on both edges and every component sizes to its cell. Below `lg` the cards stack in reading order (map, to do, the day, the rankings) and the page scrolls, kept short: three ticker rows, six ranking rows.

- **Header**: the title, the day's sentence from `GET /story` (glossary words as `Term`s), and on the right the sensor filter and Pause, which act on the live parts (map, ticker, rankings) and on the hour strip.
- **Map card**: see [The live map](#the-live-map). The map takes what the card leaves after the stats strip and the ticker.
- **Last 15 minutes** (`LiveLeaders`): one card with a switch, Addresses or Networks (the countries are on the map: its labels and dot tooltips). It opens with the finding of the ranking shown ("203.0.113.77 (France) is the busiest address: 116 events, 8% of the total."). On desktop it lists as many rows as fit the card (3 to 10, measured, never a clipped row).
- **The day** (`DayCard` in `pages/today.tsx`): five numbers in one row (Visits, Machines, Countries, Got in, Tried to install; `type-kpi`, each a link to its list, "Updated 17:22" on the right), a hairline, then the hour strip (`HourlyActivity`). No hint lines under the numbers: the header sentence already says what they count.
- **Hour strip** (`HourlyActivity`): visits per hour over 24 hours, one column per hour, stacked by family (the arc hues, so the map's strip is the same key) or, with the Families / Sensors switch, by sensor in the `--sensor-*` shades. Columns are at most 24 px wide with a 4 px round top and a square base, a 2 px gap between segments; hairline grid at zero, half and a round top value; a time label every six hours. Hover or focus shows a readout beside the column (anchored to the baseline, so it stays inside the card); a click or Enter opens that hour's sessions; the arrow keys, Home and End move between hours (one tab stop). An sr-only table carries every value. It follows the sensor filter.
- **To do** (`TodoList`): at most three items from `GET /today`, the ones with news first, in this order: form reports to submit, act now (servers to block), new campaigns, new this week, your exposure ("what happened" is the page itself). Each is one line pair: the card's name in medium weight, its sentence (two lines at most), a chevron; the whole row opens the page where it is handled. When nothing has news, "Nothing needs you right now." and the two first quiet items, muted. The last line is the alerts sent in the last 24 hours ("4 sent in the last 24 hours, the latest 14 min. ago: …"), linked to the alerts; hidden when the outbox cannot be read.
- **Act now is the only red** on the page besides severe ticker chips: its icon turns `sev-severe` when servers handed out malware.
- What left the page: the flow diagram (where from, which door, how far: the map and the five numbers carry it), the stage legend, the stories of the day (the sessions list tells every visit as a sentence) and the item lists of the to-do cards (each item opens the page that lists them).

## The live map

The hero of Today: the biggest card, and everything else stays out of its way. There is no 3D globe: a flat map is easier to read at a glance and puts every source in its real place at once.

**In the card**: the map on top, the stats strip under it on narrow cards, the live ticker as the footer. On phones the map has the World preset's own shape (11:8), 26 rem on tablets, and the rest of the card on desktop.

**The picture** (`components/map/activity.ts`): the last **15 minutes** of sources, aggregated **per country**, one arc per country to home, coloured by the country's dominant sensor family, thicker for more events (log scale) and fading with age (never below 22 % inside the window). A new event sends one short dash along its arc; active sources (last minute) pulse softly. Nothing flashes, and a quiet minute still shows where traffic came from.

- **Map** (`map/world-map.tsx`): Equal Earth, land and borders from Natural Earth 110m pre-projected into a static SVG asset (`map/data/world.svg`, by `scripts/gen-map-data.mjs`), country centres from `scripts/gen-centroids.mjs`. Presets "World" (the default, on every width: the first visit and the 0 key) and "Europe" (one click, or E), the choice remembered per browser. Presets fit the card edge to edge (no empty bands): "World" crops to the inhabited band, Alaska to New Zealand, and on near-square cards to the Americas through South-East Asia; on phones the map takes that box's own shape (11:8), so it fills with no empty band. Presets keep the 48 px overlay band clear. Wheel, drag, pinch and the keyboard (arrows, + / -, E, 0) pan and zoom; strokes, dots and labels keep their screen size.
- **Home** is a solid dot, a fixed ring, a slow pulse and a "⌂ Switzerland" label (from `GET /settings/site`), always on top and never covered by source labels.
- **Labels**: "FR 37" next to the 12 busiest visible sources, busiest first. Each label tries the right of its dot, then the left, above, below and the four diagonals, and never covers home, its label or a busier source's dot or label (a quieter dot may sit under it, still clickable); it is dropped only when every spot collides (the tight cluster around home at World scale), so the busiest neighbours keep theirs. Every source dot is a button (tooltip: country, events, addresses, sensors) that opens the country's Attacks view. The tooltip opens on the side away from home, so the lit arc stays visible.
- **Stats strip** (`FamilyStrip`): events per minute in total and per family, on the map's top-left corner on cards 896 px or wider, under the map otherwise. The family swatch is the arc colour, so the strip is also the legend. A family button filters the whole page (`?sensor=`), a second press clears it.
- **Ticker** (`LiveTicker`): the newest events as one row of fixed-width chips (sensor icon, flag, address, summary; red outline and icon for a severe event). A new chip fades in on the left while the others glide right (500 ms); the row is clipped with a short fade on the right. Hovering or focusing the ticker holds it; held events show as an "N new events" pill that resumes. Phones get the latest three as stacked `LiveEventRow`s instead. "All attacks" links to the full list.
- **Rankings** (`LiveLeaders`): Top addresses or Top networks over the same 15 minutes (see [Today](#today)). Rows show rank, flag, name, the network or AS number when the card is 22 rem or wider, up to three sensor icons (same width), count and share, with a neutral share bar. Each row opens the filtered Attacks view (`src_ip`, `asn`).
- **Linked highlight**: hovering or focusing a ranking row, a ticker chip or a map dot lights that country everywhere: its arc goes full opacity and one pixel thicker, other arcs, dots and labels step back to 28 %, its tooltip opens on the map, and matching rows and chips get the hover background.
- **Pause** freezes the whole picture (map, rankings, ticker) at the newest event; Resume or the pill catches up.
- **Reduced motion**: no dashes, pulses, glides or tweens; the picture is the same. Screenshots set `window.__SUCKERPOT_MAP__ = { freeze: true }` for the same effect.
- **Weight**: the map paths are about 30 kB gzip in `world.svg`, fetched by Today only (drawn with `<use href>`, coloured by the tokens) and cached as a hashed asset, never in the JS. No WebGL, no three.js.
- **Cost**: Today is left running, so idle must be cheap. The map is a stack of layers, each on its own compositing layer: land and borders (repainted only when the view moves), arcs, dashes, pulses, dots. Pulses and dashes are HTML elements animated with `transform` and `opacity` only, which the compositor runs without repainting anything: a pulse is a ring drawn at full size and grown from the dot (so the line stays 1 px), a dash a capsule moved along its arc by keyframes computed in `map/dash.ts`. Never animate an SVG attribute (`stroke-dashoffset`, `r`) or an SVG transform in a loop: it repaints the layer every frame. Pulses and dashes stop while the map is scrolled out of view or the tab is hidden. The map, ticker, chips and rankings are memoized, so a new event re-renders only what it changes.

## App shell

Modelled on the selfhostr siblings (dumbmonit's rail, dmsforall's sticky sidebar): one column of navigation, one slim header, the page.

- **Sidebar (desktop, from `lg`).** Sticky at the height of the window, in the page flow, so the content column takes the rest. Unfolded it is 240 px: the logo (a link to Today) with the fold switch beside it, then the three sections, then the foot. Folded it is a 56 px icon rail: the logo itself is the switch (it turns into the "expand" icon under the pointer or the focus), and every icon has its name as a tooltip on the right. `Ctrl B` (`⌘B`) folds and unfolds it, never while typing or under a dialog. The choice is kept per browser (`suckerpot.sidebar`). The fold is instant (no width transition, see Motion); the sidebar keeps its place through page transitions (`vt-sidebar`).
- **Sections, then entries.** Observe (binoculars), Understand (microscope) and Defend (shield) are the only icons in the list. Each section is a button that opens or folds its entries, listed right under it on a hairline guide, with no icons of their own. Pages that belong together are **one entry** (Attacks: Sessions, Attackers, Networks), so a section holds two to four rows: Observe is Today (with the live map) and Attacks [Sessions, Attackers, Networks]; Understand is Campaigns [Campaigns, Techniques], Payloads [Scripts, Files, Hosts & URLs] and Patterns; Defend is Block [Lists, Rules], Exposure [Services, CVEs], Reports [Queue, Results] and Network [Overview, Members]. The alert rules are a Settings tab (Alerts, beside Alert channels); the old `/live`, `/overview` and `/defend/alerts` addresses redirect, and a weekly report counts as Settings. Every section is open by default and the reader's folds are kept per browser (`suckerpot.nav.closed`). Only the sections scroll on a short window (`scroll-fade-y`); the foot stays in reach.
- **Page switch.** An entry with several pages shows a row of tabs at the top of each of them (`src/app/page-switch.tsx`), on a hairline the width of the page, with the page's "?" at the end of the row (`help-slot.ts`: `PageHeader` portals its help into the row): 40 px tall, 14 px medium labels, the current one `fg` with a 2 px `fg` underline, the others `fg-muted`. It is navigation, so it does not look like the segmented controls that filter a page (a period, a sort, a view), which often sit just below it. Plain links with `aria-current` (every page keeps its own address, filters and Back work), in a `nav` named "<entry> pages". The shell draws it outside the fading page and names it for view transitions (`vt-pageswitch`), so it stays put while its pages change under it. It never scrolls: from `sm` the tabs are as wide as their labels, 24 px apart; on a phone they share the width equally, which is why a page may carry a short `tab` name ("Networks", "Rules", "Queue", "Members") beside its title. An entry with only one page to show has no switch and leaves no space behind. Detail pages have no switch: their breadcrumb leads back to the list. Any other tab row inside a page is a filter of that page (Settings, the abuse report, Malware), never navigation between pages.
- **Where you are.** The current entry has the hover fill, medium weight and a solid segment on the guide, on every one of its pages and their detail routes (a session is under Attacks); its section's name and icon turn `fg`. A folded section that holds the current entry takes the fill itself. In the rail, the section's icon is filled, and its flyout (a menu to the right, the section name on top, then its entries) marks the entry with `aria-current`.
- **Foot.** Unfolded: one row of three equal buttons across the whole width, each an icon over its short name (Settings with a dot when an update is available, Docs, GitHub; the last two open a new tab), 56 px tall, bordered like a small control; under it the profile block: initials and the name in the nav label style (`text-sm`, medium), nothing else. In the rail they stay stacked as 40 px icons with tooltips on the right, the avatar last.
- **Profile menu**, short on purpose, opens above the block and is as wide as the sidebar (to the right of the rail when folded); every item has a leading icon: Theme (one item showing the theme in use, its icon follows the theme; a click switches light → dark → system and the menu stays open to show it), Mask IP addresses (eye-off, a check at the end when on), then Change password (not for the owner, whose password lives in `.env`) and Sign out. No header repeating the name, no role, no last sign-in, no version.
- **Version.** The running version is one 11 px line at the bottom right of every page, in `fg-subtle`, in the flow under the page so it never covers anything (as in dumbmonit). It links to Settings, where the Updates card says more; a 6 px dot marks an available update. Mock builds say "Mock data: nothing here is real traffic." beside it.
- **Live.** The connection to the live feed is a still 6 px dot beside "Today" (which carries the live map) in the sidebar (green connected, dimmed connecting, hollow offline). Nothing in the shell animates: no pulse, no blinking badge.
- **Header.** 56 px, sticky, opaque `bg` (no backdrop blur: it would repaint on every scrolled frame). On the left a breadcrumb: section, entry (left out when it is the page's own name), then page ("Observe / Attacks / Attackers", "Understand / Campaigns"); on a detail route the page is a link back to its list. On the right the research-scanner switch (its 24-hour count in the switch's tooltip and accessible description), a hairline divider and, flush right, the search box. No status, badge or tour button.
- **Phones and tablets (below `lg`).** A 56 px top bar: the drawer button, the mark, the name of the page and the search icon. The drawer is the same sidebar, unfolded, with the research-scanner switch and its count above the foot; picking a page closes it. Rows are 40 px tall there (28 px from `lg`). No bottom tab bar: pages keep their own sticky action bars at the bottom of the screen.
- **Settings is the system entry.** The guided tour ("Take the tour") and the styleguide (development and mock builds) are actions in the Settings header; `/styleguide` stays reachable and counts as Settings in the sidebar.

## Search and the glossary

- **Header.** See [App shell](#app-shell): the search box sits flush right in the desktop header and opens the palette; phones get a search icon in the top bar.
- **Palette.** The placeholder is short enough for a phone ("Search addresses, CVEs, hashes, domains"). Before typing it lists recent searches and three "Try" examples (an address start, a CVE, a campaign word) that fill the box. On phones it opens just under the top bar. `Ctrl+K` (`Cmd+K` on a Mac) opens the palette from anywhere. It searches addresses, campaigns, CVEs, file hashes and domains or URLs (`GET /search`: indexed prefix lookups, at most five hits per group, groups in a fixed order). Typing an address start such as `203.0.113.` lists the addresses under it. Results open the matching page (`/attackers/:ip`, `/campaigns/:id`, `/cves?cve=`, `/infrastructure?indicator=`); indicators are shown defanged and never as links. Recent searches show while the box is empty. A hit from a research scanner says so.
- **Glossary.** `lib/glossary.ts` holds one or two plain sentences per security term; the `Term` component draws the word with a dotted underline and opens the definition on hover, tap, or Enter (a real button, so keyboard and screen readers get it; it adds a visually hidden ", definition"). `TermText` wraps the first mention of each known word inside a sentence written elsewhere. Do not put a `Term` inside another button or link.

## Research scanners

Ingest labels sessions from known, harmless crawlers (Censys, Shodan...; the list is `ingest/rules/scanners.yaml`) `benign`. They are hidden everywhere by default: the desktop header (the phone navigation drawer) has a "Hide research scanners" switch (on by default; `?scanners=show` or `?scanners=hide` sets it, and the choice is kept per browser) whose description always says how many sessions the last 24 hours hid, or how many it now shows: a line under it in the drawer, the switch's tooltip in the header. The flag lives in the API client (`setIncludeBenign`), which adds `include_benign=1` to every list, chart and summary request, so no page passes it around; flipping the switch refetches everything and reconnects the live feed. When scanners are shown, their sessions carry a neutral dashed "Research scanner" badge (never red: they are not a threat), the same `ScannerBadge` in lists and in the palette; the rules engine's `scanner` tag is not repeated beside it. Looking at one address by name (`?src_ip=`) always shows its sessions. The continuous aggregates behind long-window charts are not split by scanner.

## Settings

Read-only by design: a dashed note says settings live in `.env`. Four cards, each with a finding sentence: Sensors (Active / Quiet / Silent with icon and label; silent is a warning, never red), Enrichment (GeoIP provider, age, the required attribution text, quota meters), Data retention, Storage (database against its ceiling; red only when the disk guard is critical).

Settings is a `wide` page built from the same parts as the rest (FindingCard, the control sizes, the type roles). The eleven sections are a vertical list on the left from `lg` (sticky, 208 px) and a select on a phone or tablet: a strip of tabs would scroll sideways and hide the last ones. The room left beside the list is used with two column stacks from 1760 px, never a grid with holes: on General the setup checklist and the sensors on the left, Language, Updates, Pipeline, Storage, Retention and Outbound traffic stacked on the right (two by two from 1360 px below that); on Reporting what a report says on the left and how it travels (sending, digest, replies) on the right (from 1760 px); on VPN the tunnel's status on the left and what changes it on the right. The API keys are tiles (three to a row from `2xl`) with their actions pinned to the bottom, so the buttons of neighbouring tiles share a line.

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
- **Act before evidence.** On Blocklists the export and your overrides sit above the entries, because the entries load more as you scroll and anything under them would drift out of reach. The firewall how-to (steps, copy, feed token) opens in a side sheet from "Firewall steps", like the Network tab's how-to, so the entries start near the top of the page.
- **Scores**: a neutral meter, orange from 70 (a warning, never red), always with the number and a word (High, Listed, Seen).
- **Exposure cards** show their numbers as label-left, value-right rows, then one muted line (trend and last attack), so cards line up whatever the label length.
- Kinds have a title (`label`, "IP addresses"), a singular (`singular`, "IP address") and an in-sentence form (`phrase`, "IP addresses and domains"). Never derive one from the other with string tricks.
- The feeds-off state keeps the tab: the finding says feeds are off, a dashed note says how to turn them on, and "Create token" is disabled.

## Campaigns and techniques

A campaign is told as up to six **stages**, always in story order: Looking around, Getting in, Running code, Staying in, Bringing tools, The goal. Stages are neutral: each has one icon (`components/campaigns/stage-icons.ts`) shown next to its name, and never a hue (a hue means a sensor family or a severity). Seen and not seen differ by shape and words, not colour.

- **List** (`CampaignRow`): severity icon, name, scale in words with flags, a compact `StageTrail` (six slots in story order: an icon in a box where the stage was seen, a dot where it was not, and "3 stages, up to bringing tools" under it), sensor badges, status and last seen.
- **Detail**, top to bottom: header (severity, status, sensors, malware family, one sentence), the counters strip, then "How the attack unfolded": the six-step stepper (`StageTrail variant="steps"`, solid ring seen, dashed ring not seen), drawn once, then the ATT&CK techniques as chips (`TechniqueChips`, once each, opening this campaign's matching sessions plus an external link). On phones and tablets **What to do** comes right after the story; on desktop it heads the side column above the clues. Then a real excerpt (repeated lines folded into "× 4"), activity per day, and the latest sessions full width so each row keeps its one-line story.
- **Techniques**: a table, busiest first (`TechniqueTable`): technique and name, the stage with its icon, a sparkline of the days, the first day seen in the window and the sessions. There is no list of techniques that were not seen.

## Alerts and reports

- **Rules read as sentences** ("Malware is dropped"), each with a switch. Switched on, a row reveals where it sends (`ChannelPicker`: a check when a channel is on, a dashed "+" when off, so the state never rests on a border shade) and, for event rules, the minimum severity ("Any", "Warning and up", "Severe only"). Both have a small visible label.
- **Delivery states** are an icon plus a word: Sent (status green), Waiting, Not sent (neutral), Failed (orange). Red stays for severe events.
- **The weekly report page** is drawn with the design system from the stored summary: four KPI tiles, "What to do next" as a numbered list, then one finding card per section (services, countries, behaviours, watched CVEs, campaigns, defanged download hosts as plain text, never links). "Print or save as PDF" opens the server's HTML page.
- **The printable report** (`ingest/ingest/reports/render.py`) is made to be forwarded as is: one A4 page, black and white, no colour carrying meaning, every value escaped, no script. Tables are capped at seven rows with an "N more" line and long values are cut with an ellipsis in print, so the worst case still fits one page.
- Prose with hyphenated words or IDs ("E-mail", "CVE-2026-…") uses `normal-nums`.

## Scripts

The library answers "what do attackers run here, and what does it do?" in one read. A row is the plain-English summary first, then the first three commands (mono, muted, cut at 90 characters), then one meta row: severity, "New this week", sensors, steps, campaign. Counts sit in fixed right-hand columns on desktop and on one line under the row on phones.

Script detail, top to bottom: the sentence (what it does, how often, which campaign), the badges, **Line by line**, techniques, facts, sessions.

- **Line by line** (`ExplainedLines`): a line-number gutter (mono, subtle, not selectable), the command on a `bg-surface-hover` code band, the explanation in prose (at most `max-w-3xl`), then a meta row with the severity first and the ATT&CK technique link. Long commands wrap inside their band, so a wrapped line never reads as the next command. Only notice, warning and severe get a badge: "info" on every line is noise. A line with no rule is italic and subtle. Rows fade in one after another (40 ms apart).
- Prose on these pages uses `normal-nums` ("4-step", "built-in"), as on CVE watch. Counts, line numbers and facts keep tabular figures.

## Loading

Heavy pages (Today, Attackers, attacker profile, session detail, styleguide) load on demand behind a `PageSkeleton` in the final layout. Skeletons are shaped like what they stand for (a top list's skeleton has the rank, label, count and share of a row) and shimmer faintly. Recharts and xterm get their own chunks, so the first load stays small.

## Scrolling

One scroll model, four rules.

1. **Lists and tables scroll the window.** Never an inner box. Column headers are sticky just under the app header (`sticky top-14 z-10 bg-surface`; the header is 56 px on every width). The card around a list uses `overflow-clip`, not `overflow-hidden` (hidden makes the card a scroll container and breaks the sticky header), and a table is not wrapped in `overflow-x-auto` for the same reason. Long lists keep `@tanstack/react-virtual` with `useWindowVirtualizer` and a `scrollMargin`; the list height is the virtualizer's total size, with one skeleton row at the end while another page exists.
2. **The next page loads by itself.** Virtualized lists fetch when the last drawn row is within ten rows of the end. Plain (not virtualized) paged lists end with `LoadMore`, which fetches when it comes within a screen of the viewport and stays a real button for keyboard and no-IntersectionObserver use. There is no "Load more" that only a click can use.
3. **Inner scroll is for raw text only** (strings, code, a message body, a copy field, a deobfuscated script). The box is capped (20 rem), takes `scroll-fade-y`, and shows an "Expand" toggle (`useExpandable` and `ExpandToggle`) only when there is more to show; expanded, it grows to its full height and the window scrolls. The capped strings list hands over to a window-scrolled list when expanded.
4. **Overview cards show the latest eight rows** (`LATEST_ROWS`) and a ghost "See all" link in the card's action slot, top right, on every page.

On long pages the list is the main thing: summaries and filters stay compact above it, and the filter bar of Blocklists and Malware stays in view while the rows scroll under it (from `md`; on a phone it scrolls away, the column header is not shown there). On a short window only the sidebar's sections scroll (rows are 28 px tall from `lg`, and a section can be folded); its foot stays in reach. A tab strip that scrolls sideways starts at the left and keeps the open tab in view (Settings is no longer one: it is a vertical list from `lg` and a select below). A box that scrolls (tab strips, segmented controls, a capped message body) takes `scroll-fade-x` or `scroll-fade-y`: its content fades out over 2 rem (2.5 rem vertically) at the edge that hides more, only while there is more, driven by its own scroll timeline (no JavaScript; browsers without scroll timelines show the plain box). The mask also fades borders and fills, so a framed box puts the class on the scrolling element inside the frame, never on the frame. Today has no scrolling list and does not scroll on desktop: its ticker and rankings are bounded (ten chips, at most ten rows), and the full history is the Attacks list.

## Components

| Component                  | File                                     | Notes                                                                                                                                      |
| -------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| FindingCard ("Card")       | `finding-card.tsx`                       | eyebrow + finding sentence + optional detail, action, footer                                                                               |
| StatTile                   | `stat-tile.tsx`                          | label, tweened value, neutral delta or hint, sparkline slot, loading                                                                       |
| Sparkline                  | `sparkline.tsx`                          | tiny line, flat 8 % area, accessible label                                                                                                 |
| SensorShare                | `sensor-share.tsx`                       | stacked bar + labelled legend, links to filtered list                                                                                      |
| SensorBadge                | `sensor-badge.tsx`                       | `badge` (family tint + sensor icon + label) or `dot`                                                                                       |
| SensorFilter               | `sensor-filter.tsx`                      | multi-select popover grouped by family, `?sensor=a,b`, keyboard: type, arrows, Enter                                                       |
| FamilyTile                 | `family-tile.tsx`                        | KPI per family: total in its hue, one line per sensor (icon, name, count), each a filtered link                                            |
| LiveMap, WorldMap          | `map/live-map.tsx`, `map/world-map.tsx`  | Today hero card: flat map, stats strip, ticker footer; linked highlight                                                                    |
| FamilyStrip                | `family-strip.tsx`                       | events / min in total and per family; family toggles filter the page; doubles as the arc legend                                            |
| LiveTicker                 | `live-ticker.tsx`                        | newest events as gliding chips (stacked rows on phones), hold on hover, "N new events" pill                                                |
| LiveLeaders                | `live-leaders.tsx`                       | top addresses or networks of the last 15 minutes behind a switch, finding first, rows fit the card, rows link to filtered Attacks          |
| SeverityBadge              | `severity-badge.tsx`                     | icon + label, or icon only with an accessible name                                                                                         |
| TagBadge                   | `tag-badge.tsx`                          | mono, neutral; red diamond for payload tags                                                                                                |
| IPChip                     | `ip-chip.tsx`                            | mono, copy button, links to `?src_ip=`, `masked`, `chip` or `ghost`                                                                        |
| CountryFlag                | `country-flag.tsx`                       | SVG flag (`country-flag-icons`, one small asset each) + name tooltip, `?` for unknown                                                      |
| RelativeTime               | `relative-time.tsx`                      | shared 30 s clock, absolute time tooltip                                                                                                   |
| EventRow                   | `event-row.tsx`                          | icon per event type, mono details, red only for downloads, optional sensor accent                                                          |
| EventTimeline              | `event-timeline.tsx`                     | EventRows with folded runs                                                                                                                 |
| SessionStory               | `session-story.tsx`                      | IP chip + flag + origin + predicate, `inline` or `block`                                                                                   |
| SessionRow                 | `session-row.tsx`                        | one line on desktop, two on mobile, stretched link; a flood group adds the FloodBadge and its hours                                        |
| FloodBadge                 | `flood-badge.tsx`                        | neutral chip: waves icon, "flood" and the count ("x812"); never red, built from the ScannerBadge tokens                                    |
| FloodFilter                | `flood-filter.tsx`                       | SegmentedControl All / Hide / Only, written as `?kind=` (`session`, `burst`)                                                               |
| CredentialsCard            | `credentials-card.tsx`                   | finding + top usernames and passwords of a flood group (TopList, `scale="total"`), rows open Trends filters                                |
| SiblingGroupsCard          | `sibling-groups-card.tsx`                | the other flood groups of the same address and UTC hour, as compact SessionRows                                                            |
| FilterBar, SensorFilter    | `filter-bar.tsx`                         | URL-synced segmented control and removable chips                                                                                           |
| SegmentedControl           | `segmented-control.tsx`                  | one choice among a few; the track is a control: `md` (32 px, filter rows), `form` (36 px, beside fields), `icon`                           |
| PageHeader                 | `page-header.tsx`                        | name for screen readers (drawn only on a detail page) + one sentence + the page's "?" + actions                                          |
| PageHelp, CardHelp         | `page-help.tsx`, `lib/help.ts`           | the "?" popover: `PageHelp` for a page (`HELP`), `CardHelp` (or `FindingCard help`) for a card, section or column (`CARD_HELP`)            |
| MetaLine                   | `meta-line.tsx`                          | facts joined by middle dots that wrap cleanly: no dot ever ends or starts a line (phone rows of tables)                                    |
| UnsavedHint                | `form-parts.tsx`                         | "Unsaved changes" with a neutral dot next to a section's Save button; pair with `useUnsaved(value)`                                        |
| EmptyState                 | `empty-state.tsx`                        | icon, optional "Coming in Mx" badge, text, action                                                                                          |
| Skeletons                  | `skeletons.tsx`                          | text, row, list, tile, card                                                                                                                |
| BarFill                    | `bar-fill.tsx`                           | the filled part of a bar, scaled with `transform: scaleX` so a new value glides; put it in a clipping track                                |
| Collapse                   | `collapse.tsx`                           | a disclosure's panel: height animation (grid rows), content mounted on first open, inert when closed                                       |
| NewRowsPill                | `new-rows-pill.tsx`                      | "N new sessions" in a zero-height sticky slot: rows held while the reader is scrolled down, click brings them in and scrolls up            |
| AnimatedNumber             | `animated-number.tsx`                    | counts to a new value (600 ms ease-out) without re-rendering; jumps under reduced motion and on phones                                     |
| LiveEventRow               | `live-event-row.tsx`                     | one live event: sensor badge, summary (text only), tags, IP, flag, time; whole row opens the session                                       |
| LiveSensorTile             | `live-sensor-tile.tsx`                   | events in the last minute for one sensor, in its hue, links to filtered Attacks                                                            |
| TodoList                   | `today/todo-list.tsx`                    | Today's to-do: three items of `GET /today` (news first), one linked row each, then the alerts line                                         |
| HourlyActivity             | `charts/hourly-activity.tsx`             | Today's hour strip: visits per hour stacked by family or sensor, readout, click opens the hour, arrow keys, sr-only table                  |
| DayBars                    | `charts/day-bars.tsx`                    | 30 neutral daily bars for one attacker, sr-only table                                                                                      |
| TopList                    | `top-list.tsx`                           | ranked rows with printed count + share ("<1%", never "0%"; bar is decoration), each row a filtered link; `scale="total"` when rows can tie |
| AttackerRow                | `attacker-row.tsx`                       | one-line attacker profile story; row opens the profile, chips/flags/tags open filtered lists                                               |
| StageTrail                 | `campaigns/stage-trail.tsx`              | the playbook in story order: `compact` (lists, icon or dot plus words) or `steps` (detail, stepper with names); never a hue                |
| TechniqueChips             | `campaigns/technique-chips.tsx`          | the ATT&CK techniques of a campaign, once each (campaign sessions + external link)                                                          |
| ExcerptBlock               | `campaigns/excerpt-block.tsx`            | real lines from one session, text only, back-to-back repeats folded with a count                                                           |
| CampaignRow, CampaignChip  | `campaigns/campaign-row.tsx`, `-chip`    | one campaign as one story line; "Part of campaign" on the session page                                                                     |
| TechniqueTable             | `techniques/technique-table.tsx`         | techniques, busiest first: stage, sparkline of the days, first seen, sessions                                                              |
| TagTable                   | `trends/tag-table.tsx`                   | tags over the period: events, sparkline per day, change of the second half against the first; the leading payload tag is the one red mark |
| Sparkline                  | `sparkline.tsx`                          | a neutral line over a flat area, no axes, an accessible name                                                                               |
| LiveIndicator, ThemeToggle | `live-indicator.tsx`, `theme-toggle.tsx` | live status, theme switch (sign-in pages; the shell has its own)                                                                           |

Primitives (button, card, badge, tooltip, dropdown-menu, sheet, separator, skeleton, scroll-area, tabs, toggle, toggle-group, command, dialog, popover, input) come from shadcn/ui via the CLI and live in `src/components/ui/`. They read our tokens through the shadcn variable contract mapped in `index.css`, and their sizes, radii and focus are ours, not shadcn's defaults: heights from the control tokens, `Card` is 12 px with no inner padding of its own, `Badge` is a 22 px chip, dialog and sheet titles use the type roles, focus is the base outline. Do not edit them for one page: add a variant here instead.

## Against the selfhostr guidelines

The organisation's guidelines (sections 3 and 6) are the reference, as for dmsforall and mccb. Where SuckerPot follows them and where it keeps its own value, with the reason:

| Topic          | Guidelines                                     | SuckerPot                                                                                                                                                    |
| -------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Fonts          | Inter 400/500/600, JetBrains Mono, self-hosted | Same                                                                                                                                                         |
| Base text      | App 13 px, line height 1.5 or more             | Same (`sm` 13/20, `xs` 12/18)                                                                                                                                |
| Radii          | plate 6, button 8, card 12                     | Same (`rounded-sm`, `rounded-md`, `rounded-lg`)                                                                                                              |
| Focus          | 2 px ink outline, 2 px offset                  | Same (`--ring` = `--fg`)                                                                                                                                     |
| Primary action | Neutral, one per view                          | Same                                                                                                                                                         |
| Tap targets    | 40 px                                          | 40 px on touch screens (`pointer: coarse`); 32 and 36 px with a mouse, because the app is a dense dashboard (section 6) and the lists would double in length |
| Button         | 40 px, 0.875rem / 600                          | `lg` is that button; `sm` and default keep 12 and 13 px at 500 so a control's label matches the 13 px text around it                                         |
| Plate (chip)   | 22 px, 0.75rem / 600, 13 px icon               | 22 px, 12 px at 500 (600 is kept for "severe" only), 14 px icon so a chip icon matches the 14 px icons beside 12 px text                                     |
| Colour tokens  | `--c-*` names, ground `#07080a`                | `--bg`, `--surface`, `--fg`… with ground `#0b0c0e`, as section 6 lists; a light theme because users asked for one                                            |
| Eyebrow        | Mono 11 px, caps, +0.06em                      | Sans 12 px at 500 in sentence case: mono is for machine values only, and a caps label on every card is noise. Column labels over tables are 11 px caps       |
| Page title     | `clamp(1.75rem, …, 2.5rem)` (sites)            | 22 px: an app page title is a label, not a hero                                                                                                              |

## Structure for feature work

- **Navigation**: `src/app/nav.ts` lists the three sections, their entries and each entry's pages, plus Settings, the Docs and GitHub links; the sidebar (`src/app/sidebar.tsx`), the drawer, the page switch and the header breadcrumb read it. A new page is one line in an entry (it then appears in that entry's switch), or a new entry of one page. Page labels are unique across the app ("SuckerPot network" and "Network members", "Attacker networks"); a page may add a shorter `tab` name for the switch. A detail page adds a "back" link to its list.
- **Pages**: one file per page in `src/pages/`. Unbuilt pages are a "Coming soon" `EmptyState`; replace the file, the route already exists in `src/app/router.tsx`.
- **API clients**: one `src/lib/<feature>-api.ts` per feature, exporting its own `<feature>QueryKeys`. Do not extend `api.ts` or its `queryKeys`.
- **Mocks**: one `src/mocks/<feature>.ts` per feature (campaigns, defend, scripts, alerts, search, today), already imported by `handlers.ts`.
- **Styleguide** (`wide`): the Type section lists every role, Space & shape shows the three control heights, one filter row on one line, the chip height, icon sizes and radii, and Components shows a form (label, field, hint, Save) and the Settings tab strip. Add `src/pages/styleguide/<feature>.tsx` exporting `section: FeatureSection` (see `registry.ts`); it is picked up automatically, listed in the table of contents and cropped by the screenshot run.
- **E2E specs**: new specs go in `e2e/<feature>.spec.ts` and import `settle`, `shoot`, `shootTall`, `h1` from `e2e/helpers.ts`.
- **Settings** is a tab layout driven by `?tab=` (general, keys, users, audit, ports, alerts, feeds, reporting, vpn, network). Add content to a tab, not a new section above it.
