# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `./suckerpot.sh` (also `scripts/suckerpot.sh` and `just menu`): one entry point for a node, in the terminal. It opens a menu (arrow keys and Enter, or the key of an item; plain numbered list without a terminal or with `TERM=dumb`; no colour with `NO_COLOR`) to install a participant node or a full install, then to see the status, edit the node, update, check the ports, read the logs, repair, leave or join, and remove it. Every item is also a command: `./suckerpot.sh status`, `./suckerpot.sh edit name`, `./suckerpot.sh remove`, ... (`./suckerpot.sh help`).
- The participant installer asks its questions first, on a terminal, then runs by itself: after the consent, the **node name** (the pseudonym: a random name by default, the host name with a warning that it may identify you, your own, or none) and whether to show a **country**. The country is compared with a GeoIP database on the machine itself and never with an outside service; on a mismatch you choose what to keep. Without a local database, the installer only offers to download DB-IP's free country list from `download.db-ip.com` (default no). New flags: `--node-name`, `--no-node-name` (the same as `--pseudonym`, `--no-pseudonym`), `--country-check local|download|off` and `--non-interactive` (never read the terminal, as in CI). An answers file written for the old prompts still works: the new questions take their defaults.
- The end of a participant install shows the node's status (stack, sensors, enrolment, what to fix) and, while the hub has not decided on the join (proof of work), offers to wait ten more minutes. `./scripts/status.sh --wait` waits for that answer later, and `--brief` prints the status in five lines.
- `scripts/participant.sh set-name NAME|--none` and `set-country CC [--hide]|--none` change the node name and the country of a participant node from the terminal and wait for the hub's answer; a refused name puts everything back. They use the new `python -m ingest.network.cli update` (the participant counterpart of `PATCH /network/membership`), and `status --json` now has `country`, `show_country` and `profile_synced`.
- One command installs a node without git: `curl -fsSLO https://github.com/selfhostr/suckerpot/releases/latest/download/get.sh && sh get.sh`. `scripts/get.sh` says what it will do, downloads the release's node bundle (new release asset `suckerpot-node-vX.Y.Z.tar.gz`, built by `scripts/make-bundle.sh` from `config/node-bundle.list`; its SHA-256 is now in the signed release manifest as `node_bundle_sha256`), checks the manifest's signature with a pinned cosign and the bundle's hash, unpacks it into `~/suckerpot` and opens the menu. It fails closed and never uses sudo. `--ref BRANCH` installs an unsigned testing build of a branch. Updates of a bundle install download and check the new bundle (`verify-release.sh --bundle`); `just rollback` puts the previous files back. Git checkouts update as before.
- The entry point at the top of the folder is now `./suckerpot.sh` (it was `./suckerpot` on the dev branch only).
- A checkout of a branch (for example `git clone -b dev`) no longer stops the install with "images mode needs --version": on a terminal it asks whether to run the signed images of the newest release (default) or to build the checkout from source; without one it says to pass `--version latest`, `--version vX.Y.Z` or `--source`. `--version latest` is new. `./scripts/update.sh` in images mode on a branch that already holds the newest release changes only the images and keeps the branch's scripts.
- The menu of an installed node lists what is missing or worth doing (an update, a pending enrolment, no node name, no country, no host firewall, automatic updates off, the stack stopped), each with a key that does it, and says which version runs and which is available. **Edit the node** shows every setting with its value and comes back to that screen after a change.
- sudo: as root (a root login, or started with `sudo`) the node scripts and `get.sh` never call `sudo` and never ask for a password; started with `sudo` by the owner of the folder, the files they write are given back to that user, the update schedule goes into that user's crontab, and the Docker setup adds that user (`$SUDO_USER`), never root, to the `docker` group. As another user they call `sudo` only for the steps that need root, and with passwordless sudo they ask nothing; otherwise they say once that sudo asks for the password (`sudo -n true` tells), and sudo itself asks.
- `set-country` on a node whose ingest image has no `update` command (v0.15.0 and older) says which version runs and changes nothing; `set-name` falls back to the older join command.
- `scripts/edit.sh` changes the node name, the country, the sensors, the VPN, the automatic updates and the host firewall, and applies each change at once; `scripts/uninstall.sh` removes SuckerPot step by step, says what it keeps, and deletes the data volumes only when you type `DELETE` (or pass `--delete-data --yes`).

### Fixed

- The installer's log line of the chosen node name said `setcurious-maple-28`; it now says `set` or `none` and never the name.
- The node-name menu numbered its items with gaps (2, 4, 5) when a choice was hidden; every menu now numbers the items it shows 1 to n.

## [0.15.0] - 2026-11-25

### Added

- The dashboard is available in nine languages: English, French, German, Spanish, Italian, Portuguese (Portugal), Portuguese (Brazil), Russian and Simplified Chinese. The first visit follows your browser's languages (English when none matches); Settings, General has a **Language** card that lists the nine by their own names and remembers your choice in this browser. Every string of the UI is translated, and numbers, dates and times follow the language. Product and sensor names, commands, ports, file names, code, MITRE ids and everything that comes from the server or the traffic stay as they are, and the text of an abuse report sent to a provider stays in English. Translations live in `web/src/i18n/locales/<code>.json` (one flat file per language, `en.json` is the source, a missing key shows the English text) and a test checks them against `en.json`.

### Changed

- Final touches. The Today map's region buttons became a "World" toggle and a "Continent" dropdown, flush right in the same one-row bar as the stats strip and exactly as tall; the map is taller (a tighter row of figures and a shorter hourly chart below it); the space between the top bar and the first row of every page is gone; Patterns has no intro sentence (it is in its "?", now at the top right) and its 7 / 30 days switch sits right after the Sensors filter; the sidebar foot (Settings, Docs, GitHub) is plain icon buttons without labels or a line above.
- The live map on Today shows the whole world: its bar (stats, region switch, zoom) sits above the map instead of over it, so the north is no longer hidden, and every region is framed whole with some air around it, on a phone as on a wide screen. The "World / Europe" switch became World, Europe, North America, South America, Africa, Asia and Oceania, each framed from its own bounds, with a smooth glide between them (instant with "reduce motion"); an earlier "Europe" or "World" choice is kept. A new expand button opens the map at the size of the window, with the same switch and zoom, still live; `Esc` or the close button returns to the page.
- Shell polish. The sidebar foot is easier to hit: Settings, Docs and GitHub are three equal buttons across the whole width, icon-only ghost buttons with a tooltip, no border and no line above (the folded rail is unchanged), and the profile name uses the same size and weight as the navigation labels. The profile menu opens above the profile block, as wide as the sidebar (beside the rail when folded), and Theme and Mask IP addresses have a leading icon like the other items. The language moved from the profile menu to a card in Settings, General. Settings no longer scrolls sideways: the eleven sections are a vertical list on the left from `lg` and a select on a phone or tablet. A page no longer repeats its name under the tab that already says it (Payloads > Scripts showed "Scripts" twice): the header and the tab say where you are, every page opens with its one-line intro, and a detail page keeps its own title; the name stays for screen readers. An entry with only one page to show has no tab row and leaves no gap. Every page has a "?" at the end of the tab row (after the intro line on a page without tabs), and the cards whose meaning is not obvious (the last 15 minutes, visits per hour, the to-do list, the pipeline, sensors, storage, outbound traffic, the setup checklist, tags over time, what is new, indicators, probable C2 addresses, your overrides, the company check, services attacked but not in your list, your node, targets, do reports make a difference, the send queue, the form queue, blocked drafts) have a small one that says what they show, where the figures come from and what to do with them, in all nine languages.
- Fewer charts, more answers. Attacks: Sessions, Attackers and Networks share one filter bar, and the tabs carry the filters they have in common (sensor, country, network, tag, period), so the same view regroups by session, address or network. Payloads: Hosts & URLs is the one table of indicators and download URLs, with a role filter (payload source, contacted host, file hash); its flow diagram opens with "Show diagram". Files now shows the collected files first, and says why when there are none; an old `/malware?url=` link opens Hosts & URLs. Patterns: the four top lists are one card with a field switch, tags over time is a table with a line per tag and its change, and the day by hour heatmap is gone. Techniques is a table, busiest first, without the "not seen" chips. A campaign draws its stages once and lists its ATT&CK techniques as chips. Results: the three answer-delay tiles join the figures on the top band, reports over time is one "this month against last month" card, and the takedown curve is gone (the 48-hour figure says the same). SuckerPot network: the weekly chart and the members-by-country bars are gone; the 30-day tiles and one sentence remain.
- Today and Live are one page. Today now fits the screen without scrolling on a computer and uses the whole width (it grows when you fold the sidebar): the live map of the last 15 minutes is the centre, with the newest events as a ticker under it and the busiest addresses or networks beside it (the countries are on the map); below, the last 24 hours in five numbers and one hour-by-hour chart, stacked by sensor family or by sensor in the map's colours, with every hour a link to its visits; and a short to-do list (at most three items, the urgent ones first, then a line for the alerts sent in the last 24 hours). The flow diagram, the stage legend, the stories of the day and the item lists of the to-do cards left the page: each number, row and hour opens the list behind it. Overview is folded in too: its numbers are the five numbers of the day, its activity chart is the hour-by-hour chart (with its Families / Sensors switch) and its latest events are the ticker. `/live` and `/overview` open Today with their filters, and signing in lands on Today. On phones the parts stack, with three ticker rows.
- Dashboard navigation: the sidebar now has three sections, Observe, Understand and Defend, that open onto their entries right underneath. Pages that belong together are one entry, with a row of tabs at the top of the page between them: Observe has Today and Attacks (Sessions, Attackers, Networks); Understand has Campaigns (Campaigns, Techniques), Payloads (Scripts, Files, Hosts & URLs) and Patterns (the former Trends); Defend has Block (Lists, Rules), Exposure (Services, CVEs), Reports (Queue, Results) and Network (Overview, Members). The entry stays highlighted on all its pages and their detail pages, every page keeps its own address, and the tabs never scroll sideways, also on phones. Live and Overview are part of Today now: their entries are gone and `/live` and `/overview` open Today (the live dot sits beside Today). The alert rules, recent alerts and weekly reports moved to a new Alerts tab in Settings, beside Alert channels; `/defend/alerts` opens it. On a computer the sidebar folds to a rail of icons with their names on hover (the button beside the logo, or `Ctrl+B`), and the browser remembers it. At its foot, Settings, the documentation and GitHub share one row of icons above your profile (stacked in the folded rail). The profile shows your name only; its menu is short: the theme (one item that switches light, dark, system), Mask IP addresses, Change password and Sign out. The version moved to the bottom right of every page, small, with the "Mock data" note beside it in mock builds. The header shows where you are ("Observe / Attacks / Attackers") on the left and the search box on the right; the tour is "Take the tour" in Settings, which also links to the Styleguide in development and mock builds. The scanner switch keeps its count in a tooltip. On phones the drawer carries the same sidebar. Every address keeps working.
- Dashboard layout: every page fills the space beside the sidebar, and grows when you fold it, instead of stopping at 1200 or 1680 px (a safety cap at 2560 px only stops rows from stretching across ultra-wide screens). Only the first-run setup keeps its column at reading width. From 1536 px wide, Results puts three cards to a row, Trends shows its four top lists in one row, and Infrastructure puts the diagram beside the control servers. Long places and network names in the Sessions list no longer get cut. The Attackers list adds its network and events columns from 1536 px instead of 1280 px, so the tags no longer get squeezed out beside the unfolded sidebar.
- Results opens with its key numbers as large figures on one ruled band instead of a row of cards.
- Blocklists: the firewall how-to moved into a side sheet ("Firewall steps"), so the entries start higher on the page. Settings lists the sensors in two columns and puts Updates beside Pipeline.
- Dashboard design: one type scale and one set of sizes on every page, following the selfhostr guidelines. Page, section and card titles, KPI values and labels are the same size everywhere; buttons, inputs, selects and segmented controls share three heights (32 px in filter rows and card headers, 36 px in forms, 40 px for a page's one action, and 40 px for every control on touch screens), so a filter row or a form field and its Save button line up; every badge and chip is 22 px with 14 px icons. Cards use one radius (12 px) and one padding, side-by-side cards share one height, and the Probable C2 panel on Infrastructure now has its title inside its card like the diagram beside it. The focus outline is the text colour, 2 px, on every control.
- Settings uses the full page width like the other pages: on wide screens General, Reporting and VPN show two columns, and the API keys are tiles with their buttons on one line. The styleguide shows the final type roles, control heights, chips, a form and the Settings tabs.
- Navigation: the attacker ASN list is "Attacker networks" and the community is "SuckerPot network" in titles and Settings. The Abuse reports page lists Drafts first, then the send queue, replies and the archive. The abuse report page keeps its review actions in view while you scroll, and the options that change the message sit right under it. The Techniques page no longer has a second "Campaigns" button (use the tab). The Settings alert channels and network tabs link to the Alerts and SuckerPot network pages.
- Live is much cheaper to leave running. The map draws land and borders once on their own layer, from a static `world.svg` asset instead of an 81 kB path inside the JavaScript; the pulses around active sources and the dashes flying along the arcs run on the compositor instead of repainting the whole map every frame; pulses and dashes stop while the map is out of view or the tab is hidden; and a new event re-renders only the parts it changes. The picture is the same.
- Motion: changing page is now a short cross-fade with the new page rising in, while the sidebar and the top bar stay still. The row you open (an attacker, a campaign, a session) turns into the title of its page and back again on Back. New sessions appear at the top of the Attacks list on their own; if you have scrolled down they wait behind an "N new sessions" button instead of pushing the list. After a filter change, numbers count to their new value, bars rescale smoothly and top lists glide to their new order. "Technical details" and other disclosures open smoothly, and loading placeholders shimmer faintly instead of blinking. Menus and dialogs close faster than they open. On phones motion is reduced to plain fades; with "reduce motion" set in the system nothing moves, except that spinners turn slowly and placeholders breathe.

### Fixed

- The tab of `/network/members` is highlighted as Members, not Overview.
- The reporting section links in Settings no longer slide under the sticky header.
- Settings, First-run setup no longer says "The setup is finished" next to a checklist with open steps.

## [0.14.2] - 2026-11-24

### Added

- Abuse reports: form reports that wait in **To submit by form** are now hard to miss. An admin sees "N reports to submit by web form, for M providers" at the top of the Today page and as a card in its to-do list, with a link to the queue. `GET /api/v1/today` has a new `form_queue` field (admins only) and a `forms` card. The weekly report lists "Waiting for a web form: N reports (M providers)" in its next actions and its alert facts. Nothing shows when the queue is empty.

### Changed

- The shared directory of abuse forms lists 11 providers: Akamai Cloud (Linode), Cloudflare, Contabo, DigitalOcean, Google Cloud, Hetzner, Hostinger, Microsoft (Azure), netcup, OVHcloud and Scaleway. Each entry was checked on the provider's own abuse page. Only Cloudflare is marked as not taking mail (its page says it is generally unable to process complaints sent by email), so only Cloudflare desks move to the form queue; the others keep getting mail.

### Fixed

- Automatic update: a release that is only too young (under its 48 h minimum age) no longer stops the run. The next older release of the same major version is tried, and it is not marked bad. Before, after a burst of releases every run saw a young newest tag and gave up, so nodes stayed on an old version for days. `refused (too_young)` is now recorded only when no candidate is old enough. Releases that are only too young do not count against the 3 tries per run; at most 10 releases are checked per run. `status.sh` names the newest release that still waits after an update.
- Abuse replies: an acknowledgement that accepts mail but suggests a web form ("while we accept email reports, we encourage you to use our abuse form") is now an automatic receipt with a "form preferred" hint (migration 0042). Mail keeps going to that desk and the report page says "This provider also has a web form; mail still works". Before, it was read as a refusal and the desk was marked form only. A desk marked this way by an earlier version stays marked until you press **Clear this flag** on its report page. A refusal from a ticket portal ("we require you to submit all tickets via our online client support portal") now marks the desk form only, also when the mail wraps the phrase over two lines or when the reply matched no report and you linked it by hand. The web form phrases are broader and stricter: "we no longer accept reports by email", "must be submitted through", "use the form at" count; an instruction next to "you can also" or "we accept email", a "not monitored" next to "do not reply", and a registrar that sends you to the hosting provider do not.

## [0.14.1] - 2026-11-22

### Fixed

- Abuse reports: when a build merges or retires an old draft (marked superseded), its pending automatic send is now cancelled in the same transaction with the new code `superseded`. Before, it stayed pending forever, since the sender only takes drafts and reviewed reports. Sends already left pending this way (since v0.14.0) are cancelled on the next build.
- CI: the `podman` job installs the newest release tag whose images are published. On a release commit, the tag exists before the Release workflow pushes its images, so the job now checks the ingest image manifest anonymously and falls back to the previous tag.

## [0.14.0] - 2026-11-22

### Upgrading

- Abuse mail now goes out as one daily digest per recipient, at a digest hour picked at random per install (06:00 to 09:00 UTC, editable in Settings). On the first build after the update, open drafts are merged into one digest per recipient and pending automatic sends are cancelled (`digest_migration`), so no burst of mail follows the update. Turn digests off in Settings to keep one draft per recipient without the daily timing.
- Every abuse mail carries X-ARF v4 JSON reports (one per source). The older X-ARF v0.2 attachment is gone.
- Migrations 0039 to 0041. A downgrade is refused once a digest was sent or a report was submitted by form; use `just rollback` instead.

### Added

- Results: **Do reports make a difference?** (M38 phase 2). Each attacking address named in a sent
  report is paired with a similar address that was not reported (exact match on the kind of
  activity, the number of events and the last sighting; then the same ASN, the same provider size
  and country, or the same provider size). The card shows whether reported addresses were still
  seen attacking 7 and 30 days later less often, with a 95 % interval (Newcombe) and one of three
  fixed verdicts. Below 30 pairs, or 10 pairs where only one was seen, it shows progress and no
  number, and the wording never claims a cause. Weeks when the sensors were down are left out.
  Runs with abuse reporting (no need for takedown tracking), at most once an hour and bounded,
  from the node's own reports and sessions only; the dashboard reads counts, never an address, and the addresses are deleted once the
  30-day outcome is old. New `GET /api/v1/results/effect`, a `Report effect` line in
  `just status` and `report_effect` in `just status --json`. Migration `0039`.
- Opt-in random holdout for the report effect measure: `ABUSE_EFFECT_HOLDOUT_PCT` (0 by default,
  at most 10) holds that share of new attacking addresses back from reports for 21 days, as a fair
  comparison group. It delays reports and never sends one that would not have been sent.
- Abuse reports carry X-ARF v4 (XARF 4.2.0, JSON): one machine-readable report per source on
  every mail, next to the text and `evidence.csv`. One source gives the RFC 6522 shape
  (`multipart/report` with `message/feedback-report` and `xarf.json`); several sources give one
  `xarf-001.json` ... per source in a `multipart/mixed` digest, each named in the text. Every JSON
  is validated against the vendored XARF 4.2.0 schema before the send (`xarf_invalid` stops it).
  Tags come from allow-lists only (services, CVE ids past gate G, malware families);
  `destination_ip`, `evidence_source` and `confidence` are never set. New optional setting
  `xarf_org` (`reporter.org`, else the reply contact's domain). The report page has an X-ARF tab
  with one JSON per source (copy, download as `xarf_json`). Design M38, phase P1.
- One mail per provider per day: every source of every kind that shares an abuse address goes
  into one daily digest, due at the node's digest hour (random between 06:00 and 09:00 UTC per
  install, editable in Settings > Reporting > Sending, `GET`/`PUT /api/v1/abuse/digest`). At most
  100 sources per digest, the rest in parts 2 hours apart, at most 3 parts a day. An automatic
  digest carries only sources active in the last 7 days. A mail sent or marked sent by hand counts
  as the recipient's digest for the day; a second one the same day needs a confirmation
  (`409 recipient_sent_today`). Pacing, the daily cap (now counting mails), the hold, deferrals,
  `shared_host`, `form_only` and `undeliverable` still apply. A recipient can be switched to one
  spec-shaped mail per source (`xarf_strict`). Digests can be turned off (`digest_enabled`).
- Replies: a new match method `xarf_id` (a reply that quotes one source's X-ARF report id), and
  outcomes per source from verified replies that name sources in their own text
  (`abuse_subject_outcomes`, shown on the report page).
- **To submit by form** (M38 phase P3): desks that take reports only through a web form get one
  form report per ISO week instead of mail. Abuse reports has a new tab with one card per provider
  and week; each opens a copy kit: the form link with its host in text (opened in a new tab with
  `noopener noreferrer` and no referrer), your email, an optional name (new setting
  `form_name`), the abuse type, the addresses, first and last seen, a short description that ends
  with `ref <token>`, a log excerpt and the evidence file, each with a copy button. Every field
  passes the identity guard, alone and together; a blocked kit shows why and has no copy button.
  A fixed warning says that a form submitted from your browser does not go through the VPN.
  **Submitted** marks the ticked addresses sent (`sent_via = form`): they count as sent for the
  14-day resend, takedown tracking, Results (new channel "Form"), the effect measure and the
  one-mail-per-day rule, but not for the SMTP daily cap. Unticked addresses wait for the next
  form report. Nothing is ever submitted automatically. New `GET /api/v1/abuse/forms`,
  `GET /api/v1/abuse/reports/{id}/kit` and `POST /api/v1/abuse/reports/{id}/submitted`.
- The shared directory of abuse forms, `reporting/forms/abuse-forms.yaml`: data only, compiled to
  JSON and shipped with each release, reviewed by the code owners. Its validator (run in CI)
  refuses a form link that is not `https`, whose host is not under the provider's own domains,
  that is an IP address, or that carries user info, a port, a fragment or a query string other
  than `lang`; it warns on entries checked more than a year ago. An entry with `accepts_mail:
  false` (or `ignored`) sends that desk to the form queue before any mail goes; it matches by the
  exact mailbox domain, or by ASN only when the mailbox is on the provider's own domains. It ships empty:
  entries are added after a maintainer checks them on the provider's own website.
- A desk can be sent to the form queue by hand ("This desk takes only a web form"), and a form
  link learned from a verified reply can be suggested for the shared directory with a short text
  to post as an issue (new issue template "Abuse form"); a link outside the kit's rule is cut to
  the provider's site (`https://<host>/`) there. A link from a reply is never added to the directory or opened by
  itself, and is a link on the report page only under the kit's rule (`form_url_clickable`).

### Changed

- Migration 0040: subject kinds and X-ARF ids (`abuse_report_subjects.kind`, `xarf_id`), the
  `digest` report kind with `due_at`, `part` and `channel`, one draft and one reviewed report per
  recipient, `abuse_replies.match_method` accepts `xarf_id`, `report_settings.xarf_org` and
  `digest_enabled`, `report_smtp.digest_minute`, `abuse_recipients.xarf_strict`. On upgrade the open
  drafts of each recipient are merged into one digest on the first build and marked superseded;
  pending automatic sends of drafts are cancelled with `digest_migration`, so nothing leaves during
  the upgrade. Reviewed reports go as they are, with their X-ARF parts. `abuse_reports.sent_xarf`
  keeps the X-ARF files exactly as they left. The downgrade is refused while a sent digest exists
  (use `just rollback`).
- The identity guard decodes base64 inside JSON values (the X-ARF evidence and any other value)
  and in JSON MIME parts before it checks them. The node's network pseudonym is a deny term for
  abuse reports and exports (never for the pseudonym check of the network itself).
- Results group a digest under each kind of source it holds; the timeline counts mails once.
- The reply contact must contain a mail address (X-ARF names it): `reply_contact_not_email`
  blocks a draft otherwise.
- Migration 0041: `abuse_reports.week` (form reports), `sent_via` accepts `form`,
  `abuse_report_subjects.submitted_at`, `abuse_recipients.form_source` and `form_entry`,
  `report_settings.form_name`, and the takedown and Results channels accept `form`. Recipients
  already marked form-only by a reply get `form_source = reply`. The API may set `submitted_at`
  once and drop unticked sources only on a report it just marked sent by form (trigger). The
  downgrade is refused while a report submitted by form exists (use `just rollback`), and clears
  the form-only flags the shared directory set.
- Clearing "web form only" on a report page now keeps the shared directory from marking that
  desk again; only a new verified form-required reply marks it again.

### Removed

- X-ARF v0.2 (YAML `report.txt`, the `X-ARF: YES` header) on the node, and the `xarf_yaml`
  download. The hub keeps its own X-ARF until phase P4.

## [0.13.0] - 2026-11-22

### Added

- CI: a `podman` job (informational while Podman support is experimental). On every pull request
  it runs `scripts/e2e/podman.sh`: a Debian 13 machine with rootful Podman 5.4 in a privileged
  container, a real `./scripts/install.sh --participant --yes` with the release images, the status,
  `egress-check --isolation` (all must pass), a reboot, and a negative check (without the firewall
  tables the isolation checks must fail). The real hub is never contacted.
- Installer on Podman (experimental): `./scripts/install.sh` installs on rootful Podman. On a
  machine with Podman only it uses it without a question. With both engines, Docker is used while
  it runs; when Docker is off and Podman is packaged, a terminal install asks (Podman by default)
  and `--yes` takes Podman. `--engine docker|podman` decides. On Podman the installer opens the root
  Podman socket to this user (group `suckerpot-podman`, sudo) and starts itself again in that
  group, checks the host, writes `docker-compose.podman.yml` into `COMPOSE_FILE`, installs the host
  firewall (required) and the boot unit before anything starts, and starts the stack through
  `suckerpot-stack.service`. `--source` is refused on Podman. A refused run (memory, disk,
  consent, `--source`) changes nothing on the host: the socket group comes after those checks, with
  an explanation on screen. Docker installs do not change.
- Installer: `--update-check` (the daily release check of a full install, off by default),
  `--no-firewall` (participant mode: skip the host firewall; writes `SUCKERPOT_NO_FIREWALL=1`),
  and `--self-address` now also in full mode.
- Installer: when Docker is missing, it shows the commands that install Docker Engine from
  Docker's package repository on Debian, Ubuntu, Fedora and the RHEL family, with no script piped
  to a shell. The downloaded key file goes through a throwaway keyring: a file with more than one
  key is refused, and the package manager gets only the key with the pinned fingerprint. On a
  terminal it runs the commands after one "yes", then continues in the `docker` group with
  `sg docker`, or says to log in again. Without a terminal it prints the commands and stops.
  Every path that installs nothing exits with status 1.
- Installer: the rich display shows whether the hub accepted the new participant node ("Join the
  network"), as the plain output already did.
- Installer, plain output: `[n/10] ok` when a step ends, and a last `result: ok ...` or
  `result: failed step=N ...` line for scripts and CI.
- Podman support, phase 3 (experimental; installer support follows): the update, rollback,
  automatic update, restore, status and participant scripts run on an installed rootful Podman
  node. They first check the host and refuse with the reason: Podman 5.4 or newer, rootful,
  netavark with the nftables driver, cgroup v2, `docker-compose` 2.26 or newer, systemd, Docker not
  active, and `docker-compose.podman.yml` in `COMPOSE_FILE`. Every start on Podman (`just up`,
  update, rollback, restore, `just set`/`just sensors`, participant tools) goes through
  `systemctl start suckerpot-stack` when the boot unit is installed, so the stack is bound to the
  host firewall. New `scripts/host/podman-socket.sh` opens the root Podman socket to the group
  `suckerpot-podman` (with a tmpfiles rule for `/run/podman`) and sets netavark's firewall driver
  to nftables; the boot unit fails when netavark's nftables table is missing after a start.
  `participant.sh uninstall` offers to remove the socket access (the group is root-equivalent).
  `just up-test` refuses Podman. `participant.sh firewall` also
  installs the boot unit on Podman, `participant.sh uninstall` removes it, `participant.sh
  firewall status` reads the tables. `just status` shows the engine and the boot unit on Podman,
  and a missing firewall there is an error.


### Changed

- Docs: the install, participate, VPS and getting-started pages, the README, the network and update
  pages and the configuration reference now match the two-question installer (`--full` for a full
  install, the Docker offer from Docker's repository, `--update-check`, `--join-network`) and
  Podman support (experimental; Debian 13 and Ubuntu 26.04 supported, Fedora and RHEL 10
  experimental, host firewall required, socket group root-equivalent).
- The installer asks at most two questions: the install type (participant node or full install,
  when no `--participant` or `--full` says it), and the participant consent. Everything else takes
  its default, and each default has a flag:
  - a full install no longer asks about the SuckerPot network: it is off unless `--join-network`;
  - the admin password is generated and shown once (`--admin-password-stdin` for your own);
  - the install mode, sensors, dashboard access, admin user, low-memory mode, WireGuard file,
    own address, busy ports and admin SSH port are no longer asked (see `docs/install.md`);
  - little swap is a warning, not a question; a small participant machine takes the lite setup
    by itself;
  - the participant host firewall is installed without a question (`sudo` may ask for its
    password; `--no-firewall` skips it);
  - the end of a participant install no longer asks to recheck the ports;
  - the switch to full mode keeps the automatic updates without asking.
  With `--yes`, the default type stays the full install, so existing scripts keep working.
  Without a terminal and without `--yes`, an install needs `--full` or
  `--participant`, as before. A participant install without a terminal still needs `--yes`.
- A full install now sets `ADMIN_SSH_PORT` from the sshd configuration (or the ssh.socket port)
  when port 22 is free, as participant installs already did, so no sensor can take that port.
- When port 22 is busy, the SSH sensor moves to host port 2222 only if 2222 is free; otherwise it
  stays off, with a warning, like any other sensor whose port is taken.
- On a terminal with neither `--participant` nor `--full`, the type question defaults to `1`, the
  participant node (VPS participants are the main audience). The full-install commands in the
  README and the docs now pass `--full`.
- The participant summary gives the DMZ advice in one line that links to
  `docs/participate.md#open-the-ports`.

### Fixed

- Installer: a command that fails where no message was planned now names itself and its line
  (screen and `install.log`) instead of a bare "failed" step. On Podman, a client that could not
  reach its socket yet printed its version block where the disk check expected a folder, which
  ended a fresh install at step 1 without a word; only a real folder path is used now.
- `just rollback` across a database migration could stop with "SUCKERPOT_VOLUME_PREFIX must be
  set" before restoring the pre-update dump (images mode).
- Podman: helper containers (cosign, the broker test) no longer pass tmpfs `uid=`/`gid=` options,
  which Podman refuses; a restore no longer fails at the end of a successful `pg_restore`.

## [0.12.2] - 2026-11-21

### Added

- Podman support, phase 2 (the security core; the installer still refuses Podman):
  `docker-compose.podman.yml` and `scripts/ensure-networks.sh` (SuckerPot creates the sp-*
  networks with `isolate=strict`, `--internal` and `--disable-dns`), Podman lines in the host
  firewall templates (aardvark-dns DNS, `podman*` bridges, a `bridge suckerpot_bridge` table that
  blocks sensor-to-sensor traffic), the firewall made required on Podman (with an opt-out), and a
  `suckerpot-stack.service` boot unit that starts the stack only after the firewall. Docker nodes
  do not change: the Docker firewall rendering is byte-for-byte the same.
- `just isolation-check` (also part of `just egress-check`): from each running sensor, service
  names resolve, outside names do not, and there is no connection to the internet, to another
  sensor, or to the host's SSH and dashboard ports. Runs on Docker too; without the host firewall
  on Docker, a reachable host port is a note, not a failure.
  It also checks that the host firewall is really in force (the unit active and its nftables
  tables present; reading the tables needs root, so run it with `sudo` for the full check). On a
  Docker node, a firewall that is installed but not active, or whose tables are gone, now fails;
  `just status` reports it too.
- Network: `status.sh` shows the last network error with its age, a plain explanation and the
  fix when known ("Last network error: hub_unreachable (3 h ago). ..."). A member with no hub
  contact 2 h after joining, or the same error for more than 6 h, goes to **Needs attention**.
- Network: the installer and `participant.sh join` wait for the hub's answer. A refused
  pseudonym is reported with a free variant to use (`join --pseudonym NAME-NN`).
- Hub: dormant members. A node that enrolled more than 7 days ago and never sent a batch, or
  that sent no batch for 30 days, is left out of `members` and the member list of the network
  summary, the public feed statistics and the observatory (`nodes.members`, countries). The
  counted set is a weekly snapshot (`hub_count_snapshot`, hub-internal, kept five weeks), so
  one node cannot move a count day by day. A dormant node is kept and counts again from the
  next snapshot after a batch. New column
  `nodes.last_batch_day` (migration h0013; a node older than the 14 days of batch markers gets a
  conservative value). `hub-admin stats` shows the dormant count.
- Hub: a pseudonym held by a node that NEVER sent a batch (a reinstall's ghost) is freed for a
  new or renaming node once that holder made no request on two days the hub was serving (days
  with an outage, or with many address-limiter blocks or authentication failures, do not
  count; new table `hub_served_days` with three counters per day). A node
  that ever sent a batch never loses its name. Every other claim is refused with
  `pseudonym_taken`, also when two claims race.

### Upgrading

- `just egress-check` and `just isolation-check` now check from each sensor that an outside name
  (example.com) does **not** resolve. On a Docker node whose upstream resolver is on loopback for
  Docker (for example a local `dnsmasq` or `unbound` on `127.0.0.1` that Docker hands to the
  embedded resolver from the host), this can newly FAIL. That failure is a real leak: a
  compromised sensor could send data out through DNS queries. Fix it by giving Docker a resolver
  that the sensors cannot use through loopback, for example `"dns": ["192.0.2.53"]` with your
  router's or provider's address in `/etc/docker/daemon.json` (then `sudo systemctl restart docker`
  and `just up`), or by pointing `/etc/resolv.conf` at a non-loopback resolver. Then run the check
  again.
- The host firewall unit now starts after the stock `nftables.service` and is restarted with it
  (`PartOf=`), so `systemctl restart nftables` no longer leaves the host without the SuckerPot
  table. Run `scripts/host/install-firewall.sh FILE` once to install the new unit.
- Docker nodes, visible changes: `just egress-check` (and `just isolation-check`) now has sensor
  lines, and it FAILs when the host firewall is installed but not in force: the unit is stopped
  or failed (`sudo systemctl start suckerpot-firewall.service`), or its table is gone after a
  `nft flush ruleset` (`sudo systemctl reload suckerpot-firewall.service`). Run it with `sudo` to
  let it read the tables; without root, an active unit is only a NOTE. It also FAILs when no
  sensor runs. `just status` shows a new warning in the same case, "the host firewall is installed
  but its rules are not loaded", on full and participant nodes. A node without the host firewall
  is not affected (it stays optional on Docker).

### Changed

- The installer is easier to read on a terminal: a short list of steps with one progress bar in
  the project colours, the questions shown in the open, and a short final screen. The full output
  of every command goes to `install.log` (mode `0600`). A failed step shows the last lines of the
  log, the log path and, once `.env` is written, the `--repair` command. Ctrl-C restores the
  terminal. Without a terminal, with `TERM=dumb` or with the new `--plain` flag, the output is the
  same as before, plus the log path after a failure. `NO_COLOR` keeps the display without
  colours. The questions, flags and defaults do not change.
- Internal, no behaviour change: the host scripts call the container engine through
  `scripts/lib/engine.sh` (`dc`, `ctr`), and `.env` records `SUCKERPOT_ENGINE=docker`. This
  prepares Podman support; until it is finished, the installer and the updater refuse Podman.

### Fixed

- The blocklist worker's per-address read of `sessions` no longer times out after a restart or
  under load. It walked the address index and fetched one table row per session, scattered over
  a table that flood folding left mostly empty: about 200,000 page reads, 5.6 s with a warm cache
  and past the 30 s statement timeout with a cold one. A new covering index (migration 0038,
  window filter first, every column the read needs) turns it into an index-only scan: 0.44 s
  instead of 12 s on a copy of that table, from cold shared buffers. The first blocklist cycle
  now also waits 5 minutes after ingest starts.
- Network: `status.sh` no longer shows "Member as ..." with exit code 0 when the hub refused the
  join. A refused join (for example a pseudonym already used by another node) now reads
  "Not a member: ..." with the reason and the fix, exit code 2, and a **Needs attention** item.
  An enrolment in progress shows as "Joining", not as a membership.
- Network: a failing profile sync or batch no longer stops the pull of targets and the daily
  summary. Each step of the member cycle runs on its own and the first error is kept. A transport
  failure (hub out of reach, path closed) still ends the cycle, as before. A good signed answer
  of the hub counts as hub contact even when another step failed.
- Network: `participant.sh join` now also restarts a join the hub refused, and a member that
  passes `--pseudonym` sends the new name to the hub.
- The participant consent screen said signed releases install "once a day". It now says the
  check runs every 6 h and a release installs once it is 48 h old.
- Network: a refused enrolment heals by itself. A node left in state `error` after
  `pseudonym_taken` or `pseudonym_invalid` no longer needs a command: the network worker tries a
  new `NETWORK_PSEUDONYM` from `.env` on its next cycle, replaces a taken generated name (with
  backoff), and tries a chosen name again once every 24 hours. Only while the consent in `.env`
  is valid and fresh, and never after a leave. A node stuck this way heals on its first cycle
  after the update. `status.sh` says when SuckerPot tries again by itself.

## [0.12.1] - 2026-11-21

### Added

- Replies: the node now suggests the "Mail provider name". **Test connection** reads the headers
  of the last 20 mails (read-only, nothing marked as read) and counts the name on the top-most
  `Authentication-Results` header of each. The most common one (if on 3+ mails from 3+ sender
  domains and on at least half of them) is shown under the field with a
  **Use it** button, which fills the field but does not save it. While the field is empty, the
  regular check records the same suggestion for the settings page.
- Trap packs, phase 2: signed distribution (M37). A pack merged on `main` is signed in a
  protected GitHub environment (`trap-packs`, the owner approves), relayed unchanged by the hub
  to the feed site, fetched by `ingest` every 30 minutes through the route it already has (VPN
  egress, or `hubproxy` in participant direct mode), and loaded by the web sensor within 30
  seconds, without a restart. Ingest and the sensor each check the signature with the pack key
  and refuse a forged signature, another key or a lower `seq`. A kill list
  (`traps/disabled.yaml`) and `TRAP_PACKS_DISABLED` turn packs off, bundled ones too. For 48
  hours after a pack first loads, its CVE tags do not count as `exploit` activity (gate G). New
  settings `TRAP_PACKS_REMOTE`, `TRAP_PACK_KEY` and `TRAP_PACKS_DISABLED`, new volume
  `trap-packs`, new table `trap_state` (migration 0037), new recipe `just trap-import`, and
  `data.trap_seq` on web events. The pack key is not set yet, so downloaded packs stay off until
  a release ships it. See [Trap packs](docs/trap-packs.md#signed-distribution).

### Changed

- Trap pack evidence: the value of a common parameter (`page`, `id`, `s`, `offset`, ...) is never
  CVE evidence, however long it is, and `match.path` refuses `%xx` escapes like the needles do.

### Fixed

- The blocklist worker no longer fails every cycle on a large database. To mark demo addresses
  it read every `connect` event of the 30-day window again for each 2,000 candidate addresses
  (8 s and 1.4 GB of disk reads each time on a 5 GB node), and the cycle hit its 30 s statement
  timeout. It now reads only the addresses that sent a demo `connect`, from a new small partial
  index (migration 0036, empty on a node that never ran `just demo`). Each step of the cycle now
  runs in its own transaction, and a failure logs the step and the database error (for example
  `step ip-demo: QueryCanceledError: canceling statement due to statement timeout`) instead of
  only `DBAPIError`. The statement and its values are never logged.
- The live feed backfill and `/api/v1/events/recent` no longer time out on a large database. The
  query asked for the newest event ids with no time bound, so it decompressed and sorted every
  compressed `events` chunk (5 s on a node with 9 million events). It now reads the last 24 hours
  first and widens to 7 days, then to everything, only when the page is not full (0.2 ms on the
  same node). The rows and their order stay the same, except that an event stored more than
  24 hours after its own timestamp is not shown while newer events fill the page.

## [0.12.0] - 2026-11-21

### Upgrading

- ATT&CK labels, campaigns, blocklist scoring and the script library are now on by default.
  They only read your own database and make no outbound request. An install that never set
  `ATTACK_ENABLED`, `CAMPAIGNS_ENABLED`, `BLOCKLIST_ENABLED` or `SCRIPTS_ENABLED` starts running
  them after the update (the first campaign and script passes can use some CPU for a few minutes
  on a large database). To keep one off, set it to `false` in `.env`; an explicit `false` always
  wins.
- `scripts/env-migrate.sh` (run by `just update`) now removes the lines of the removed LLM
  explainer (`LLM_*` and `ANTHROPIC_API_KEY`) from `.env`. It prints the names it removed, never a value.

### Added

- Trap packs, phase 1 (M37). A trap pack is a data file that teaches the web sensor a new trap
  without a code change: byte needles, flags, an optional fake answer from a fixed template. The
  strict validator (`suckerpot_common.traps`) is shared by the sensor, ingest and the checks, and
  enforces size, count, memory and cost limits, an evidence rule for CVE claims and content rules
  for fake answers. An invalid pack is rejected alone with a log line. Packs are bundled in the web
  sensor image; `just trap-new`, `just trap-build` and `just trap-check` help write them (see
  [Trap packs](docs/trap-packs.md)). The PHPUnit `eval-stdin.php`, Log4Shell and Boa/GPON router
  rules moved from the sensor's code into three packs with the same behaviour, proven by a
  differential test. Requests that hit a pack trap carry `data.traps`.

### Fixed

- Abuse reports no longer name shared services. The never-block list now also holds video and
  social platforms, URL shorteners, and file, paste and code hosts, and every abuse candidate
  (attack source, payload host, command server) skips it, domain suffixes and addresses alike.
  A draft or queued send that names such a value is cancelled with the new code `shared_host`
  and shown as such in the dashboard. The hub's never-list gets the same entries.
- Replies from desks that only accept a web form ("reports sent to this address will not be
  processed", "this inbox is not monitored", "submit via our online portal") are now read as
  rejected. A matched one marks the recipient `form_only`: automatic sending skips it
  (`form_only`) and the report page shows the form link (kept only from a verified reply, on the
  provider's own domain). Migration 0035.
- Hard bounces mark the address `undeliverable` (one "user unknown" bounce, or two other 5.x.x
  bounces) and automatic sending skips it. A delayed-delivery notice is no longer counted as an
  automatic receipt, and the owner can clear both flags.
- Reply rules read "has been blocked" and "is no longer reachable" as resolved, "has been logged as
  ... is being investigated" as a ticket, and "forwarded the case details to our end customer" as
  an answer from a person, not a resolution. Rules never read the quoted original of a reply.

### Changed

- `.env.example` is much shorter: it lists only what a normal owner sets or changes (about 120
  names instead of 305). Limits, timeouts, rates, intervals, container ports, per-role database
  names and other tuning knobs are no longer in the template. They keep working with the same
  names and defaults, and are documented in the new "Advanced tuning" part of
  `docs/configuration.md`, which now starts with "Common settings". Documentation drift is fixed:
  `BACKUP_KEEP`, `AUTO_UPDATE_MIN_AGE_H`, `EGRESS_DENY_ASNS`, `NETWORK_DEFAULT_PINNED` and
  `RDP_NLA_MODE` are documented, and the empty "not used yet" section is gone.
- The `/styleguide` page is no longer part of the production web bundle. It loads only in
  `just web-dev` and the mock and demo builds.
- The ATT&CK, campaign, blocklist and script workers default to on (see Upgrading).
- Participant installs set themselves up without follow-up commands. `install.sh --participant --yes`
  now installs the host firewall when `sudo` works without a password (otherwise it prints the one
  command to run), and the interactive question defaults to yes. A failed update schedule no longer
  switches automatic updates off for good: the flag stays on, the installer prints the fix, and
  `--repair` tries again.
- `status.sh` and `participant.sh status` show a "Needs attention" block on a participant node when
  automatic updates are off, the host firewall is not installed, or the node runs a release at least
  three days older than the newest one it knows, each with the command that fixes it. Each is a warning
  (exit code 1).
- The documentation describes one product in four parts: Observe, Defend, Report and Share.
  A new [Reporting attacks](docs/reporting.md) page explains abuse reports at node and network
  level, the sending modes and pacing, and how to send without getting a mailbox blocked; the
  network report rules now match the hub code. The passivity rule is stated precisely (SuckerPot
  never probes an attacker, with the optional collector named as the one exception; reporting is off by default and the owner chooses manual, one-click
  or automatic sending). The development journal moved to `docs/dev/` (roadmap history,
  progress log, design notes), a short public [roadmap](docs/roadmap.md) was added, the docs
  index is organised by part, and one vocabulary is used (node, full install, participant
  install, hub, abuse report, sensor).

### Removed

- The last mentions of the LLM explainer (removed in 0.11.0) in the configuration reference.

## [0.11.13] - 2026-11-19

### Changed

- Automatic sending of abuse reports only takes reports whose last activity is less than 7 days
  old, newest first. Providers check the reported host when the mail arrives, and weeks later
  they close the report as "cannot be substantiated". A queued report that ages past 7 days is
  cancelled (`too_old`). An older report can still be sent by hand.

## [0.11.12] - 2026-11-18

### Fixed

- Automatic sending of abuse reports sent the due reports one after the other, about one a
  second. A mailbox provider took the burst for spam and refused the rest. Automatic sends now go
  at least 3 minutes apart. A "try later" reply (SMTP 4xx) is `deferred`: automatic sends wait one
  hour and the report is scheduled again by itself, at most 3 times. A send error now keeps the
  server's numeric reply code (`refused:550`, `deferred:451`) and the dashboard shows it.
- A node kept searching for its enrolment proof of work for up to 15 minutes, while the hub
  forgets the challenge after 10. On a slow machine the answer always came too late. The search
  now stops 30 seconds before the challenge expires, and the node tries again later.

## [0.11.11] - 2026-11-18

### Fixed

- A new install on a small VPS (1 core, 1 GB) could stop at "container suckerpot-hubproxy-1 is
  unhealthy": the hub proxy's health check starts a Python process inside 0.25 CPU and took
  about 20 seconds there, against a 3-second timeout. The proxy itself worked. The check now has
  a 30-second timeout, a 30-second interval and a 120-second start period.

## [0.11.10] - 2026-11-18

### Changed

- Automatic updates check every 6 hours instead of once a day, so a release is installed at most
  about 6 hours after its 48-hour minimum age instead of up to a day after. The minimum age does
  not change. An existing once-a-day schedule moves to every 6 hours by itself on its first run.
  A target whose update failed is tried again on a later day only, so the attempt cap still counts
  days and a failing update does not take a dump and roll back 4 times a day.

## [0.11.9] - 2026-11-18

### Fixed

- An update no longer stops at "the signature of vX could not be checked" on a machine whose DNS
  is a Tailscale or VPN resolver (such as 100.100.100.100): the signature checker now runs on the
  host network and uses the host's own DNS.

## [0.11.8] - 2026-11-18

### Fixed

- A participant node stopped sending batches when its learned own address expired. Attackers
  name the address they attack in their commands (`wget http://<address>/x`), and the learning
  refused to refresh an address that an indicator named, so a single such command froze the
  refresh and the address expired 72 hours later. An address that is already learned is now
  refreshed whatever indicators name it; a new candidate is still refused.
- `./scripts/status.sh` said "batches are paused" nowhere: a node that held a day back for its own
  address only showed "waiting to be learned from traffic". It now warns
  (`submit_paused_self_address`) and names the fix (`SELF_ADDRESS` in `.env`), and ingest logs a
  warning when it pauses.
- `./scripts/status.sh` called an automatic update that waits for a release to be 48 hours old
  ("refused (too_young)") an update that "did not complete". Only a failure or another refusal
  is a warning now.

## [0.11.7] - 2026-11-15

### Added

- `scripts/host/proxmox-firewall.sh`: manages the Proxmox VE firewall of the SuckerPot VM
  (`/etc/pve/firewall/<vmid>.fw`) from the node. It writes `enable`, open `policy_in` and
  `policy_out`, `macfilter`, then in order: `OUT DROP` of DHCP server replies (udp ports 68 and
  546), `OUT ACCEPT` of DNS only to the LAN gateway (every port with `--gateway-all`) and to each
  `--dns` resolver, and of every port to each `--allow-out` host, `OUT DROP` to the private ranges (RFC 1918, CGNAT, link-local,
  IPv6 unique local) and of tcp and udp to IPv6 link-local `fe80::/10` (ICMPv6 and neighbour
  discovery stay), the admin SSH port open to one CIDR only, and each `--private-port` (the
  dashboard, a hub port) open to the tunnel host only. `--vm-addr` (an address, or a CIDR
  no broader than a `/24` or a `/64`) writes the `ipfilter-<NIC>` set that filters that NIC, and
  never the `ipfilter` option, which would give every NIC an empty set. Every value is validated, the admin
  port has no default and may not be a sensor port, and a source wider than a `/16` or an
  `--allow-out` that covers a whole private range gets a warning. The default is a dry run with a
  unified diff. `--apply` needs root on a Proxmox node, pushes the current file on a stack of
  checked backups in `/root/suckerpot-firewall-backups/`, writes the new one atomically, runs
  `pve-firewall compile` and restores the backup when it fails (a failed apply, or a read-only
  `/etc/pve`, changes nothing and leaves no backup); it refuses to drop rules or options it did not
  generate unless `--replace` is given. `--undo` goes back one backup per call. It never touches the
  datacenter or node firewall: it warns when the datacenter firewall is off (and about the
  `policy_in: DROP` lockout risk of enabling it) and when a VM NIC lacks `firewall=1`, and only
  runs `qm set` with `--set-nic-firewall`. See
  [Proxmox firewall](docs/deployment.md#proxmox-firewall) and `scripts/host/README.md`.

### Changed

- The install commands in the README and the docs (install, join the network, VPS, getting
  started) no longer name a fixed release tag. They clone the repository and run
  `git switch --detach "$(git describe --tags --abbrev=0)"`, which picks the newest release, so
  the pages stay right after each release. An older release is still one
  `git switch --detach vX.Y.Z` away.

## [0.11.6] - 2026-11-12

### Added

- Flood groups in the database. A source that opens many plain connections in one UTC hour (a
  credential spray, a scanner) no longer leaves one `sessions` row per connection: the new fold
  function merges them into one group row (`kind = 'burst'`, `connections = N`, id `burst-...`),
  keeping the sums, and never merges a connection that did something (a successful login, a
  command, a download, an HTTP request, 20 or more passwords, more events than its passwords
  explain, a campaign, an indicator or a demo event), whatever tag list it is given for CVE,
  payload and severe tags. Each call reads only the rows it folds and their own events, so its
  cost does not grow with what a source sent in the hour. A second function gives a folded
  connection that gets a late event its row back and takes it out of its group, so it is never
  counted twice. Events are never touched. Counts of sessions now sum `connections`, the hourly
  roll-up into `sessions_daily` included. Migration 0034; the ingest role gets `EXECUTE` on both
  functions and still has no `DELETE` on `sessions`; going back to 0033 is refused while a group
  exists.
  See [Data retention](docs/retention.md#flood-groups).
- Flood groups in ingest. The writer folds a connection into its group as soon as it closes, when
  its source has opened enough connections in the hour (`SESSION_FOLD_MIN`, default 20). A sweep
  worker (every minute: the last three hours, then the history, six hours at a time, resuming after
  a restart) folds what the writer did not: connections that never sent a disconnect, a flood
  already under way when ingest started, and the rows stored before this release. Which tags a
  plain connection may carry is `ingest/rules/floods.yaml`; ingest refuses to start when it lists a
  payload or severe tag, a CVE tag, `bluekeep` or `eternalblue`. A failing or slow fold never
  fails or delays a batch: the writer caps each call at 2 s, asks about a source and hour at most
  once a minute and pauses after a timeout; the sweep caps its statements at 10 s and backs off. A
  connection with no disconnect is idle against how far ingest has stored the streams, never the
  clock, so a backlog (a restart, a maintenance stop) never folds a live connection. An event
  whose session id starts with `burst-` is dropped and counted like a forged sensor, campaigns
  never cluster a group, and every count of sessions in ingest (abuse candidates, blocklists,
  network batches, reports, alerts, takedown sightings) now sums `connections`, so the numbers are
  the same with and without folding. New settings
  `SESSION_FOLD_ENABLED`, `SESSION_FOLD_MIN` and `SESSION_FOLD_IDLE_MIN`.
- Flood groups in the API. Sessions carry `kind` and `connections`; `/api/v1/sessions` takes
  `kind=session|burst`; `/api/v1/stats/summary` adds `flood_sessions` and `flood_sources`;
  `/api/v1/sessions/{id}?at=` finds the group a folded connection joined; a group's events
  are read from its source, sensor and port inside its hour, and the new
  `/api/v1/sessions/{id}/credentials` lists the usernames, passwords and pairs a session or
  group tried. Every count of sessions in the API sums `connections`, so folding changes no
  number, and the value filters of the session list still find a flood. The brute-force
  threshold of the CERT exports is per connection.
- Flood groups in the dashboard. A flood group reads as one story on the Attacks list ("203.0.113.7
  opened 812 RDP connections, one login each") with a neutral "flood x812" chip (icon,
  word and count, never red) and the hours it ran in your time zone. The Attacks headline says how
  much of the day came in floods, a new **Floods** control (All, Hide, Only) is kept in the URL as
  `?kind=`, and the end of the list counts connections. A group has its own page: a finding, the
  window, the connections, the logins tried, a **Credentials tried** card whose rows open the Trends
  filters, the first 200 events, the other groups of the same hour and a link to every session of
  the address (no replay, no source port). Links to a session from an event (the Live feed, the
  latest events) carry `?at=`, so a connection that was folded into a group opens its group. The
  attacker profile adds "of which N in floods". The mock data and the demo build include flood
  groups.

### Fixed

- The Docker and Synology sensors named their `events_suppressed` summary events `sum-<counter>`,
  and the counter restarted at zero with every sensor restart. After a restart new summaries
  reused ids already stored, so ingest merged unrelated summaries, even from different source
  addresses, into one session row. Summaries now carry a random 24 character session id like every
  other sensor event. No other sensor builds a session id from a counter or a fixed string.

## [0.11.5] - 2026-11-12

### Fixed

- The collector no longer wanders the public web. It used to read every URL inside a fetched HTML
  page (and any other text file) as a possible next stage, so one connectivity check typed by an
  attacker queued the page's scripts, style sheets, images and links, and then theirs, down to the
  depth cap, and the Malware page filled with unknown text. The analyzer now recognises HTML, SVG
  and other XML, CSS, JSON and the JavaScript of a web page as their own kinds (`html`, `svg`,
  `xml`, `css`, `json`, `javascript`), at the lowest severity with no family unless a detection
  rule matched (any match raises it). A file gets a web kind only when it plausibly is that format
  (JSON must parse, a style sheet must be made of rules, JavaScript needs a token only JavaScript
  has) and its whole input holds no shell command, downloader, code runner or active content (ASP,
  JSP and PHP tags, HTA, scriptlets, WSH, PowerShell, `iex`, `certutil`, `bitsadmin`, `python -c`,
  `perl -e`, `php -r`, `ruby -e`, `node -e`, an interpreter fed by its input (`python3 -`,
  `perl -`, `python3 <<E`) or run on a path, `sh`/`bash`/`dash`/`ksh`/`zsh` as commands, through
  `env` or fed by a redirection, shell `eval`, `base64 -d`, `source <(...)`, `. /path`,
  `/dev/udp/`, gawk `/inet/tcp/`, `ftpget`, Node `child_process`, a Node module load used to write
  or run something, `eval` of anything but one plain string, the `Function` constructor directly
  or through `.constructor`, a global looked up by a built name such as `window["ev"+"al"]`);
  anything else keeps the `script` or `text` kind. Every one of these checks is linear in the file size (a 4 MiB hostile file
  classifies in well under a second). Samples already collected are classified again on their own
  after the update (the analysis version went from 1 to 2).
- The kind alone never spares a file, because a program can be dressed as a page. Web content is
  "plain web" only when no detection rule matched it AND the collector reached it only through the
  assets of other web content: every one of its sources is a fetch target that no attacker ever
  typed (an indicator from a sensor event pointed at it; the mark stays when the indicator is
  pruned), at depth 1 or more, and EVERY file that links to it (not only the first) names it as
  an asset and is itself web content. An asset is an attribute that the element loads, in a real
  start tag (`<img src>`, `<link href>`, `<form action>`, `<video poster>`, `<object data>`...),
  or a style sheet `url()` or `@import` outside comments and strings; text such as `src=...`, a
  comment, the body of a `<script>` or an attribute the element does not load (`<b src>`) is not. A link in the text of a page, in a
  web script, in JSON, in a shell script or in a binary makes the file attacker content (network
  verification fetches count neither way). A plain web sample is kept and shown, but its
  links are not followed, it gets no hash indicator, and it is left out of the network batch, the
  hash lookups (VirusTotal, abuse.ch and the contact checks), the blocklist candidates and the
  abuse report drafts, whether or not a hash indicator was recorded for it before the update.
  Anything an attacker asked for is attacker content whatever its kind: a file from a typed URL
  (depth 0, or a URL that also has an indicator) or from a link inside a script or a binary has
  its links followed within the existing caps (depth 2, 20 next-stage URLs per file), gets a hash
  indicator and feeds all of the above. So a typed page costs at most 20 fetches for its assets,
  and those stop there. A spared file (a `spared` flag on the sample) is analysed again when an
  attacker later asks for it: a typed URL serves the same bytes, an attacker types the URL that
  served it, or a script or a binary links to that URL, even long after a page queued it first.
  If that new analysis fails or times out, the file is no longer spared and its hash becomes an
  indicator.
- The collector skips, when it claims a queued target, any target that no attacker typed and that
  only plain web samples link to. It is marked `refused` with the error `web_parent`, is never
  fetched and spends no quota, so the targets queued before the update do not drain onto the
  public web. If an attacker later types the same URL, or attacker content links to it, it goes
  back in the queue. Links already recorded from old pages stay in their sample's link list.
  Migration 0033 adds the `typed` and `spared` marks, an index on the links of a target, and the
  one function that lets the analyzer put such a target back in the queue: only when a link that
  is not a web asset points at it, and with the time set by the database.
- The Malware page names plain web content in plain words (Web page, Stylesheet, Script (web),
  Image (SVG), Data (JSON), Data (XML)) instead of "Unknown" and the raw kind, and the "new files
  this week" sentence no longer counts it. Sample items in the API carry a `crawled` flag for
  this.

## [0.11.4] - 2026-11-12

### Fixed

- An update no longer leaves the checkout unreadable by the containers. `scripts/update.sh` keeps
  `umask 077` for its state file, but it ran the checkout (and, in source mode, the image build)
  under it too, so every file git rewrote became `0600` (`0700` for executables). In source mode the
  images are built from those files and the non-root user inside a container could not read them:
  the `migrate` container failed with `Permission denied` on its migrations and the update stopped
  with ingest, api, collector and analyzer down. Scripts such as `scripts/backup-service.sh` also
  became `0700`. The checkout, the pull and the build now run under `umask 022`, whatever umask the
  caller has (`scripts/auto-update.sh` runs under `077`), and `scripts/rollback.sh` does the same.
  After every checkout the update, the rollback, the installer and `scripts/env-migrate.sh` make
  the files of the committed tree readable again (`chmod go+rX`, listed from `HEAD`, not the index).
  The folders that hold those files are opened too (`hub/` becomes `0755`), so `hub/.env` is set to
  `0600` afterwards. Never touched: every `.env*` file (the example files excepted), `hub/.env`,
  `hub/secrets` and `.suckerpot-state`, symlinks, and anything that resolves outside the
  checkout. A node that was already hit is repaired by its next update. How to repair one by hand:
  [docs/updates.md](docs/updates.md#unreadable-files-after-an-update).

## [0.11.3] - 2026-11-12

### Added

- Common reconnaissance now carries a tag instead of leaving most Redis, Docker, web, MySQL, ADB
  and Telnet sessions untagged. Two new informational tags (never red, never a malware family):
  `service-probe` for read-only requests that identify an exposed service (Redis `INFO`, `PING`,
  `GET` and `CONFIG GET`; the Docker API `/_ping`, `/version`, `/info` and listings; MySQL and SQL
  Server version and database-list queries; a GET for the signature path of a web application such
  as WordPress, phpinfo, Jenkins or a VPN portal) and `iot-shell-probe` for the shell-escape and
  BusyBox probe sequence that loaders type first on a Telnet device shell (`enable`, `system`,
  `shell`, `sh`, `/bin/busybox <word>`, `cat /proc/self/exe`). Existing tags cover more too:
  `env-file-probe` now follows the web sensor's dotfile, config-file and backup flags (for example
  `/admin/config.php` or `/.vscode/sftp.json`), `scanner` follows its scanner and fuzzer
  user-agent flag, and `recon` includes the Android `getprop` and `screencap` commands. Both new
  tags are mapped to MITRE ATT&CK, named in campaigns and insights and explained on the Defend
  page. A homepage, `robots.txt` or favicon request stays untagged.

### Changed

- Abuse reports now say why a draft is blocked and what to do. Settings, Reporting checks each text (reply contact, signature, introduction, closing, note, subject template, X-ARF user agent) on its own: a text that would block every draft, for example a reply address on a domain that names the project, is refused with one sentence under the field and nothing is saved. The same sentences show when a text you saved earlier blocks drafts today, because the rules grow over time. The list of drafts gets a Blocked drafts card (how many, one sentence per reason, what to do, and the setting that causes it) and a few words on each blocked row. The report page gives a next step for every reason instead of a bare description. The API adds `fields` to a refused settings save, `field_issues` to `GET /abuse/settings` and `blocked_drafts` to `GET /abuse/status`.

### Fixed

- AbuseIPDB lookups no longer go to the same busy addresses every day while new sources stay
  unscored. The hourly maintenance job deleted every stored answer after 48 hours, so each known
  address looked new again and the daily quota was spent on re-checks. Answers are now kept and
  used until they are refreshed, and the migration rebuilds the lost ones from the sessions. The
  quota goes to addresses never looked up first (busiest first), then to answers older than the
  new `REPUTATION_RECHECK_DAYS` (default 7, from 1 to 30). A fifth of each day's quota (at least
  one lookup, at most half) is kept for those refreshes, so old answers are still renewed when
  new sources arrive all day. Addresses that cannot be looked up no longer hold the first places
  of the queue.
- GreyNoise: a "too many requests" answer now stops lookups until the next UTC day and marks the
  day's counter as full (so the key test in Settings reports "quota exhausted" until then, even
  after a key change), instead of retrying every hour. The free Community tier allows far fewer
  lookups than most configured quotas, so the retries only produced more errors.
- Open drafts are checked again after the reporting settings or the "never in a report" list change. Before, a draft kept the result of its last build for up to an hour (longer for a draft the lookup cap skipped), so a reply contact fixed in Settings left every draft marked blocked. The worker now re-checks the open drafts from their stored evidence, with no lookup and no rebuild, when the settings revision or the deny set changed. The check is the one the build and the send path run (text, X-ARF and `.eml`, with the reply reference), and nothing is ever sent by this pass. It never clears what the build found in the evidence (an internal id, a private or a documentation address): only a rebuild does. The sessions the API and the SMTP sender treat as internal ids now include the attacker sessions behind a payload host, as the build does. A draft whose options the owner edited is re-checked on its own. A draft that carries one of those codes is not rendered, downloaded or exported either, and cannot be marked reviewed, until a rebuild clears it.

- Campaigns of one actor are now merged. The worker only merged two campaigns when a single new
  session carried a key of both, which almost never happens: an actor that does credential
  stuffing, then drops a file, then leaves a ransom note produces three keys in separate
  sessions, so it stayed split into three campaigns by kind (the status showed `"merged": 0`
  for ever). A new pass compares the source addresses of the campaigns that changed: two live
  campaigns on a common sensor merge when they share at least 5 addresses and at least 60 % of
  the smaller campaign's addresses are also in the other one. The oldest campaign keeps its id,
  so shared links keep working; the others show as merged and point to it, and the page of a
  merged campaign links to the combined one. It applies to campaigns that already exist, with
  nothing to run: every campaign is checked once after the update (a few hundred per cycle), then
  only the ones that change. A merged campaign is named after its two main goals ("Malware
  dropper and database ransom over MySQL #12"), keeps the highest severity of its parts and
  counts a shared address once. Credential-only floods (many logins, no commands, few addresses
  in one network) still do not form campaigns; the limits and what it would take are in
  [Architecture](docs/ARCHITECTURE.md#how-the-features-fit-together).
- `update.sh` and `install.sh` no longer report a failed update or install on a healthy node
  whose dashboard is bound to a LAN address while `API_ALLOWED_ORIGINS` is set. Their final
  dashboard check sent the bind address as `Host`, which the API rejects; it now sends
  `localhost`, which the API always accepts.
- An honest node on a network too small for corroboration no longer loses reputation every day.
  The hub's daily volume penalty (a node sending many values that no other node sees) now applies
  only while at least `HUB_VOLUME_MIN_NODES` (default 5) active nodes old enough to count have
  reported in the last 14 days. Before, a lone node was penalised daily and ended up
  soft-suspended after about a week.
- The network status no longer shows "0 sent" for a day whose batch was sent twice (after a
  restart or a lost answer). When the hub reports it already holds the batch, the node now
  records the item counts it sent instead of the hub's zeros.

## [0.11.2] - 2026-11-11

### Changed

- The installer now accepts a machine sold as "2 GB" (about 1.9 GiB, for example `MemTotal: 2009976 kB`): the memory bar is 1.75 GiB (1,835,008 kB) instead of about 1.94 GiB, and the default setup runs there with the low-memory limits. Between 1.75 and 2 GiB it warns and asks when there is less than 512 MiB of swap (not with `--yes`). Below 1.75 GiB, participant mode says what the machine reports and offers the lite setup in one question (default yes; `--yes` takes it and prints a note); accepting it behaves exactly as `--lite`. Full mode and machines below the lite minimum (1 GiB) are still refused, and the message states the reported memory and, in full mode, the exact `--participant --lite` command.

### Fixed

- A fresh install no longer fails with `backup` stuck waiting. The `db` healthcheck now probes over TCP (`pg_isready -h 127.0.0.1`), so the database reports healthy only once it accepts network connections, not while the image still runs its temporary start-up server on the Unix socket. The `backup` service also retries a failed dump after 30 s, 60 s, 120 s and so on (never later than the hourly check) instead of waiting an hour. The hub database healthcheck got the same TCP probe.
- A participant node installed without a VPN can now join the network. The installer leaves the hub address out of `.env` so that the one shipped with the release applies, but the egress gate of `ingest` built its direct-mode scope from `.env` only, found no host, and stayed closed with `direct_allow_mismatch`: the node kept running its sensors and never reached the hub. The scope now uses the same shipped defaults as the network code. A node that already agreed to join at install time keeps its request and retries by itself after the update, with nothing to run. VPN mode is unchanged.
- `./scripts/install.sh --feeds` now really fetches the community lists: the feed worker uses the feed address and key shipped with the release when `NETWORK_FEED_URL` and `NETWORK_FEED_KEY` are both left out, instead of staying unconfigured. Set both to point at another feed.
- `./scripts/status.sh` no longer says `Not joined. Join: ./scripts/participant.sh join` for a node that agreed to join but is not accepted by the hub yet. It says `Joining as <pseudonym>: not accepted by the hub yet`, with the last problem in plain words, and exits with code 1 (warning `join_pending`) while a problem blocks the join.

## [0.11.1] - 2026-11-11

### Added

- `scripts/move-admin-ssh.sh`: moves your own admin SSH from the port it uses to another one in one command on Debian and Ubuntu (`sudo ./scripts/move-admin-ssh.sh [PORT]`, default 22222; run it again with another port to change it; `--undo` goes back to port 22, with SuckerPot stopped), including systemd socket activation. It opens the new port next to the current one, waits until a real login on the new port is seen (not just a connection), and only then closes the current one; on a timeout, Ctrl-C, a failure or a killed earlier run, SSH goes back to the port it started from. It refuses SSH bound to a specific address, several ports it did not set up, and a port held by another program, and it opens ufw or firewalld only where SSH is open to everyone. The installer is unchanged and still never edits the SSH configuration; its messages and `docs/vps.md`, `docs/install.md` and `docs/participate.md` point to the script.

## [0.11.0] - 2026-11-11

### Upgrading

- **Check `NETWORK_ENABLED` before you update.** When it is not set in `.env`, a node is now OFF the collaborative network (the compose default changed from `true` to `false`). A node that takes part must have `NETWORK_ENABLED=true` in `.env`; the installer writes it when you join. Check with `grep '^NETWORK_ENABLED=' .env`. A node that has the line set to `true` is unchanged.
- The database migration `0031` runs with the update (the `migrate` service applies it); it replaces one function in place and rewrites no data. Hub operators get `h0011` (a new, empty table) when they update the hub.
- A broker volume written by Redis 8.10 is handled at start. Valkey cannot read the RDB preamble in the AOF file that Redis 8.10 wrote, so the entrypoint moves the unreadable data aside (`*.unreadable-<UTC time>` in the volume, two copies kept) and starts with an empty buffer. Only the events still waiting in the buffer are lost, a few seconds on a healthy node. To keep them, run the `CONFIG SET aof-use-rdb-preamble no` and `BGREWRITEAOF` commands from `docs/updates.md` ("The stream buffer on update and rollback") on the running Redis before you update. This is optional.
- Two features were removed. You can delete these variables from `.env`: `ABUSECH_SUBMIT_ENABLED`, and `LLM_ENABLED`, `LLM_DAILY_QUOTA`, `LLM_MONTHLY_TOKEN_CAP`, `LLM_MODEL` and `ANTHROPIC_API_KEY`. If they stay, they are ignored and the node starts normally. Stored submission rows stay in the database, unused. A key stored in Settings for the removed explanation provider is deleted when the API starts.
- The default of `GREYNOISE_DAILY_QUOTA` is now 7 (it was 50): the free Community tier allows about 50 lookups a week. A value you set in `.env` is kept, so lower it if it is above 7 and you use the free tier.
- `just restore` now restores into a side database and swaps it in, so it needs room for a second copy of the database until the swap. Check `docker system df` and the size of the `db-data` volume first.
- Sign-in has two new settings, `LOGIN_VERIFY_CONCURRENCY` (default 2) and `LOGIN_VERIFY_WAIT` (default 5). The defaults need no change. Each password check holds about 64 MiB, so keep the value inside the `api` memory limit.
- Updates and rollbacks behave differently: a rollback restores the database only when the schema moved (`--restore-db` and `--keep-db` override it), and an update fails only on a service that was healthy before it. Details in `docs/updates.md`.
- Stored sessions keep the tags they already have: there is no re-tagging. The renamed annotation rules make the scripts worker rebuild the stored script explanations once.

### Added

- Hub: public network observatory (design M34). With `HUB_OBSERVATORY_ENABLED=true` (off by default) the worker publishes `network.json` (schema `selfhostr-network-stats/1`, CC0) on the feed site once a day, independent of `HUB_FEED_MODE`: node counts, the bootstrap state against `HUB_MIN_NODES`, confirmations, reports and takedowns, attack traffic per day and the most targeted services, tags and malware families. Every figure is a network total from consensus-eligible nodes only, at day level, published with a delay, rounded, and coarse (weekly, one significant figure, small figures left out) while fewer than three eligible nodes contribute; outcomes are exact only with production consensus thresholds, and bootstrap figures are counted once a week. No per-node value appears. Caddy allows one browser origin to read it (`HUB_OBSERVATORY_ORIGIN`, default `https://suckerpot.selfhostr.io`, `GET` only).
- Hub migration `h0010`: `observatory_daily`, network-wide aggregates of each final day, counted once (the worker role cannot update them) and kept 400 days.
- CI job `licences`: fails when a Python (`uv.lock`) or web (pnpm) dependency has a licence outside the open-source allow-list (MIT, Apache-2.0, BSD, ISC, MPL-2.0, OFL-1.1, CC0, Unlicense, 0BSD, Zlib, BSL-1.0, LGPL/GPL/AGPL). `pnpm run licences` runs the web half locally.
- `scripts/install.sh --participant --lite` for a 1 GiB VPS or Raspberry Pi: a new `docker-compose.lite.yml` overlay (stacked after the low-memory overlay, recorded in `COMPOSE_FILE` so updates keep it) lowers the database and Redis limits, and the default sensors become SSH, Telnet, web and Redis. Total memory limit of the participant stack: 3,248 MiB by default, 1,936 MiB with the low-memory overlay, 1,424 MiB with `--lite`. No security setting changes; a new guardrail test only allows memory figures in the overlay, and the CLI guardrail renders it.
- `docs/vps.md`: join the network from a cheap VPS (no home address, no router change) with the steps to move admin SSH off port 22 first, including the `ssh.socket` case of Ubuntu 24.04 and newer, and a Raspberry Pi section (64-bit system, arm64 images).
- Dashboard banner when the pipeline is stalled: a severe notice above every page ("Events have not been stored for 42 minutes. Attacks reaching your sensors are being lost.") with the last error and the commands to check the service, and a quiet, dismissible notice when events were set aside. A Pipeline card on Settings shows the same state. Nothing is shown while the pipeline is healthy or when the API cannot say.
- `GET /api/v1/settings/pipeline` returns `ok`, `stalled` or `unknown` from a heartbeat that ingest writes (`PIPELINE_STALL_SECONDS`, default 300, sets the stall limit).
- Settings, retention card: a new "Oldest stored event" field, and `retention.oldest_event_at` in `GET /api/v1/settings/system`. When the size ceiling (`DB_MAX_SIZE_GB`) has already dropped older data, the finding says so instead of promising the full 90 days.
- `scripts/install.sh --join-network`: the only way to join the collaborative network without answering the question. `scripts/restore-db.sh --keep-previous` keeps the replaced database as `<db>_before_restore`.
- `just test-backup-restore` and a `backup-restore` CI job: a restore tested end to end on a throwaway project, including a truncated dump that must be refused. `just broker-test` and a `broker` CI job do the same for the broker volume cases.
- Hub migration `h0011`: the `recheck_assignments` table (see Security).
- `scripts/check-release-ref.sh` and a `check` job in the release workflow (see Security).

### Changed

- The message broker is now Valkey 9.1 (`valkey/valkey:9.1.3-alpine3.24`, BSD-3-Clause) instead of Redis 8.10. It is a drop-in replacement: same protocol, same configuration and ACL file, same volumes and ports. The Streams buffer survives the engine change only when the AOF holds no RDB preamble (see Fixed). The container now runs `valkey-server` and the health check `valkey-cli`.
- The collaborative network is presented as an experimental preview and is off unless you ask for it. The installer question defaults to no (`[y/N]`), `--yes` alone never joins, and `NETWORK_ENABLED` defaults to `false` in compose, `.env.example`, ingest and the API. Participant mode still joins, because running that mode is the request. The consent screens say what is sent, to whom, what comes back today (nothing yet) and how to leave.
- Docs corrected to match the code: `docs/network.md` no longer says the hub cannot learn a node's address (Cloudflare, the reverse proxy and the hub operator see the address a request comes from, and the probe-linking limit is described), the never-listed claims match `never.yaml` and `ranges.yaml`, `feeds.md` uses the shipped feed URL, and the GreyNoise free tier is about 50 lookups a week, not a day. `SECURITY.md` names the latest release tag as the supported version. The README gains a short "How it compares" section.
- Sign-in no longer has a global window that refuses everyone: 30 wrong passwords a minute from anywhere used to lock the owner out. Password checks (argon2) run in a small pool (`LOGIN_VERIFY_CONCURRENCY`, default 2) with a short queue (`LOGIN_VERIFY_WAIT`, default 5 seconds). Over the `LOGIN_RATE_GLOBAL` budget, each refused sign-in is answered one second later, and a correct password is never delayed. A client address can have one sign-in check in flight at a time; a second one at once gets `429`. The per-address limit and the global window of re-authentication are unchanged.
- `GREYNOISE_DAILY_QUOTA` defaults to 7 instead of 50 (see Upgrading).
- Tags that name a malware family, a CVE or a fraud now need specific evidence, and generic traffic gets a probe or recon tag instead. `sip-fraud` needs an INVITE to an international number (plain REGISTER or INVITE is `sip-probe`), `synology-exploit` also needs a DSM web API call, `smb-eternalblue` needs an explicit `eternalblue` or `ms17_010` flag (SMB1-only clients get `smb-v1-probe`), `mirai-busybox`, `adb-mirai` and `adb-mirai-download` need a variant token or a `mirai.<arch>` binary name (`mirai-telnet-loader` is removed), `php2shell` needs PHP code in the upload-progress field or the include of a session file the sensor saw created (plain touches get the new `php-upload-progress-probe`), `db-ransom` needs a ransom note, `persistence` needs a write, a crontab pipe or file, `systemctl enable` or `chattr`, and OpenSSH CVE relevance covers OpenSSH CVEs only. The rules engine gains a `has_all` operator, and the two new probe tags are benign, mapped to ATT&CK T1595.002 and have guidance text. The demo generator still produces PHP2Shell sessions.
- Fake SSH server and shell: the authentication methods are exactly `publickey,password` as on a stock Ubuntu OpenSSH (keyboard-interactive is gone), the key exchange lists match and compression is not offered. The fake image derives its machine identity (machine-id, host key fingerprints, boot time, MAC, binary sizes) per install from a secret, binaries have believable sizes and an ELF header, `/proc/self` and a `/proc/<pid>` entry for every process `ps` lists exist, the shell handles `$(( ))` and `$RANDOM`, `wget`, `curl` and `git clone` print what the real tools print for an unresolvable, loopback or reachable host (nothing is fetched, the sensor still only records the URL), downloads vary per URL, and common tools no longer answer "command not found". Several inputs that crashed a command are handled.
- The other service sensors give each install its own coherent identity from its secret: Docker (2 to 6 containers from real images, consistent across the API), Redis (a keyspace with several usage styles, `TTL`, `PTTL` and the `INFO` keyspace line, install-specific paths), ADB (one build date behind the build id, patch level, fingerprint and kernel), web (site title, tagline and posts), SIP (26 Asterisk versions, FreePBX user agents on about 30% of installs) and Synology (29 models with their platform, 28 host names).
- The static safety test of all 12 sensors and `sensors/common` is stricter: no process spawning, no dynamic import or `getattr` indirection on `os` or `builtins`, no outbound primitive. `common` also checks that nothing writes and that only `publisher.py` imports redis. No violation was found.
- Lookups of a session's events carry a time range taken from the session row, so TimescaleDB opens only the chunks that can hold them instead of every compressed chunk. This covers the session events endpoint, campaign excerpts, the session value filter, the story builder and campaign clustering in ingest (candidates are cut into slices of at most one day or 200 sessions). A new static test fails when a query on `events` by `session_id` has no time bound.
- `just restore` (`scripts/restore-db.sh`) loads the dump into a side database while ingest and the API keep running, checks it, and only then swaps it in (see Upgrading). A failure before the swap leaves the live database and the services untouched. After the swap both databases are kept and the swap-back commands are printed. `scripts/rollback.sh` gets the same protection.

### Removed

- The node-side abuse.ch submission: the ingest worker that sent captured malware URLs to URLhaus and command-and-control addresses to ThreatFox, its review queue, its settings card, the Submissions page and `ABUSECH_SUBMIT_ENABLED`. It was off by default, needed a personal abuse.ch account and made each node speak to a third party in its owner's name; the hub already submits centrally. Kept: abuse.ch lookups for enrichment (`ABUSECH_AUTH_KEY`, `ABUSECH_DAILY_QUOTA`), takedown tracking and its listing checks, the hub and the database schema (no migration: the submissions table stays, unused, and retention still prunes it). Takedown targets are now synced from sent reports only.
- The optional LLM explanation of captured scripts: the ingest worker, `POST /scripts/{id}/explain`, the `ai` and `llm` fields of the script answers, the panel on the script page and the `LLM_*` and `ANTHROPIC_API_KEY` variables. It was off by default, needed a paid key and sent normalised commands to an outside service. The built-in line by line explanation from the local rules base and the whole script library stay. No migration: the two tables stay, unused. A key stored for it in Settings is deleted when the API starts, and the API refuses to store a new one.

### Fixed

- Ingest could stop storing events about a week after install, silently. Once the oldest chunk of `events` was compressed, the `retract_benign` call that clears a research scanner's earlier events decompressed it, hit the 30 second statement timeout and made ingest retry the same batch forever, on every stream, while the sensors' capped streams dropped events. Migration `0031` rewrites the function so it only touches the chunks of the session. Ingest now also runs it in a savepoint (a failure no longer fails the batch), isolates streams from each other, counts timeouts and permission errors as failed attempts, bisects a stuck batch and parks the event the database refuses in the small, capped `events:parked` stream (500 entries, 2 KB of data each), and logs the stream, SQLSTATE and database message. A new `pipeline_state` row and `GET /api/v1/settings/pipeline` report a stalled pipeline (`PIPELINE_STALL_SECONDS`, `INGEST_MAX_BATCH_FAILURES`). The `ingest` Redis user gets `XADD` on `events:parked` only.
- Updates no longer fail, roll back and blacklist a release because a service was already unhealthy before the update: the health of every service is recorded first and only a regression fails (`UPDATE_HEALTH_WAIT_SECONDS`, default 180, bounds the wait for `starting` services). A rollback restores the database only when the Alembic revision changed (`--restore-db` and `--keep-db` override it), and the automatic updater adds a release to `bad-versions` only when the release itself is at fault (or after `AUTO_UPDATE_MAX_ATTEMPTS`, default 3, repeated failures).
- Broker: Valkey 9.1 cannot read the RDB preamble of a Redis 8.10 AOF (`Can't handle RDB format version 15`), so the first start on an existing volume crash-looped. The base file is now plain commands (`aof-use-rdb-preamble no`), and when the server cannot load `/data` the entrypoint moves it aside (`*.unreadable-<UTC time>`, two copies kept) and starts empty. An update from Redis 8.10 therefore works unattended and loses only the events still waiting in the buffer; `docs/updates.md` gives the optional command that keeps them. Tested by `scripts/test-broker.sh`.
- Sign-in: a locked or disabled account no longer answers faster than a wrong password, and a flood of wrong passwords can no longer keep the owner queued out.
- Settings no longer says raw events are kept for 90 days when the size ceiling has already dropped older chunks.
- The guardrails read the admin SSH port from `ADMIN_SSH_PORT`, like `scripts/check-ports.sh`, instead of a constant.

### Security

- The hub counted a takedown vote for any open target id a node sent, so two enrolled nodes could push any open target to `taken_down` on their own. The hub now records which recheck items it hands to which node (`recheck_assignments`, at most 200 per node per day, pruned after 3 days) and a vote counts only against such an assignment, once. The wire protocol and the consensus thresholds are unchanged, and nodes on a previous release keep working.
- A release can only come from main: the release workflow first checks that the tag is exactly `vMAJOR.MINOR.PATCH` and that its commit is an ancestor of `origin/main` (`scripts/check-release-ref.sh`), before anything is built or signed. The jobs that write to the registry, sign or publish run in the GitHub environment `release`, where maintainers can require reviewers. Until that environment is configured, only the new check applies. `docs/updates.md` has a new section "What a release proves".

## [0.10.0] - 2026-11-06

### Upgrading

- Images are rebuilt on Python 3.15 and Debian trixie: participants pull the new signed images as usual (`just update v0.10.0`), source installs rebuild with `docker compose up -d --build`.
- The database image moves to TimescaleDB 2.31, still on PostgreSQL 17, so the data volume is reused as is. An existing database keeps loading its current TimescaleDB extension version until `ALTER EXTENSION timescaledb UPDATE;` is run, which is optional.

### Changed

- Every dependency is upgraded in one go:
  - Python 3.13 -> 3.15 (`python:3.15.2-slim-trixie`) in every image, and uv 0.8.24 -> 0.13.7. The test and tooling image is `ghcr.io/astral-sh/uv:0.13.7-python3.15-trixie-slim` (uv no longer publishes bookworm variants), CI uses Python 3.15, and every package targets 3.15 (`requires-python`, ruff, mypy). Debian moves from bookworm to trixie in the Python and Node images. `ruff format` now writes `except A, B:` without parentheses (PEP 758), and string annotations are unquoted.
  - Every `uv.lock` is refreshed. Notable: asyncpg 0.32 (first release with Python 3.15 wheels), SQLAlchemy 2.1, redis-py 8 (RESP3 on the wire by default, same response shapes). The `db` package now allows `sqlalchemy <2.2` and `asyncpg >=0.32,<0.33`, `ingest` allows `redis <9`.
  - PyYAML has no Python 3.15 wheel yet: it is built from its source archive, without the libyaml C extension (pure Python, slower). It only reads rule and configuration files and writes small report documents.
  - Node 22 -> 26 in the web build stage and the justfile. Node 25+ no longer bundles corepack, so a pinned corepack (0.36.0) is installed first; it still provides the pnpm version from `packageManager` (pnpm 10.34.9).
  - Web: react-router 8, ESLint 10 and @eslint/js 10, TypeScript 6.0 (`baseUrl` removed, path aliases via `paths`), @types/node 26, jsdom 31, Playwright 1.65 (screenshot image `v1.65.0-noble`) and the latest minor of every other package.
  - Redis 7.4 -> 8.10 (`redis:8.10.3-alpine3.23`); the configuration and the ACL file are unchanged.
  - TimescaleDB 2.22.1 -> 2.31.0 (still PostgreSQL 17), gluetun v3.41.1 -> v3.41.3.
  - Hub: PostgreSQL 17.6 -> 17.11, Caddy 2.11.2 -> 2.11.9, Alpine 3.21 -> 3.24.
  - GitHub Actions: checkout v7, setup-uv v10, setup-node v7, pnpm/action-setup v6, upload-artifact v7, download-artifact v8.
- Dependabot runs monthly, with one entry per ecosystem over all its directories: minor and patch updates come as one grouped pull request per ecosystem, major updates as another.

### Fixed

- With TimescaleDB 2.31, the aggregate backfill run by `migrate` failed with SQLSTATE 55P03 when the hourly refresh policy ran at the same moment. It now retries with a short backoff.
- Ingest reads both reply shapes of `XREADGROUP` that redis-py 8 declares.
- API types follow SQLAlchemy 2.1, which types `Select` and `Row` by their columns.

### Deliberately held back

- The hub stays on PostgreSQL 17. PostgreSQL 18 images moved `PGDATA` and an existing hub database needs a `pg_upgrade` or a dump and restore, so the major upgrade is done by hand; Dependabot ignores PostgreSQL majors.
- TypeScript stays on 6.0: typescript-eslint, the lint toolchain, does not support TypeScript 7 yet (its peer range is `<6.1.0`). Dependabot ignores TypeScript majors until it does.
- pnpm stays on 10.x (latest 10.34.9); pnpm 11 and 12 are majors with a new lockfile and settings format, left for a separate change.

## [0.9.0] - 2026-11-04

### Added

- `./scripts/participant.sh ports-check [--wait SECONDS] [--since ISO | --since-install]` tells whether the internet reaches your sensors, and the participant installer runs it at the end and offers to re-check after you open the ports on your router. It makes no outside connection: it counts sessions from public addresses that your sensors already recorded, prints no address, reads the database in a read-only transaction, and exits 0 (reached) or 3 (nothing yet). `status.sh` points to it.

### Changed

- The participant installer no longer prints a fixed "14 days" date. The hub decides the probation period; `./scripts/status.sh` shows the date from which the sensor counts.
- Participant docs and installer summary: use port forwards rather than a DMZ, explain the DMZ risk, and say precisely when the route-out restriction holds (host firewall loaded) and that the firewall does not filter internet traffic to the machine's own services.

### Security

- Host firewall for participant mode: `scripts/host/firewall-participant.nft` loads with no placeholder other than the admin SSH port, rendered by `scripts/host/render-firewall.sh` and installed with `scripts/host/install-firewall.sh` (systemd unit, survives a reboot, `--uninstall` to undo). In its own nft table, it drops everything new, invalid or untracked from the sensors' uplink to the host and to the internet or the LAN, and limits `hubproxy`'s uplink to TCP 443 on public addresses plus UDP DNS to the resolvers Docker uses. The full-mode template's DNS rule is narrowed the same way. The renderer refuses a host bridge that is not Docker's but matches the rule names, to avoid a lockout.
- Every internal network has an isolated gateway (`gateway_mode_ipv4: isolated`), a fixed bridge name and IPv6 off, so a compromised container no longer reaches services on the host through its bridge. This needs Docker Engine 28 or newer, and the first update recreates the stack once (see `docs/updates.md`).
- A guardrail checks the hardening of every service of every supported stack: read-only root, all capabilities dropped, no-new-privileges, a non-root `uid:gid`, memory, CPU and process limits, a healthcheck, `noexec,nosuid,nodev` tmpfs, no host namespaces, devices, Docker socket or unlisted bind mounts, isolated internal networks, and third-party images pinned by digest.
- The TimescaleDB image is pinned by digest.
- The installers offer to install the host firewall at the end (participant mode; asks before using sudo, never blocks, prints the two commands otherwise; `participant.sh vpn` reminds you to re-run it), and `./scripts/participant.sh firewall [install|uninstall|status]` does it later.
- Updates and rollbacks recreate the stack once (`down --remove-orphans`, never `-v`) when compose says an existing network cannot be reused (matched on its wording, not on any mention of a network); a foreign container attached to one of our networks stops the run with instructions instead of being disconnected.
- CI pins the TimescaleDB test image by digest, like `docker-compose.yml`.
- Automatic updates: the minimum release age is now at least 48 h whatever the release's own manifest says; `AUTO_UPDATE_MIN_AGE_H` in `.env` can raise it.
- Automatic updates: a release that is unsigned, does not match its tag or has a signature cosign rejects is marked bad with its reason (network, Docker, Sigstore or disk problems are never held against a release) and the next newest release of the same major version is tried (3 at most per run), so one bad tag no longer blocks updates.
- The installer warns when Docker Engine is older than 28, where internal networks are not isolated from the host.

## [0.8.0] - 2026-11-04

### Changed

- The offline mock-data demo moved to https://suckerpot.selfhostr.io/demo/. GitHub Pages and `site/` are removed from the repo (the product site is maintained separately).
- Documentation moved from Read the Docs to https://suckerpot.selfhostr.io/docs/ (Selfhostr docs kit, Starlight). `.readthedocs.yaml`, `docs/conf.py`, `docs/requirements.txt` and the Sphinx CI job are removed; `docs/` stays the source.
- The project moved from `github.com/Theroxat/suckerpot` to `github.com/selfhostr/suckerpot`. Release images are now published as `ghcr.io/selfhostr/suckerpot-*` and signed by the release workflow of the new repository, and the documentation is at `https://suckerpot.selfhostr.io/docs/`. `scripts/env-migrate.sh` rewrites the old default `SUCKERPOT_IMAGE_PREFIX` and `UPDATE_CHECK_REPO` in an existing `.env`; the signature checks are as strict as before (exact repository, `release.yml`, exact tag). An install on v0.7.1 verifies releases against the old repository, so its first update needs `SUCKERPOT_IMAGE_PREFIX=ghcr.io/selfhostr/suckerpot` set in `.env` by hand; see `docs/updates.md`.
- The network is now called the SuckerPot network, and the blocklists the SuckerPot blocklists. Selfhostr is the small organisation that makes SuckerPot, no longer the name of the product or the network.
- New addresses: the site is `https://suckerpot.selfhostr.io/` (hosted on Cloudflare Pages), the hub is `https://suckerpot-hub.selfhostr.io` and the feeds are `https://suckerpot-feeds.selfhostr.io/v1`. The old `selfhostr.io` site, `hub.selfhostr.io` and `feeds.selfhostr.io` are gone. Nodes pick up the new hub address with the next release; the hub keys are unchanged. `abuse@selfhostr.io` stays.

## [0.7.1] - 2026-11-04

### Fixed

- Settings → Network said "No network hub is configured" and greyed out the join button on installs whose `.env` does not set `NETWORK_HUB_URL`, which is every install made by the installer. The dashboard now uses the hub address and key shipped with each release, like ingest already did.
- Clicking Join again while a join is pending showed "The change could not be made". It now says the system has already asked to join and refreshes the page.
- A new node's standing no longer promises "two weeks": the hub's thresholds are configurable, so the page points to the Eligibility date instead.

## [0.7.0] - 2026-11-04

### Added (M33)

- The network is on by default. The full installer asks "Join the Selfhostr network? [Y/n]" (default yes; `--no-network` declines) and the node joins at first start, through the VPN only. Design: [M33](docs/dev/design/m33.md).
- Joining in the dashboard is one button: the dialog lists what is shared and asks for your password. Leaving is one button, and a node that left can join again. Setup step 8 has the join button.

### Fixed

- The setup wizard's sensor list timed out on busy systems. It now reads the newest event per sensor from the index.

### Upgrade note

- The network feature is now on by default (`NETWORK_ENABLED=true`). When you update an install that was made before this change and its `.env` has no active `NETWORK_ENABLED` line, the update adds `NETWORK_ENABLED=false` (and a `NETWORK_DEFAULT_PINNED=1` marker), so nothing changes for you. To use the network, run `just set NETWORK_ENABLED=true` and join in the dashboard.

### Changed

- The installer consent record is spent after 7 days: ingest joins from it only within 7 days of its date, so restoring an old database cannot undo a leave. `just set NETWORK_CONSENT=` (empty value only) clears the record. `SELF_TERMS_AUTO_CONFIRM` only applies in participant mode.
- The installer's network question treats end of input as an error, not as a yes. `--yes` also joins the network unless `--no-network` is given.

## [0.6.0] - 2026-11-03

### Added (M32)

- Participant mode (M32). `./scripts/install.sh --participant` installs sensors, database, ingest and the network node only: no dashboard, no admin account, no wizard, no API key and no VPN needed. Choosing it is the consent to join; a random pseudonym is generated. Three commands, then open the printed ports. Guide: [Join the network](docs/participate.md). `--full` switches an existing participant install to the full product and keeps its data.
- `hubproxy` (profile `direct`, M32): a small allow-list proxy that lets a participant without a VPN reach the hub and nothing else. Ingest keeps no route out. The overlay is `docker-compose.participant.yml`.
- Honest privacy note: without a VPN the hub, and a tunnel provider in front of it, see the participant's home address. The hub never stores it. A VPN can be added at any time with `./scripts/participant.sh vpn <file>`.
- `scripts/participant.sh` (`status`, `leave`, `join`, `vpn`, `auto-update`, `uninstall`) and `scripts/status.sh` (sensors, network state, what was sent, updates; exit codes 0, 1, 2; `--json`, `--last-batch`).
- Automatic signed updates (M32). A daily job in the user's crontab runs `scripts/auto-update.sh`: it verifies a signed release manifest and the image signatures, accepts only releases at least 48 hours old and of the same major version, takes a backup, and rolls back and blocks a release that fails. On by default in participant mode, off in full mode. Turn off: `./scripts/participant.sh auto-update off`. A compromised release channel would reach every auto-updating participant. See [Updates](docs/updates.md#automatic-updates).
- Verifier nodes (M32). When two nodes report the same download link, the hub can ask a verifier to fetch it through its VPN and attest its hash, size, type and family. The role is opt-in on the node and granted by the hub operator. An attestation never counts as a sighting.
- The hub address and key ship inside each release, with a key rollover that auto-updating participants follow.
- Documentation: [Join the network](docs/participate.md) (new), participant mode in [Install](docs/install.md), participants and verifiers in [The network](docs/network.md), a "Help the network" section on the project site.

### Added

- Community blocklist feeds (M30). The hub publishes five free, signed lists for firewalls: `inbound`, `inbound-high`, `outbound`, `outbound-high` and `outbound-domains`. They come as plain text (IPv4 and IPv6 files too), nftables, ipset, MikroTik, CSV, JSON and STIX 2.1. An entry needs observations from at least five independent sensors (k-support). Inbound entries need TCP evidence. Outbound entries need a fetched payload with a known malware family, or a high-confidence command server seen in two samples. Tor exit relays, CDN ranges, public resolvers and shared hosting names are never listed. A hold, expiry, size caps and a change breaker sit between the data and the files. Every file is signed with minisign, with a feed key that is separate from the hub key. The hub feed is off by default (`HUB_FEED_MODE=off`). Operators: [hub/README.md](hub/README.md#public-feeds). Users: [Community blocklist feeds](docs/feeds.md), with steps for OPNsense, pfSense and pfBlockerNG, nftables, ipset, MikroTik, MISP and DNS filters. The lists are CC0 1.0.
- Delisting and lookup (M30). Anyone can ask for a removal through a form, or the API, with a small proof-of-work puzzle. Requests get a decision target of 72 hours. An inbound value is hidden until the decision, within a daily cap. Outbound values wait for review. `GET /v1/lookup` answers `listed`, `removed` or `not_listed` for one value. Migration `h0005` (hub database).
- Node side of the community lists (M30). `NETWORK_FEED_ENABLED` (off by default) fetches the public lists through the VPN gate, independent of membership. A file is stored only after its signature, its serial (no rollback), its expiry and its sha256 check out. Migration `0029` (node database). The Blocklists page has a Network tab with the state, one card per list, copy-URL menus, a filterable table and a plain "why join" card. API: `GET /api/v1/network/feed/status` and `/entries`.
- Local mirror of the community lists (M30). With `FEEDS_ENABLED=true` and a token of kind `network`, a firewall can fetch the entries that the node verified from its own dashboard, as text or CSV. Overrides still apply, and the mirror is empty when the lists are stale.
- `scripts/feeds/fetch-verify.sh` (M30): a short POSIX shell script that downloads `index.json` and a list, verifies both with `minisign`, checks the sha256 and replaces the local file only after every check passed.
- Documentation: [Community blocklist feeds](docs/feeds.md) (new), with the Network tab in [Defend](docs/defend.md), the network section in [The Selfhostr network](docs/network.md), the threat model in [Security](docs/SECURITY.md#community-lists-m30), the settings in [Configuration](docs/configuration.md#community-lists-m30) and the endpoints in [API](docs/api.md#community-lists-m30).
- Replies to reports (M26): Selfhostr can read the answers to your abuse reports from a dedicated mailbox, through the VPN only. Replies are matched by a reference in the subject, by Message-ID (only from parties you wrote to), by delivery failure notices, by ticket number or by sender domain, and are verified before they change an outcome (DKIM or DMARC with the trusted provider name, or your confirmation). Each reply is classified (resolved, rejected, ticket opened, automatic receipt, bounce, answered by a person, or not understood). Mail is only marked as read or moved, never deleted. Replies can also be pasted or uploaded as `.eml`, with no mailbox. Off by default (`ABUSE_REPLIES_ENABLED`). Migration `0026`, `/api/v1/abuse/imap`, `/api/v1/abuse/replies` and `/api/v1/abuse/outcomes`. See [Replies to reports](docs/replies.md).
- Results page (M26, M27): "did anyone answer", how fast providers answer, reports over time and a provider table, with one plain sentence per card. The **Results** and **Submissions** tabs sit next to **Reports** in the Abuse reports hub.
- Takedown tracking (M27): the collector re-checks each reported payload URL with one bounded GET through the VPN (only URLs that already served a sample; C2 servers and attacking addresses are never contacted). The worker follows the targets with passive signals and URLhaus, ThreatFox and AbuseIPDB lookups within quotas. Each target gets a state (still serving, serving a new file, down, active, quiet, unknown), and the Results page shows the share taken down within 48 hours, 7 days and 30 days, with right-censoring, and the median time to takedown. Off by default (`TAKEDOWN_ENABLED`). Migration `0027`, `/api/v1/takedown/*`. See [Takedowns](docs/takedowns.md).
- abuse.ch submission (M27, optional): captured malware URLs can be submitted to URLhaus, and C2 `ip:port` addresses to ThreatFox, after a lookup that the value is not already known. Off by default, twice: the server switch `ABUSECH_SUBMIT_ENABLED` and a mode in Settings (Off, Review each, Automatic). The submission Auth-Key is stored encrypted and is write-only. The body passes the identity check and is delivered at most once. The abuse.ch answer codes are not yet confirmed against a live answer.
- Installable Selfhostr (M28). Install with one command from a release tag: `./scripts/install.sh` (also `just install`). The installer checks the machine, asks a few questions, creates every secret on the host, writes `.env` (mode `0600`), creates the data volumes and starts the stack. It never overwrites `.env`, never adopts existing volumes and never looks up the public address. Guide: `docs/install.md`.
- Two install modes: signed release images (default) and a build from the checkout (`--source`).
- Sensor switches `SENSOR_<NAME>` (default `1`). Choose the sensors with `just sensors`, or change any allowed setting with `just set`. The port guard follows the selection.
- First-run setup in the dashboard (`/setup`, migration `0025`): welcome, sensors, ports, VPN, own address, abuse reports, alerts and a checklist. It can be skipped, finished later and opened again from Settings. Settings has a new "Sensors & ports" tab with the router port and the state of each sensor.
- Safe updates: `just update` takes a database dump first, records how to roll back and checks the health of the new version. An update that did not finish blocks the next one until `--force` or a rollback. `just rollback` restores the previous code, images and database after confirmation. Guide: `docs/updates.md`.
- Signed images: the release workflow publishes amd64 and arm64 images on version tags, signs them with cosign (keyless) and runs an install smoke test. `scripts/verify-images.sh` checks the signatures, and the installer and the updater refuse to run an image that does not verify (fail closed).
- Low-memory mode (`docker-compose.lowmem.yml`) for machines of about 2 GiB.
- The running version is shown in the dashboard. An optional daily update check (`UPDATE_CHECK_ENABLED`, off by default) asks GitHub through the VPN only, sends no version or identifier, and never installs anything.
- VPN idle mode: the egress profile starts before a WireGuard file is uploaded. The tunnel stays closed, with no route out, until a configuration is uploaded or passed to the installer.
- The Selfhostr network (M29): an opt-in, anonymous pool of what many Selfhostr sensors see. Joining needs `NETWORK_ENABLED=true` in `.env` (`just set NETWORK_ENABLED=true`) and an administrator's join in Settings, Network, with the password typed again and five consents ticked. Nothing is sent before both. A member's batch carries attacker addresses, rounded counts, blinded download links, malware hashes and command servers, never credentials, commands, ports, exact times or anything of the member's own. A target is confirmed only by consensus of at least five eligible nodes. Leaving deletes the node's data at the hub. Documented in [The Selfhostr network](docs/network.md), [Network protocol](docs/network-protocol.md) and [configuration](docs/configuration.md#suckerpot-network-m29).
- The Network pages: Overview and Members under Defend, a Network tab in Settings, a Network item in the setup checklist and an optional Network step in the first-run setup. The pages show what the network did in the last 30 days and what the sensor helped confirm.
- The hub (`hub/`): the server of the network, deployed separately with its own compose file, Caddy, PostgreSQL, daily backups and an operator CLI. It keeps no client address. It sends grouped abuse reports for confirmed targets, one review at a time by default. Command-server reports are never sent automatically. See [hub/README.md](hub/README.md).
- The `spn/1` protocol library (`netproto/`): Ed25519 request and answer signatures bound to the whole request, replay protection, blinding of links and domains, proof of work for enrolment, and golden test vectors.
- Migration `0028` (node database): membership, submissions, the network's targets and summary, with their roles and retention.

### Known limits

- Network takedown checks are not active yet. M27's local re-checks exist, but the network adapter (`ingest/ingest/network/takedown.py`) does not read them yet, so members send no re-check results and no network target becomes taken down for now.

### Changed

- `docs/deployment.md` "Upgrading" now points to `just update`. The old `git pull` and `docker compose up` steps are replaced.
- Renamed to Selfhostr. The product name in the dashboard, documentation and exported reports changes; technical names (packages, volumes, environment variables, database roles) keep the `suckerpot` prefix so existing installs and data are unaffected.
- Abuse report wording is now optional (owner decision of 2026-11-01). Only the reply contact is required. An empty introduction, closing, note or signature is left out of every rendering (text, X-ARF, `.eml`), an empty subject template gives `Abuse report for <address>`, and an empty X-ARF user agent gives `Mozilla/5.0`. The `custom_intro_required` gate on marking a report reviewed is gone, and the report detail answers `missing` instead of `custom_intro`. The setup checklist item is green once the reply contact is set. The `default_wording` identity check still refuses text that equals wording published earlier.

## [0.5.0] - 2026-11-01

### Added

- Sending abuse reports (M25): a "To send" queue on the Abuse reports page opens each ready report in the mail app (the full text is copied to the clipboard), then marks it sent and moves on, with keyboard shortcuts. Free Proton addresses have no SMTP access, so this is the way to use them.
- Optional SMTP for reports, configured in Settings > Reporting > Sending (password encrypted and write-only, re-authentication, a preset for Proton paid plans with a custom domain). Three modes: off (the default: nothing is ever sent), send on click, and automatic after a waiting time with Cancel and a daily cap. Mail leaves only through the VPN, after a last identity check on the complete message (headers, envelope, EHLO name and every part); with the tunnel down nothing is sent. Delivery is at most once: a send whose outcome is unknown is never retried. Migration `0022`, `/api/v1/abuse/smtp`, `/api/v1/abuse/send-queue` and `/api/v1/abuse/reports/{id}/send`.

### Changed

- Alerts (email, Discord, Teams) now go through the identity check too: the honeypot's own addresses and terms are masked, and alerts pause until the owner's own address is confirmed in Settings > Reporting.
- The SMTP EHLO name of alert emails is the sender's domain, never the container's host name.

## [0.4.0] - 2026-11-01

### Added

- Guided tour (M24): a seven-step tour opens on each account's first login and can be replayed from the "Tour" button in the top bar. It explains daily reading, campaigns and tools, how payloads are fetched and analysed without ever being run, the VPN and its kill switch, abuse reports and alerts, each with a small flow diagram.
- Page help: a "?" next to every page title says what the page shows, where its data comes from and one useful action.
- Setup checklist: `GET /api/v1/setup/status` and a card in Settings > General (and the tour's last step) show, from the real state, what is done and what is left: sensor traffic, the outbound gate, the payload collector, report wording, your own address, abuse report drafts, alert channels and reputation keys.
- VPN tab: "Check now" asks the gate to re-check at once (`POST /api/v1/settings/vpn/check`, table `egress_check_requests`, migration `0021`) and "Reconnect" restarts the tunnel after asking for the password again (`POST /api/v1/settings/vpn/reconnect`, a marker file the `vpn` entrypoint watches).

### Changed

- While the egress gate is closed it re-checks every 20 seconds (for ten tries, then at the normal interval) instead of waiting the full interval, so lookups resume within a minute after a tunnel restart.

### Fixed

- Two flaky tests: the auth event-loop check and the collector table reset.

## [0.3.0] - 2026-11-01

### Changed

- `just test-integration` uses `docker-compose.it.yml`, an overlay that keeps `redis` on the backend network only, so the throwaway project fits in Docker's default address pools next to the live stack.
- The sidebar is grouped into ten entries. Related pages sit behind one entry with tabs: Attacks (Sessions, Attackers, Networks), Campaigns (Campaigns, Techniques), Tools (Scripts, Malware, Infrastructure), Trends (Activity, Patterns), Protection (Blocklists, Detections) and Exposure (Your exposure, CVE watch). Every old URL still works; `/attackers?view=asns` now redirects to `/networks`.
- Today is a visual story of the last 24 hours in plain words: a flow from country to service to how far each visit got, an hour-by-hour strip, and three to five stories of the day with their technical details one click away. Hard words have a short definition on hover.

### Added

- VPN configuration upload (M23): Settings > VPN takes the WireGuard `.conf` from your VPN provider, parses it strictly (no `PostUp` and the like, IP endpoint only, full tunnel) after asking for the password again, and writes it to the new `vpn-config` volume. The `vpn` service notices the new file and restarts on it; nothing leaves outside the tunnel during the switch, and the API gets no Docker socket. A new exit address stays blocked until the owner trusts the /24 the gate observed (table `egress_trusted_exits`, migration `0020`); an exit inside the honeypot's own addresses or in an AS listed in the new `EGRESS_DENY_ASNS` can never be trusted, and the exit's AS is shown next to it. `/api/v1/settings/vpn` endpoints, new guardrails.
- Anonymous reporting (M22): an ingest worker (`ABUSE_REPORTS_ENABLED`, off by default) finds abuse contacts over RDAP through the egress gate and prepares draft reports per recipient. The new `reporting/` package renders plain text, X-ARF v0.2, `.eml`, STIX 2.1 and MISP JSON and builds password-protected sample bundles. An identity guard checks every artefact before it is returned and fails closed. Learned self terms need the owner's confirmation. The package ships no wording: the owner writes it in Settings > Reporting. Nothing is ever sent by the stack. Migration `0019`, `/api/v1/abuse` endpoints, the Abuse reports page, Export for CERT, the sample bundle and the Reporting tab in Settings, `just abuse-guard-check` and the `ABUSE_*` settings.
- Anonymous egress (M21): a `vpn` service (WireGuard through gluetun, profile `egress`) with a kill switch and an HTTP proxy is the only container with a route to the internet. `ingest` and the new `collector` go through the proxy, an egress gate pauses outbound work when the tunnel or its exit address looks wrong, and the old `egress` network is removed. New `just guardrails` and `just egress-check`, new host firewall rules for `sp-vpn`, `sp-egress` and `sp-samples`.
- Payload collection and static analysis (M21): the `collector` service fetches captured download URLs through the VPN into a quarantine volume (SSRF validator, size, time and rate caps, never executed), and the network-less `analyzer` service identifies, hashes, scans with YARA, deobfuscates shell scripts and extracts C2 addresses in a limited child process. Migration `0018`, roles `suckerpot_collector` and `suckerpot_analyzer`, the `/api/v1/samples` and `/api/v1/egress` endpoints, a Samples tab, a sample page and an Egress card in Settings. `FETCH_PAYLOADS`, `PAYLOAD_MAX_BYTES` and `PAYLOAD_TIMEOUT_SECONDS` are replaced by `COLLECTOR_ENABLED` and the `COLLECTOR_*` and `QUARANTINE_*` settings.
- Synology NAS sensor (M20): a fake unpatched Synology NAS on DSM 7.2.1 (Update 11), with the DSM login page and Web API on HTTP 5000 and HTTPS 5001. Logins always fail with real DSM error codes and are recorded. Requests that match the forged-session and SCGI shapes of CVE-2026-13639 and CVE-2026-13684 are tagged `synology-exploit`, ransomware indicators of the C3RB3R campaign are tagged `c3rb3r`, and DSM API calls are tagged `synology-dsm`. Migration `0017` adds the sensor to the inventory.
- Probable C2 lookups ignore VirusTotal contacts in big shared networks (Google, Cloudflare, Microsoft, Akamai, Fastly, Meta, Apple, from the local ASN database) and CDN or update domains, and clean up already stored rows on start.
- Probable C2 addresses: for file hashes that VirusTotal or abuse.ch already know, ingest reads which addresses sandboxes saw the malware contact (VirusTotal relationships, ThreatFox `botnet_cc`), with the same fixed hosts, quotas and 24 h cache as the other intel lookups and no contact with the addresses. New table `indicator_contacts` (migration 0016), `GET /api/v1/indicators/c2`, and a blocklist reason "probable C2" (75 for ThreatFox, 40 for VirusTotal, capped at 45 when no sensor computed the hash and fewer than three networks dropped it).
- `GET /api/v1/story`, the plain-language summary behind Today.
- A `stage` filter on `GET /api/v1/sessions` and on the Attacks page (looked, guessed, got in, ran commands, tried to install, sent an exploit), plus `since` and `until` in the Attacks URL.

### Fixed

- The abuse, alerts and intel workers no longer wait up to an hour for their first run on a host that booted recently.
- CVE watch: the NVD window is 60 days (was 30) and is read in one-day chunks, oldest first, with a page budget, so a busy day no longer loses CVEs silently at the 10,000-result limit. A run that stops early resumes from its last complete chunk.
- CVE watch: GitHub advisories are read in seven-day chunks, oldest first. A one-time start-up rewind refills a shallow history, and watched CVEs that are missing from the table are fetched by id (at most 10 per run, once per id per 24 hours).

### Docs

- A "Provider API keys" guide: what each optional key adds and how to get it, step by step.
- A Troubleshooting section in the deployment guide, and the upgrade command.
- Refreshed screenshots and a new README gallery for the three-space navigation.

## [0.2.0] - 2026-10-26

### Added

- Seven more sensors (M9): Redis, Docker Engine API, MySQL, Microsoft SQL Server, Android ADB, SMB and SIP (UDP and TCP), each with real-client tests, per-IP fairness for CPU, memory and events, and a security review. SIP never sends a reply larger than its request.
- Provider keys in Settings (M11): AbuseIPDB, GreyNoise and MaxMind keys stored encrypted (AES-256-GCM), write-only in the UI, with re-authentication and a "Test key" button.
- CVE watch (M12): daily CISA KEV, NVD and GitHub advisory feeds ranked by relevance to the emulated services, with "seen in our traffic" counts and a trap-proposal sheet.
- Indicators and threat intelligence (M13): URLs, domains, IPs and hashes extracted from events, enriched by URLhaus, ThreatFox and VirusTotal, shown on an Infrastructure page with CSV and STIX export. Passive only.
- Users and roles (M14): admin and read-only viewer accounts, one-time temporary passwords, per-source lockout and an audit log. The `.env` owner account stays the root of trust.
- Campaigns and MITRE ATT&CK (M15): sessions that share a script, payload host, hash, malware family, exploit or credential list are grouped into campaigns, with a Techniques heatmap. Off by default (`CAMPAIGNS_ENABLED`, `ATTACK_ENABLED`).
- Defend (M16): scored blocklists, overrides, exports for OPNsense and pfSense aliases, an opt-in token feed (`FEEDS_ENABLED`), Sigma and Suricata rules marked "review before deploying", and "Your exposure".
- Script library (M17): command scripts with plain-English explanations, and an optional LLM explainer (`LLM_ENABLED`, off by default) that sees only normalised script text.
- Alerts and reports (M18): Discord, Microsoft Teams and e-mail (TLS) channels, alert rules that are off until switched on, a test message button, and a weekly report with a printable view. Off by default (`ALERTS_ENABLED`, `REPORTS_ENABLED`).
- Today, search and research scanners (M19): a Today home page, a global search box, a glossary, and known research scanners labelled benign by network ownership.
- Migrations `0011` to `0015` add the campaign, ATT&CK, Defend, script, alert and search tables and columns.

- RDP sensor (M10): the NTLM challenge flow, so `nmap --script rdp-ntlm-info` returns the full Windows Server 2022 identity and logins arrive as `rdp-ntlm` events with the user name and domain.
- RDP decoy accounts (`RDP_ACCOUNTS`): a login with a decoy password is verified against the NTLM response and tagged `weak-credentials`. Nothing else is ever checked.
- Optional NLA-off mode (`RDP_NLA_MODE=optional`, off by default): records the cleartext user name and password from clients that skip NLA (`rdp-nla-off` events), tagged `rdp-cleartext`.
- RDP client tool identification (nmap, FreeRDP, rdesktop, ncrack, mstsc), stored on sessions as `client_tool` and shown on the session page.
- Tag `bluekeep` for RDP sessions that bind the `MS_T120` channel.
- RDP limit `RDP_MAX_TLS_PER_IP` (default 4), so a few addresses cannot hold every TLS slot.

### Changed

- Migration `0007` adds the nullable `sessions.client_tool` column.
- Live page: the 3D globe is replaced by a flat world map (Equal Earth) with per-country arcs for the last 15 minutes, a stats strip, a ticker of the newest events and rankings of addresses, countries and networks. `SITE_HOME_LAT`, `SITE_HOME_LON`, `SITE_HOME_LABEL` and `GET /api/v1/settings/site` are unchanged.

## [0.1.0] - 2026-10-25

### Added

- Bootstrap (M0) and foundations (M1): MIT licence, project rules, roadmap, architecture and security docs, a gitleaks pre-commit hook and CI; the shared event schema, a Redis Streams pipeline, a TimescaleDB schema with Alembic migrations, an ingest consumer and an API with a live WebSocket feed.
- Demo data generator (`just demo`): synthetic sessions across all four sensors with documentation IP ranges only, plus a live mode.
- SSH sensor: OpenSSH 9.6 fingerprint, configurable weak logins, an emulated shell on a fake filesystem, download recording without fetching, and timed session recording for replay.
- Telnet sensor: BusyBox telnetd look-alike with Mirai-style flows.
- Web sensor: byte-identical Apache 2.4.58 with PHP 8.3, fake WordPress and phpMyAdmin pages, and PHP2Shell (upload-progress) detection.
- RDP sensor: Windows Server look-alike with NLA and username capture.
- Enrichment: GeoIP and ASN from DB-IP Lite (no key) or MaxMind GeoLite2, optional AbuseIPDB and GreyNoise Community reputation with a 24 h cache and enforced daily quotas.
- Tagging: a declarative YAML rules engine without regular expressions (`recon`, `mirai`, `crypto-miner`, `malware-drop`, `php2shell`).
- Dashboard: Live (3D globe and event feed), Overview (KPIs and auto-written insights), Attacks, Session detail with terminal replay, Attackers, Trends, Malware (defanged URLs) and Settings, in dark and light on desktop and mobile; a design system; a screenshot mode (`?mask=1`); Playwright screenshots.
- Dashboard login: a single admin account with an argon2 password hash, CSRF protection and a rate-limited login.
- Retention and storage: raw events kept 90 days, aggregates forever, compression, a disk guard, and `just backup` / `just restore`.
- Hardened Docker Compose stack with a host firewall template in `scripts/host/`.
- Documentation site (Sphinx, Read the Docs) and a project page.
- Repository meta: README, `CONTRIBUTING.md`, `SECURITY.md`, issue and pull request templates, Dependabot and release-note configuration.

### Security

- No attacker input is ever executed: every sensor passed several rounds of adversarial security review (the web sensor's final review is pending).
- Isolation: four networks with an internal backend, one Redis ACL user per sensor limited to `XADD` on its own stream, least-privilege database roles, no outbound route for the API, non-root read-only containers with all capabilities dropped.
- The first review of the M1 stack found unbounded stream growth, egress, poison-message and default-credential issues; all were fixed and the second pass passed.

[Unreleased]: https://github.com/selfhostr/suckerpot/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/selfhostr/suckerpot/compare/v0.14.2...v0.15.0
[0.14.2]: https://github.com/selfhostr/suckerpot/compare/v0.14.1...v0.14.2
[0.14.1]: https://github.com/selfhostr/suckerpot/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/selfhostr/suckerpot/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/selfhostr/suckerpot/compare/v0.12.2...v0.13.0
[0.12.2]: https://github.com/selfhostr/suckerpot/compare/v0.12.1...v0.12.2
[0.12.1]: https://github.com/selfhostr/suckerpot/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/selfhostr/suckerpot/compare/v0.11.13...v0.12.0
[0.11.13]: https://github.com/selfhostr/suckerpot/compare/v0.11.12...v0.11.13
[0.11.12]: https://github.com/selfhostr/suckerpot/compare/v0.11.11...v0.11.12
[0.11.11]: https://github.com/selfhostr/suckerpot/compare/v0.11.10...v0.11.11
[0.11.10]: https://github.com/selfhostr/suckerpot/compare/v0.11.9...v0.11.10
[0.11.9]: https://github.com/selfhostr/suckerpot/compare/v0.11.8...v0.11.9
[0.11.8]: https://github.com/selfhostr/suckerpot/compare/v0.11.7...v0.11.8
[0.11.7]: https://github.com/selfhostr/suckerpot/compare/v0.11.6...v0.11.7
[0.11.6]: https://github.com/selfhostr/suckerpot/compare/v0.11.5...v0.11.6
[0.11.5]: https://github.com/selfhostr/suckerpot/compare/v0.11.4...v0.11.5
[0.11.4]: https://github.com/selfhostr/suckerpot/compare/v0.11.3...v0.11.4
[0.11.3]: https://github.com/selfhostr/suckerpot/compare/v0.11.2...v0.11.3
[0.11.2]: https://github.com/selfhostr/suckerpot/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/selfhostr/suckerpot/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/selfhostr/suckerpot/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/selfhostr/suckerpot/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/selfhostr/suckerpot/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/selfhostr/suckerpot/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/selfhostr/suckerpot/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/selfhostr/suckerpot/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/selfhostr/suckerpot/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/selfhostr/suckerpot/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/selfhostr/suckerpot/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/selfhostr/suckerpot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/selfhostr/suckerpot/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/selfhostr/suckerpot/releases/tag/v0.1.0
