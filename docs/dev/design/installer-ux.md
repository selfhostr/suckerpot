# Installer experience

Status: approved by the owner on 2026-11-21 (decisions in section 7). Not implemented yet.

## 1. Problem and goals

Testers and the owner find `scripts/install.sh` hard to read. A participant install prints well over a hundred lines, a full install asks up to 13 questions, and the important lines (the dashboard address, the generated password, the next command) are lost in the output of `verify-images.sh` and `docker compose`.

The main audience is participants who install on a VPS over SSH, and owners who do a full install at home.

Goals:

- G1. At most 2 or 3 questions in an interactive run. Everything else takes a smart default or a flag.
- G2. A short header in the project style, a fixed list of steps with one progress bar, and a short final screen.
- G3. All verbose output goes to a log file. On error, the screen shows the failing step, the last lines of the log, the log path and the fix.
- G4. A stable plain mode for CI, scripts and redirected output, that the guardrails and the participant end-to-end test can rely on.
- G5. Pure bash, no new dependency. Every existing flag keeps working.

Non-goals: a full-screen TUI, mouse or arrow-key menus, translations, and `curl | bash` (`docs/install.md:64` and `docs/dev/design/m28.md:28` rule it out on purpose).

## 2. What exists today (inventory)

Line numbers are from `origin/main` at `7bf0a1e`. The Podman Phase 1 branch (`feat/podman-p1-engine`) changes about 40 lines of `install.sh` (`docker` becomes `ctr` or `dc`, plus an engine check after line 250); the line numbers below shift by a few lines after it merges.

### 2.1 Questions

Answers are read from `/dev/tty` (or `SELFHOSTR_TTY` in the tests) on fd 3, so stdin stays free for `--admin-password-stdin` (`scripts/install.sh:179-185`). `ask` returns the default when `noask=1` (`:192-201`); `ask_always` asks even in participant mode, only `--yes` skips it (`:204-209`). Participant mode sets `noask=1` (`:267`).

| # | Question | Where | Flag | Default | Asked when |
| --- | --- | --- | --- | --- | --- |
| 1 | Continue without enough swap? (yes/no) | `install.sh:173` | `--yes` continues | no (stops) | less than 512 MiB swap on a 1 GiB lite or a "2 GB" machine |
| 2 | Use the lite setup instead? | `install.sh:345` | `--lite` | yes | participant, 0.875 to 1.75 GiB of memory |
| 3 | Install mode: images or source | `install.sh:431` | `--images`, `--source` | images | fresh full |
| 4 | Sensors: recommended, all, or a list | `install.sh:442` | `--sensors` | recommended | fresh full |
| 5 | Dashboard reached [l]ocally or through an [h]ttps tunnel | `install.sh:460` | `--dashboard-bind`, `--public-host` | l | full |
| 6 | Public host name of the dashboard | `install.sh:464` | `--public-host` | none (required) | answer h to 5 |
| 7 | Admin user name | `install.sh:481` | `--admin-user` | admin | full |
| 8 | Admin password, then repeat | `install.sh:494-506` | `--admin-password-stdin` | empty = generate | full |
| 9 | Use the low-memory mode? | `install.sh:520` | `--lowmem` | yes | fresh full, less than 6 GiB |
| 10 | Check once a day for a newer release? | `install.sh:536` | none | n | fresh full |
| 11 | Keep the automatic daily updates? | `install.sh:541` | none | yes | switch participant to full, auto-update on |
| 12 | Path to a WireGuard .conf | `install.sh:548` | `--wg-conf` | empty (upload later) | fresh full |
| 13 | Your own public address | `install.sh:559` | none in full mode (`--self-address` is participant only) | empty | fresh full |
| 14 | Join the SuckerPot network as described? [y/N] | `install.sh:587` after the consent screen (`lib/env.sh:407-446`, 30 lines) | `--yes` is the consent | N (stops) | fresh participant |
| 15 | Join the SuckerPot network? [y/N] | `install.sh:619` after `consent_screen_full` (`lib/env.sh:448-485`, 28 lines) | `--join-network`, `--no-network` | N | fresh full |
| 16 | SSH sensor: [m]ap to 2222, [o]ff, [k]eep 22 | `install.sh:655` | none | m | full, port 22 busy (participant maps without asking) |
| 17 | Port N is in use: another port, or off | `install.sh:667` | none (`--sensors`) | off | full, any other busy port (participant: off) |
| 18 | Port of this machine's own admin SSH | `install.sh:695` | `--admin-ssh-port` | detected | fresh full |
| 19 | Install the host firewall now? [Y/n] | `lib/firewall.sh:118`, called at `install.sh:1113` | `--yes`: installs if `sudo -n` works, else prints the command | Y | participant, after the stack runs |
| 20 | Ports not reachable yet: [r]echeck or [c]ontinue | `install.sh:1137` | `--yes` skips | c | participant, no traffic within 90 s |

A typical interactive full install asks 10 to 13 of these. An interactive participant install asks 14, 19 and often 20, and 1 or 2 on small machines. Questions 10 and 13 have no flag in full mode.

### 2.2 Phases

`TOTAL=10`, printed as `[n/10] Title` by `step` (`install.sh:61-64`).

| Step | Title | Lines | What it does |
| --- | --- | --- | --- |
| 1 | Checking this machine | 212-409 | bash, OS, arch, worktree, existing `.env` and mode, flag checks, lite offer, Docker 24+ (warns below 28), Compose 2.24+, memory, swap, disk 15 GiB, no existing volumes or containers, crontab or systemctl |
| 2 | Settings | 412-628 | questions 2 to 15, consent screens |
| 3 | Checking ports | 631-699 | `ss` for busy ports, questions 16 to 18 |
| 4 | Generating secrets | 702-718 | 24 secrets |
| 5 | Hashing the admin password / Checking the images | 721-788 | verify and pull the api image and hash (full), verify the ingest image (participant) |
| 6 | Writing .env | 791-979 | writes `.env` 0600, backup before a mode switch |
| 7 | Creating the data volumes | 988-995 | `ensure-volumes.sh`, one line per volume |
| 8 | Checking the port layout and VPN settings | 998-1008 | `check-ports.sh`, `check-vpn-env.sh`, `check-participant.sh` |
| 9 | Starting SuckerPot | 1011-1053 | `verify-images.sh --pull`, `docker compose pull --policy missing`, `up --wait`, dashboard `/healthz` |
| 10 | Done | 1056-1194 | update schedule, final text, firewall (`fw_step`), ports check |

### 2.3 What it prints

Measured in a throwaway copy with the guardrail fakes (`scripts/guardrails/tests/conftest.py`), which print nothing for `verify-images.sh` and `docker compose`:

| Run | Lines (fakes) | Estimate on a real host |
| --- | --- | --- |
| `--participant --yes` | 130 | 200 to 250: add two `verify-images.sh` runs (about 3 + one line per image each) and the compose pull and up output |
| `--yes` (full) | 57 | 120 to 180 |
| full, interactive, Enter on every question | 81 (13 prompts) | 150 to 200 |

The participant run spends 30 lines on the consent screen, 20 on volume names, 9 on a DMZ warning (`install.sh:1105-1109`), 10 to 15 on the firewall (`lib/firewall.sh:96-137`) and 25 on the ports check (`lib/ports-check.sh:60-101`). `docker compose up` draws its own live progress on a terminal.

`install.log` (`install.sh:53, 60`) only holds timestamped step lines and `FAILED:` lines. The verbose output goes to the screen and is lost when the terminal scrolls.

### 2.4 Modes

| Mode | Where | Behaviour today |
| --- | --- | --- |
| `--yes` | `install.sh:104`, `:189` | no question; generates the admin password and prints it once, or reads it with `--admin-password-stdin`; never joins the network in full mode (`:611-612`); is the participant consent (`:583-585`); firewall installed only if `sudo -n` works (`lib/firewall.sh:107-112`); no recheck question |
| `--participant` | `install.sh:123`, `:256-267` | images mode, recommended sensors (lite: 4), no dashboard questions, consent screen; `ask_always` questions still asked |
| `--full` | `install.sh:124`, `:238-242` | switches a participant install to full mode (asks the dashboard questions, backup first) |
| `--repair` | `install.sh:135`, `:229-232`, `:247` | existing install only, keeps settings; volumes, checks, start and schedule again |
| `--dry-run --env-out PATH` | `install.sh:121`, `:144`, `:981-985` | writes the would-be `.env`, no Docker call, no log, stops after step 6 |
| no flag, `.env` exists | `install.sh:233-237` | prints "already installed", runs `status.sh`, exits 0 |
| non-TTY | `install.sh:181-185` | without `--yes` it needs `/dev/tty`, else "no terminal to ask questions on; use --yes". Output is the same as on a terminal; only the ports check draws a `\r` countdown when stdout is a terminal (`lib/ports-check.sh:82-86`) |

### 2.5 Other entry points

- `scripts/participant.sh join` (`:144-185`) prints the same consent screen and asks `Join the SuckerPot network as described? [y/N]` (`confirm`, `:51-60`). `vpn`, `firewall`, `auto-update` and `uninstall` print one or two lines each.
- `scripts/update.sh` uses the same `[n/N]` steps (`:102`, `:135-374`). It mostly runs unattended through `auto-update.sh`, with output in `.suckerpot-state/auto-update.log`.
- Website (`src/templates/download.html:23-33`): `git clone`, `git switch --detach "$(git describe --tags --abbrev=0)"`, then `./scripts/install.sh`.
- Website (`src/templates/participate.html`): step 1 installs Docker with `curl -fsSL https://get.docker.com | sudo sh` and `sudo usermod -aG docker $USER` (`:11-13`); step 2 clones (`:21-22`); step 3 `sudo ./scripts/move-admin-ssh.sh` (`:30`); step 4 `./scripts/install.sh --participant` (`:37`); a command table for `participant.sh` (`:175-181`).
- The participant end-to-end test runs `install.sh --participant --yes --source ...` with output to a file and uses only the exit code and `tail -n 14`/`-n 40` (`scripts/e2e/participant.sh:178-180`).
- The guardrails (`scripts/guardrails/tests/test_install.py`, 1594 lines) assert about 60 substrings of the output (for example `"--yes was given"`, `"Use port forwards, not your router's DMZ"`, `"Automatic updates:      off"`, `"SuckerPot is running in participant mode (v0.8.0)."`), the generated password through the regex `password .*: (\S+)`, and that no secret reaches the output or `install.log` (`:282-284`, `:806-810`).

## 3. Target experience

### 3.1 Questions

An interactive run asks at most three things. Each is skipped when a flag answers it.

1. **Install type** (`--participant`, `--full`). Participant node or full install. On a machine below 1.75 GiB, full is shown as not possible and participant (lite) is preselected. Without a terminal and without a flag the default stays full, as today.
2. **Engine** (`--engine docker|podman`, new; also `SUCKERPOT_ENGINE`). Auto-detected with `engine_detect` from `scripts/lib/engine.sh`. Asked only when:
   - both engines are installed and usable. Podman Phase 2 refuses a host where Docker is also active, so in practice this offers Podman only when `docker.service` is stopped; otherwise Docker is used and the screen says why.
   - neither is installed. The installer reads `/etc/os-release` and offers to install the right one with sudo, or to print the one command and stop (3.8).
   Until Podman Phase 3 lands, Podman is refused (`engine_ready`, `ENGINE_UNREADY_MSG`) and this question never shows Podman.
3. **Consent** (participant: `--yes`; full: `--join-network`, `--no-network`). The participant consent screen is shown in full, unchanged, with its `[y/N]`. It is the legal basis of the network and stays a real question.

Everything else gets a default:

| Today | New default | How to change it |
| --- | --- | --- |
| 1 swap | warn on the final screen, continue | add swap, `--repair` |
| 2 lite | lite when 0.875 to 1.75 GiB (as `--yes` does today) | `--lite`, a bigger machine |
| 3 install mode | images | `--source` |
| 4 sensors | recommended | `--sensors`, `just sensors` |
| 5, 6 dashboard access | 127.0.0.1, SSH tunnel | `--public-host`, `--dashboard-bind` |
| 7 admin user | admin | `--admin-user` |
| 8 password | generated, shown once on the final screen | `--admin-password-stdin` |
| 9 low memory | on below 6 GiB | `--lowmem` |
| 10 update check | off | `--update-check` (new), dashboard |
| 11 keep auto-update | yes | `participant.sh auto-update off` |
| 12 WireGuard file | upload later in the dashboard | `--wg-conf` |
| 13 own address | learnt from traffic | `--self-address` (now also in full mode) |
| 15 full-mode network join | not joined; joined in the dashboard (decision O2) | `--join-network` |
| 16 port 22 busy | SSH sensor on host port 2222, as participant does today | `--admin-ssh-port`, `move-admin-ssh.sh` |
| 17 other busy port | that sensor off, listed on the final screen | `just sensors` |
| 18 admin SSH port | detected (sshd config, port 22 busy) | `--admin-ssh-port` |
| 19 firewall | installed by default; sudo is asked in the open (3.6) | `--no-firewall` (new; Podman D5 adds it anyway) |
| 20 ports recheck | no question; the final screen gives the command | `participant.sh ports-check` |

### 3.2 Header

The website logo is a violet drop with a dark eye and a white pupil (`img-family/ic-suckerpot.svg`), next to the word "SuckerPot" in Inter. The terminal header draws the drop in four lines of block characters, in the accent colour, with the wordmark in bold and one dim line of context:

```
    ▄     SuckerPot
   ███    participant node · v0.13.0 · Docker 28.1.1
  ██●██   log: ~/suckerpot/install.log
   ▀▀▀
```

Without UTF-8 (`locale charmap` is not UTF-8), the drop is dropped and the header is one line: `SuckerPot  participant node - v0.13.0 - Docker 28.1.1`.

Palette, from `src/css/site.css` of the website (`:root` and the terminal tokens `--t-*` of `.guard` and `.demo`):

| Role | Site token | Truecolor | 256 colours | 8 colours |
| --- | --- | --- | --- | --- |
| accent: logo, bar, current step | `--accent` | `#a78bfa` | 141 | magenta (35) |
| done (✓) | `--t-ok` | `#6fd3b5` | 79 | green (32) |
| warning | `--t-stop` | `#f5a35c` | 215 | yellow (33) |
| failed (✗) | `--severe` | `#f2555a` | 203 | red (31) |
| prompt, links, commands | `--t-prompt` | `#8fbcf3` | 111 | blue (34) |
| dim text, pending steps, empty bar | `--t-dim` | `#8b8f99` | 246 | dim attribute (2) |
| text | `--t-fg` | terminal default | default | default |

The background is never set: the terminal's own background stays. Truecolor when `COLORTERM` is `truecolor` or `24bit`; 256 colours when `TERM` ends in `256color` (this covers `tmux-256color` and `screen-256color`); 8 colours otherwise.

### 3.3 Progress

- A fixed list of steps, known before the first one starts, each with `·` pending, a spinner while it runs, `✓` done, `–` skipped, `✗` failed, and a short result on the right (for example `20/20, 19 signatures valid`).
- One overall bar under the list. Steps have weights (images about 40 %, start of the stack about 35 %). Inside a step the bar moves when a count is known: `verify-images.sh` prints one `ok` line per image, compose prints one line per pulled image and per healthy container. The `ui_run` helper counts these lines in the log. Elapsed time on the right.
- The list is redrawn in place: cursor up, erase line, rewrite. No alternate screen, no terminal query, no scrolling region. What is above the list stays in the scrollback.
- All output of the commands goes to the log. `docker compose` runs with `--progress plain` there, so its live display never reaches the terminal.

Participant steps: Check this machine, Settings and secrets, Data volumes, Verify and download images (the 19 signed images by verified digest, then the pinned database and VPN images), Start SuckerPot, Host firewall, Automatic updates, Sensor reachability. Full steps: Check this machine, Settings and secrets, Admin account (verify the api image, hash), Data volumes, Verify and download images, Start SuckerPot, Dashboard answers. `--repair` and `--full` (switch) mark the steps they do not run as skipped.

### 3.4 Log

`install.log` stays where it is (the checkout). Each run appends a header (date, version, flags without values, mode), then every command line and its full output, with timestamps on the step lines as today. The file is mode 0600.

Secrets never reach it. Rule for callers: secrets are never in command arguments (the log records them) and never printed by a logged command. The password goes on stdin to the hasher, as today. The guardrails already check `.env` secrets and the password against the log (`test_install.py:282-284, 806-810`); they now also cover the verbose output.

### 3.5 Errors

On a failure the spinner turns into `✗`, the bar stops, and below it:

- one sentence: what failed (the existing `die` text);
- the last 15 lines of the log, indented with `│`;
- `Fix:` with the command, when known;
- `Log:` with the absolute path.

Once `.env` is written, a new plain run only prints "already installed". So every fix after step "Settings and secrets" ends with `./scripts/install.sh --repair`. `die` gets an optional second argument for the fix; the existing messages that already say "run: ..." or "Try: ..." move their command there.

### 3.6 Prompts, sudo and interruptions

- All questions are asked before the progress starts. Only two things can interrupt it: the sudo password for the firewall, and a fatal error.
- `ui_pause` erases the live list, shows the cursor and restores the terminal; `ui_resume` redraws the list below. The sudo prompt runs between the two: `sudo -n true` first; if it needs a password, the screen says why on one line, then `sudo -v` runs in the foreground on the terminal. The firewall step then runs with the cached credentials. A failed or refused sudo marks the step `–` with the command for later; the stack keeps running.
- Ctrl-C (INT), TERM and HUP: kill the running command, mark the step `✗ interrupted`, show the cursor, restore `stty` (a hidden password read can leave echo off), print the log path, exit 130. The temporary `.env.tmp` is removed as today (`install.sh:801`): `ui.sh` keeps a list of exit hooks so the installer's own trap and the UI trap do not overwrite each other.
- Window resize (WINCH): read the new size, erase from the top of the list, redraw.

### 3.7 Final screen

Short: what runs, how to reach it, and the one next command. Warnings collected during the run (Docker older than 28, little swap, a sensor left off because its port is busy) are repeated here, one line each. The longer texts (DMZ advice, firewall details, port table) stay in the docs and in `./scripts/status.sh`; the final screen links to them. The existing auto-fixes stay: the firewall by default, the automatic update schedule, and the **Needs attention** block of `./scripts/status.sh` for anything left to do.

### 3.8 No engine installed

When neither engine is found (`command -v docker` and `command -v podman` fail):

| Distribution | Docker | Podman (after Podman Phase 3 only) |
| --- | --- | --- |
| Debian 13, Ubuntu 24.04 and 26.04 | `curl -fsSL https://get.docker.com \| sudo sh` and `sudo usermod -aG docker $USER`, as on the website | `sudo apt install -y podman docker-compose` (Debian 13, Ubuntu 26.04) |
| Fedora, RHEL 10 family | same script | `sudo dnf install -y podman docker-compose` |
| other | print the docs link and stop | not offered |

After installing Docker, the user is in the `docker` group only in a new login. The installer continues under `sg docker -c` (shadow-utils, present wherever `usermod` is) and tells the user to log in again before using `docker` by hand (decision O4).

### 3.9 Plain mode

Plain mode is selected when any of these holds: stdout or stderr is not a terminal, `TERM` is empty or `dumb`, the new `--plain` flag is given, or `SUCKERPOT_UI=plain`. `SUCKERPOT_UI=rich` forces the rich mode (tests). `--yes` on a terminal keeps the rich display (decision O6). `NO_COLOR` keeps the rich display without any colour (decision O5).

Plain mode writes no escape sequence, no `\r` and no cursor movement, one event per line. Its grammar is fixed and covered by tests:

```
<header>   SuckerPot installer <version> (<type>, <engine>)
           log: <absolute path>
<start>    [<n>/<N>] <title>
<note>     6 spaces, then text
<warning>  6 spaces, "warning: ", text
<end>      [<n>/<N>] ok|skipped|failed[: <detail>]
<error>    install: <message>
           fix: <command>
           log| <one of the last 15 log lines>
<result>   result: ok|failed key=value ...
```

The last line is always `result:`, for example `result: ok type=participant version=v0.13.0 engine=docker log=/home/user/suckerpot/install.log` or `result: failed step=6 log=...`. Free text between steps (the consent screen, the final screen) keeps today's wording, so the strings the guardrails assert stay true. The ports check prints its table once, without the countdown.

## 4. Hard constraints

- Pure bash 4 and coreutils. No `tput`, `dialog`, `whiptail`, `gum`. Width from `$COLUMNS`, then `stty size < /dev/tty`, then 80.
- Over SSH and in tmux: only CR, `ESC[nA`, `ESC[2K`, `ESC[J`, `ESC[?25l`/`ESC[?25h` and SGR colours. At most 8 redraws per second, and only the list region. No terminal query that waits for an answer.
- Lines are cut to the width minus one, so nothing wraps and the cursor arithmetic holds. Below 60 columns the right-hand results are dropped; below 40 columns, or when the terminal is shorter than the list plus 4 lines, the list collapses to the current step and the bar.
- Non-TTY, `TERM=dumb` and `--plain`: plain mode (3.9). `NO_COLOR`: rich display, no colour. `--yes` on a terminal: rich display, no question.
- Prompts are never hidden: no question is asked while the list is live (3.6).
- sudo prompts run in the paused state (3.6).
- Every existing flag keeps its meaning. New flags (approved): `--plain`, `--engine`, `--no-firewall`, `--update-check`, `--verbose` (streams the log to the screen in plain mode), and `--self-address` in full mode.
- `SELFHOSTR_TTY` keeps working for the tests.

## 5. Implementation plan

### 5.1 `scripts/lib/ui.sh`

| Function | Purpose |
| --- | --- |
| `ui_init TOOL LOGFILE` | detect plain or rich, colours, UTF-8, width; open the log; set the traps (INT, TERM, HUP, WINCH, EXIT) |
| `ui_header TITLE CONTEXT` | the header (3.2) or its plain line |
| `ui_plan ID:TITLE:WEIGHT ...` | declare the fixed step list |
| `ui_step ID` / `ui_done [DETAIL]` / `ui_skip [DETAIL]` | start and end a step that runs shell code in the foreground (no animation while it runs; these steps are short) |
| `ui_run ID [--count REGEX N] -- CMD ARGS...` | run a long command in the background with output to the log, animate the spinner, count lines for the bar, return its status |
| `ui_note TEXT`, `ui_warn TEXT` | a note under the current step (plain) or in the step result (rich); warnings are also kept for the final screen |
| `ui_choose VAR TITLE DEFAULT N:LABEL:HELP ...` | a numbered choice on fd 3 |
| `ui_confirm VAR QUESTION y|n` | a yes or no question |
| `ui_secret VAR PROMPT` | a hidden read that always restores `stty echo` |
| `ui_pause`, `ui_resume`, `ui_sudo REASON` | hand the terminal over (3.6) |
| `ui_fail MESSAGE [FIX]` | the error screen (3.5), exit 1 |
| `ui_summary` with `ui_kv KEY VALUE`, `ui_line TEXT` | the final screen |
| `ui_on_exit CMD` | chain an exit hook |

`ui.sh` is self-contained: it does not source `env.sh` or `engine.sh`, so it can land before or after them.

### 5.2 Order with the Podman phases

| Order | Change | Touches `install.sh`? | Conflict risk |
| --- | --- | --- | --- |
| 1 | Podman Phase 1 (`engine.sh`, `ctr`/`dc`) merges | yes, about 40 lines | none for this plan |
| 2 | UI phase A: `scripts/lib/ui.sh` and its tests only | no | none |
| 3 | UI phase B: `install.sh` moves to `ui.sh` in one PR, rebased on Phase 1 | yes, most `step`/`note`/`die`/`ask` call sites and the end | Podman Phase 2 edits the engine checks in step 1. Land B before Phase 2 touches `install.sh`, or write Phase 2's checks with `ui_fail`; the second to merge rebases |
| 4 | UI phase C: install-type question, Docker install offer, fewer questions (3.1) | yes | low |
| 5 | Podman Phase 2 and 3 (Podman works, firewall mandatory) | engine checks, firewall step | the firewall step already exists in the UI plan; Phase 3 makes it non-skippable on Podman |
| 6 | UI phase D: the engine question offers Podman | small | none |
| 7 | UI phase E: `participant.sh` and `update.sh` | no | low |

### 5.3 Tests

- `ui.sh` unit tests (guardrails, bash called from pytest): plain grammar; no `\x1b` and no `\r` in plain output under `TERM=dumb`, a pipe and `--plain`; no colour sequence under `NO_COLOR=1`; colour tier by `TERM`/`COLORTERM`; line cut at `COLUMNS=30, 50, 80`; `ui_fail` prints the last 15 log lines, `fix:` and `log:`; Ctrl-C during `ui_run` (a fake command that sleeps, then SIGINT): exit 130, `ESC[?25h` printed, child gone, log kept, `.env.tmp` removed.
- Golden plain output: `install.sh` in the existing sandbox for `--participant --yes`, `--yes` (full), `--repair`, a failed start (`SHIM_UP_RC=1`) and `--dry-run`. Pseudonyms, times, durations and paths are normalised. Fixtures in `scripts/guardrails/tests/fixtures/install-plain/`, refreshed with `UPDATE_GOLDEN=1`.
- Rich mode with `SUCKERPOT_UI=rich` and the answers file: no line longer than `COLUMNS`, the cursor shown at exit, the last frame has every step `✓`.
- The existing substring and secret tests stay; the secret tests now also read the verbose log.
- `scripts/e2e/participant.sh` runs unchanged (it is `--yes` to a file, so plain mode). Its `tail -n 40` on failure now shows the error block.
- shellcheck on `ui.sh` and every caller.

### 5.4 Phases and acceptance

**Phase A, `ui.sh`.** Acceptance: the unit tests pass; the plain grammar is documented in `docs/dev/`; no caller yet.

**Phase B, `install.sh` on `ui.sh`.** Same questions and flags as today; only the display changes. Acceptance: every existing guardrail passes with at most wording changes reviewed one by one; golden plain files committed; the participant e2e passes; a manual run over SSH in tmux, at 50 and 120 columns, with a resize and a Ctrl-C during the image download, leaves a clean terminal; a full and a participant install print at most 30 lines on the rich screen (header, list, bar, final screen) on a real host.

As built (phases A and B, one PR): plain mode prints exactly the old output, with stdout and stderr kept apart, plus one line after a failure: `      log: <path>` on stderr (the golden files in `scripts/guardrails/tests/fixtures/install-plain/` pin it). The `[n/N] ok` end lines and the `result:` line of 3.9 are left for a later phase, so no guardrail had to change. The rich list keeps the order of the code: participant installs show Check this machine, Settings and secrets, Data volumes and checks, Verify and download images, Start SuckerPot, Automatic updates, Host firewall, Sensor reachability; full installs show Admin account after Settings and secrets, and Dashboard answers at the end. Warnings are printed above the list when they happen, not repeated on the final screen. Consent screens and questions keep their wording; on the rich display they are printed above the list, indented like the rest. An error that no step reported (a failed `cp` under `set -e`, a full disk) still ends with the failure screen, written to the terminal only. Ctrl-C, TERM and HUP stop the running command at once, shell functions included.

**Phase C, fewer questions.** The defaults of 3.1, the install-type question, the Docker install offer, the new flags. Acceptance: an interactive full install asks at most 2 questions (type, plus the network question if O2 keeps it), a participant install at most 2 (type, consent); every removed question has a flag; `docs/install.md`, `docs/participate.md`, `docs/vps.md` and the website pages are updated.

**Phase D, engine question.** After Podman Phase 3. Acceptance: on a VM with both engines (Docker stopped) and with neither, the question appears and the choice is written to `SUCKERPOT_ENGINE`; with one engine, no question.

**Phase E, other scripts.** `participant.sh join` uses `ui_confirm` and the same consent text; `update.sh` uses the steps and the plain grammar (auto-update stays plain). Acceptance: their guardrails pass; `auto-update.log` keeps its format or the change is documented.

## 6. Mockups

Interactive participant install, mid-progress (80 columns):

```
    ▄     SuckerPot
   ███    participant node · v0.13.0 · Docker 28.1.1
  ██●██   log: ~/suckerpot/install.log
   ▀▀▀

  ✓ Check this machine           1.9 GiB memory, 2 GiB swap, 38 GiB free
  ✓ Settings and secrets         pseudonym sleek-violet-46
  ✓ Data volumes                 20 created
  ⠹ Verify and download images   9/20 · sensor-web
  · Start SuckerPot
  · Host firewall
  · Automatic updates
  · Sensor reachability

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━━━━━━━━━━━━━━━━━  52%   1:42
```

The same install, finished:

```
    ▄     SuckerPot
   ███    participant node · v0.13.0 · Docker 28.1.1
  ██●██   log: ~/suckerpot/install.log
   ▀▀▀

  ✓ Check this machine           1.9 GiB memory, 2 GiB swap, 38 GiB free
  ✓ Settings and secrets         pseudonym sleek-violet-46
  ✓ Data volumes                 20 created
  ✓ Verify and download images   20/20, 19 signatures valid
  ✓ Start SuckerPot              11 services healthy
  ✓ Host firewall                loaded, starts at boot
  ✓ Automatic updates            every 6 h from 05:41
  ✓ Sensor reachability          no traffic yet (normal before the forwards)

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%   3:57

  SuckerPot is running in participant mode.
    Pseudonym  sleek-violet-46       Path   direct (no VPN)
    Hub        suckerpot-hub.selfhostr.io

  ! Port 6379 is in use here: the redis sensor is off (free it, then: just sensors)

  Forward these router ports to this machine, not a DMZ:
    22→2222 ssh   23 telnet   80, 443 web   2375 docker   5555 adb
  Never forward your admin SSH port (22).

  Next   ./scripts/participant.sh ports-check   after the forwards
         ./scripts/status.sh                    any time
```

A failed step:

```
    ▄     SuckerPot
   ███    participant node · v0.13.0 · Docker 28.1.1
  ██●██   log: ~/suckerpot/install.log
   ▀▀▀

  ✓ Check this machine           1.9 GiB memory, 2 GiB swap, 38 GiB free
  ✓ Settings and secrets         pseudonym sleek-violet-46
  ✓ Data volumes                 20 created
  ✓ Verify and download images   20/20, 19 signatures valid
  ✗ Start SuckerPot              db is unhealthy
  · Host firewall
  · Automatic updates
  · Sensor reachability

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━━━━━  78%   failed

  ✗ The stack did not become healthy.

    │  Container suckerpot-redis-1  Healthy
    │  Container suckerpot-db-1  Waiting
    │  container suckerpot-db-1 is unhealthy
    │  ...                                  (15 lines in the real screen)

  Fix   docker compose logs db
        then: ./scripts/install.sh --repair
  Log   /home/user/suckerpot/install.log
```

Question 1, install type:

```
    ▄     SuckerPot
   ███    installer · v0.13.0
  ██●██
   ▀▀▀

  What do you want to install?

    1  Participant node   Sensors only. Joins the SuckerPot network.
                          For a VPS. 1 GiB of memory or more.
    2  Full install       Sensors, dashboard, VPN egress, reports.
                          For a home server. 2 GiB of memory or more.

  Choose 1 or 2 [1]: _
```

Question 2, engine (only when both, or neither, are present):

```
  Docker 28.1.1 and Podman 5.4.2 are both installed.

    1  Docker   recommended
    2  Podman   experimental; the host firewall is required

  Choose 1 or 2 [1]: _
```

```
  No container engine was found. SuckerPot needs Docker or Podman.

    1  Install Docker now   sudo, Docker's script from get.docker.com
    2  Install Podman now   sudo apt install podman docker-compose (experimental)
    3  Show the command and stop

  Choose 1, 2 or 3 [1]: _
```

Question 3, participant consent (the full text of `consent_screen`, unchanged, shortened here):

```
  SuckerPot participant mode (experimental preview)

  This machine will run honeypot sensors and send what they see to a hub run by the
  SuckerPot maintainers. What is sent, once a day and a few hours late:
    - source addresses seen by your sensors, with the services they used, what they did and
      rounded counts;
    ...
  Leave at any time: ./scripts/participant.sh leave

  Pseudonym: sleek-violet-46   (change: --pseudonym NAME, none: --no-pseudonym)

  Join the SuckerPot network as described? [y/N] _
```

Plain output (`./scripts/install.sh --participant --yes > install.out`):

```
SuckerPot installer v0.13.0 (participant, docker)
log: /home/user/suckerpot/install.log
[1/8] Check this machine
      warning: Docker Engine 27.0.1 is older than 28. On this engine the internal networks are NOT isolated from the host (the isolation needs gateway_mode_ipv4: isolated, from Engine 28). Upgrading Docker Engine to 28 or newer is strongly recommended.
[1/8] ok: 1.9 GiB memory, 2 GiB swap, 38 GiB free
[2/8] Settings and secrets

SuckerPot participant mode (experimental preview)
... consent screen, unchanged ...
--yes was given: this counts as your agreement to join as described above.

      Mapped the SSH sensor to host port 2222.
[2/8] ok: pseudonym sleek-violet-46
[3/8] Data volumes
[3/8] ok: 20 created
[4/8] Verify and download images
[4/8] ok: 20/20, 19 signatures valid
[5/8] Start SuckerPot
[5/8] ok: 11 services healthy
[6/8] Host firewall
      The host firewall needs sudo, which asks for a password here. To install it now, run:
        ./scripts/participant.sh firewall
[6/8] skipped: needs sudo
[7/8] Automatic updates
[7/8] ok: every 6 h from 05:41
[8/8] Sensor reachability
[8/8] ok: no traffic yet

SuckerPot is running in participant mode (v0.13.0).
  Pseudonym: sleek-violet-46   Hub: suckerpot-hub.selfhostr.io   Path: direct (no VPN)
... ports to forward, next commands, as today ...
result: ok type=participant version=v0.13.0 engine=docker log=/home/user/suckerpot/install.log
```

## 7. Decisions

The owner decided on 2026-11-21. The new flags of section 4 (`--plain`, `--engine`, `--no-firewall`, `--update-check`, `--verbose`, `--self-address` in full mode) are approved.

| # | Question | Decision |
| --- | --- | --- |
| O1 | Default of the install-type question | **Approved.** Participant, the main audience. Without a terminal and without a flag the default stays full, so existing scripts do not change |
| O2 | Keep the full-mode network question (15) in the installer? | **Approved.** Remove it: not joined by default, join in the dashboard or with `--join-network`. This saves a 28-line screen |
| O3 | Admin password in a full install | **Approved.** Always generated and shown once on the final screen; `--admin-password-stdin` for your own. No more typed-twice prompt |
| O4 | Engine install when none is found | **Approved.** Offer it (Docker by `get.docker.com`, as the website does; Podman from distro packages) and continue under `sg docker`. |
| O5 | `NO_COLOR` | **Changed by the owner.** `NO_COLOR` keeps the live display, without colour. Plain mode is not selected by it |
| O6 | `--yes` on a real terminal | **Changed by the owner.** `--yes` on a terminal uses the rich display. Plain mode is only for non-TTY output, `TERM=dumb`, or the new `--plain` flag |
| O7 | Firewall step | **Approved.** On by default; it asks for the sudo password in the open. With `--yes` and no passwordless sudo it is skipped with the command, as today |
| O8 | Final screen | **Approved.** Short, and the long DMZ advice moves to the docs and `status.sh`. Plain mode keeps today's full text in phase B |
| O9 | Log location | **Approved.** Keep `install.log` in the checkout. |
| O10 | Website step 1 (Docker install command on `participate.html`) | **Approved.** Keep it until phase C ships, then drop it: the installer offers the install |
