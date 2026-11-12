# Update and roll back

SuckerPot updates with one command, `just update`. Before anything changes, the update takes a database dump. If the update fails, or you want to go back, `just rollback` puts the previous code, images and database back.

This page covers:

- what `just update` does, step by step;
- how image signatures are checked;
- the database dump taken before each update;
- `just rollback`, and what it costs;
- the lock that stops a second update after a failed one, and `--force`;
- the optional update check.

```{warning}
A rollback replaces the database with the dump. Everything written after that dump is lost: events, sessions, settings and accounts. Read [Rollback](#rollback) before you use it.
```

## Commands

| Command | What it does |
| --- | --- |
| `just update` | Update to the newest release tag (`v*.*.*`). Asks you to confirm. |
| `just update vX.Y.Z` | Update to a given release. |
| `just update --yes` | Skip the confirmation. |
| `just update --no-backup` | Update without a database dump. Asks you to type `no backup`. Not recommended. |
| `just update --skip-verify` | Do not check the image signatures. Not recommended. |
| `just update --force` | Start an update even though the last one did not finish. See [the unfinished-update lock](#the-unfinished-update-lock). |
| `just rollback` | Go back to the state of the last update. Asks you to type `rollback`. |
| `just version` | Show the checkout version, the install mode, the image version and the version that is running. |

Flags can be combined, for example `just update v0.9.0 --yes`.

## What `just update` does

`just update` runs `scripts/update.sh`. It prints one line per step, `[n/9]`.

1. **Check the installation.** `.env` must exist and name the project and the volume prefix. The stack must be up, with the `backup` service healthy. Tracked files must not have local changes (source mode refuses, images mode warns). It then fetches the tags and works out the target.
2. **Back up the database.** The `backup` service takes a dump named `suckerpot-preupdate-<time>.dump`. If the dump fails, nothing is changed.
3. **Record how to roll back.** It writes `.suckerpot-state/last-update.json` (mode `0600`, ignored by git). The file holds the versions, the commit, the dump name and the image IDs. It holds no secret.
4. **Fetch the new code.** It checks out the release tag. In source mode on a branch, it runs `git pull --ff-only` instead. Git runs under `umask 022` and the tracked files are made readable again afterwards, so the containers can read them (see [unreadable files after an update](#unreadable-files-after-an-update)).
5. **Update `.env`.** `scripts/env-migrate.sh` adds the secrets and defaults that are new, and never changes a line that already exists. See [settings that are added](#settings-that-are-added).
6. **Get the new images.** Images mode verifies the signatures and pulls exactly the verified images. Source mode rebuilds from the checkout.
7. **Restart.** `docker compose up` runs. The `migrate` service applies the database changes first.
8. **Check the health.** The dashboard must answer on `/healthz`, every service must be healthy, and the API must report the new version.
9. **Done.** It marks the update as finished in the state file.

Before step 1 finishes, the update prints the current version, the target version and the release notes of the target tag. It asks for your confirmation, unless you pass `--yes`.

If you are already on the target, it says `Already on vX.Y.Z. Nothing to update.` and stops.

### What the target is

| Install mode | `just update` with no version | Notes |
| --- | --- | --- |
| `images` | The newest `v*.*.*` tag. | The release images for that tag are pulled. |
| `source`, on a branch | The newest commit of the branch (`git pull --ff-only`). | The checkout must be clean. |
| `source`, on a tag | The newest `v*.*.*` tag. | The images are rebuilt from the checkout. |

Installs made before the install modes existed count as `source`. An update keeps them on source, unless you change the mode in `.env` yourself.

### Health is judged against the node before the update

Before it changes anything, the update records the health of every service. After the restart it fails only on a regression: a service that was healthy (or had no healthcheck) before and is not healthy afterwards. A service that was `starting` gets up to `UPDATE_HEALTH_WAIT_SECONDS` (default 180) to turn healthy. Before the snapshot, services that are still `starting` get up to 60 seconds to settle; one that is still starting then counts as healthy. A service without a healthcheck is healthy only while its container is `running`: one that is restarting or has exited is treated like an unhealthy one.

A service that was already unhealthy before and still is does not fail the update. The update prints a warning (`was already unhealthy before the update`) so you can fix it. The same goes for the dashboard answer check and the network client check when the `api` or `ingest` service was not healthy before; the running-version check is always strict. This matters when a release fixes the very bug that made the service unhealthy.

### Settings that are added

Step 5 adds three kinds of settings to `.env`, under a comment with the date:

- Every secret that is missing. A new secret is generated on this host.
- `SUCKERPOT_INSTALL_MODE=source`, when it is missing. This keeps an older install on source mode.
- Any other setting listed in `MIGRATE_DEFAULTS`.

The script then prints the names of what it added. It never prints a value. It also lists the optional settings from `.env.example` that your `.env` does not have yet. Those are only comments, and they can stay that way.

The database password `POSTGRES_PASSWORD` is never generated during an update. The database owner's password lives inside the data volume, so a new value would lock you out. If it is missing, the update prints it as a name to set by hand.

### Removed settings

`ABUSECH_SUBMIT_ENABLED` no longer does anything (node-side abuse.ch submission was removed in v0.11.0): you can delete it from `.env`. Submission rows already stored are kept until the retention job removes them, and the abuse.ch lookup key is unchanged.

## Automatic updates

Automatic updates are on by default in participant mode (see [Join the network](participate.md)). In full mode they are off, so an existing install does not change.

A full install can turn them on at any time, if it uses the signed release images (`SUCKERPOT_INSTALL_MODE=images`). Run `./scripts/participant.sh auto-update on`. The command name says participant, but it works on any install. In full mode it first warns you that the update checks (GitHub, the image registry and Sigstore) leave from this machine's own address, not through the VPN, and asks you to confirm. In source mode it refuses.

### Where it runs

The update runs from the **crontab of the installing user**, or from a systemd user timer when that is not available. It calls `scripts/auto-update.sh`. This is the one documented exception to "nothing runs on the host except Docker". The reason: an updater container would need the Docker socket (root on the host) and a route to the internet, and that is worse. The cron line is visible with `crontab -l`. It carries the marker `# selfhostr-auto-update`, so install and removal never touch your other lines. No `sudo` is needed.

The time is a random minute between 03:00 and 05:59 local time, chosen at install. A random wait of up to 30 minutes is added, so many machines do not update at the same second.

### What a run does

1. It takes a lock, so only one run happens at a time.
2. It stops if automatic updates are off, if an earlier update never finished, or if the install is in `source` mode.
3. It picks the newest release tag of the **same major version** that is newer than the running one and not marked bad.
4. It verifies the signed release manifest (`scripts/verify-release.sh`) and the image signatures. The manifest must be signed by the release workflow, its commit must be the commit of the tag, and the release must be old enough. The minimum age is the largest of 48 hours, the `auto_min_age_h` of the manifest and `AUTO_UPDATE_MIN_AGE_H` in `.env` (hours; it can only make the wait longer, never below 48). A release cannot shorten its own waiting time.
5. It runs `update.sh --yes --auto`, which takes a database dump first.
6. It waits for the services, the running version to match, and the network node to answer. See [Health is judged against the node before the update](#health-is-judged-against-the-node-before-the-update).
   If the release has a real verdict against it (no signed manifest, a manifest that does not match its tag, or a signature that cosign rejects), it is written to `.suckerpot-state/bad-versions` with its reason in `bad-versions.log`, and the next newest release of the same major version is tried, up to 3 per run. It never installs a version older than the running one. A release that is only too young stops the run and is tried again the next day. Anything that gives no verdict (a download that fails, Docker or Sigstore not reachable, a full disk) is not held against the release: the run ends as `verification_unavailable` and tries again the next day. To allow a tag again, delete its line from `bad-versions`.
7. If anything fails after the code changed, it runs the [rollback](#rollback). The version is marked as bad, and never tried again, only when the release itself is at fault: a service that was healthy turned unhealthy, a migration failed, or the wrong version is running. Any other failure (including a registry or Sigstore outage during the image check) is logged and the release is tried again on the next run, so a node that was already degraded never blacklists a fix. To keep that from looping for ever, the same target is blacklisted (`update_failed_repeatedly` in `bad-versions.log`) after `AUTO_UPDATE_MAX_ATTEMPTS` failed attempts in a row (default 3, counted in `.suckerpot-state/update-attempts`, reset by a success or a newer target). The next release is tried normally.

The outcome of the last run is in `.suckerpot-state/auto-update.json`, and the log is in `.suckerpot-state/auto-update.log` (rotated at 1 MiB). `./scripts/status.sh` shows both.

### The one-time network recreate

A release can change the name or the options of a Docker network, and Docker cannot change those on a network that exists. When `docker compose up` fails for that reason during an update (or a rollback), the script runs `docker compose down --remove-orphans` once and starts the stack again. Volumes are never removed. The services are down for a short time. If a container from another project is attached to one of the SuckerPot networks, the `down` cannot remove it: the script stops and prints the network, the container and the `docker network disconnect` command. It never disconnects a foreign container for you.

### Turn it on or off

```bash
./scripts/participant.sh auto-update off
./scripts/participant.sh auto-update on
```

This adds or removes the cron line and sets `AUTO_UPDATE_ENABLED` in `.env`. At install, `--no-auto-update` skips the schedule. A manual `just update` always works.

### The risk

Automatic updates trade control for convenience. If the release channel of the project were compromised (the signing workflow, the repository or the registry), every participant that updates automatically would receive the bad release. The signature check and the 48-hour minimum age reduce the risk and give time to notice and withdraw a release. They do not remove it. If you cannot accept that, turn updates off and update by hand.

## Image signatures

Every release image is signed when it is published. The signature proves that the release workflow of the project built the image from a version tag. The signature is made with [cosign](https://docs.sigstore.dev/cosign/) and GitHub's identity, so no private key is kept.

SuckerPot checks 18 images for each release:

| Images |
| --- |
| `redis`, `migrate`, `ingest`, `api`, `collector`, `demo` |
| `sensor-ssh`, `sensor-rdp`, `sensor-telnet`, `sensor-web`, `sensor-redis`, `sensor-docker`, `sensor-mysql`, `sensor-mssql`, `sensor-adb`, `sensor-smb`, `sensor-sip`, `sensor-synology` |

The check uses this rule. The image must be signed by the release workflow of the repository named in `SUCKERPOT_IMAGE_PREFIX`, for the tag you asked for. A fork therefore verifies its own releases.

### What a release proves

A release is a version tag (`vMAJOR.MINOR.PATCH`) on a commit that is part of `main`, so it went through review and the required checks. The release workflow refuses any other tag before it builds anything (`scripts/check-release-ref.sh`). It then builds and signs the images in the `release` GitHub environment, and the updater verifies those signatures and the signed manifest before it installs anything. A tag on an unmerged commit cannot produce a release that passes this chain.

For maintainers: the workflow cannot configure its own environment. In the repository settings, create the `release` environment, add required reviewers and limit deployments to the tag pattern `v*.*.*`. Without that, anyone who can push a tag can still start the signing jobs for a commit that is on `main`.

### Moving from the old repository (v0.7.1 and earlier)

The project moved from `Theroxat/suckerpot` to `selfhostr/suckerpot`. Releases after the move are signed by the release workflow of the new repository and published under `ghcr.io/selfhostr/suckerpot-*`. An install made before the move keeps `SUCKERPOT_IMAGE_PREFIX=ghcr.io/theroxat/suckerpot` in `.env`, and its scripts accept only a signature from that repository, so the first update refuses the new release (the automatic updater records `signature_invalid` and changes nothing). This is deliberate: the check is not relaxed. Make the move yourself once, by editing `.env` (set `SUCKERPOT_IMAGE_PREFIX=ghcr.io/selfhostr/suckerpot` and `UPDATE_CHECK_REPO=selfhostr/suckerpot`) and pointing the checkout at the new address:

```bash
git remote set-url origin https://github.com/selfhostr/suckerpot.git
just update
```

From that update on, the scripts of the new release do the rest, and `scripts/env-migrate.sh` rewrites the old defaults by itself.

### Verify, then run by digest

The check is the gate, not a report:

1. For each image, cosign verifies the tag and reports the digest (a fixed fingerprint of the image).
2. The image is pulled by that digest, not by the tag.
3. The local name is pointed at the pulled digest.

So what runs is exactly what was verified. A tag that the registry changes later cannot slip in between the check and the start.

If one image fails, nothing starts. The update, or the installer, exits with an error.

### Run the check yourself

`just verify-images` runs the script below and passes its arguments on.

```bash
just verify-images vX.Y.Z
scripts/verify-images.sh vX.Y.Z           # check only: nothing is pulled or started
scripts/verify-images.sh --pull vX.Y.Z    # check, then pull the verified digests
scripts/verify-images.sh --only api vX.Y.Z
```

| Option or variable | Meaning |
| --- | --- |
| `--pull` | Pull the verified digests and tag them. |
| `--only "api ingest"` | Check only these image names. |
| `VERIFY_IMAGES_NO_AUTH=1` | Do not pass the registry login from `~/.docker/config.json` to cosign. |

The cosign tool runs in a pinned container. It contacts the registry and the public Sigstore services from this host, the same way `docker pull` does. It is not sent through the VPN.

```{note}
Source mode has no signatures to check. You build the images from the checkout you have, so review that checkout first.
```

### `--skip-verify`

`--skip-verify` turns the check off for that run. The update then warns, and pulls the images by tag. Use it only when you accept running images that you could not check, for example for a release that the signing workflow has not finished yet. A failed check is never a reason to ignore the result by default.

## The database dump

Every update takes a dump with the `backup` service before it changes anything. The dump is a complete PostgreSQL dump with the TimescaleDB data. It is stored in the `suckerpot_backups` volume (the name uses your volume prefix).

| Rule | Detail |
| --- | --- |
| Name | `suckerpot-preupdate-<time>.dump` |
| Kept | The newest two pre-update dumps. They are separate from the daily dumps. |
| Daily dumps | Kept by `BACKUP_KEEP` (default 7), as described in [Deployment](deployment.md#daily-backups). |
| Where | The `suckerpot_backups` volume. Not on the host's file system. |

If the backup fails, the update stops and nothing is changed. You can list the dumps with `just backups`.

Migrations are forward-only. A new release may change the database in a way that the old code cannot read. That is why the rollback restores the dump, and does not try to undo migrations.

## The state file

`.suckerpot-state/last-update.json` is written by step 3. It looks like this, with example values:

```json
{
  "from_version": "v0.8.0",
  "from_ref": "9f2c1ab3e4d5...",
  "from_branch": "",
  "mode": "images",
  "dump": "suckerpot-preupdate-20261102T031500Z.dump",
  "alembic_before": "3f1a9c0d2b7e",
  "target": "v0.9.0",
  "at": "2026-11-02T03:15:00Z",
  "completed": false,
  "images": {
    "api": "sha256:..."
  }
}
```

It is a record for `just rollback`. It has no password and no secret. Step 9 changes `"completed": false` to `"completed": true`.

## The unfinished-update lock

An update that stops after step 3 leaves `"completed": false` in the state file. A new `just update` then refuses to start:

```text
update: the previous update never finished (see .suckerpot-state/last-update.json). Run just rollback, or finish it, or retry with --force
```

The lock protects you from a second update on top of a half-done one. There is no automatic way to finish the first one. Choose one of these:

- **Roll back.** Run `just rollback`. Read [Rollback](#rollback) first.
- **Fix the cause and retry.** Run `just update --force`. This skips the lock check only. It does not skip the backup or the signature check.

After a successful rollback, the state file is kept but marked `"completed": true`, so the lock is released and the next `just update` does not need `--force`. A rollback that fails part way leaves the lock in place.

## Rollback

`just rollback` runs `scripts/rollback.sh`. It restores the state recorded by the last update.

Before it changes anything, it checks:

- the state file exists and is valid;
- the dump is in the `suckerpot_backups` volume (if the retention removed it, rollback stops);
- the update was made with a backup (an update with `--no-backup` cannot be rolled back).

It then compares the database schema revision (Alembic) recorded before the update with the current one. If the schema moved, or the revision cannot be read, the database is restored from the dump. If it did not move, the data is kept and only the code and images go back. Force either choice with `bash scripts/rollback.sh --restore-db` or `--keep-db`.

It then prints what it will do and asks you to type `rollback`. When the schema moved:

```text
Rollback of the update made at 2026-11-02T03:15:00Z:
  code:     back to v0.8.0 (commit 9f2c1ab3e)
  images:   images mode, then pull
  database: REPLACED by the dump suckerpot-preupdate-20261102T031500Z.dump

Events received since that dump are lost.
Type "rollback" to continue:
```

When the schema did not move, the database line reads `database: KEPT as it is, no event is lost`. After you confirm, it runs four steps:

| Step | Action |
| --- | --- |
| `[1/4]` | Checks out the previous code, on its branch when it had one. |
| `[2/4]` | Restores the previous version in `.env`. In images mode it verifies the old images and pulls them by digest. In source mode it rebuilds. |
| `[3/4]` | Restores the database from the dump, only when the schema moved (or with `--restore-db`). `scripts/restore-db.sh` asks its own confirmation. |
| `[4/4]` | Starts the stack and waits until every service is healthy. |

### What a rollback costs

- When the database is restored, every row written to it after the dump is gone. That includes events, sessions, indicators, reports, alerts, accounts and settings changed after the dump.
- Only the database is restored. The other volumes, such as the sensor data, are not touched.
- `.env` is not rolled back. Settings that the update added stay in it. Only `SUCKERPOT_VERSION` changes, in images mode.
- The dump is restored into a side database first and swapped in only when that worked, so a failed restore leaves the current database as it was. It needs room for a second copy of the database. See [Deployment](deployment.md#data-volumes-and-backups).

### The stream buffer on update and rollback

The Redis Stream (`redis-data`) is only a buffer between the sensors and the database. Losing it costs at most the events not yet consumed, a few seconds in normal operation, and never touches the database.

- The broker is Valkey, and its AOF base file holds plain commands (`aof-use-rdb-preamble no`) so that Redis and Valkey read each other's files. A volume written by Valkey therefore loads in Redis 8.10 again after a rollback of the image alone.
- A volume written by Redis 8.10 with its old default (an RDB preamble in the AOF base file) cannot be read by Valkey 9.1: it stops with `Can't handle RDB format version 15`. The broker then moves `appendonlydir` and `dump.rdb` aside as `*.unreadable-<UTC time>` (two copies at most), logs one line saying so, and starts with an empty buffer. Events not yet consumed at that moment are lost. To keep them, rewrite the AOF on the running Redis before the update, and wait until `INFO persistence` shows `aof_rewrite_in_progress:0`:

  ```bash
  docker compose exec -T redis sh -c 'export REDISCLI_AUTH="$REDIS_PASSWORD"; redis-cli --user admin CONFIG SET aof-use-rdb-preamble no && redis-cli --user admin BGREWRITEAOF'
  ```

  This is optional: without it the update still works, and only the events waiting in the buffer are lost.
- The same safety net applies to any AOF or RDB the server cannot load. It only acts when the server exits with an error twice at start-up, its own output reports a data-load failure (a bad directive or ACL file never counts), and `valkey-check-aof` rejects the AOF directory (`valkey-check-rdb` rejects `dump.rdb` only when there is no AOF directory, the only case where it is loaded). A torn last write and a stale `dump.rdb` next to a healthy AOF are left alone.
- A rollback never touches `redis-data`, whether or not it restores the database.
- `scripts/test-broker.sh` runs these cases against throwaway containers (it is part of CI).

### When a rollback happens

SuckerPot never rolls back by itself. If an update fails after the code has changed, it prints the command to run:

```text
update FAILED after the code was changed. Nothing was rolled back automatically.
  To go back to v0.8.0 and restore the database dump 'suckerpot-preupdate-...':
      just rollback
```

A rollback is your decision, because it may replace the database.

## Automatic updates and the docker group

The daily update job (`./scripts/participant.sh auto-update on`) runs from the crontab of the user who installed SuckerPot. That user is in the `docker` group, which is root-equivalent on the host: anyone who can write that user's files or crontab can run code as root. Keep the checkout and the crontab writable by that user only. The job refuses a release whose signed manifest does not match its commit or its image digests (`error_code` values such as `commit_mismatch` and `digest_mismatch` in `.suckerpot-state/auto-update.json`).

## The optional update check

The update check tells you when a newer release exists. It never installs anything.

It is **off by default**. The installer asks the question, with `no` as the default. To change it later:

```bash
just set UPDATE_CHECK_ENABLED=true
just set UPDATE_CHECK_ENABLED=false
```

### What it does

- It runs through the VPN, and only through the VPN. If the VPN gate is closed, nothing is sent. The state shows `no_egress`, and the check tries again after 30 minutes.
- It runs once, 1 to 6 hours after the stack starts. After that it runs about every 24 hours, with a random offset of up to 6 hours. The request times therefore do not form a pattern.
- It makes one request: the latest release of the repository in `UPDATE_CHECK_REPO`.
- The request carries exactly two headers, `Accept` and `User-Agent`. It carries no version, no install identifier, no cookie and no token.
- From the answer it keeps only the tag name, its date, and the pre-release and draft flags. Release notes are never read or shown from the answer.
- It never downloads, pulls or runs anything.

### Where you see it

- A dot in the footer of the dashboard, with the text "Update available".
- An Updates card in Settings > General, with the current version, the latest version, the time of the last check, a link to the release, and the update command.

The dashboard only compares versions. The update itself is always a command you run on the host.

### What GitHub can see

| Who | What they learn |
| --- | --- |
| GitHub | A VPN exit address asked for the latest release of a public repository, about once a day. |
| Your VPN provider | A TLS connection to GitHub. It already sees all outbound traffic. |
| Attackers | Nothing. The check does not open any inbound port. |

The VPN exit address is shared with other users of the same provider. The request does not say which SuckerPot install made it.

### Forks

`UPDATE_CHECK_REPO` names the repository the check reads, as `owner/name`. Its default is the public project repository. Set it to your fork if you publish your own releases:

Edit `UPDATE_CHECK_REPO` in `.env` by hand, then run `just up`. `just set` does not accept this variable. A value that is not a plain `owner/name` is ignored, and the default is used.

## Version check

```bash
just version
```

Example output, with placeholder values:

```text
checkout: v0.9.0
mode:     images
image:    v0.9.0
running:  v0.9.0
```

If `checkout` and `running` differ, the stack has not been restarted since the update. Run `just up`.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `the stack is not up or the backup service is not healthy`. | Run `just up`, wait for it to be healthy, then update. |
| `tracked files have local changes`. (source mode) | Commit or discard the changes with `git status`. |
| `the previous update never finished`. | Read [the unfinished-update lock](#the-unfinished-update-lock). |
| `the image signatures could not be verified`. | Nothing was started. Check the version and the image prefix. Run `scripts/verify-images.sh vX.Y.Z` to see which image failed. |
| `the backup failed; nothing was changed`. | Run `just backup` and read the error. Fix it, then update again. |
| `the dashboard does not answer on .../healthz`. | Run `docker compose logs api`. Then decide: fix and run `just up`, or roll back. |
| `the api reports version ... but ... was expected`. | The new images did not start. Run `docker compose ps` and `docker compose logs api`. |
| `could not fetch tags from the remote`. | The update uses the tags already on this host. Check the network, then run `git fetch --tags`. |
| `Permission denied` on a file of the checkout (for example `/app/migrations/versions/...` in the `migrate` container), or a script that is `0700`. | The files were unreadable for the containers. See [unreadable files after an update](#unreadable-files-after-an-update). |
| `the dump ... is no longer in the backups volume`. | The rollback cannot run. Only the newest two pre-update dumps are kept. Run `just backups` to see what is left. If you need the data of another dump, restore it by hand with `just restore volume:<name>`. |

### Unreadable files after an update

An update from v0.11.2 to v0.11.3 could leave the files of the checkout with mode `0600` (and scripts with `0700`), because the checkout ran under the update's private `umask 077`. In source mode the images are built from those files, and the non-root user inside a container cannot read them: the `migrate` service failed with `PermissionError: [Errno 13] Permission denied: '/app/migrations/versions/...'`, and the update stopped with `ingest`, `api`, `collector` and `analyzer` down. Scripts that the containers mount, such as `scripts/backup-service.sh`, were affected in both install modes.

From the release that follows v0.11.3, the update runs git and the build under `umask 022` and makes the tracked files readable again after every checkout. Only the files git tracks are touched: `.env`, `.env.bak-*`, `hub/.env`, `hub/secrets` and `.suckerpot-state` keep their mode. A node that was already hit is repaired by its next update.

To repair a node now, run this in the checkout folder. The first line fixes the tracked files and the second the folders that hold them:

```bash
git ls-files -z | xargs -0 chmod go+rX
git ls-files | awk -F/ '{ p = ""; for (i = 1; i < NF; i++) { p = p $i "/"; print p } }' | sort -u | xargs -d '\n' chmod go+rX
```

Then run the update again (`just update`), or start the stack again with the code you have. In source mode:

```bash
docker compose build && docker compose up -d --wait
```

In images mode nothing is built, so `docker compose up -d --wait` is enough.

## Next steps

- [Install SuckerPot](install.md)
- [Deployment](deployment.md)
- [Configuration](configuration.md)
