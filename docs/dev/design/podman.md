# Podman support

Status: approved on 2026-11-21. The owner's decisions are in section 12. Implemented: phase 1 (engine library) and the security core (networks, overlay, Podman firewall, boot unit, isolation checks); the installer still refuses Podman until it wires them in.

## 1. Problem and goals

SuckerPot runs on Docker Engine with the Compose v2 plugin, for full installs and for participant installs. A user asked for Podman. Some distributions ship Podman and not Docker (Fedora, RHEL and its rebuilds), and some people prefer a daemonless engine.

SuckerPot is a honeypot. Its value depends on a few containment guarantees: a compromised sensor cannot reach the host, the other sensors, the LAN or the internet, and the only route out goes through the VPN (full mode) or through `hubproxy` (participant mode without a VPN). Today these guarantees come from Docker network options plus the host firewall. Podman must keep every one of them, or SuckerPot must refuse to run on it.

Goals:

- G1. A full install and a participant install work on a supported Podman host with the same commands (`./scripts/install.sh`, `just update`, `./scripts/status.sh`, `./scripts/participant.sh`).
- G2. Every containment guarantee in section 7 holds on Podman, and a script proves it on the running node.
- G3. Docker installs do not change. A Docker node never runs a Podman code path.
- G4. Automatic updates, signature checks, backups and restores work the same way.
- G5. CI proves G1 and G2 on every change.

Non-goals:

- N1. No rootless Podman in the first version (section 4.4 explains why).
- N2. No Kubernetes YAML, no Quadlet units, no `podman play kube`. The Compose files stay the single source of truth.
- N3. No Docker and Podman on the same host. Docker's own `FORWARD` drop cuts off Podman containers (see the Fedora note in section 10), and two engines would fight over the bridges.
- N4. No change to the images or to the release workflow. The same signed images run on both engines.

## 2. Summary

Recommendation: **approach A**. Rootful Podman 5.4 or newer, with the netavark network stack and its nftables firewall driver, and the Docker Compose v2 binary (`docker-compose`, 2.26 or newer) talking to the Podman socket through `DOCKER_HOST=unix:///run/podman/podman.sock`. One-shot helper containers (cosign, chown, pg_restore) run with the `podman` CLI.

Three findings shape the design:

1. **Podman ignores three of the Docker network options SuckerPot depends on.** Its Docker-compatible API translates `com.docker.network.bridge.name` but only warns about `enable_ip_masquerade`, `enable_icc` and `gateway_mode_ipv4` (section 5.2). On Podman, the sensor network would have an outbound route, its sensors could talk to each other, and every internal network would keep a host address. So on Podman the networks are created by SuckerPot with `podman network create` and marked external in a Podman overlay, and the host firewall becomes **mandatory**, with one new bridge-family table.
2. **Podman's DNS server runs on the host, not in the container.** aardvark-dns listens on each bridge's gateway address and forwards outside names from the host's network namespace. The host firewall's forward rules do not see those queries. Without care, a sensor or ingest could resolve outside names (a DNS channel out). The design turns DNS off on the networks that do not need it and proves the rest with `just egress-check` (section 5.3).
3. **Rootless Podman loses the attacker's source address** on custom bridge networks (the default `rootlessport` forwarder rewrites it). A honeypot without source addresses is useless. Rootless is out for now.

The rest is mechanical: one engine library in `scripts/lib/`, version checks, a few `docker` calls that become `podman` calls, fully qualified image names, a boot unit, a CI job, and docs.

## 3. What exists today (inventory)

Line numbers are those of `main` at v0.12.1. "Compat" means Podman's Docker-compatible REST API, which `docker-compose` uses through `DOCKER_HOST`.

### 3.1 Engine checks and install

| Item | Where | Under Podman |
| --- | --- | --- |
| `command -v docker`, then `docker version --format '{{.Server.Version}}'`, must be 24 or newer, warns below 28 | `scripts/install.sh:357-363` | Through compat, the server version is the Podman version (5.x), so "24 or newer" fails. Needs an engine branch: Podman 5.4 or newer, netavark backend, nftables driver |
| Error text "sudo usermod -aG docker $USER" | `scripts/install.sh:359` | Podman has no `docker` group. Socket access is through a group on `podman.socket` (section 12, D3) |
| `docker compose version --short`, 2.24 or newer | `scripts/install.sh:364-365` | `docker-compose version --short` (standalone binary). 2.26 or newer (Debian 13 ships 2.26.1) |
| `docker info --format '{{.DockerRootDir}}'` for the free disk check | `scripts/install.sh:389` | Use `podman info --format '{{.Store.GraphRoot}}'` (`/var/lib/containers/storage`) |
| `docker volume ls -q --filter "name=^${prefix}_"` | `scripts/install.sh:399` | `podman volume ls --filter name=` exists. Whether it takes a regex anchor like Docker is unverified: test it, or filter with `grep` |
| `docker ps -a -q --filter label=com.docker.compose.project=$project` | `scripts/install.sh:402` | The label is set by `docker-compose`, so it is there. `podman ps --filter label=` works |
| `docker pull` of the ingest and api images | `scripts/install.sh:749, 767` | `podman pull`. Same refs |
| `docker build` of the api image (source mode) | `scripts/install.sh:777` | `podman build` (Buildah). Source mode stays Docker-only at first (D6) |
| `docker run --rm -i --network none --cap-drop ALL` to hash the admin password | `scripts/install.sh:779` | `podman run` with the same flags |
| `docker compose exec -T backup ...` before a mode switch | `scripts/install.sh:966` | Through `docker-compose` on the Podman socket: unchanged |
| `docker compose --profile direct rm -sf hubproxy`, `pull`, `pull --policy missing`, `up -d --no-build --pull never --wait --wait-timeout 600` | `scripts/install.sh:1019-1036` | Unchanged under approach A. These flags are the main reason not to use podman-compose (section 4) |
| Dry run says "Docker ... checks skipped" | `scripts/install.sh:355` | Wording only |
| Warns when neither crontab nor systemctl exists | `scripts/install.sh:406` | Unchanged. Podman needs systemd anyway (healthchecks, section 5.7) |

### 3.2 Update, rollback, status, participant

| Item | Where | Under Podman |
| --- | --- | --- |
| `health_snapshot`: `docker compose ps --format '{{.Service}} {{.State}} {{.Health}}'` | `scripts/update.sh:75` | Unchanged under A (compose formats it from inspect data) |
| `docker compose exec -T db ...` (alembic revision), `exec -T backup ...` (pre-update dump) | `scripts/update.sh:96, 250-252` | Unchanged |
| `docker compose ps backup --format '{{.Health}}'` | `scripts/update.sh:144` | Unchanged |
| `docker image inspect --format '{{.Id}}'` per running image | `scripts/update.sh:267-271` | `podman image inspect --format '{{.Id}}'`. Same field |
| `docker compose pull`, `pull --policy missing`, `build`, `compose_up_recreating ... --wait` | `scripts/update.sh:341-363` | Unchanged under A |
| `docker compose ps -a migrate --format '{{.State}} {{.ExitCode}}'` | `scripts/update.sh:368` | Unchanged. Check that compat reports `exited` and the exit code the same way (Phase 2 test) |
| `docker compose exec -T <svc> printenv SUCKERPOT_RUNNING_VERSION` | `scripts/update.sh:426` | Unchanged |
| `compose_up_recreating`: parses compose's error text to decide that a network must be recreated, then `down --remove-orphans`, `docker network ls/inspect/disconnect` | `scripts/lib/env.sh:480-524` | The error strings come from the engine. Podman's differ. With external networks (section 5.2) this path changes: SuckerPot recreates its own networks. Needs a Podman branch |
| `rollback.sh`: `docker compose exec -T db`, `docker volume inspect`, `docker run ... --user 70:70` on the backups volume, `pull --policy missing`, `build`, `compose_up_recreating` | `scripts/rollback.sh:75-166` | Same as above: `podman volume inspect`, `podman run` |
| `status.sh`: `command -v docker`, `docker compose ps --format`, `docker compose exec -T ingest python ...` | `scripts/status.sh:35, 49, 61, 79, 136-138` | Engine check through the library; the rest unchanged. Add an "engine: podman 5.x (rootful, netavark nftables)" line |
| `participant.sh`: `compose_up` (`up -d --no-build --pull never --wait --wait-timeout 300`), `compose exec -T ingest`, `compose --profile X rm -sf`, `compose down`, prints a `docker volume ls` and `docker volume rm` pipeline for deleting the data | `scripts/participant.sh:42-46, 107-112, 234-235, 339-343` | Unchanged under A, except the printed commands, which use the engine name |
| `check-participant.sh`: checks `COMPOSE_FILE` names the participant overlay | `scripts/check-participant.sh:31-32` | Must also accept the Podman overlay (section 5.2) |
| `compose-fresh.sh`: `docker compose rm -sf sensor-X`, `up --no-build --pull never`, `exec docker compose` | `scripts/compose-fresh.sh:19-32` | Through the library |
| `env-set.sh`, `env-migrate.sh` | `scripts/env-set.sh:3` (comment), `scripts/env-migrate.sh` | No engine call. `env-migrate.sh` must add `SUCKERPOT_ENGINE` and `DOCKER_HOST` keys when they are missing (section 8) |
| `move-admin-ssh.sh`: messages "docker compose down" | `scripts/move-admin-ssh.sh:510, 559` | Wording only |
| `check-ports.sh`, `lib/ports-check.sh`: `docker compose exec -T db psql`, `exec -T ingest python` | `scripts/lib/ports-check.sh:31-33` | Unchanged |

### 3.3 Volumes, backup and restore

| Item | Where | Under Podman |
| --- | --- | --- |
| All 20 data volumes are `external: true`, named `${SUCKERPOT_VOLUME_PREFIX}_<name>` | `docker-compose.yml:1797-1868` | Works. Podman named volumes are directories under `/var/lib/containers/storage/volumes` |
| `ensure-volumes.sh`: `docker volume inspect` (exists), `docker volume create`, `docker run --user 0:0 --cap-add CHOWN --entrypoint chown` for `backups` (70:70), `vpn-config` and `trap-packs` (10001:10001), `docker run --user 70:70` to count dumps | `scripts/ensure-volumes.sh:41-80` | `podman volume inspect/create`, `podman run` with the same flags |
| Copy-up: an empty named volume takes the content and owner of the image directory on first mount (redis uid 999, db uid 70, api `/vpn-config` uid 10001) | comments at `docker-compose.yml:34-35, 82-84, 1856-1857` | Podman also copies image content into an empty named volume. Whether it also copies the owner of the mount point in every case is **unverified**. Phase 2 test: fresh install, then `stat` each volume root |
| `backup-db.sh`: `docker compose exec -T db pg_dump` | `scripts/backup-db.sh:40` | Unchanged |
| `backup` service: runs inside the timescaledb image, bind-mounts `./scripts/backup-service.sh` read-only | `docker-compose.yml:180-212`, `:191` | Unchanged. On SELinux hosts the bind mount needs a label (section 5.11) |
| `restore-db.sh`: `docker run --network none ... --user 70:70` on the backups volume, then `docker compose exec -T db`, `stop`, `up -d --wait`, `run --rm migrate` | `scripts/restore-db.sh:40-233` | `podman run` for the one-shot; compose calls unchanged |
| `test-backup-restore.sh`: throwaway project, `docker ps --filter label`, `dc config`, `docker run` chown, `docker inspect .State.Health.Status` | `scripts/test-backup-restore.sh:35-164` | Through the library. Runs in the Podman CI job |
| `just backup`, `just backups`, `just restore` | `justfile:171-185` | Through the library |

Backups are logical dumps (`pg_dump -Fc`) inside the `backups` volume, not copies of volume directories. So they do not depend on the engine. A dump made on Docker restores on Podman with `just restore`. This is also the migration path from Docker to Podman (section 9, Phase 2).

### 3.4 Helper containers (`docker run`)

| Helper | Where | Under Podman |
| --- | --- | --- |
| cosign `verify-blob` of the release manifest: `docker image inspect`, `docker pull`, `docker run --rm --network host --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:...,uid=65532,gid=65532` | `scripts/verify-release.sh:110-124` | `podman run` with the same flags. The exit codes 125, 126, 127 that mean "the engine could not start the container" are the same in Podman. 137 (killed) too |
| cosign `verify` of each image, mounts `~/.docker/config.json` for private registries, then `docker pull <ref>@<digest>` and `docker tag` | `scripts/verify-images.sh:102-139` | `podman pull`, `podman tag`. Podman's own login file is `${XDG_RUNTIME_DIR}/containers/auth.json` (root: `/run/containers/0/auth.json`). Images on GHCR are public, so no login is needed. Mount Podman's file only if it exists |
| Test traffic: `alpine` (ssh-test), `curlimages/curl` (web-test), `python` (telnet-test, rdp-test), all `--network host` | `scripts/ssh-test.sh:14`, `web-test.sh:14`, `telnet-test.sh:13`, `rdp-test.sh:12` | `podman run`. Short image names: see section 5.9 |
| Development: uv (`ghcr.io/astral-sh/uv`), node (web build, `-p 127.0.0.1:5173:5173`), shellcheck (`koalaman/shellcheck`), guardrails | `justfile:101, 153, 212, 231, 321, 351-391` | Developer tools, not part of a node. They stay Docker-only (D8). With `podman` they work with the same flags plus `--userns=keep-id` for files owned by the caller, which is a later nicety |
| `test-broker.sh`: builds the redis image, `docker network create --internal`, `docker run --read-only --cap-drop ALL`, `docker exec`, `docker stop -t 30`, `docker inspect .State.Status/.ExitCode/.State.Health` | `scripts/test-broker.sh:29-292` | Works with `podman` (same flags). Runs in CI |
| `just integration`: `docker create`, `docker network connect`, `docker start -a` | `justfile:345-364` | Same with `podman` |

### 3.5 `docker network` and `docker inspect`

| Item | Where | Under Podman |
| --- | --- | --- |
| `docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}...{{$v.Gateway}}...{{$v.IPAddress}}'` on the vpn container | `scripts/egress-check.sh:80-85` | `podman inspect` has the same `NetworkSettings.Networks` map with `Gateway` and `IPAddress`. But on Podman the internal bridges always have a gateway address, so the PASS line "egress-proxy bridge has no gateway address" (`:87-89`) never prints and the "refuses the egress-proxy gateway" checks always run, which is correct |
| `docker network ls --filter driver=bridge`, `docker network inspect --format '{{.Id}} {{index .Options "com.docker.network.bridge.name"}}'` to list the engine's bridges | `scripts/host/render-firewall.sh:139-147` | `podman network ls --format '{{.NetworkInterface}}'` gives the bridge names directly. The fallback `br-<12 hex>` is Docker's naming; Podman's default names are `podman0`, `podman1`, and so on |
| `docker network create --internal` (broker test), `docker network rm`, `docker network ls --filter label=` (e2e) | `scripts/test-broker.sh:31, 42`, `scripts/e2e/participant.sh:104-150` | `podman network ...` with the same flags |
| CI: `docker inspect --format '{{.State.Health.Status}}'` per sensor | `.github/workflows/ci.yml:310-369` | `podman inspect` has the same field |

### 3.6 Compose file features

`docker-compose.yml` (1,868 lines) and its overlays (`lowmem`, `lite`, `participant`, `ci`, `it`, `participant-it`).

| Feature | Where | Under Podman (rootful, approach A) |
| --- | --- | --- |
| `x-hardening`: `read_only: true`, `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true"]` on every service | `docker-compose.yml:12-16` | Supported. Note: with `--read-only`, Podman also mounts a writable tmpfs on `/dev/shm`, `/run`, `/tmp` and `/var/tmp` unless `read-only-tmpfs` is off (Podman CLI default; whether compat applies the same default is unverified). The services already mount their own tmpfs, so the extra mounts only add writable, size-limited paths. Phase 2 checks with `findmnt` inside a sensor |
| `tmpfs` with `mode`, `uid`, `gid`, `size`, `noexec,nosuid,nodev` | many, e.g. `:62-64`, `:112-114`, `:1391-1395` | Supported |
| `logging: json-file` with `max-size: 10m`, `max-file: 3` | `docker-compose.yml:5-9` | Podman's log drivers are `k8s-file`, `journald`, `none`, `passthrough`. Through compat, `json-file` maps to `k8s-file`. `max-size` maps to the log size limit; `max-file` has no equivalent in Podman (unverified for compat: it may be ignored). Logs stay bounded by size. A Podman overlay can switch to `journald` (D7) |
| `mem_limit`, `memswap_limit`, `cpus`, `pids_limit`, `oom_score_adj`, `shm_size` | every service | Supported on cgroup v2 (Podman 6 requires cgroup v2) |
| `user: "999:999"`, `"70:70"`, `"10001:10001"` | most services | Supported |
| `restart: unless-stopped` | every long-running service | Podman supports the policy, but there is no daemon to start containers at boot. `podman-restart.service` does that; which policies it restarts (only `always`, or `unless-stopped` too) depends on the version and is unverified. The design adds a SuckerPot boot unit instead (section 5.7) |
| `healthcheck` on every service, `depends_on` with `condition: service_healthy` (14 times), `service_completed_successfully` (`migrate`), `service_started` | e.g. `:71-76`, `:173-175`, `:414-419`, `:1411-1413` | Podman runs healthchecks with systemd timers (rootful). `docker-compose` evaluates the conditions itself by polling inspect, so they behave as on Docker. `--wait` works the same way |
| `deploy.replicas: 0` for a sensor switched off | sensor services, `scripts/compose-fresh.sh:14-19` | Evaluated by `docker-compose`: unchanged |
| `profiles: [egress]` (vpn, collector, analyzer), `[direct]` (hubproxy), `[tools]` (demo), `[dashboard]` (participant overlay) | `:1324, 1427, 1474, 1548, 1596`, `docker-compose.participant.yml` | Evaluated by `docker-compose`: unchanged |
| `!reset {}` YAML tag | `docker-compose.participant.yml` (`vpn.depends_on`) | `docker-compose` 2.24+ feature: fine under A. Unsupported or partial in podman-compose |
| Published ports, many below 1024: 22, 23, 80, 443, 445, plus 2375, 3306, 3389, 5000, 5001, 5060 tcp/udp, 5555, 6379, 1433; the dashboard on `127.0.0.1:8443` | `:535, 599, 661, 715, 783-784, 848, 909, 971, 1032, 1091, 1155, 1219-1220, 1291-1292` | Rootful: netavark DNATs in the kernel, the source address is kept, ports below 1024 are fine. Rootless: see section 4.4 |
| `dns: ["127.0.0.1"]` on ingest, api, sensors, collector, analyzer, vpn | e.g. `:407, 532, 601, 1400, 1522, 1572` | Behaves differently: section 5.3 |
| Network aliases (`hubproxy-internal`), `gw_priority: 100` on the uplinks of vpn and hubproxy | `:1401-1404, 1450-1453` | Aliases are supported. `gw_priority` through compat is unverified. On Podman an internal network adds no default route, so the uplink is the only default route anyway |
| VPN: gluetun as root, `cap_add: [NET_ADMIN]`, `devices: ["/dev/net/tun"]`, `sysctls: net.ipv4.conf.all.src_valid_mark=1`, userspace WireGuard, `read_only` | `docker-compose.yml:1322-1418` | Rootful: all supported. Section 5.5 |
| `network_mode: service:<name>` | not used | No service shares another's network namespace. The VPN is reached as an HTTP proxy on the internal `egress-proxy` network |
| `ulimits`, `privileged`, `cgroup_parent`, `extra_hosts`, `userns_mode`, a mounted Docker socket | not used | Nothing to port. No container mounts `/var/run/docker.sock` |
| Networks: fixed bridge names via `com.docker.network.bridge.name` (`sp-ingress`, `sp-s-*`, `sp-backend`, `sp-tools`, `sp-vpn`, `sp-egress`, `sp-hubgate`, `sp-hubproxy`, `sp-samples`, `sp-dashboard`) | `docker-compose.yml:1631-1796` | Translated by compat to the netavark interface name |
| `internal: true` (16 networks) | `:1651-1789` | Supported: no default route, IP forwarding off on the bridge, aardvark-dns answers container names only |
| `com.docker.network.bridge.gateway_mode_ipv4: isolated` (Engine 28+: no host address on internal bridges) | every internal network | **Ignored** by compat (warning only). The host keeps an address on every bridge |
| `com.docker.network.bridge.enable_ip_masquerade: "false"` (`sp-ingress`, `sp-dashboard`) | `:1648`, `:1795` | **Ignored**. Netavark masquerades every managed bridge |
| `com.docker.network.bridge.enable_icc: "false"` (`sp-ingress`, `sp-vpn`, `sp-hubgate`) | `:1649`, `:1756`, `:1773` | **Ignored**. No netavark equivalent within one bridge |
| `enable_ipv6: false` | every network | Supported (Podman networks are IPv4 only unless asked) |
| Image refs without a registry: `timescale/timescaledb:...@sha256`, `qmcgaw/gluetun:...@sha256`, `local/<project>-*:dev` for source builds | `:79`, `:1325`, every `build` service | Section 5.9 |
| Bind mounts of repository files (`./scripts/backup-service.sh`, `./vpn/*.sh`, `./vpn/control-auth.toml`) | `:191`, `:1387-1390` | Need an SELinux label on Fedora and RHEL: section 5.11 |
| Test overlays drop the fixed bridge names and turn volumes project-local | `docker-compose.it.yml`, `docker-compose.ci.yml`, `docker-compose.participant-it.yml` | Unchanged; the Podman overlay must not apply to throwaway projects (section 5.2) |

### 3.7 Host firewall

| Item | Where | Under Podman |
| --- | --- | --- |
| A separate nftables table `inet suckerpot_host`, chains on the `input` and `forward` hooks at priority -10, drops only. It does not use the `DOCKER-USER` chain and does not touch Docker's rules | `scripts/host/firewall.nft`, `scripts/host/firewall-participant.nft` | Engine-agnostic by construction. In nftables a drop in any base chain is final, whatever another table accepts. So it works next to netavark's `inet netavark` table (nftables driver) and next to netavark's iptables rules (Podman 5 iptables driver) |
| Rules match bridges by name: `sp-*`, and `docker0`, `br-*` for "any Docker network" (protected ports rule) | `firewall.nft` input chain | Add `podman*` to the protected-ports rule, so containers on Podman's default network cannot reach the admin SSH port either |
| Comments and rules that rely on the isolated gateway on Engine 28 ("covers older engines") | `firewall.nft:12-15`, input rule (1) | On Podman the input drops on internal bridges are the only control. They are already there |
| `HUBGATE_DNS`: allows hubproxy's DNS through `sp-hubgate` because Docker's embedded resolver forwards from the container's namespace | `firewall.nft:40-47`, `render-firewall.sh:190-230` | aardvark-dns forwards from the host's namespace, so these queries never cross `sp-hubgate`. The rule stays harmless. A new input rule must let containers reach aardvark-dns where DNS is on (section 5.3) |
| `render-firewall.sh`: refuses when a host bridge that matches `br-*` or `sp-*` is not the engine's; asks `docker network ls/inspect`; reads `/etc/docker/daemon.json` for `"dns"` | `scripts/host/render-firewall.sh:23-30, 135-170, 204-206` | Ask `podman network ls` instead. Also check bridges that match `podman*`. Read `dns_servers` in `containers.conf` instead of `daemon.json` |
| `fw_step`: offered, never fatal; the stack runs without it | `scripts/lib/firewall.sh:96-137`, `scripts/install.sh:688-690, 1110-1113` | On Podman the firewall carries guarantees that Docker gave by itself (section 5.2). Decided (D5): on Podman the install refuses to finish without the firewall, unless `--no-firewall` says the owner filters elsewhere (D5) |
| `install-firewall.sh`: own systemd unit, never the stock `nftables.service` (its `flush ruleset` would wipe Docker's rules) | `scripts/host/install-firewall.sh:3-4` | Same reason with netavark: `flush ruleset` wipes `inet netavark` until the next network setup |
| `suckerpot-firewall.service`: `After=docker.service network-online.target` | `scripts/host/suckerpot-firewall.service:5` | On Podman: `Before=` the SuckerPot boot unit (section 5.7), so no container starts before the table is loaded |
| `proxmox-firewall.sh` | `scripts/host/proxmox-firewall.sh` | Hypervisor side, matches the VM NIC. Engine-agnostic. Text mentions Docker only |
| Optional `suckerpot-sensors.slice` (needs `cgroup_parent`), `sysctl-suckerpot.conf` (conntrack) | `scripts/host/` | Slice: Podman with the systemd cgroup manager accepts `cgroup_parent` too (unverified through compat). Sysctls: engine-agnostic |
| Docs that tell owners to filter "in the `DOCKER-USER` chain" | `.env.example:106`, `docs/deployment.md:18, 404`, `docs/SECURITY.md:28` | Podman has no `DOCKER-USER` chain. Point to the router, the hypervisor, or a forward-hook table like `suckerpot_host` |

### 3.8 Egress guarantees and `just egress-check`

| Item | Where | Under Podman |
| --- | --- | --- |
| `just egress-check` runs `scripts/egress-check.sh` | `justfile:106-107` | Same entry point |
| `dc() { docker compose "$@"; }`, `dc exec -T <svc> python -m suckerpot_egress.selftest --direct/--gate/--refuse`, kill-switch test (`ip link set wg0 down`, `dc stop vpn`) | `scripts/egress-check.sh:27-158` | Through the library. The selftests run inside the containers and are engine-agnostic. This is the main proof of G2 |
| Direct mode: hubproxy is the only way out, ingest has no route and no external DNS, `redis` and `db` have no route | `scripts/egress-check.sh:33-60` | Same checks. Add DNS checks for the sensors (section 5.3) |
| Selftest code | `egress/suckerpot_egress/` | No change expected |

### 3.9 Automatic updates and scheduling

| Item | Where | Under Podman |
| --- | --- | --- |
| The update runs from the installing user's crontab, or a systemd **user** timer; never sudo | `scripts/lib/schedule.sh:17-102`, `scripts/auto-update.sh:2` | The user's timer or crontab calls compose, which needs the root-owned Podman socket. Same model as the `docker` group, with a group on `podman.socket` instead (decided, D3) |
| `PATH` extended with `/usr/local/bin:/usr/bin:/bin:/snap/bin` | `scripts/auto-update.sh:38` | `docker-compose` from the distribution is in `/usr/bin`. Fine |
| `verify-release.sh --auto`, `verify-images.sh`, then `update.sh --yes --auto`, `rollback.sh --yes` | `scripts/auto-update.sh` | Covered above |

### 3.10 Signatures, registry and release

| Item | Where | Under Podman |
| --- | --- | --- |
| Images on `ghcr.io/<owner>/suckerpot-<name>`, multi-arch (amd64, arm64) | `.github/workflows/release.yml:120-121, 130-237` | OCI images: Podman pulls them as is |
| Keyless cosign signatures on images and on `release-manifest.json`; verified on the node with a pinned cosign image | `release.yml:276-325, 419-447`, `scripts/verify-release.sh`, `scripts/verify-images.sh` | Unchanged. cosign talks to the registry itself, not to the engine. Podman's own `policy.json` signature checks are not needed and not used |
| Verified digest, then `pull <ref>@<digest>` and `tag` to the version tag | `scripts/verify-images.sh:138-139` | `podman pull` and `podman tag` keep the digest. Compose then runs the tag with `--pull never` |
| Release build: `docker buildx` with the docker-container driver (SBOM, provenance), `docker login ghcr.io` | `release.yml:185-325` | Unchanged. The release workflow stays on Docker (N4) |
| Release smoke test: pulls and starts the release images with Docker | `release.yml:341-395` | A Podman smoke job can be added later (Phase 4, optional) |

### 3.11 CI

| Job | Where | Under Podman |
| --- | --- | --- |
| `compose`: `config -q`, `up -d --build --wait`, health per sensor, demo data, a lowmem pass, `down -v` | `.github/workflows/ci.yml:274-381` | Model for the new `podman` job (Phase 4) |
| `participant-e2e`: the real installer in a temporary copy, a test hub, containment checks, enrolment, leave, switch to full | `ci.yml:383-402`, `scripts/e2e/participant.sh` | Run it on Podman too: it is the best end-to-end proof |
| `backup-restore`, `broker`, `python-integration`, `hub-integration` | `ci.yml:143-272` | `backup-restore` and `broker` on Podman; the others test application code and stay on Docker |
| Guardrails: static tests with a fake `docker` binary that records calls | `scripts/guardrails/tests/conftest.py:3, 44-49`, `test_install.py`, `test_update.py`, `test_status.py`, `test_firewall.py`, `test_compose.py`, ... | Add a fake `podman` and `docker-compose`, and run the script tests once per engine |

### 3.12 Docs and website

| Where | What says "Docker" |
| --- | --- |
| `docs/install.md:11-21` | Requirements table: Docker Engine 24+ (28 recommended), Compose 2.24+, "run docker without sudo", "Docker's data folder" |
| `docs/install.md:150-151, 334` | Troubleshooting: "Docker is missing", `usermod -aG docker` |
| `docs/getting-started.md:18-29` | Requirements: Docker Engine 24, Compose 2.24 |
| `docs/participate.md:20` | Software: Docker Engine 24+ with the Compose plugin |
| `docs/vps.md:25` | Software: Docker Engine 24+ |
| `docs/deployment.md:18, 160-238, 404, 551` | Host firewall text ("Docker bridges", "Engine 28 isolated gateways", `DOCKER-USER`), SIP and Docker NAT |
| `docs/updates.md:43, 112, 184-186` | `docker compose up`, network recreation, `~/.docker/config.json` |
| `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/configuration.md` | About 60 mentions, mostly "Docker network", "Docker's embedded resolver" |
| `scripts/host/README.md:4-139` | Firewall reference: "Docker bridges", "Docker's embedded resolver", `daemon.json` |
| Website `src/templates/download.html:79-80` | Requirements rows "Docker Engine", "Docker Compose" |
| Website `src/templates/participate.html:10-15` | Step 1 installs Docker with the `get.docker.com` script piped to `sudo sh` and `usermod -aG docker` |
| Website `strings/*.json` (en: `home_cta_install`, `home_fact_compose`, `join_v_software`, `inst_s1_p`, `inst_v_docker`, `feat_g_2`, `download_meta_title`, `download_meta_desc`, `join_step1`, `join_step1_fine`, `join_copy_docker`, `join_small_lede`) | The same facts in 9 languages |

## 4. Approaches compared

| Criterion | A. Rootful Podman + Docker Compose v2 on the Podman socket | B. `podman compose` | C. podman-compose | D. Rootless Podman |
| --- | --- | --- | --- | --- |
| Compose implementation | `docker-compose` 2.26+ | Whatever it finds first: `docker-compose`, else podman-compose | podman-compose (Python), translates to `podman` CLI calls | A or C, run as a normal user |
| `--wait`, `--wait-timeout`, `--pull never`, `--no-build`, `pull --policy missing`, `ps --format` Go templates | Yes | Only if it picked `docker-compose` | No or partial (unverified per flag). The scripts use all of them | As A or C |
| `depends_on` conditions, `deploy.replicas`, `!reset`, `COMPOSE_FILE`, `COMPOSE_PROFILES` | Yes, same code as on Docker | As A or C | Partial, version-dependent (unverified) | As A or C |
| Docker network options | Bridge name only (section 5.2) | Same as A or worse | Its own translation; unverified | As A or C |
| Published ports below 1024 | Yes | Yes (rootful) | Yes (rootful) | Needs `net.ipv4.ip_unprivileged_port_start` lowered, a host-wide change |
| Attacker source address on published ports | Kept (kernel DNAT) | Kept | Kept | **Lost** with the default `rootlessport` on custom networks. The pasta forwarder that keeps it is experimental (merged 2026-05) |
| VPN: `NET_ADMIN`, `/dev/net/tun`, sysctl | Yes | Yes | Yes | Works inside the user namespace, with limits; unverified |
| Host firewall on bridges | Yes: real `sp-*` bridges in the host namespace | Yes | Yes | No: the bridges live in the rootless network namespace, invisible to the host's nftables |
| Same behaviour as the Docker path | Highest: one compose implementation for both engines | Unpredictable: the provider depends on what is installed | Low: a second compose implementation to test | Lowest |
| Socket or root access | Root socket, like Docker | Same | Same (or none, if run as root directly) | None: the main attraction |

Notes:

- **B** adds nothing over A when `docker-compose` is installed, and silently becomes C when it is not. SuckerPot needs a known compose implementation, so the scripts call `docker-compose` directly, with `DOCKER_HOST` set. `podman compose` stays fine for owners at the shell.
- **C** would need a second set of tests for every compose flag and YAML feature SuckerPot uses. Its value is "no Docker binary at all", but `docker-compose` is a single static Go binary, packaged by Debian, Ubuntu and Fedora.
- **D** fails two hard requirements: the source address (a honeypot records who attacked) and the host firewall (it cannot see rootless bridges). Section 12 keeps it as a later question.

## 5. What changes under Podman, by topic

### 5.1 Netavark, nftables and the Docker chains

Docker writes iptables rules (`DOCKER`, `DOCKER-USER`, `DOCKER-ISOLATION-*`). Netavark, Podman's network stack, writes either iptables rules or, with the nftables driver, one table `inet netavark`. Podman 6 removed the iptables driver; Fedora made nftables the default in Fedora 41.

SuckerPot never used `DOCKER-USER`. Its firewall is its own table on the `input` and `forward` hooks, at priority -10, with drops only. A packet passes through every base chain on a hook, and a drop in any of them ends it. So the table works the same next to Docker, netavark-iptables or netavark-nftables. What changes is the set of bridges to name (`podman*` in addition to `docker0` and `br-*`) and the things Docker did that netavark does not (5.2, 5.3).

Requirement: netavark backend (not CNI) and, on Podman 5, the nftables driver (`firewall_driver = "nftables"` in `containers.conf`). The firewall would also work with the iptables driver, but one supported combination is easier to test, and it is the only one on Podman 6. The installer reads `podman info --format '{{.Host.NetworkBackend}}'` and the firewall driver, and refuses CNI.

### 5.2 Network options Podman ignores, and the Podman overlay

Podman's compat API translates `com.docker.network.bridge.name` and the MTU option. For any other driver option it only returns a warning (`... is not a recognized option`) and creates the network anyway. So with the current file on Podman:

| Docker option | Docker effect | On Podman, unchanged file | Replacement on Podman |
| --- | --- | --- | --- |
| `enable_ip_masquerade: "false"` on `sp-ingress`, `sp-dashboard` | No outbound NAT: sensors and the api cannot reach the internet even without the host firewall | Masquerade on: a sensor can open connections to the internet | Host firewall forward drop on `sp-ingress`, `sp-dashboard` (already in the table). The firewall becomes mandatory |
| `enable_icc: "false"` on `sp-ingress`, `sp-vpn`, `sp-hubgate` | Sensors on `sp-ingress` cannot talk to each other | Sensors on `sp-ingress` can reach each other across the bridge. Bridge-local traffic never hits the `inet forward` hook (no `br_netfilter`) | New table `bridge suckerpot_bridge`: a `forward` chain that drops every port-to-port frame on `sp-ingress`, `sp-dashboard`, `sp-vpn` and `sp-hubgate` (`meta ibrname`). Native nftables bridge family, no `br_netfilter` needed |
| `gateway_mode_ipv4: isolated` on internal networks | The host has no address on the bridge | The host has the gateway address on every bridge (aardvark-dns needs it) | Host firewall input drops on `sp-s-*`, `sp-backend`, `sp-tools`, `sp-egress`, `sp-samples`, `sp-hubproxy` (already there), plus a narrow DNS accept (5.3) |

Netavark has options Docker lacks: `isolate=strict` (no traffic between this bridge and any other bridge network) and `--disable-dns`. Compat does not pass them either. So on Podman, SuckerPot creates its networks itself:

- `scripts/ensure-networks.sh` (Podman only, called next to `ensure-volumes.sh` by `just up`, the installer and the updater) creates each `sp-*` network with `podman network create --interface-name sp-<x> --opt isolate=strict [--internal] [--disable-dns] --label io.suckerpot.net=<version>`. It recreates a network whose label is older than the release (the stack is down at that point, as `compose_up_recreating` already arranges).
- `docker-compose.podman.yml` marks every network `external: true` with its `sp-*` name. The installer adds it to `COMPOSE_FILE` on Podman only. The guardrails check that it changes networks and nothing else, the way `test_participant.py` guards the participant overlay.
- DNS is off (`--disable-dns`) on `sp-ingress`, `sp-dashboard` and `sp-vpn`: no member needs a name there. It stays on for the internal networks (service names) and `sp-hubgate` (hubproxy resolves the hub).
- The test overlays (`it`, `ci`, `participant-it`) keep project-local networks without fixed names. On Podman they still get compat networks, which is fine for throwaway tests but means those tests do not prove isolation. The Podman CI job runs one pass with the real overlay (Phase 4).

### 5.3 DNS: aardvark-dns runs on the host

On Docker, each container asks the embedded resolver at 127.0.0.11 inside its own namespace. It answers service names, and forwards other names from the container's namespace, so those queries cross the bridge and the host firewall sees them. With `dns: ["127.0.0.1"]` the upstream is the container's own loopback, so outside names fail. That is how ingest, the api and the sensors have "no external DNS" today.

On Podman, aardvark-dns is a host process. It listens on the gateway address of each bridge with DNS on. Containers get those addresses in `/etc/resolv.conf`. On an internal network it answers container names only and returns NXDOMAIN for the rest. On a non-internal network it forwards other names upstream **from the host's namespace**, where the SuckerPot forward rules do not apply. How Podman combines a service's `dns:` list with aardvark (as aardvark's upstream for that container, or instead of aardvark) is unverified. If it is aardvark's upstream, `127.0.0.1` would mean the host's loopback, where a local resolver may answer.

Consequences and design:

1. Turn DNS off on `sp-ingress`, `sp-dashboard`, `sp-vpn` (5.2). A sensor then only has the aardvark of its own internal network, which never resolves outside names.
2. Ingest, collector and analyzer are on internal networks only, so aardvark already refuses outside names. The vpn uses gluetun's own resolver (`dns: 127.0.0.1` inside its namespace), which is unchanged.
3. hubproxy resolves the hub through aardvark on `sp-hubgate`, from the host's namespace. That is allowed traffic; the forward rule for `HUBGATE_DNS` becomes unused on Podman, and hubproxy's own allow-list still limits what it connects to.
4. The host firewall must accept DNS to aardvark where DNS is on: `iifname { "sp-s-*", "sp-backend", "sp-tools", "sp-egress", "sp-samples", "sp-hubproxy", "sp-hubgate" } fib daddr type local udp dport 53 accept` (and TCP 53), placed before the input drops, Podman template only. aardvark-dns becomes part of the attack surface of a compromised sensor (a root host process that parses its packets). That is new compared with Docker and is listed as a risk.
5. Verification: `just egress-check` gains a sensor DNS check (each running sensor resolves `redis` and fails to resolve an outside name), and keeps the existing `--direct` checks for ingest and collector, which already test "no external DNS".

### 5.4 Privileged ports and the source address

Rootful Podman publishes ports with kernel DNAT rules, like Docker without its userland proxy. Ports below 1024 need nothing, and the container sees the attacker's address. This is required by every sensor, and especially by the SIP sensor, whose per-source limits and source checks depend on it (`docs/deployment.md:551`, `sensors/sip/README.md:229`). Phase 2 tests it: a connection from a second address to each published port must log that address.

Rootless Podman cannot bind below 1024 unless `net.ipv4.ip_unprivileged_port_start` is lowered for the whole host, and its default forwarder for custom networks (`rootlessport`) replaces the source address. The pasta forwarder that keeps it is experimental. This alone rules out D for now.

### 5.5 The VPN container

gluetun needs `NET_ADMIN`, `/dev/net/tun`, the `src_valid_mark` sysctl, and runs as root inside the container with every other capability dropped. Rootful Podman supports all of these through compat. gluetun programs its kill switch with iptables inside its own namespace; that is independent of the host's netavark driver. Two points to test in Phase 2:

- gluetun's iptables inside the container: the image chooses `iptables-nft` or legacy. Both work in a container namespace on a kernel with nf_tables.
- The default route of `vpn` must be `sp-vpn`. On Docker this uses `gw_priority: 100`. On Podman the other network (`egress-proxy`) is internal and adds no default route, so the uplink is the only candidate. If compat refuses `gw_priority`, the Podman overlay resets it.

The host firewall keeps the outer kill switch: from `sp-vpn`, only UDP to the one WireGuard endpoint. `egress-check` already tests the kill switch (tunnel down, then vpn stopped).

### 5.6 Internal networks

`internal: true` maps to netavark's internal networks: no default route in the containers, no IP forwarding on the bridge, no NAT. With `isolate=strict` (5.2) netavark also drops traffic between `sp-*` bridges. The host keeps an address on each bridge, so the input drops of the host firewall are required (they exist already, written for Docker before Engine 28).

### 5.7 Healthchecks, `depends_on`, restart and boot

- Healthchecks: rootful Podman runs each container's healthcheck from a transient systemd timer. A host without systemd gets no health status, and `--wait` would never finish. Requirement: systemd as PID 1. Every target distribution has it.
- `depends_on` conditions and `--wait` are evaluated by `docker-compose` from the inspect data, as on Docker. `service_completed_successfully` reads the exit code of `migrate`.
- Restart at boot: Docker's daemon restarts `unless-stopped` containers. Podman has no daemon; `podman-restart.service` restarts some policies, version-dependent (unverified for `unless-stopped`). And the containers must not start before the firewall table is loaded. Design: a system unit `suckerpot-stack.service` (`After=network-online.target suckerpot-firewall.service podman.socket`, `Requires=suckerpot-firewall.service`), `ExecStart` runs `docker-compose up -d --no-build --pull never --wait` in the checkout as the installing user, with `DOCKER_HOST` set. Do not enable `podman-restart.service` for these containers: one boot path is easier to reason about.
- Restart after a crash while the host runs: conmon handles restart policies without a daemon. Supported.

### 5.8 Named volumes and their backups

The external, prefixed volumes work as named Podman volumes. Their data sits under `/var/lib/containers/storage/volumes/<name>/_data`. Points to check:

- Copy-up of image content and ownership into an empty volume (redis, db, `vpn-config` from the api image). Podman copies content; the owner of the volume root is the part to test. If it differs, `ensure-volumes.sh` sets the owner explicitly on Podman, as it already does for `backups`, `vpn-config` and `trap-packs`.
- Backups are `pg_dump` files in the `backups` volume (3.3). They are engine-independent. Owners who copy volume directories by hand must use the new path; the docs say so.
- Moving a node from Docker to Podman: `just backup` on Docker, copy the newest dump and `.env`, install on Podman with the same prefix, `just restore <dump>`. The sensor state volumes (host keys, profile secrets) are small and can be moved with `tar` from the old `_data` to the new; losing them only changes the sensor fingerprint. This path is documented; there is no migration script (D9).

### 5.9 Images and short names

Compat normalises short names to `docker.io`, as Docker does (unverified for every Podman version). The `podman` CLI, used for helpers, applies `registries.conf` instead, and with `short-name-mode = "enforcing"` and no terminal, an ambiguous short name fails. So:

- Qualify the two third-party images in the compose file: `docker.io/timescale/timescaledb:...@sha256:...` and `docker.io/qmcgaw/gluetun:...@sha256:...`. Identical meaning on Docker.
- Qualify the helper images in the scripts the same way (`docker.io/library/alpine`, `docker.io/curlimages/curl`, `docker.io/library/python`, `docker.io/koalaman/shellcheck`). The cosign and uv images are already on `ghcr.io`.
- Source builds tag `local/<project>-<name>:dev`. Podman stores an unqualified build tag as `localhost/local/...` and finds it again by short name. Source mode on Podman stays unsupported at first (D6); Phase 2 tests images mode only.

### 5.10 Logging

`json-file` with `max-size` and `max-file` keeps each container at 30 MiB. Through compat, Podman uses `k8s-file` with a size limit; rotation into 3 files is not available. Two options: keep `json-file` (bounded by size, one file), or use `journald` in the Podman overlay so that journald's own limits apply. Decision D7: keep `json-file` if Podman honours both `max-size` and `max-file`, otherwise use `journald` in the Podman overlay. A Phase 2 test decides.

### 5.11 SELinux

Fedora and RHEL run SELinux enforcing. Podman labels containers, and a bind mount of a host file without a relabel option is denied. Four bind mounts are affected (`./scripts/backup-service.sh`, `./vpn/control-auth.toml`, `./vpn/entrypoint.sh`, `./vpn/health.sh`). The Podman overlay adds the `z` option to them (shared label, read-only stays read-only). Named volumes are labelled by Podman. Debian and Ubuntu use AppArmor, where Podman applies its default profile.

## 6. Recommendation

Approach A, rootful.

| Component | Minimum | Why |
| --- | --- | --- |
| Podman | 5.4 | Debian 13's version; netavark-only; `--interface-name`, `isolate=strict`, `--disable-dns` all available. Podman 6 accepted once the CI job passes on it |
| Network backend | netavark (not CNI), firewall driver nftables | 5.1. Podman 6 has nothing else |
| aardvark-dns | as shipped with the Podman version | 5.3 |
| Compose | `docker-compose` 2.26 | Debian 13 ships 2.26.1; Ubuntu 26.04 and Fedora ship newer. The Docker CLI is not needed |
| Kernel | nftables with the `bridge` family, cgroup v2 | 5.2, resource limits |
| Init | systemd | Healthcheck timers, boot unit |
| Architectures | amd64, arm64 | Same as today |

Distributions for the first version (D2, decided):

| Distribution | Podman in the archive | Status |
| --- | --- | --- |
| Debian 13 (trixie) | 5.4.2 | Supported target, the CI reference |
| Ubuntu 26.04 LTS | 5.7.0 | Supported target |
| Fedora (current releases) | 5.x or 6.x | Experimental, tested in Phase 2 (SELinux path) |
| RHEL 10, AlmaLinux 10, Rocky Linux 10 | 5.x (exact minor unverified) | Experimental, tested in Phase 2 (SELinux path) |
| Ubuntu 24.04 LTS | 4.9.3 | Not supported (Podman 4) |
| Debian 12 (bookworm) | 4.3.1 | Not supported |

Not supported, and refused by the installer: rootless Podman, CNI backend, Podman machine (macOS and Windows), Docker and Podman both active on one host.

## 7. Guarantees on Podman

| Guarantee | On Docker today | On Podman | Verified by |
| --- | --- | --- | --- |
| A sensor cannot open a connection to the internet | `enable_ip_masquerade=false` on `sp-ingress`, internal sensor networks, plus host firewall forward drop | Host firewall forward drop on `sp-ingress` (required), internal sensor networks | New `egress-check` line: from each sensor, a TCP connect to a public test address fails. Firewall counter on that rule |
| A sensor cannot resolve outside names | Embedded resolver with upstream 127.0.0.1 | DNS off on `sp-ingress`; aardvark on internal networks answers container names only | New `egress-check` line per sensor (resolves `redis`, fails on an outside name) |
| Sensors cannot reach each other | `enable_icc=false` on `sp-ingress`, one internal network per sensor | `bridge suckerpot_bridge` drop on `sp-ingress`; `isolate=strict` between bridges | New `egress-check` line: from `sensor-ssh`, a connect to `sensor-web`'s `sp-ingress` address fails |
| A container cannot reach the host (except published replies and aardvark DNS) | Firewall input drops, isolated gateways on Engine 28 | Firewall input drops; only UDP/TCP 53 to the local gateway address on DNS-enabled internal bridges | `egress-check`: from a sensor and from ingest, connects to the gateway on 22 and on the dashboard port fail (the `--refuse` checks exist for ingest and collector; extend to a sensor) |
| No container reaches the admin SSH port or the dashboard port | Firewall protected-ports rule on `docker0`, `br-*`, `sp-*` | Same rule plus `podman*` | Same checks; `nft list table inet suckerpot_host` shows the rule |
| Ingest, collector, analyzer have no route out except the VPN proxy | Internal networks, `dns: 127.0.0.1` | Internal networks (no default route, no forwarding), aardvark NXDOMAIN for outside names | Existing `selftest --direct` and `--gate` in `egress-check` |
| The VPN uplink only reaches the one WireGuard endpoint; kill switch | gluetun firewall plus host forward rule on `sp-vpn` | Same | Existing kill-switch part of `egress-check` |
| Participant without VPN: only hubproxy goes out, only TCP 443 to public addresses, only to the hub and feed names | hubproxy allow-list plus forward rules on `sp-hubgate` | Same (DNS goes through aardvark on the host instead) | Existing direct-mode `egress-check` |
| No IPv6 from any SuckerPot network | `enable_ipv6: false` plus firewall IPv6 drop | Same | `podman network inspect` shows no IPv6 subnet; firewall counter |
| The firewall is loaded before any container starts after a boot | Not guaranteed (Docker starts containers itself) | `suckerpot-stack.service` requires `suckerpot-firewall.service` | `systemctl list-dependencies suckerpot-stack.service`; reboot test in Phase 3 |
| Images are the signed release images | cosign on the node, `--pull never` | Same | Existing `verify-release.sh`, `verify-images.sh` |

A new command `just isolation-check` (or new sections in `egress-check`) runs the rows above that `egress-check` does not cover today. It runs on both engines, so Docker nodes gain the sensor checks too.

## 8. Engine abstraction in the scripts

A new `scripts/lib/engine.sh`, sourced by `scripts/lib/env.sh` so every script gets it:

| Function or variable | Docker | Podman |
| --- | --- | --- |
| `SUCKERPOT_ENGINE` (from `.env`, else detected) | `docker` | `podman` |
| `engine_detect` | `docker version` answers | `podman info` answers as root or through the socket, `NetworkBackend` is netavark, not rootless |
| `ctr ARGS...` (one-shot containers, volumes, networks, inspect) | `docker ARGS...` | `podman ARGS...` |
| `dc ARGS...` (compose) | `docker compose ARGS...` | `DOCKER_HOST=unix:///run/podman/podman.sock docker-compose ARGS...` |
| `engine_check_versions` | Engine 24 (warn below 28), Compose 2.24 | Podman 5.4, netavark, nftables driver, compose 2.26, systemd |
| `engine_data_root` | `docker info --format '{{.DockerRootDir}}'` | `podman info --format '{{.Store.GraphRoot}}'` |
| `engine_bridges` | `docker network ls/inspect` | `podman network ls --format '{{.NetworkInterface}}'` |
| `engine_name` | `Docker` | `Podman` (for messages) |

Rules:

- Every `docker compose` call in `scripts/`, the node recipes of the `justfile` and the docs examples becomes `dc` (the `justfile` sources the library in its recipes). Every other `docker` call becomes `ctr`. A guardrail test fails on any new literal `docker ` call outside `scripts/lib/engine.sh`.
- The installer writes `SUCKERPOT_ENGINE` to `.env`. `env-migrate.sh` writes `SUCKERPOT_ENGINE=docker` to an existing `.env` that has none, so old nodes never switch.
- `DOCKER_HOST` is set by `dc` only, never exported to the whole script, so a stray Docker CLI call cannot hit the wrong engine.
- The library refuses to run when `.env` says one engine and only the other answers.

## 9. Phases

### Phase 1: detection and the engine library

- `scripts/lib/engine.sh` as in section 8. `install.sh`, `update.sh`, `rollback.sh`, `status.sh`, `participant.sh`, `compose-fresh.sh`, `ensure-volumes.sh`, `restore-db.sh`, `backup-db.sh`, `verify-release.sh`, `verify-images.sh`, `egress-check.sh`, `lib/ports-check.sh`, `lib/env.sh` and the `justfile` use `dc` and `ctr`.
- Image names fully qualified (5.9).
- Guardrails: fake `podman` and `docker-compose`; script tests run for both engines; the literal-`docker` test.

Acceptance:

- On Docker, the behaviour is byte-for-byte the same: the existing guardrails, `compose`, `participant-e2e`, `backup-restore` and `broker` jobs pass unchanged.
- With `SUCKERPOT_ENGINE=podman` and the fakes, each script calls `podman` or `docker-compose` with the expected arguments (guardrail tests).
- `grep -rn 'docker compose\|docker run\|docker volume\|docker network\|docker inspect' scripts/ justfile` finds only `scripts/lib/engine.sh` and the developer recipes of the `justfile`, which stay Docker-only (D8).

### Phase 2: install, update and status on Podman

- Version and backend checks; refusal of rootless, CNI, Podman 4 and a host where Docker is also active.
- `ensure-networks.sh` and `docker-compose.podman.yml` (5.2), with SELinux `z` options (5.11).
- `suckerpot-stack.service` (5.7).
- Volume ownership on Podman (5.8).
- `status.sh` shows the engine line.
- Docs for the Docker to Podman move (5.8).

Acceptance, on Debian 13 and Ubuntu 26.04 VMs, and on Fedora and AlmaLinux 10 VMs with SELinux enforcing (D2). The participant install on a small VPS-sized VM (1 to 2 GiB) comes first, because participant nodes on VPSs are the main target:

- `./scripts/install.sh` (full) and `./scripts/install.sh --participant` finish, every service is healthy, `./scripts/status.sh` is green.
- A connection from a second host to each published sensor port logs that host's address.
- `just update` from release N to N+1 succeeds; an update that breaks a service rolls back.
- `just backup`, then `just restore latest`, leaves the same row counts.
- A dump from a Docker node restores on a Podman node.
- After a reboot the stack comes back healthy, with no manual step.
- `findmnt` inside a sensor shows a read-only root and only the expected writable mounts.

### Phase 3: firewall

- Podman templates (or Podman blocks in the existing templates): `podman*` in the protected-ports rule, DNS accept to aardvark on the internal bridges, the `bridge suckerpot_bridge` table.
- `render-firewall.sh` asks `podman network ls`, checks `podman*` bridges, reads `containers.conf` DNS settings.
- `suckerpot-firewall.service` ordered before `suckerpot-stack.service`.
- Firewall mandatory on Podman (D5).
- `egress-check` (or `isolation-check`) gains the rows of section 7.

Acceptance:

- `just egress-check` passes on Podman in full mode with the VPN, in participant mode with the VPN, and in participant direct mode.
- With the firewall unloaded (`nft delete table inet suckerpot_host`), the new sensor checks FAIL on Podman. This proves the checks test the firewall and not luck.
- `nft -c` accepts both templates on Debian 13 and Ubuntu 26.04.
- On Docker, the rendered firewall is unchanged (guardrail compares with the fixture).

### Phase 4: CI job on Podman

- A `podman` job on `ubuntu-latest`. Hosted runners ship Docker; the job stops and masks Docker (`docker.service`, `docker.socket`, `containerd`), removes its iptables chains, installs Podman 5.4+ and `docker-compose` 2.26+ (from Ubuntu 26.04 packages when the runner image has them, or a pinned build checked against a SHA-256), sets the nftables driver, enables `podman.socket`.
- It runs: `compose` steps through `dc` with the Podman overlay, `scripts/e2e/participant.sh`, `test-backup-restore.sh`, `test-broker.sh`, and the Phase 3 isolation checks (no VPN endpoint in CI: the kill-switch part is skipped, as in the existing jobs).
- Optional, later: a Podman release smoke job in `release.yml`.

Acceptance:

- The job is green for 10 consecutive runs on `main` before it becomes required.
- A deliberate break (for example removing `--disable-dns` from `sp-ingress`) makes it fail.
- Its run time stays under 45 minutes.

### Phase 5: docs and website

- `docs/install.md`: requirements table with a "Container engine" row (Docker Engine 24+ or Podman 5.4+ rootful), a Podman subsection (packages, `podman.socket`, nftables driver, socket access), troubleshooting rows.
- `docs/getting-started.md`, `docs/participate.md`, `docs/vps.md`: one-line requirement change, link to the install page.
- `docs/deployment.md`, `scripts/host/README.md`: firewall differences (mandatory on Podman, aardvark DNS rule, bridge table), `DOCKER-USER` advice reworded.
- `docs/updates.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/configuration.md`: "Docker network" becomes "container network" where the text is engine-neutral; Podman notes where behaviour differs (embedded resolver, isolated gateways).
- Website: `download.html` requirements rows; `participate.html` step 1 gets a second tab or a line for Podman (`apt install podman docker-compose`); `strings/*.json` updated in all 9 languages; the "Install with Docker Compose" wording reviewed.

Acceptance:

- Every command in the Podman docs was run in the Phase 2 VMs.
- The docs build has no new warning.
- The website strings pass its existing checks in all languages.

## 10. Facts checked, and what could not be checked

Checked on the web for this note:

- Podman's compat `CreateNetwork` translates `com.docker.network.bridge.name` (bridge driver) and `com.docker.network.driver.mtu`; other options produce a warning only, and `Internal` is copied. Source: `pkg/api/handlers/compat/networks.go` on Podman's `main` branch.
- `podman network create`: `--internal` disables forwarding on the bridge and adds no default route, aardvark-dns then answers container names only; `isolate` takes `strict`, `true`, `false`; no option disables masquerade or traffic within one bridge; `--interface-name`, `--disable-dns` exist. Source: docs.podman.io, `podman-network-create(1)`.
- Netavark nftables support since 1.10, table `inet netavark`; Fedora 41 change to make it the default; Docker's forward drop cuts off Podman containers on the same host. Source: Fedora wiki "Changes/NetavarkNftablesDefault".
- Podman 6 removed the iptables backend, CNI, slirp4netns and cgroup v1 (secondary coverage of the 6.0 release and the Fedora Podman 6 change page; the official release notes were not read).
- `podman compose` runs an external provider, `docker-compose` first, then `podman-compose`; selectable with `compose_providers` or `PODMAN_COMPOSE_PROVIDER`. Source: docs.podman.io, `podman-compose(1)`.
- Rootless: `rootlessport` does not keep the client source address; a pasta-based forwarder that does was merged in May 2026 and is marked experimental. Source: `podman-rootless(7)`, Podman blog and pull request.
- Package versions: Debian 12 Podman 4.3.1, Debian 13 Podman 5.4.2 and `docker-compose` 2.26.1, Ubuntu 26.04 Podman 5.7.0 (packages.debian.org, launchpad.net).

Not checked (to verify in Phase 2 before relying on it):

- Whether the gateway address is always assigned to an internal netavark bridge (the design assumes yes, the safe assumption).
- How a service's `dns:` list combines with aardvark-dns, and whether `--disable-dns` on one network changes the resolver order in a multi-network container.
- `gw_priority` through compat.
- Copy-up ownership of empty named volumes.
- `json-file` options through compat (`max-file`).
- The `read-only-tmpfs` default through compat.
- Which restart policies `podman-restart.service` handles.
- `podman volume ls --filter name=^x_` regex semantics.
- Ubuntu 24.04's exact Podman version (4.9.3 from memory) and the RHEL 10 minor version.
- podman-compose's support for each flag and YAML feature in section 4.

Checked in Phase 2, on rootful Podman 5.4.2 (Debian 13, netavark 1.14, docker-compose 2.26.1) and
Podman 5.8.9 (Fedora 43, netavark 1.17, docker-compose 5.7.0), both with the nftables driver, in
privileged containers running systemd (SELinux was not enforcing there):

- An internal netavark bridge always gets the gateway address (the first address of its
  subnet). The host firewall's input drops are needed, as assumed.
- A service's `dns:` entries are written into the container's `/etc/resolv.conf` after the
  aardvark-dns addresses of its DNS-enabled networks (so `127.0.0.1` is the container's own
  loopback). A network made with `--disable-dns` adds no nameserver. A sensor (DNS off on
  `sp-ingress`, DNS on its internal network) resolves `redis` and no outside name. A container on
  an internal network and a DNS-enabled non-internal one (hubproxy) resolves outside names through
  either aardvark address, in both network orders.
- `gw_priority`: docker-compose 2.26.1 drops it. It does not matter on Podman: the other network of
  `vpn` and `hubproxy` is internal and adds no route, so the uplink is the only default route
  (checked in both containers).
- Copy-up keeps the owner of the image directory (redis `/data` 999:1000, ssh host keys 10001,
  `vpn-config` 10001); no change to `ensure-volumes.sh` is needed.
- `json-file`: `max-size` is honoured, `max-file` is not (one file, cut at 10 MB). So the Podman
  overlay logs to journald (D7); `docker-compose logs` still works.
- `read-only-tmpfs` applies through the compat API: Podman adds writable `/run` and `/var/tmp`
  without `noexec` or a size limit, where a program could be written and run. The Podman overlay
  mounts both as 1 MB `noexec` tmpfs in every service.
- `podman-restart.service` is disabled by default on both. On 5.4 it starts `always` containers
  only; on 5.8 it uses `should-start-on-boot`, which includes `unless-stopped`. The stack unit's
  installer orders it after the firewall in case an owner turns it on.
- `podman volume ls --filter name=^x_` treats the value as a regular expression, like Docker.
- `docker-compose ps -a migrate --format '{{.State}} {{.ExitCode}}'` prints `exited 0`.
- Not in the list above, found while testing: Podman refuses the `uid=` and `gid=` tmpfs options
  (the overlay uses Podman's `U` option); docker-compose refuses `healthcheck.start_interval` on
  Podman 5.4, which announces Docker API 1.41 (the overlay drops it for `backup`); and Podman's
  tmpfiles rule keeps `/run/podman` at mode 0700, so a `SocketGroup=` drop-in alone does not let
  the group reach the socket (Phase 3 must also relax that folder).

Still open: Ubuntu 24.04's exact Podman version and the RHEL 10 minor version, podman-compose
(not used), and the SELinux `z` option under enforcing SELinux.

## 11. Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| A Podman node runs without the firewall | Sensors have an outbound route and reach each other | Firewall mandatory on Podman (D5); `status.sh` turns red when the table is missing; `suckerpot-stack.service` requires it |
| aardvark-dns as attack surface | A compromised sensor can send packets to a root host process | DNS off where not needed; only port 53 to the local gateway; track aardvark-dns security advisories |
| A Podman update changes compat behaviour | A network option starts or stops being honoured | SuckerPot creates its networks itself on Podman (5.2), so compat translation no longer matters for them; CI on Podman |
| Owner also installs Docker later | Docker's forward drop breaks Podman networking | `status.sh` and the updater detect both engines active and warn |
| Two engine paths double the test matrix | Slower CI, more maintenance | One compose implementation; the engine library is the only branch point; Podman marked experimental until the CI job has been stable (D1) |
| Engine-specific error texts (network recreation) | `compose_up_recreating` does not recognise a Podman error | On Podman, network recreation is done by `ensure-networks.sh` before `up`, so the text parsing is not needed |

## 12. Decisions

The owner approved the design and these decisions on 2026-11-21. The main target is participant nodes on VPSs. Full installs on Podman are in scope, but participant installs come first in testing and docs.

| # | Question | Decision |
| --- | --- | --- |
| D1 | Status of Podman at first: "supported" or "experimental"? | Experimental in the first release that ships it. The docs say so, and the installer prints a notice. Podman becomes supported after the CI job has been required for one minor release and one real node has gone through an update |
| D2 | Which distributions? | Supported: Debian 13 and Ubuntu 26.04. Experimental: Fedora and the RHEL 10 family. They are still tested in Phase 2 (SELinux enforcing), because the user who asked probably runs one of them. Refused: Podman 4 hosts (Ubuntu 24.04, Debian 12) |
| D3 | How does a non-root user reach the root Podman socket (install, auto-update)? | A group on `podman.socket`, set with a systemd drop-in (`SocketGroup=`). The updater keeps running without sudo. The docs say the group is root-equivalent, as they already do for `docker` |
| D4 | Rootless Podman? | No. It can be raised again when the forwarder that keeps the source address is no longer experimental, and only if something else can do the host firewall's job (the host cannot see rootless bridges) |
| D5 | Make the host firewall mandatory on Podman? | Yes. A `--no-firewall` flag lets an owner who filters at the hypervisor (for example with the Proxmox firewall script) skip it, with a clear warning |
| D6 | Source installs (`--build`) on Podman? | Images mode only at first. Source mode stays Docker-only until it is tested |
| D7 | Logging driver on Podman | Use `json-file`, as on Docker, if Podman honours both `max-size` and `max-file`. Otherwise use `journald` in the Podman overlay. Phase 2 decides with a test: fill a container's log past 30 MiB and check the files on disk |
| D8 | Developer recipes (`just check`, lint, web build) on Podman? | Docker-only. The owner keeps developing on Docker |
| D9 | A script to move a running node from Docker to Podman? | No script. The backup-and-restore path (section 5.8) is documented in Phase 5 |
| D10 | Run the new sensor isolation checks and the bridge table on Docker nodes too? | The checks run on Docker nodes too: they also test Docker's guarantees. The bridge table stays optional on Docker, where `enable_icc=false` already covers it |
