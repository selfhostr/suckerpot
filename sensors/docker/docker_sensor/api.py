"""The fake Docker Engine API: routing and canned answers.

Nothing is ever run: containers and execs are small in-memory records (per source IP, bounded)
so that ``docker run`` and ``docker exec`` sequences make sense to the client. Answers are
JSON documents built here; output of trivial commands comes from ``analysis.canned_output``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from docker_sensor import analysis
from docker_sensor.config import Config
from docker_sensor.httpio import Request, to_text
from docker_sensor.profile import FakeContainer, Profile

SWARM_MSG = (
    'This node is not a swarm manager. Use "docker swarm init" or "docker swarm join" '
    "to connect this node to swarm and try again."
)
_ADJ = ["quirky", "brave", "eager", "gifted", "jolly", "keen", "lucid", "nifty", "stoic", "witty"]
_NOUN = ["curie", "darwin", "euler", "fermat", "galileo", "hopper", "kepler", "lovelace", "turing"]
_NAME_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
_HEX = frozenset("0123456789abcdef")
_REGISTRY_HOST_MARKERS = (".", ":")
MAX_NAME = 128


@dataclass
class Resp:
    status: int = 200
    body: bytes = b""
    ctype: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)
    stream: list[bytes] | None = None  # chunked JSON progress lines
    hold: float = 0.0  # seconds a stream with no lines stays open (GET /events)
    hijack: bool = False  # attach / exec start: raw stream, 101 when the client asked
    raw: bytes = b""  # payload of a hijacked stream
    close: bool = False
    no_content_length: bool = False


@dataclass
class Outcome:
    """What the server should record besides the plain http_request event."""

    route: str = ""
    flags: set[str] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)
    commands: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    logins: list[dict[str, Any]] = field(default_factory=list)
    important: bool = False


@dataclass
class ContainerRec:
    id: str
    name: str
    spec: analysis.ContainerSpec
    created: float
    state: str = "created"  # created / running / exited
    started: float = 0.0
    output: str = ""


@dataclass
class ExecRec:
    id: str
    container: str
    cmd: list[str]
    tty: bool
    detach: bool = False
    ran: bool = False


@dataclass
class IPState:
    containers: OrderedDict[str, ContainerRec] = field(default_factory=OrderedDict)
    execs: OrderedDict[str, ExecRec] = field(default_factory=OrderedDict)
    pulled: OrderedDict[str, tuple[str, int, int]] = field(default_factory=OrderedDict)
    removed: OrderedDict[str, None] = field(default_factory=OrderedDict)  # auto-removed ids
    touched: float = field(default_factory=time.monotonic)
    bytes: int = 0

    def size(self) -> int:
        total = 256 + sum(len(k) + 56 for k in self.pulled) + 80 * len(self.removed)
        for c in self.containers.values():
            total += c.spec.size() + len(c.output) + len(c.name) + 400
        for e in self.execs.values():
            total += 400 + sum(len(x) + 56 for x in e.cmd)
        return total


_SALVAGE_BYTES = 32 * 1024  # an unparseable create body is only scanned this far


def jdump(obj: Any, *, nl: bool = True) -> bytes:
    """JSON as dockerd writes it: compact, with the encoder's trailing newline."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + (
        b"\n" if nl else b""
    )


def err(status: int, message: str) -> Resp:
    return Resp(status, jdump({"message": message}))


def _mac(ip: str) -> str:
    """Docker derives a bridge endpoint MAC from its IPv4 address (02:42 + the four octets)."""
    return "02:42:" + ":".join(f"{int(o):02x}" for o in ip.split("."))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "000Z"


def _ago(seconds: float) -> str:
    s = int(seconds)
    if s < 120:
        return f"{s} seconds"
    if s < 7200:
        return f"{s // 60} minutes"
    if s < 172800:
        return f"{s // 3600} hours"
    return f"{s // 86400} days"


def mux_frames(text: str, tty: bool) -> bytes:
    data = text.encode()
    if tty or not data:
        return data
    return struct.pack(">BxxxI", 1, len(data)) + data


def _valid_name(name: str) -> bool:
    return 0 < len(name) <= MAX_NAME and name[0] not in "_.-" and all(c in _NAME_OK for c in name)


def split_ref(image: str) -> tuple[str, str]:
    """Split ``name[:tag]`` or ``name@digest`` (hand parsed)."""
    if "@" in image:
        name, _, digest = image.partition("@")
        return name, digest
    if ":" in image.rpartition("/")[2]:
        name, _, tag = image.rpartition(":")
        return name, tag
    return image, ""


def parse_version(seg: str) -> tuple[int, int] | None:
    if len(seg) < 2 or seg[0] != "v":
        return None
    major, _, minor = seg[1:].partition(".")
    minor = minor or "0"
    if not (major.isascii() and major.isdigit() and minor.isascii() and minor.isdigit()):
        return None
    if len(major) > 3 or len(minor) > 3:
        return None
    return int(major), int(minor)


class DockerApi:
    def __init__(self, cfg: Config, profile: Profile) -> None:
        self.cfg = cfg
        self.p = profile
        self.api = tuple(int(x) for x in cfg.api_version.split("."))
        self.min_api = tuple(int(x) for x in cfg.min_api_version.split("."))
        self._state: OrderedDict[str, IPState] = OrderedDict()
        self.state_bytes = 0
        self._static = {c.id: c for c in profile.containers}

    # -- per-IP state ----------------------------------------------------------------------

    def state(self, ip: str) -> IPState:
        now = time.monotonic()
        while self._state:  # least recently used first: expire what nobody touched for the TTL
            oldest = next(iter(self._state))
            old = self._state[oldest]
            if oldest == ip or now - old.touched <= self.cfg.state_ttl:
                break
            self._drop_state(oldest)
        st = self._state.get(ip)
        if st is None:
            st = IPState()
            self._state[ip] = st
            while len(self._state) > self.cfg.state_ips:
                self._drop_state(next(iter(self._state)))
        else:
            self._state.move_to_end(ip)
        st.touched = now
        return st

    def _drop_state(self, ip: str) -> None:
        st = self._state.pop(ip, None)
        if st is not None:
            self.state_bytes -= st.bytes

    def _account(self, ip: str) -> None:
        """Re-measure one IP's state; evict least recently used IPs while over the budget."""
        st = self._state.get(ip)
        if st is None:
            return
        size = st.size()
        self.state_bytes += size - st.bytes
        st.bytes = size
        while self.state_bytes > self.cfg.state_bytes and len(self._state) > 1:
            victim = next(iter(self._state))
            if victim == ip:
                self._state.move_to_end(ip)
                continue
            self._drop_state(victim)

    def _remember[T](self, store: OrderedDict[str, T], key: str, value: T, cap: int) -> None:
        store[key] = value
        store.move_to_end(key)
        while len(store) > cap:
            store.popitem(last=False)

    @staticmethod
    def _norm_ref(image: str) -> str:
        """``name:tag`` with the default registry and library prefix removed."""
        name, tag = split_ref(image)
        if "@" in image:
            tag = "latest"
        for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
            if name.startswith(prefix):
                name = name[len(prefix) :]
        if name.startswith("library/"):
            name = name[8:]
        return f"{name}:{tag or 'latest'}"[:300]

    def _image_known(self, st: IPState, image: str) -> bool:
        full = self._norm_ref(image)
        if full in st.pulled:
            return True
        ident = image.removeprefix("sha256:")
        for ref, iid, _size, _created in self.p.images:
            if ref == full or (len(ident) >= 4 and iid.removeprefix("sha256:").startswith(ident)):
                return True
        return False

    def _pulled_image(self, full: str) -> tuple[str, int, int]:
        h = self.p.derive("pl-" + full)
        return (
            "sha256:" + hashlib.sha256(h.encode()).hexdigest(),
            5_000_000 + int(h[:6], 16) % 90_000_000,
            int(time.time()),
        )

    def _find(self, st: IPState, ref: str) -> ContainerRec | FakeContainer | None:
        ref = ref.lstrip("/")
        if not ref or len(ref) > MAX_NAME:
            return None
        for rec in st.containers.values():
            if rec.name == ref or (len(ref) >= 3 and rec.id.startswith(ref)):
                return rec
        for c in self.p.containers:
            if c.name == ref or (len(ref) >= 3 and c.id.startswith(ref)):
                return c
        return None

    # -- entry point -----------------------------------------------------------------------

    def handle(self, req: Request, ip: str) -> tuple[Resp, Outcome]:
        out = Outcome()
        segs = [unquote(s) for s in req.path.split("/") if s]
        method = req.method
        if segs and segs[0].startswith("v") and len(segs[0]) > 1 and segs[0][1].isdigit():
            ver = parse_version(segs[0])
            if ver is None:
                out.route = "not_found"
                return err(404, "page not found"), out
            vtext = segs[0][1:9]
            out.extra["api_version"] = vtext
            segs = segs[1:]
            if not (segs and segs[0] == "_ping"):
                if ver > self.api:
                    out.route = "version_too_new"
                    return err(
                        400,
                        f"client version {vtext} is too new. "
                        f"Maximum supported API version is {self.cfg.api_version}",
                    ), out
                if ver < self.min_api:
                    out.route = "version_too_old"
                    return err(
                        400,
                        f"client version {vtext} is too old. Minimum supported API "
                        f"version is {self.cfg.min_api_version}, please upgrade your client "
                        "to a newer version",
                    ), out
        resp = self._route(req, method, segs, ip, out)
        self._account(ip)
        return resp, out

    def _route(self, req: Request, method: str, segs: list[str], ip: str, out: Outcome) -> Resp:
        st = self.state(ip)
        n = len(segs)
        head = segs[0] if segs else ""
        out.route = "/" + "/".join(segs[:2])[:64] if segs else "/"
        ro = method in ("GET", "HEAD")
        if head == "_ping" and n == 1 and ro:
            out.route = "_ping"
            body = b"" if method == "HEAD" else b"OK"
            return Resp(
                200,
                body,
                "text/plain; charset=utf-8",
                {
                    "Builder-Version": "2",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Swarm": "inactive",
                },
            )
        if head == "version" and n == 1 and ro:
            out.flags.add("recon")
            return Resp(200, jdump(self._version()))
        if head == "info" and n == 1 and ro:
            out.flags.add("recon")
            return Resp(200, jdump(self._info()))
        if head == "containers":
            return self._containers(req, method, segs, st, ip, out)
        if head == "images":
            return self._images(req, method, segs, st, out)
        if head == "exec" and n >= 2:
            return self._exec(req, method, segs, st, out)
        if head == "auth" and n == 1 and method == "POST":
            return self._auth(req, out)
        if head == "build" and n == 1 and method == "POST":
            return self._build(req, out)
        if head == "commit" and n == 1 and method == "POST":
            out.important = True
            out.flags.add("commit")
            return Resp(201, jdump({"Id": "sha256:" + secrets.token_hex(32)}))
        if head in ("swarm", "nodes", "services", "tasks", "secrets", "configs"):
            return self._swarm(req, method, segs, out)
        if head == "networks":
            return self._networks(req, method, segs, out)
        if head == "volumes":
            return self._volumes(req, method, segs, out)
        if head == "plugins" and ro:
            return Resp(200, b"[]\n")
        if head == "events" and n == 1 and ro:
            return Resp(200, b"", "application/json", stream=[], hold=self.cfg.events_hold)
        if head == "system" and n == 2 and segs[1] == "df" and ro:
            return Resp(200, jdump(self._df()))
        if head == "session" or head == "grpc":
            return err(400, "no upgrade")
        return err(404, "page not found")

    # -- static documents ------------------------------------------------------------------

    def _version(self) -> dict[str, Any]:
        c = self.cfg
        k = self.p.kernel
        return {
            "Platform": {"Name": "Docker Engine - Community"},
            "Components": [
                {
                    "Name": "Engine",
                    "Version": c.engine_version,
                    "Details": {
                        "ApiVersion": c.api_version,
                        "Arch": "amd64",
                        "BuildTime": "2024-09-20T11:39:28.000000000+00:00",
                        "Experimental": "false",
                        "GitCommit": "41ca978",
                        "GoVersion": "go1.22.7",
                        "KernelVersion": k,
                        "MinAPIVersion": c.min_api_version,
                        "Os": "linux",
                    },
                },
                {
                    "Name": "containerd",
                    "Version": "1.7.22",
                    "Details": {"GitCommit": "7f7fdf5fed64eb6a7caf99b3e12efcf9d60e311c"},
                },
                {
                    "Name": "runc",
                    "Version": "1.1.14",
                    "Details": {"GitCommit": "v1.1.14-0-g2c9f560"},
                },
                {"Name": "docker-init", "Version": "0.19.0", "Details": {"GitCommit": "de40ad0"}},
            ],
            "Version": c.engine_version,
            "ApiVersion": c.api_version,
            "MinAPIVersion": c.min_api_version,
            "GitCommit": "41ca978",
            "GoVersion": "go1.22.7",
            "Os": "linux",
            "Arch": "amd64",
            "KernelVersion": k,
            "BuildTime": "2024-09-20T11:39:28.000000000+00:00",
        }

    def _info(self) -> dict[str, Any]:
        c, p = self.cfg, self.p
        total = len(p.containers)
        return {
            "ID": p.daemon_id,
            "Containers": total,
            "ContainersRunning": total,
            "ContainersPaused": 0,
            "ContainersStopped": 0,
            "Images": len(p.images),
            "Driver": "overlay2",
            "DriverStatus": [
                ["Backing Filesystem", "extfs"],
                ["Supports d_type", "true"],
                ["Using metacopy", "false"],
                ["Native Overlay Diff", "true"],
                ["userxattr", "false"],
            ],
            "Plugins": {
                "Volume": ["local"],
                "Network": ["bridge", "host", "ipvlan", "macvlan", "null", "overlay"],
                "Authorization": None,
                "Log": [
                    "awslogs",
                    "fluentd",
                    "gcplogs",
                    "gelf",
                    "journald",
                    "json-file",
                    "local",
                    "splunk",
                    "syslog",
                ],
            },
            "MemoryLimit": True,
            "SwapLimit": True,
            "CpuCfsPeriod": True,
            "CpuCfsQuota": True,
            "CPUShares": True,
            "CPUSet": True,
            "PidsLimit": True,
            "IPv4Forwarding": True,
            "BridgeNfIptables": True,
            "BridgeNfIp6tables": True,
            "Debug": False,
            "NFd": 28 + 4 * total,
            "OomKillDisable": False,
            "NGoroutines": 44 + 6 * total,
            "SystemTime": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "000Z",
            "LoggingDriver": "json-file",
            "CgroupDriver": "systemd",
            "CgroupVersion": "2",
            "NEventsListener": 0,
            "KernelVersion": p.kernel,
            "OperatingSystem": p.os_name,
            "OSVersion": "24.04",
            "OSType": "linux",
            "Architecture": "x86_64",
            "IndexServerAddress": "https://index.docker.io/v1/",
            "RegistryConfig": {
                "AllowNondistributableArtifactsCIDRs": None,
                "AllowNondistributableArtifactsHostnames": None,
                "InsecureRegistryCIDRs": ["127.0.0.0/8"],
                "IndexConfigs": {
                    "docker.io": {
                        "Name": "docker.io",
                        "Mirrors": [],
                        "Secure": True,
                        "Official": True,
                    }
                },
                "Mirrors": [],
            },
            "NCPU": p.cpus,
            "MemTotal": p.mem_bytes,
            "GenericResources": None,
            "DockerRootDir": "/var/lib/docker",
            "HttpProxy": "",
            "HttpsProxy": "",
            "NoProxy": "",
            "Name": c.hostname,
            "Labels": [],
            "ExperimentalBuild": False,
            "ServerVersion": c.engine_version,
            "Runtimes": {"io.containerd.runc.v2": {"path": "runc"}, "runc": {"path": "runc"}},
            "DefaultRuntime": "runc",
            "Swarm": {
                "NodeID": "",
                "NodeAddr": "",
                "LocalNodeState": "inactive",
                "ControlAvailable": False,
                "Error": "",
                "RemoteManagers": None,
            },
            "LiveRestoreEnabled": False,
            "Isolation": "",
            "InitBinary": "docker-init",
            "ContainerdCommit": {
                "ID": "7f7fdf5fed64eb6a7caf99b3e12efcf9d60e311c",
                "Expected": "7f7fdf5fed64eb6a7caf99b3e12efcf9d60e311c",
            },
            "RuncCommit": {"ID": "v1.1.14-0-g2c9f560", "Expected": "v1.1.14-0-g2c9f560"},
            "InitCommit": {"ID": "de40ad0", "Expected": "de40ad0"},
            "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"],
            "CDISpecDirs": ["/etc/cdi", "/var/run/cdi"],
            "Warnings": None,
        }

    def _df(self) -> dict[str, Any]:
        return {
            "LayersSize": sum(i[2] for i in self.p.images),
            "Images": [],
            "Containers": [],
            "Volumes": [],
            "BuilderSize": 0,
            "BuildCache": [],
        }

    # -- containers ------------------------------------------------------------------------

    def _list_entry(self, c: FakeContainer) -> dict[str, Any]:
        now = time.time()
        return {
            "Id": c.id,
            "Names": ["/" + c.name],
            "Image": c.image,
            "ImageID": c.image_id,
            "Command": c.command,
            "Created": c.created,
            "Ports": [
                {"IP": "0.0.0.0", "PrivatePort": priv, "PublicPort": pub, "Type": "tcp"}  # noqa: S104 - what dockerd reports
                if pub
                else {"PrivatePort": priv, "Type": "tcp"}
                for priv, pub in c.ports
            ],
            "Labels": {},
            "State": "running",
            "Status": "Up " + _ago(now - c.created),
            "HostConfig": {"NetworkMode": "bridge"},
            "NetworkSettings": {
                "Networks": {
                    "bridge": {
                        "IPAMConfig": None,
                        "Links": None,
                        "Aliases": None,
                        "MacAddress": _mac(c.ip),
                        "NetworkID": self.p.derive("net-bridge"),
                        "EndpointID": self.p.derive("ep-" + c.id),
                        "Gateway": self.p.net_prefix + ".1",
                        "IPAddress": c.ip,
                        "IPPrefixLen": 16,
                        "IPv6Gateway": "",
                        "GlobalIPv6Address": "",
                        "GlobalIPv6PrefixLen": 0,
                        "DriverOpts": None,
                    }
                }
            },
            "Mounts": [],
        }

    def _rec_entry(self, rec: ContainerRec) -> dict[str, Any]:
        s = rec.spec
        return {
            "Id": rec.id,
            "Names": ["/" + rec.name],
            "Image": s.image,
            "ImageID": "sha256:" + hashlib.sha256(s.image.encode()).hexdigest(),
            "Command": analysis.join_command(s.entrypoint + s.cmd, 200),
            "Created": int(rec.created),
            "Ports": [],
            "Labels": {},
            "State": rec.state,
            "Status": "Up " + _ago(time.time() - rec.started)
            if rec.state == "running"
            else ("Created" if rec.state == "created" else "Exited (0) 2 seconds ago"),
            "HostConfig": {"NetworkMode": s.network_mode or "bridge"},
            "NetworkSettings": {"Networks": {}},
            "Mounts": [],
        }

    def _inspect(self, c: FakeContainer | ContainerRec) -> dict[str, Any]:
        if isinstance(c, FakeContainer):
            cmd = c.command.split()
            created, state, image, name, cid = float(c.created), "running", c.image, c.name, c.id
            started = created + 1
            binds: list[str] | None = None
            priv = False
            env = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
            ip = c.ip
            image_id = c.image_id
        else:
            s = c.spec
            cmd = s.entrypoint + s.cmd
            created, state, image, name, cid = c.created, c.state, s.image, c.name, c.id
            started = c.started or created
            binds = s.binds or None
            priv = s.privileged
            env = s.env[:16]
            ip = self.p.net_prefix + ".9"
            image_id = "sha256:" + hashlib.sha256(image.encode()).hexdigest()
        running = state == "running"
        return {
            "Id": cid,
            "Created": _iso(created),
            "Path": cmd[0] if cmd else "",
            "Args": cmd[1:],
            "State": {
                "Status": state,
                "Running": running,
                "Paused": False,
                "Restarting": False,
                "OOMKilled": False,
                "Dead": False,
                "Pid": 1000 + int(cid[:4], 16) % 60000 if running else 0,
                "ExitCode": 0,
                "Error": "",
                "StartedAt": _iso(started) if state != "created" else "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z"
                if running or state == "created"
                else _iso(started + 2),
            },
            "Image": image_id,
            "ResolvConfPath": f"/var/lib/docker/containers/{cid}/resolv.conf",
            "HostnamePath": f"/var/lib/docker/containers/{cid}/hostname",
            "HostsPath": f"/var/lib/docker/containers/{cid}/hosts",
            "LogPath": f"/var/lib/docker/containers/{cid}/{cid}-json.log",
            "Name": "/" + name,
            "RestartCount": 0,
            "Driver": "overlay2",
            "Platform": "linux",
            "MountLabel": "",
            "ProcessLabel": "",
            "AppArmorProfile": "unconfined" if priv else "docker-default",
            "ExecIDs": None,
            "HostConfig": {
                "Binds": binds,
                "NetworkMode": "bridge",
                "Privileged": priv,
                "PidMode": "",
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            },
            "Mounts": [],
            "Config": {
                "Hostname": cid[:12],
                "Domainname": "",
                "User": "",
                "Tty": False,
                "Env": env,
                "Cmd": cmd,
                "Image": image,
                "WorkingDir": "",
                "Entrypoint": None,
                "Labels": {},
            },
            "NetworkSettings": {
                "Bridge": "",
                "Gateway": self.p.net_prefix + ".1",
                "IPAddress": ip,
                "IPPrefixLen": 16,
                "MacAddress": _mac(ip),
                "Networks": {"bridge": {"IPAddress": ip, "Gateway": self.p.net_prefix + ".1"}},
            },
        }

    def _containers(
        self, req: Request, method: str, segs: list[str], st: IPState, ip: str, out: Outcome
    ) -> Resp:
        n = len(segs)
        if n == 2 and segs[1] == "json" and method in ("GET", "HEAD"):
            out.flags.add("recon")
            entries = [self._list_entry(c) for c in self.p.containers]
            if req.qget("all") in ("1", "true"):
                entries += [self._rec_entry(r) for r in reversed(st.containers.values())]
            else:
                entries += [
                    self._rec_entry(r)
                    for r in reversed(st.containers.values())
                    if r.state == "running"
                ]
            return Resp(200, jdump(entries))
        if n == 2 and segs[1] == "create" and method == "POST":
            return self._create(req, st, out)
        if n == 2 and segs[1] == "prune" and method == "POST":
            out.important = True
            return Resp(200, jdump({"ContainersDeleted": None, "SpaceReclaimed": 0}))
        if n >= 2 and segs[1] not in ("json", "create", "prune"):
            return self._container_action(req, method, segs, st, out)
        return err(404, "page not found")

    def _create(self, req: Request, st: IPState, out: Outcome) -> Resp:
        out.important = True
        body = req.body
        if not body:
            out.route = "containers/create"
            return err(400, "config cannot be empty in order to create a container")
        obj = analysis.bounded_json(
            body,
            max_bytes=self.cfg.body_cap,
            max_depth=self.cfg.json_max_depth,
            depth_checked=req.depth_checked,
        )
        if not isinstance(obj, dict):
            out.route = "containers/create"
            self._salvage(out, body)
            if req.body_truncated:
                return err(400, "unexpected end of JSON input")
            first = to_text(body.lstrip()[:1]) or "?"
            if first.isprintable():
                return err(400, f"invalid character '{first}' looking for beginning of value")
            return err(400, "unexpected end of JSON input")
        spec = analysis.parse_container_spec(obj)
        out.route = "containers/create"
        out.flags |= spec.flags
        out.extra["container"] = spec.summary()
        out.commands.append(
            {
                "input": spec.input,
                "kind": "container_create",
                "image": spec.image[:256],
                "flags": sorted(spec.flags),
            }
        )
        for url in analysis.spec_urls(spec):
            out.downloads.append(
                {
                    "url": url,
                    "tool": analysis.detect_tool(spec.input + " " + " ".join(spec.env)),
                    "command": spec.input,
                    "source": "container_create",
                }
            )
        name = req.qget("name")
        if name and not _valid_name(name):
            return err(
                400,
                f"Invalid container name ({name[:64]}), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed",
            )
        if not spec.image:
            return err(404, "No such image: ")
        if not self._image_known(st, spec.image):
            return err(404, f"No such image: {self._norm_ref(spec.image)}")
        if not name:
            name = self._random_name(st)
        clash = self._find_exact(st, name)
        if clash is not None:
            return err(
                409,
                f'Conflict. The container name "/{name}" is already in use by container '
                f'"{clash}". You have to remove (or rename) that container to be able to '
                "reuse that name.",
            )
        cid = secrets.token_hex(32)
        rec = ContainerRec(
            id=cid,
            name=name,
            spec=spec.compact(),
            created=time.time(),
            output=analysis.canned_output(spec.entrypoint + spec.cmd)[:2048],
        )
        self._remember(st.containers, cid, rec, self.cfg.state_per_ip)
        out.extra["container_id"] = cid[:12]
        return Resp(201, jdump({"Id": cid, "Warnings": []}))

    def _salvage(self, out: Outcome, body: bytes) -> None:
        """A body that did not parse (too big, too deep, broken): still look for the obvious."""
        text = body[:_SALVAGE_BYTES].decode("utf-8", "replace")
        out.flags.add("container_create")
        out.flags.add("unparsed_body")
        if analysis.is_miner(text):
            out.flags.add("miner")
        for url in analysis.find_urls(text):
            out.downloads.append(
                {
                    "url": url,
                    "tool": analysis.detect_tool(text),
                    "command": "",
                    "source": "container_create",
                }
            )

    def _random_name(self, st: IPState) -> str:
        # Like dockerd: a generated name never clashes, so retry, then add a digit suffix.
        for attempt in range(16):
            r = secrets.randbelow(len(_ADJ) * len(_NOUN))
            name = f"{_ADJ[r % len(_ADJ)]}_{_NOUN[r // len(_ADJ)]}"
            if attempt >= 8:
                name += str(secrets.randbelow(10))
            if self._find_exact(st, name) is None:
                return name
        return f"{name}{secrets.randbelow(10**6)}"

    def _find_exact(self, st: IPState, name: str) -> str | None:
        for rec in st.containers.values():
            if rec.name == name:
                return rec.id
        for c in self.p.containers:
            if c.name == name:
                return c.id
        return None

    def _container_action(
        self, req: Request, method: str, segs: list[str], st: IPState, out: Outcome
    ) -> Resp:
        ref = segs[1]
        action = segs[2] if len(segs) > 2 else ""
        out.route = "containers/{id}" + ("/" + action if action else "")
        c = self._find(st, ref)
        rec = c if isinstance(c, ContainerRec) else None
        if method == "DELETE" and len(segs) == 2:
            out.important = True
            out.flags.add("container_remove")
            if c is None:
                return err(404, f"No such container: {ref[:64]}")
            if rec is not None:
                if rec.state == "running" and req.qget("force") not in ("1", "true"):
                    return err(
                        409,
                        f'cannot remove container "/{rec.name}": container is running: stop '
                        "the container before removing or force remove",
                    )
                st.containers.pop(rec.id, None)
            return Resp(204)
        if method in ("GET", "HEAD") and len(segs) == 3 and action == "json":
            if c is None:
                return err(404, f"No such container: {ref[:64]}")
            return Resp(200, jdump(self._inspect(c)))
        if c is None:
            if method == "POST" and action in ("wait", "resize", "start") and ref in st.removed:
                # `docker run --rm` waits for the container before it starts it.
                if action == "start":
                    out.important = True
                    out.flags.add("container_start")
                    return Resp(204)
                if action == "wait":
                    return Resp(200, jdump({"StatusCode": 0}))
                return Resp(200, b"", "text/plain; charset=utf-8")
            if method == "POST" or action in ("logs", "top", "changes", "stats", "export"):
                if action == "exec":
                    self._exec_event(req, out, None)
                return err(404, f"No such container: {ref[:64]}")
            return err(404, "page not found")
        cid = c.id
        if action == "exec" and method == "POST":
            return self._exec_create(req, st, c, out)
        if action == "start" and method == "POST":
            out.important = True
            out.flags.add("container_start")
            if rec is not None:
                if rec.state == "running":
                    return Resp(304)
                rec.state, rec.started = "running", time.time()
            return Resp(204)
        if (
            action in ("stop", "kill", "restart", "pause", "unpause", "resize", "update")
            and method == "POST"
        ):
            if action in ("stop", "kill"):
                out.flags.add("container_stop")
            if rec is not None and action in ("stop", "kill"):
                rec.state = "exited"
            if action == "update":
                return Resp(200, jdump({"Warnings": []}))
            if action == "resize":
                return Resp(200, b"", "text/plain; charset=utf-8")
            return Resp(204)
        if action == "wait" and method == "POST":
            if rec is not None:
                rec.state = "exited"
                if rec.spec.auto_remove:
                    st.containers.pop(rec.id, None)
                    st.removed[rec.id] = None
                    while len(st.removed) > 8:
                        st.removed.popitem(last=False)
            return Resp(200, jdump({"StatusCode": 0}))
        if action == "rename" and method == "POST":
            return Resp(204)
        if action == "attach" and method == "POST":
            out.flags.add("container_attach")
            text = rec.output if rec is not None else ""
            tty = rec.spec.tty if rec is not None else False
            return Resp(200, ctype=_stream_type(tty), hijack=True, raw=mux_frames(text, tty))
        if action == "logs" and method == "GET":
            text = rec.output if rec is not None else ""
            tty = rec.spec.tty if rec is not None else False
            body = mux_frames(text, tty)
            return Resp(200, body, _stream_type(tty))
        if action == "top" and method == "GET":
            return Resp(
                200,
                jdump(
                    {
                        "Titles": ["UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"],
                        "Processes": [
                            ["root", "1", "0", "0", "08:12", "?", "00:00:00", "sleep infinity"]
                        ],
                    }
                ),
            )
        if action == "archive" and method in ("PUT", "GET", "HEAD"):
            out.important = method == "PUT"
            out.flags.add("archive_put" if method == "PUT" else "archive_get")
            if method == "PUT":
                return Resp(200)
            return err(
                404, f"Could not find the file {req.qget('path')[:128]} in container {cid[:12]}"
            )
        if action == "stats" and method == "GET":
            return Resp(200, jdump({"read": _iso(time.time()), "id": cid}))
        if action == "changes" and method == "GET":
            return Resp(200, b"[]\n")
        return err(404, "page not found")

    # -- exec ------------------------------------------------------------------------------

    def _exec_event(
        self, req: Request, out: Outcome, c: FakeContainer | ContainerRec | None
    ) -> None:
        out.important = True
        obj = analysis.bounded_json(
            req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
        )
        body = obj if isinstance(obj, dict) else {}
        cmd = analysis.as_str_list(body.get("Cmd"))
        env = analysis.as_str_list(body.get("Env"), max_chars=8192)
        text = analysis.join_command(cmd)
        flags = {"exec"}
        if body.get("Privileged") is True:
            flags.add("privileged")
        if analysis.is_miner(text, " ".join(env)):
            flags.add("miner")
        out.flags |= flags
        user = body.get("User")
        out.commands.append(
            {
                "input": text,
                "kind": "exec",
                "container": c.id[:12] if c is not None else req.path.split("/")[-2][:64],
                "user": user[:64] if isinstance(user, str) else "",
                "flags": sorted(flags),
            }
        )
        for url in analysis.find_urls(text + "\n" + "\n".join(env)):
            out.downloads.append(
                {"url": url, "tool": analysis.detect_tool(text), "command": text, "source": "exec"}
            )

    def _exec_create(
        self, req: Request, st: IPState, c: FakeContainer | ContainerRec, out: Outcome
    ) -> Resp:
        self._exec_event(req, out, c)
        obj = analysis.bounded_json(
            req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
        )
        if not isinstance(obj, dict):
            return err(400, "invalid character looking for beginning of value")
        cmd = analysis.as_str_list(obj.get("Cmd"))
        if not cmd:
            return err(400, "No exec command specified")
        if isinstance(c, ContainerRec) and c.state != "running":
            return err(409, f"Container {c.id} is not running")
        eid = secrets.token_hex(32)
        rec = ExecRec(eid, c.id, analysis.cap_list(cmd, 16, 1024), obj.get("Tty") is True)
        self._remember(st.execs, eid, rec, self.cfg.state_execs)
        return Resp(201, jdump({"Id": eid}))

    def _exec(self, req: Request, method: str, segs: list[str], st: IPState, out: Outcome) -> Resp:
        out.route = "exec/{id}" + ("/" + segs[2] if len(segs) > 2 else "")
        rec = st.execs.get(segs[1]) if len(segs[1]) <= 64 else None
        if rec is None:
            return err(404, f"No such exec instance: {segs[1][:64]}")
        if len(segs) == 3 and segs[2] == "start" and method == "POST":
            out.important = True
            obj = analysis.bounded_json(
                req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
            )
            detach = isinstance(obj, dict) and obj.get("Detach") is True
            rec.ran = True
            if detach:
                return Resp(200, b"", "text/plain; charset=utf-8")
            text = analysis.canned_output(rec.cmd)
            return Resp(
                200, ctype=_stream_type(rec.tty), hijack=True, raw=mux_frames(text, rec.tty)
            )
        if len(segs) == 3 and segs[2] == "json" and method in ("GET", "HEAD"):
            return Resp(
                200,
                jdump(
                    {
                        "CanRemove": False,
                        "ContainerID": rec.container,
                        "DetachKeys": "",
                        "ExitCode": 0 if rec.ran else None,
                        "ID": rec.id,
                        "OpenStderr": True,
                        "OpenStdin": False,
                        "OpenStdout": True,
                        "ProcessConfig": {
                            "arguments": rec.cmd[1:],
                            "entrypoint": rec.cmd[0] if rec.cmd else "",
                            "privileged": False,
                            "tty": rec.tty,
                            "user": "",
                        },
                        "Running": not rec.ran,
                        "Pid": 0 if rec.ran else 4242,
                    }
                ),
            )
        if len(segs) == 3 and segs[2] == "resize" and method == "POST":
            return Resp(201)
        return err(404, "page not found")

    # -- images ----------------------------------------------------------------------------

    def _images(
        self, req: Request, method: str, segs: list[str], st: IPState, out: Outcome
    ) -> Resp:
        n = len(segs)
        if n == 2 and segs[1] == "json" and method in ("GET", "HEAD"):
            out.flags.add("recon")
            items = [
                {
                    "Containers": -1,
                    "Created": created,
                    "Id": iid,
                    "Labels": None,
                    "ParentId": "",
                    "RepoDigests": [ref.split(":")[0] + "@sha256:" + self.p.derive("dg-" + ref)],
                    "RepoTags": [ref],
                    "SharedSize": -1,
                    "Size": size,
                    "VirtualSize": size,
                }
                for ref, iid, size, created in (
                    *self.p.images,
                    *((r, i, sz, cr) for r, (i, sz, cr) in st.pulled.items()),
                )
            ]
            return Resp(200, jdump(items))
        if n == 2 and segs[1] == "create" and method == "POST":
            return self._pull(req, st, out)
        if n == 2 and segs[1] == "load" and method == "POST":
            out.important = True
            out.flags.add("image_load")
            return Resp(
                200,
                jdump({"stream": "Loaded image ID: sha256:" + secrets.token_hex(32) + "\n"}),
            )
        if n == 2 and segs[1] == "search" and method == "GET":
            return Resp(200, b"[]\n")
        if n == 2 and segs[1] == "prune" and method == "POST":
            return Resp(200, jdump({"ImagesDeleted": None, "SpaceReclaimed": 0}))
        if n >= 3 and segs[-1] in ("json", "history") and method == "GET":
            name = "/".join(segs[1:-1])[:256]
            for ref, iid, size, created in (
                *self.p.images,
                *((r, i, sz, cr) for r, (i, sz, cr) in st.pulled.items()),
            ):
                if name in (ref, ref.split(":")[0]) or name == iid:
                    if segs[-1] == "history":
                        return Resp(
                            200,
                            jdump(
                                [
                                    {
                                        "Id": iid,
                                        "Created": created,
                                        "CreatedBy": "CMD",
                                        "Tags": [ref],
                                        "Size": size,
                                        "Comment": "",
                                    }
                                ]
                            ),
                        )
                    return Resp(
                        200,
                        jdump(
                            {
                                "Id": iid,
                                "RepoTags": [ref],
                                "RepoDigests": [],
                                "Parent": "",
                                "Comment": "",
                                "Created": _iso(created),
                                "Architecture": "amd64",
                                "Os": "linux",
                                "Size": size,
                                "VirtualSize": size,
                                "Config": {"Env": [], "Cmd": None, "Labels": None},
                            }
                        ),
                    )
            return err(404, f"No such image: {name}")
        if n >= 2 and method == "DELETE":
            out.important = True
            name = "/".join(segs[1:])[:256]
            return Resp(200, jdump([{"Untagged": name}]))
        return err(404, "page not found")

    def _pull(self, req: Request, st: IPState, out: Outcome) -> Resp:
        out.important = True
        out.route = "images/create"
        image = req.qget("fromImage")[:256]
        tag = req.qget("tag")[:128]
        src = req.qget("fromSrc")[:2048]
        if src:
            out.flags.add("image_import")
            for url in analysis.find_urls(src):
                out.downloads.append(
                    {
                        "url": url,
                        "tool": "docker-import",
                        "command": src[:512],
                        "source": "image_import",
                    }
                )
            return Resp(200, jdump({"status": "sha256:" + secrets.token_hex(32)}))
        if not image:
            return err(400, "invalid reference format")
        name, ref_tag = split_ref(image)
        if not tag:
            tag = ref_tag or "latest"
        full = f"{name}:{tag}"
        first = name.split("/", 1)[0]
        registry = (
            first
            if "/" in name
            and (any(m in first for m in _REGISTRY_HOST_MARKERS) or first == "localhost")
            else "docker.io"
        )
        out.extra["pull"] = {"image": name[:256], "tag": tag[:128], "registry": registry[:128]}
        out.flags.add("image_pull")
        out.flags.add("image:" + full[:128])
        if registry != "docker.io":
            out.flags.add("custom_registry")
        if analysis.is_miner(full):
            out.flags.add("miner")
        self._registry_auth(req, out)
        norm = self._norm_ref(full)
        self._remember(st.pulled, norm, self._pulled_image(norm), 16)
        repo = name if "/" in name else "library/" + name
        if registry != "docker.io":
            repo = name.split("/", 1)[1]
        return Resp(200, stream=self._pull_lines(repo, tag, full, full))

    def _pull_lines(self, repo: str, tag: str, full: str, key: str) -> list[bytes]:
        h = hashlib.sha256(key.encode()).hexdigest()
        layers = 1 + int(h[0], 16) % 3
        lines: list[dict[str, Any]] = [{"status": f"Pulling from {repo}", "id": tag}]
        ids = [h[i * 12 : i * 12 + 12] for i in range(layers)]
        lines += [{"status": "Pulling fs layer", "progressDetail": {}, "id": i} for i in ids]
        for k, i in enumerate(ids):
            total = 1_000_000 + int(h[20 + k : 26 + k], 16) % 30_000_000
            bar = "[==================================================>]"
            lines.append(
                {
                    "status": "Downloading",
                    "progressDetail": {"current": total // 2, "total": total},
                    "progress": f"[=========================>                         ]  {total // 2:,}B/{total:,}B".replace(
                        ",", ""
                    ),
                    "id": i,
                }
            )
            lines.append({"status": "Verifying Checksum", "progressDetail": {}, "id": i})
            lines.append({"status": "Download complete", "progressDetail": {}, "id": i})
            lines.append(
                {
                    "status": "Extracting",
                    "progressDetail": {"current": total, "total": total},
                    "progress": f"{bar}  {total}B/{total}B",
                    "id": i,
                }
            )
            lines.append({"status": "Pull complete", "progressDetail": {}, "id": i})
        lines.append({"status": "Digest: sha256:" + h})
        lines.append({"status": f"Status: Downloaded newer image for {full}"})
        return [jdump(x, nl=False) + b"\r\n" for x in lines]

    def _registry_auth(self, req: Request, out: Outcome) -> bool:
        raw = req.header("x-registry-auth")
        if not raw or len(raw) > 4096:
            return False
        try:
            data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except binascii.Error, ValueError:
            return False
        obj = analysis.bounded_json(data, max_bytes=4096, max_depth=6)
        if not isinstance(obj, dict) or not obj:
            return False
        user = obj.get("username")
        pw = obj.get("password")
        if isinstance(user, str) and user:
            out.logins.append(
                {
                    "username": user[:128],
                    "password": pw[:256] if isinstance(pw, str) else "",
                    "success": False,
                    "method": "registry_auth",
                    "server": str(obj.get("serveraddress", ""))[:128],
                }
            )
            out.flags.add("registry_credentials")
            return True
        return False

    def _auth(self, req: Request, out: Outcome) -> Resp:
        out.important = True
        out.route = "auth"
        obj = analysis.bounded_json(
            req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
        )
        body = obj if isinstance(obj, dict) else {}
        user = body.get("username")
        pw = body.get("password")
        server = body.get("serveraddress")
        out.logins.append(
            {
                "username": user[:128] if isinstance(user, str) else "",
                "password": pw[:256] if isinstance(pw, str) else "",
                "success": False,
                "method": "registry_auth",
                "server": server[:128] if isinstance(server, str) else "",
            }
        )
        out.flags.add("registry_credentials")
        return err(
            401,
            'Get "https://registry-1.docker.io/v2/": unauthorized: incorrect username or password',
        )

    def _build(self, req: Request, out: Outcome) -> Resp:
        out.important = True
        out.route = "build"
        out.flags.add("image_build")
        remote = req.qget("remote")[:2048]
        for url in analysis.find_urls(remote):
            out.downloads.append(
                {"url": url, "tool": "docker-build", "command": remote[:512], "source": "build"}
            )
        msg = "failed to read dockerfile: open Dockerfile: no such file or directory"
        return Resp(
            200, stream=[jdump({"errorDetail": {"message": msg}, "error": msg}, nl=False) + b"\r\n"]
        )

    # -- swarm and friends ------------------------------------------------------------------

    def _swarm(self, req: Request, method: str, segs: list[str], out: Outcome) -> Resp:
        if method in ("GET", "HEAD"):
            out.flags.add("recon")
        if (
            segs[0] == "swarm"
            and len(segs) == 2
            and segs[1] in ("init", "join")
            and method == "POST"
        ):
            out.important = True
            out.flags.add("swarm_" + segs[1])
            obj = analysis.bounded_json(
                req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
            )
            if isinstance(obj, dict):
                remote = analysis.as_str_list(obj.get("RemoteAddrs"), max_items=8, max_chars=1024)
                out.extra["swarm"] = {
                    "remote_addrs": remote,
                    "token": str(obj.get("JoinToken", ""))[:128],
                }
            if segs[1] == "init":
                return Resp(200, jdump(secrets.token_hex(12)[:25]))
            return err(
                503,
                'rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp: i/o timeout"',
            )
        return err(503, SWARM_MSG)

    def _networks(self, req: Request, method: str, segs: list[str], out: Outcome) -> Resp:
        if len(segs) == 1 and method in ("GET", "HEAD"):
            out.flags.add("recon")
            nets = []
            for nid, name, driver in (
                (self.p.derive("net-bridge"), "bridge", "bridge"),
                (self.p.derive("net-host"), "host", "host"),
                (self.p.derive("net-none"), "none", "null"),
            ):
                nets.append(
                    {
                        "Name": name,
                        "Id": nid,
                        "Created": _iso(self.p.boot_ts),
                        "Scope": "local",
                        "Driver": driver,
                        "EnableIPv6": False,
                        "IPAM": {
                            "Driver": "default",
                            "Options": None,
                            "Config": [
                                {
                                    "Subnet": self.p.net_prefix + ".0/16",
                                    "Gateway": self.p.net_prefix + ".1",
                                }
                            ]
                            if name == "bridge"
                            else [],
                        },
                        "Internal": False,
                        "Attachable": False,
                        "Ingress": False,
                        "ConfigFrom": {"Network": ""},
                        "ConfigOnly": False,
                        "Containers": {},
                        "Options": {},
                        "Labels": {},
                    }
                )
            return Resp(200, jdump(nets))
        if len(segs) == 2 and segs[1] == "create" and method == "POST":
            out.important = True
            return Resp(201, jdump({"Id": secrets.token_hex(32), "Warning": ""}))
        return err(404, "page not found")

    def _volumes(self, req: Request, method: str, segs: list[str], out: Outcome) -> Resp:
        if len(segs) == 1 and method in ("GET", "HEAD"):
            out.flags.add("recon")
            return Resp(200, jdump({"Volumes": [], "Warnings": None}))
        if len(segs) == 2 and segs[1] == "create" and method == "POST":
            out.important = True
            obj = analysis.bounded_json(
                req.body, max_bytes=self.cfg.body_cap, max_depth=self.cfg.json_max_depth
            )
            name = obj.get("Name") if isinstance(obj, dict) else None
            name = name[:64] if isinstance(name, str) and name else secrets.token_hex(32)
            return Resp(
                201,
                jdump(
                    {
                        "CreatedAt": _iso(time.time())[:19] + "Z",
                        "Driver": "local",
                        "Labels": {},
                        "Mountpoint": f"/var/lib/docker/volumes/{name}/_data",
                        "Name": name,
                        "Options": {},
                        "Scope": "local",
                    }
                ),
            )
        return err(404, "page not found")


def _stream_type(tty: bool) -> str:
    return (
        "application/vnd.docker.raw-stream" if tty else "application/vnd.docker.multiplexed-stream"
    )
