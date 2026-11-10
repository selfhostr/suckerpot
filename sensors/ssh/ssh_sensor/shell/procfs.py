"""Per-session ``/proc/self`` and ``/proc/<pid>``.

``/proc/cpuinfo`` and ``/proc/meminfo`` live in the base image (they agree with ``nproc``,
``lscpu``, ``free`` and ``top`` through the same constants). The nodes here depend on the
session (its shell's pid and user), so they are added to the session's filesystem view with
``FakeFS.seed``: read-only, generated once, not charged to the session's budget.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ssh_sensor.shell import baseimage as bi
from ssh_sensor.shell.fs import Node

if TYPE_CHECKING:
    from ssh_sensor.shell.interp import Shell

CPU_COUNT = 2  # matches nproc, lscpu and the two blocks of /proc/cpuinfo


def _status(name: str, pid: int, ppid: int, uid: int, gid: int, rss_kb: int, state: str) -> str:
    cpus = (1 << CPU_COUNT) - 1
    rows = [
        ("Name", name),
        ("Umask", "0022"),
        ("State", state),
        ("Tgid", str(pid)),
        ("Ngid", "0"),
        ("Pid", str(pid)),
        ("PPid", str(ppid)),
        ("TracerPid", "0"),
        ("Uid", f"{uid}\t{uid}\t{uid}\t{uid}"),
        ("Gid", f"{gid}\t{gid}\t{gid}\t{gid}"),
        ("FDSize", "256"),
        ("Groups", f"{gid} "),
        ("NStgid", str(pid)),
        ("NSpid", str(pid)),
        ("NSpgid", str(pid)),
        ("NSsid", str(pid)),
        ("VmPeak", f"{rss_kb * 2:>8} kB"),
        ("VmSize", f"{rss_kb * 2:>8} kB"),
        ("VmLck", f"{0:>8} kB"),
        ("VmPin", f"{0:>8} kB"),
        ("VmHWM", f"{rss_kb:>8} kB"),
        ("VmRSS", f"{rss_kb:>8} kB"),
        ("RssAnon", f"{rss_kb // 4:>8} kB"),
        ("RssFile", f"{rss_kb - rss_kb // 4:>8} kB"),
        ("RssShmem", f"{0:>8} kB"),
        ("VmSwap", f"{0:>8} kB"),
        ("Threads", "1"),
        ("SigQ", f"0/{bi.MEM_TOTAL_KB // 256}"),
        ("Cpus_allowed", f"{cpus:x}"),
        ("Cpus_allowed_list", f"0-{CPU_COUNT - 1}"),
        ("Mems_allowed_list", "0"),
        ("voluntary_ctxt_switches", "41"),
        ("nonvoluntary_ctxt_switches", "3"),
    ]
    return "".join(f"{key}:\t{value}\n" for key, value in rows)


_UIDS = {"root": 0, "www-data": 33, "mysql": 102}


def _node(kind: str, who: str, mt: int, content: str = "", target: str = "") -> Node:
    mode = {"d": 0o555, "l": 0o777}.get(kind, 0o444)
    return Node(
        kind, mode=mode, owner=who, group=who, mtime=mt, content=content.encode(), target=target
    )


def cwd_links(sh: Shell) -> dict[str, Node]:
    """The ``cwd`` link of the session's bash, which follows ``cd``."""
    return {
        f"/proc/{sh.pid + 1}/cwd": _node("l", sh.user.name, sh.profile.boot_epoch, target=sh.cwd)
    }


def proc_nodes(sh: Shell) -> dict[str, Node]:
    """``/proc/self`` (the session's bash) and one directory per process ``ps`` lists."""
    from ssh_sensor.shell.cmd_sys import _PROCS

    pid = sh.pid + 1
    mt = sh.profile.boot_epoch
    uid, gid = sh.user.uid, sh.user.gid
    owner = sh.user.name
    nodes: dict[str, Node] = {"/proc/self": _node("l", owner, mt, target=str(pid))}

    def add(
        p: int, ppid: int, who: str, u: int, g: int, cmd: str, rss: int, comm: str | None = None
    ) -> None:
        base = f"/proc/{p}"
        name = comm or cmd.split()[0].rsplit("/", 1)[-1]
        argv = "" if cmd.startswith("[") else cmd.replace(" ", "\x00") + "\x00"
        nodes[base] = _node("d", who, mt)
        nodes[f"{base}/status"] = _node(
            "f", who, mt, _status(name[:15], p, ppid, u, g, rss, "S (sleeping)")
        )
        nodes[f"{base}/cmdline"] = _node("f", who, mt, argv)
        nodes[f"{base}/comm"] = _node("f", who, mt, name[:15] + "\n")

    for user, p, _c, _m, _v, rss, _tty, _stat, _start, _cpu, cmd in _PROCS:
        who_uid = _UIDS.get(user, 0)
        comm = "systemd" if p == 1 else None
        add(p, 0 if p <= 2 else 1, user, who_uid, who_uid, cmd, rss, comm)
    add(sh.pid, 702, owner, uid, gid, f"sshd: {owner}@pts/0", 9216, "sshd")
    add(pid, sh.pid, owner, uid, gid, "-bash", 5120, "bash")
    nodes[f"/proc/{pid}/exe"] = _node("l", owner, mt, target="/usr/bin/bash")
    nodes["/proc/1/exe"] = _node("l", "root", mt, target="/usr/lib/systemd/systemd")
    nodes["/proc/1/cwd"] = _node("l", "root", mt, target="/")
    nodes.update(cwd_links(sh))
    return nodes
