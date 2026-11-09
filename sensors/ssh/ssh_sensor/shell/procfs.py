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


def proc_nodes(sh: Shell) -> dict[str, Node]:
    """``/proc/self`` (the session's bash), ``/proc/<its pid>`` and ``/proc/1``."""
    pid = sh.pid + 1
    mt = sh.profile.boot_epoch
    uid, gid = sh.user.uid, sh.user.gid
    owner = sh.user.name

    def d(path: str, who: str) -> Node:
        return Node("d", mode=0o555, owner=who, group=who, mtime=mt)

    def f(text: str, who: str, mode: int = 0o444) -> Node:
        return Node("f", mode=mode, owner=who, group=who, mtime=mt, content=text.encode())

    def link(target: str, who: str) -> Node:
        return Node("l", mode=0o777, owner=who, group=who, mtime=mt, target=target)

    shell = f"/proc/{pid}"
    init = "/proc/1"
    return {
        "/proc/self": link(str(pid), owner),
        shell: d(shell, owner),
        f"{shell}/status": f(_status("bash", pid, sh.pid, uid, gid, 5120, "S (sleeping)"), owner),
        f"{shell}/cmdline": f("-bash\x00", owner),
        f"{shell}/comm": f("bash\n", owner),
        f"{shell}/exe": link("/usr/bin/bash", owner),
        f"{shell}/cwd": link(sh.cwd, owner),
        init: d(init, "root"),
        f"{init}/status": f(_status("systemd", 1, 0, 0, 0, 13408, "S (sleeping)"), "root"),
        f"{init}/cmdline": f("/sbin/init\x00", "root"),
        f"{init}/comm": f("systemd\n", "root"),
        f"{init}/exe": link("/usr/lib/systemd/systemd", "root"),
        f"{init}/cwd": link("/", "root"),
    }
