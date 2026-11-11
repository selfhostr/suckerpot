"""Android-flavoured commands of the fake box.

Generic commands (cat, echo, grep, cp, ...) are the SSH sensor's emulations. The ones whose
output depends on the platform (getprop, pm, am, ps, uname, ls ...) are written here in the
format of an Android 7 to 9 TV box. Nothing executes and nothing is fetched: download tools only
append a ``download_attempt`` to ``shell.pending`` and drop a small stub file.
"""

from __future__ import annotations

import hashlib
import posixpath
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from ssh_sensor.shell import cmd_fs, cmd_text
from ssh_sensor.shell.commands import COMMANDS as SSH_COMMANDS
from ssh_sensor.shell.core import CmdIO, PendingEvent, ShellExit, parse_flags, parse_uint
from ssh_sensor.shell.fs import FSError, Node
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.util import mode_string
from suckerpot_common import EventType

from adb_sensor.device import BUSYBOX_APPLETS, Device, elf_stub

Command = Callable[[Shell, CmdIO], int]

MAX_URLS = 4
SCRIPT_STUB = b"#!/system/bin/sh\nexit 0\n"
FAKE_PACKAGES = (
    "com.android.settings",
    "com.android.providers.settings",
    "com.android.systemui",
    "com.android.launcher3",
    "com.android.vending",
    "com.android.packageinstaller",
    "com.android.inputmethod.latin",
    "com.android.webview",
    "com.android.chrome",
    "com.google.android.gms",
    "com.google.android.gsf",
    "com.google.android.youtube.tv",
    "com.google.android.tvlauncher",
    "com.netflix.ninja",
    "com.android.tv.settings",
    "org.chromium.webview_shell",
    "com.droidlogic.appinstall",
    "com.android.shell",
    "android",
)


def device_of(sh: Shell) -> Device:
    dev = getattr(sh, "device", None)
    if not isinstance(dev, Device):  # pragma: no cover - AndroidShell always sets it
        raise RuntimeError("shell without a device")
    return dev


def node_size(node: Node) -> int:
    """Size shown for a node: pushed files keep their real size in the tag, not their bytes."""
    if node.kind == "d":
        return 4096
    if node.tag.startswith("size:"):
        value = parse_uint(node.tag[5:], 12)
        if value is not None:
            return value
    return len(node.content)


def _wait(sh: Shell, seconds: float) -> None:
    if sh.cfg.command_delay:
        sh.delay += seconds


def _date_iso(ts: int) -> str:
    t = time.gmtime(ts)
    return f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}"


# ---- identity and system information ------------------------------------------------------
def cmd_getprop(sh: Shell, io: CmdIO) -> int:
    props = device_of(sh).getprop()
    if io.args:
        key = io.args[0][:128]
        io.write(props.get(key, io.args[1][:256] if len(io.args) > 1 else "") + "\n")
        return 0
    for key, value in sorted(props.items()):
        io.write(f"[{key}]: [{value}]\n")
    return 0


def cmd_setprop(sh: Shell, io: CmdIO) -> int:
    if len(io.args) != 2:
        io.error("usage: setprop NAME VALUE\n")
        return 1
    return 0


def cmd_uname(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    flags, _, _ = parse_flags(io.args)
    parts = {
        "s": "Linux",
        "n": "localhost",
        "r": dev.model.kernel,
        "v": dev.kernel_build,
        "m": "armv7l",
        "o": "Android",
    }
    if "a" in flags:
        io.write(" ".join(parts[k] for k in "snrvm") + "\n")
        return 0
    chosen = [k for k in "snrvmo" if k in flags]
    io.write(" ".join(parts[k] for k in chosen or ["s"]) + "\n")
    return 0


def _uptime_seconds(sh: Shell) -> int:
    return max(0, int(sh.now()) - sh.profile.boot_epoch)


def cmd_uptime(sh: Shell, io: CmdIO) -> int:
    up = _uptime_seconds(sh)
    t = time.gmtime(sh.now())
    days, rem = divmod(up, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    span = f"{days} day{'s' if days != 1 else ''}, " if days else ""
    span += f"{hours:2d}:{minutes:02d}"
    io.write(
        f" {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d} up {span},  0 users,  load average: 0.25, 0.30, 0.28\n"
    )
    return 0


def cmd_id(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    u = sh.user
    if "u" in flags:
        io.write((u.name if "n" in flags else str(u.uid)) + "\n")
    elif "g" in flags:
        io.write((u.name if "n" in flags else str(u.gid)) + "\n")
    else:
        extra = "1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc)"
        ctx = "u:r:su:s0" if u.uid == 0 else "u:r:shell:s0"
        groups = f"{u.gid}({u.name}),{extra}"
        io.write(f"uid={u.uid}({u.name}) gid={u.gid}({u.name}) groups={groups} context={ctx}\n")
    return 0


def cmd_whoami(sh: Shell, io: CmdIO) -> int:
    io.write(sh.user.name + "\n")
    return 0


_PROCS = (
    (1, 0, "root", 14216, 2132, "SyS_epoll_", "S", "/init"),
    (2, 0, "root", 0, 0, "kthreadd", "S", "kthreadd"),
    (178, 1, "root", 9564, 1380, "SyS_epoll_", "S", "/sbin/ueventd"),
    (251, 1, "system", 10532, 1936, "binder_thr", "S", "/system/bin/servicemanager"),
    (252, 1, "root", 7216, 1744, "poll_sched", "S", "/system/bin/logd"),
    (266, 1, "root", 12188, 2824, "SyS_epoll_", "S", "/system/bin/vold"),
    (301, 1, "root", 2216344, 125800, "poll_sched", "S", "zygote"),
    (302, 1, "system", 41232, 6320, "binder_thr", "S", "/system/bin/surfaceflinger"),
    (330, 1, "root", 9308, 1688, "SyS_epoll_", "S", "/system/bin/netd"),
    (338, 1, "root", 9148, 1544, "do_sigtime", "S", "/system/bin/adbd"),
    (352, 1, "root", 9940, 2100, "SyS_epoll_", "S", "/system/bin/healthd"),
    (902, 301, "system", 2379140, 171220, "poll_sched", "S", "system_server"),
    (1214, 1, "dhcp", 9096, 1500, "SyS_epoll_", "S", "/system/bin/dhcpcd"),
    (1488, 301, "u0_a12", 1865312, 103952, "poll_sched", "S", "com.android.systemui"),
    (1721, 301, "u0_a8", 1812736, 93188, "poll_sched", "S", "com.android.launcher3"),
)


def cmd_ps(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    me = (sh.pid, 338, sh.user.name, 2704, 1324, "0", "S", "/system/bin/sh")
    ps_row = (sh.pid + 6, sh.pid, sh.user.name, 2492, 1104, "0", "R", "ps")
    rows = (*_PROCS, me, ps_row)
    legacy = dev.model.sdk <= 25
    if legacy:
        io.write("USER     PID   PPID  VSIZE  RSS     WCHAN            PC  NAME\n")
        for pid, ppid, user, vsz, rss, wchan, stat, name in rows:
            io.write(
                f"{user:<8} {pid:<5} {ppid:<5} {vsz:<6} {rss:<7} {wchan[:10]:<10} 00000000 {stat} {name}\n"
            )
    else:
        io.write("USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n")
        for pid, ppid, user, vsz, rss, wchan, stat, name in rows:
            io.write(
                f"{user:<8} {pid:>8} {ppid:>5} {vsz:>7} {rss:>6} {wchan[:16]:<16} {0:>4} {stat} {name}\n"
            )
    return 0


def cmd_free(sh: Shell, io: CmdIO) -> int:
    io.write(
        "                total        used        free      shared     buffers\n"
        "Mem:       1911221248  1692028928   219192320    18898944    14548992\n"
        "-/+ buffers/cache:     1677480000   233741248\n"
        "Swap:               0           0           0\n"
    )
    return 0


def cmd_df(sh: Shell, io: CmdIO) -> int:
    io.write(
        "Filesystem            1K-blocks      Used Available Use% Mounted on\n"
        "tmpfs                    932816       204    932612   1% /dev\n"
        "tmpfs                    932816         0    932816   0% /mnt\n"
        "/dev/block/system       1032088    836920    195168  81% /system\n"
        "/dev/block/cache         253920      4456    249464   2% /cache\n"
        "/dev/block/data         5681296   1204680   4476616  22% /data\n"
        "/data/media             5681296   1204680   4476616  22% /storage/emulated\n"
    )
    return 0


def cmd_mount(sh: Shell, io: CmdIO) -> int:
    if io.args:
        return 0
    for line in sh.fs.read("/proc/mounts").decode().splitlines():
        parts = line.split()
        io.write(f"{parts[0]} {parts[1]} {parts[2]} {parts[3]} 0 0\n")
    return 0


def cmd_ifconfig(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    up = _uptime_seconds(sh)
    rx, tx = up * 311 + 4_048_576, up * 97 + 824_288
    ip = dev.profile.ip
    if dev.model.sdk <= 25:
        io.write(
            f"eth0: ip {ip} mask 255.255.255.0 flags [up broadcast running multicast]\n"
            "lo: ip 127.0.0.1 mask 255.0.0.0 flags [up loopback running]\n"
        )
        return 0
    io.write(
        f"eth0      Link encap:Ethernet  HWaddr {dev.mac}  Driver rk_gmac-dwmac\n"
        f"          inet addr:{ip}  Bcast:{'.'.join([*ip.split('.')[:3], '255'])}  Mask:255.255.255.0 \n"
        "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
        f"          RX packets:{rx // 700} errors:0 dropped:0 overruns:0 frame:0 \n"
        f"          TX packets:{tx // 600} errors:0 dropped:0 overruns:0 carrier:0 \n"
        "          collisions:0 txqueuelen:1000 \n"
        f"          RX bytes:{rx} TX bytes:{tx} \n\n"
        "lo        Link encap:Local Loopback  \n"
        "          inet addr:127.0.0.1  Mask:255.0.0.0 \n"
        "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
        "          RX packets:812 errors:0 dropped:0 overruns:0 frame:0 \n"
        "          TX packets:812 errors:0 dropped:0 overruns:0 carrier:0 \n"
        "          collisions:0 txqueuelen:0 \n"
        "          RX bytes:61520 TX bytes:61520 \n\n"
    )
    return 0


def cmd_netstat(sh: Shell, io: CmdIO) -> int:
    ip = device_of(sh).profile.ip
    remote = f"{sh.client_ip[:39]}:{sh.client_port}"
    io.write(
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:5037          0.0.0.0:*               LISTEN\n"
        f"tcp        0      0 {ip + ':5555':<23} {remote:<23} ESTABLISHED\n"
    )
    return 0


def cmd_ip(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    ip = dev.profile.ip
    sub = io.args[0] if io.args else ""
    if sub.startswith("r"):
        net = ".".join(ip.split(".")[:3])
        io.write(
            f"default via {dev.profile.gateway} dev eth0 \n{net}.0/24 dev eth0  proto kernel  scope link  src {ip} \n"
        )
    else:
        io.write(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\n"
            f"    link/ether {dev.mac} brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {ip}/24 brd {'.'.join([*ip.split('.')[:3], '255'])} scope global eth0\n"
        )
    return 0


def cmd_dmesg(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    io.write(
        f"[    0.000000] Booting Linux on physical CPU 0x0\n"
        f"[    0.000000] Linux version {dev.model.kernel} (root@android-build) {dev.kernel_build}\n"
        "[    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7), cr=10c5387d\n"
    )
    return 0


def cmd_which(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    status = 0
    for name in parse_flags(io.args)[2][:16]:
        if name in sh.base.binaries:
            io.write(f"/system/bin/{name}\n")
        elif dev.busybox and (name == "busybox" or name in BUSYBOX_APPLETS):
            io.write(f"/system/xbin/{name}\n")
        elif name == "su":
            io.write("/system/xbin/su\n")
        else:
            status = 1
    return status


def cmd_nothing(sh: Shell, io: CmdIO) -> int:
    return 0


# ---- ls ---------------------------------------------------------------------------------------
def cmd_ls(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    flags, _, operands = parse_flags(io.args)
    long = "l" in flags
    show_all = "a" in flags or "A" in flags
    targets = operands[:32] or ["."]
    status = 0
    legacy = dev.model.sdk <= 25
    for index, target in enumerate(targets):
        try:
            path = sh.abspath(target)
        except FSError:
            io.error(f"ls: {target[:100]}: File name too long\n")
            status = 1
            continue
        node = sh.fs.stat(path)
        if node is None:
            io.error(f"ls: {target[:100]}: No such file or directory\n")
            status = 1
            continue
        if node.kind == "d" and "d" not in flags:
            names = sorted(sh.fs.listdir(path))
            if not show_all:
                names = [n for n in names if not n.startswith(".")]
            if len(targets) > 1:
                io.write(("\n" if index else "") + f"{target}:\n")
            rows = [(n, sh.fs.stat(posixpath.join(path, n))) for n in names[:2000]]
            if long and not legacy:
                io.write(f"total {max(0, len(rows)) * 4}\n")
            for name, child in rows:
                if child is None:
                    continue
                _ls_row(io, name, child, long, legacy, sh)
        else:
            _ls_row(io, target, node, long, legacy, sh)
    return status


def _ls_row(io: CmdIO, name: str, node: Node, long: bool, legacy: bool, sh: Shell) -> None:
    if not long:
        io.write(name + "\n")
        return
    when = _date_iso(node.mtime)
    shown = name + (f" -> {node.target}" if node.kind == "l" else "")
    if legacy:
        size = "" if node.kind == "d" else str(node_size(node))
        io.write(f"{mode_string(node)} {node.owner:<8} {node.group:<8} {size:>8} {when} {shown}\n")
    else:
        nlink = 2 if node.kind == "d" else 1
        io.write(
            f"{mode_string(node)} {nlink} {node.owner:<8} {node.group:<8} {node_size(node):>7} {when} {shown}\n"
        )


def cmd_stat(sh: Shell, io: CmdIO) -> int:
    return cmd_fs.cmd_stat(sh, io)


# ---- pm, am, dumpsys, settings ... -----------------------------------------------------------
def _install_args(sh: Shell, io: CmdIO, tool: str) -> None:
    """Mark the command line as an install / activity launch (read back by the session)."""
    flags = getattr(sh, "flags", None)
    if isinstance(flags, set):
        flags.add("adb_install")


def cmd_pm(sh: Shell, io: CmdIO) -> int:
    args = io.args
    sub = args[0] if args else ""
    if sub == "list" and len(args) > 1:
        what = args[1]
        if what == "packages":
            flags = {a for a in args[2:] if a.startswith("-")}
            for pkg in FAKE_PACKAGES:
                if "-3" in flags and pkg.startswith(("com.android", "com.google", "android")):
                    continue
                if "-f" in flags:
                    io.write(f"package:/system/app/{pkg.rsplit('.', 1)[-1]}/{pkg}.apk={pkg}\n")
                else:
                    io.write(f"package:{pkg}\n")
            return 0
        if what == "features":
            io.write(
                "feature:reqGlEsVersion=0x30000\nfeature:android.hardware.wifi\nfeature:android.software.leanback\n"
            )
            return 0
        return 0
    if sub == "path" and len(args) > 1:
        pkg = args[1][:128]
        if pkg in FAKE_PACKAGES:
            io.write(f"package:/system/app/{pkg.rsplit('.', 1)[-1]}/{pkg}.apk\n")
            return 0
        return 1
    if sub in ("install", "install-create", "install-write", "install-commit"):
        _install_args(sh, io, "pm")
        _wait(sh, 1.0)
        if sub == "install-create":
            io.write("Success: created install session [1394857201]\n")
        else:
            io.write("Success\n" if sub != "install-write" else "Success: streamed 0 bytes\n")
        return 0
    if sub in ("uninstall", "clear", "enable", "disable", "disable-user", "grant", "revoke"):
        pkg = next((a for a in args[1:] if not a.startswith("-")), "")
        if sub == "uninstall":
            io.write(
                "Success\n"
                if pkg and pkg not in FAKE_PACKAGES
                else "Failure [DELETE_FAILED_INTERNAL_ERROR]\n"
            )
        elif sub == "clear":
            io.write("Success\n")
        elif sub in ("disable", "disable-user", "enable"):
            io.write(
                f"Package {pkg[:128]} new state: {'enabled' if sub == 'enable' else 'disabled-user'}\n"
            )
        return 0
    if not args:
        io.error("usage: pm [list|path|install|uninstall|clear|enable|disable|grant|revoke] ...\n")
        return 1
    io.error(f"Error: unknown command '{sub[:64]}'\n")
    return 1


def cmd_cmd(sh: Shell, io: CmdIO) -> int:
    """``cmd package ...`` and ``cmd activity ...`` are what newer adb clients send."""
    sub = io.args[0] if io.args else ""
    inner = CmdIO(args=io.args[1:], stdin=io.stdin, cmdline=io.cmdline)
    if sub == "package":
        status = cmd_pm(sh, inner)
    elif sub == "activity":
        status = cmd_am(sh, inner)
    else:
        io.error(f"Can't find service: {sub[:64]}\n")
        return 20
    io.absorb(inner)
    return status


def cmd_am(sh: Shell, io: CmdIO) -> int:
    args = io.args
    sub = args[0] if args else ""
    if sub in ("start", "startservice", "start-service", "start-activity"):
        _install_args(sh, io, "am")
        intent = " ".join(a[:256] for a in args[1:12])
        act = _opt(args, "-a")
        dat = _opt(args, "-d")
        comp = _opt(args, "-n")
        parts = []
        if act:
            parts.append(f"act={act[:128]}")
        if dat:
            parts.append(f"dat={dat[:256]}")
        if comp:
            parts.append(f"cmp={comp[:128]}")
        if not parts:
            parts.append(intent[:200])
        io.write(f"Starting: Intent {{ {' '.join(parts)} }}\n")
        _wait(sh, 0.5)
        return 0
    if sub == "broadcast":
        _install_args(sh, io, "am")
        act = _opt(args, "-a")
        io.write(
            f"Broadcasting: Intent {{ act={act[:128]} flg=0x400000 }}\nBroadcast completed: result=0\n"
        )
        return 0
    if sub in ("force-stop", "kill", "kill-all", "set-debug-app", "clear-debug-app"):
        return 0
    if sub == "instrument":
        io.write("INSTRUMENTATION_STATUS: Error=Unable to find instrumentation info\n")
        return 1
    if not args:
        io.error("usage: am [subcommand] [options]\n")
        return 1
    io.error(f"Error: Unknown command: {sub[:64]}\n")
    return 1


def _opt(args: list[str], flag: str) -> str:
    for i, a in enumerate(args[:-1]):
        if a == flag:
            return args[i + 1]
    return ""


def cmd_dumpsys(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    name = io.args[0] if io.args else ""
    if not name:
        io.write(
            "Currently running services:\n  activity\n  battery\n  connectivity\n  display\n"
            "  package\n  power\n  window\n"
        )
        return 0
    if name == "battery":
        io.write(
            "Current Battery Service state:\n  AC powered: true\n  USB powered: false\n"
            "  Wireless powered: false\n  status: 2\n  health: 2\n  present: true\n  level: 100\n"
            "  scale: 100\n  voltage: 5000\n  temperature: 250\n  technology: Li-ion\n"
        )
    elif name in ("window", "display"):
        io.write(
            f"  mCurrentFocus=Window{{2e1a4b9 u0 com.android.launcher3/com.android.launcher3.Launcher}}\n  init=1920x1080 {dev.model.density}dpi\n"
        )
    elif name == "power":
        io.write("POWER MANAGER (dumpsys power)\n\nMwakefulness=Awake\n  mScreenOn=true\n")
    elif name in ("activity", "package", "connectivity"):
        io.write(f"{name.upper()} MANAGER (dumpsys {name})\n")
    else:
        io.write(f"Can't find service: {name[:64]}\n")
    return 0


def cmd_settings(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    args = io.args
    if len(args) >= 3 and args[0] == "get":
        key = args[2]
        io.write(
            (dev.android_id if key == "android_id" else "1" if key == "adb_enabled" else "null")
            + "\n"
        )
        return 0
    return 0


def cmd_wm(sh: Shell, io: CmdIO) -> int:
    dev = device_of(sh)
    sub = io.args[0] if io.args else ""
    if sub == "size":
        io.write("Physical size: 1920x1080\n")
    elif sub == "density":
        io.write(f"Physical density: {dev.model.density}\n")
    return 0


def cmd_logcat(sh: Shell, io: CmdIO) -> int:
    t = time.gmtime(sh.now())
    stamp = f"{t.tm_mon:02d}-{t.tm_mday:02d} {t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}.000"
    io.write(
        f"--------- beginning of main\n{stamp}   902   915 I ActivityManager: Start proc 2310:com.android.vending/u0a21\n"
        f"{stamp}   902   915 I art     : Background sticky concurrent mark sweep GC freed 8242(1MB)\n"
    )
    return 0


def cmd_su(sh: Shell, io: CmdIO) -> int:
    args = io.args
    command = ""
    if "-c" in args and args.index("-c") + 1 < len(args):
        command = args[args.index("-c") + 1]
    elif len(args) >= 2 and args[0].isdigit():
        command = " ".join(args[1:])
    if not command:
        return 0
    text, status = sh.run_nested(command, io.stdin, limit=io.room)
    io.write(text)
    return status


def cmd_reboot(sh: Shell, io: CmdIO) -> int:
    setattr(sh, "rebooted", True)  # noqa: B010 - flag read by the session, see AndroidShell
    raise ShellExit(0)


def cmd_ping(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "csWwIiqt")
    hosts = [a for a in operands if not a.startswith("-")]
    if not hosts:
        io.error(
            "usage: ping [-LRUbdfnqrvVaAB] [-c count] [-i interval] [-w deadline] destination\n"
        )
        return 1
    host = hosts[0][:255]
    count = min(parse_uint(values.get("c", "4")) or 4, 10)
    ip = sh.profile.resolve(host)
    digest = hashlib.sha256(f"{sh.profile.seed}|rtt|{host}".encode()).digest()
    base_ms = 8 + digest[0] % 40
    io.write(f"PING {host} ({ip}) 56(84) bytes of data.\n")
    for seq in range(count):
        ms = base_ms + (digest[1 + seq % 8] % 90) / 10
        io.write(
            f"64 bytes from {ip}: icmp_seq={seq + 1} ttl={52 + digest[9] % 8} time={ms:.1f} ms\n"
        )
    io.write(
        f"\n--- {host} ping statistics ---\n"
        f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000 + 3}ms\n"
        f"rtt min/avg/max/mdev = {base_ms:.3f}/{base_ms + 2:.3f}/{base_ms + 5:.3f}/1.204 ms\n"
    )
    _wait(sh, min(float(count), 3.0))
    return 0


def cmd_nc(sh: Shell, io: CmdIO) -> int:
    words = [a for a in io.args if not a.startswith("-")]
    if len(words) >= 2:
        _wait(sh, 3.0)
        io.error("nc: connect: Connection timed out\n")
        return 1
    io.error("usage: nc [-46DdFhklnrStUuvZz] [-I length] [-i interval] [-O length]\n")
    return 1


# ---- downloads: recorded, never fetched -----------------------------------------------------
def _record(sh: Shell, url: str, tool: str, io: CmdIO) -> None:
    sh.pending.append(
        PendingEvent(
            EventType.download_attempt,
            {"url": url[:2048], "tool": tool, "command": io.cmdline[:2048]},
        )
    )


def _drop(sh: Shell, path: str, url_path: str) -> int:
    script = url_path.endswith((".sh", ".py", ".pl"))
    data = SCRIPT_STUB if script else elf_stub(400)
    if not sh.fs.may_write(path, sh.user.name, sh.user.home):
        raise FSError("Permission denied")
    sh.fs.write(path, data, append=False, owner=sh.user.name, tag="script" if script else "elf")
    return len(data)


def _safe_name(raw: str, default: str = "index.html") -> str:
    name = "".join(c for c in raw if c.isalnum() or c in "._-+@")[:100]
    return name or default


def cmd_wget(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "OPUYTt")
    urls = [o[:2048] for o in operands][:MAX_URLS]
    if not urls:
        io.error(
            "BusyBox v1.30.1 multi-call binary.\n\n"
            "Usage: wget [-c|--continue] [-s|--spider] [-q|--quiet] [-O|--output-document FILE]\n"
            "\t[-Y|--proxy on/off] [-P DIR] [-U|--user-agent AGENT] URL\n\n"
            "Retrieve files via HTTP or FTP\n\n"
        )
        return 1
    quiet = "q" in flags
    status = 0
    for raw in urls:
        url = raw if "://" in raw else "http://" + raw
        _record(sh, url, "wget", io)
        parts = urlsplit(url)
        if parts.scheme not in ("http", "ftp"):
            io.error(f"wget: not an http or ftp url: {url[:200]}\n")
            status = 1
            continue
        try:
            port = parts.port or (21 if parts.scheme == "ftp" else 80)
        except ValueError:
            io.error(f"wget: bad port spec '{url[:200]}'\n")
            status = 1
            continue
        host = (parts.hostname or "localhost")[:255]
        ip = sh.profile.resolve(host)
        name = _safe_name(posixpath.basename(parts.path))
        out_name = values.get("O")
        try:
            if out_name == "-":
                size, shown = len(SCRIPT_STUB), "-"
            else:
                directory = sh.abspath(values["P"]) if "P" in values else sh.cwd
                dest = sh.abspath(out_name) if out_name else posixpath.join(directory, name)
                size = _drop(sh, dest, parts.path)
                shown = posixpath.basename(dest)
        except FSError as exc:
            io.error(f"wget: can't open '{(out_name or name)[:100]}': {exc}\n")
            status = 1
            continue
        if not quiet:
            io.error(f"Connecting to {host} ({ip}:{port})\n")
            if shown != "-":
                bar = "*" * 31
                io.error(f"{shown[:20]:<20} 100% |{bar}| {size:>5}  0:00:00 ETA\n")
        _wait(sh, 1.0)
    return status


def cmd_tftp(sh: Shell, io: CmdIO) -> int:
    flags, values, operands = parse_flags(io.args, "lrbc")
    host = operands[0] if operands else ""
    port = operands[1] if len(operands) > 1 else "69"
    if not host or not (flags & {"g", "p"}):
        io.error("BusyBox v1.30.1 multi-call binary.\n\nUsage: tftp [OPTIONS] HOST [PORT]\n\n")
        return 1
    remote = values.get("r", "")
    local = values.get("l") or posixpath.basename(remote)
    if not remote and not local:
        io.error("tftp: no file specified\n")
        return 1
    remote = remote or local
    _record(sh, f"tftp://{host[:255]}:{port[:5]}/{remote.lstrip('/')[:1024]}", "tftp", io)
    if "g" in flags:
        try:
            _drop(sh, sh.abspath(local), remote)
        except FSError as exc:
            io.error(f"tftp: can't open '{local[:100]}': {exc}\n")
            return 1
    _wait(sh, 1.0)
    return 0


def cmd_ftpget(sh: Shell, io: CmdIO) -> int:
    _, values, operands = parse_flags(io.args, "upPs")
    if len(operands) < 2:
        io.error(
            "BusyBox v1.30.1 multi-call binary.\n\nUsage: ftpget [OPTIONS] HOST [LOCAL_FILE] REMOTE_FILE\n\n"
        )
        return 1
    host, remote = operands[0], operands[-1]
    local = operands[1] if len(operands) > 2 else posixpath.basename(remote)
    _record(
        sh,
        f"ftp://{host[:255]}:{values.get('P', '21')[:5]}/{remote.lstrip('/')[:1024]}",
        "ftpget",
        io,
    )
    try:
        _drop(sh, sh.abspath(local), remote)
    except FSError as exc:
        io.error(f"ftpget: can't open '{local[:100]}': {exc}\n")
        return 1
    _wait(sh, 1.0)
    return 0


DOWNLOAD_TOOLS = frozenset({"wget", "curl", "tftp", "ftpget", "busybox", "toybox", "fetch"})


def record_missing_download(sh: Shell, name: str, io: CmdIO) -> None:
    """A download tool that is not on the box: the attempted URL is still worth keeping."""
    if name not in DOWNLOAD_TOOLS:
        return
    args = io.args[:24]
    if name in ("busybox", "toybox") and args:
        name, args = args[0][:32], args[1:]
    if name == "tftp":
        _, values, operands = parse_flags(args, "lrbc")
        if operands and (values.get("r") or values.get("l")):
            remote = values.get("r") or values.get("l", "")
            _record(sh, f"tftp://{operands[0][:255]}:69/{remote.lstrip('/')[:1024]}", "tftp", io)
        return
    for arg in args:
        if "://" in arg:
            _record(sh, arg, name, io)
        elif not arg.startswith("-") and "." in arg and "/" in arg:
            _record(sh, "http://" + arg, name, io)


def cmd_busybox(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        io.write(
            "BusyBox v1.30.1-android multi-call binary.\n"
            "BusyBox is copyrighted by many authors between 1998-2015.\n"
            "Licensed under GPLv2. See source distribution for detailed\ncopyright notices.\n\n"
            "Usage: busybox [function [arguments]...]\n"
            "   or: busybox --list[-full]\n"
            "   or: function [arguments]...\n"
        )
        return 0
    applet = io.args[0]
    if applet == "--list":
        io.write("\n".join(BUSYBOX_APPLETS) + "\n")
        return 0
    if applet in COMMANDS or applet in BUSYBOX_APPLETS:
        return sh.run_argv(io.args, io)
    io.error(f"{applet[:128]}: applet not found\n")
    return 127


def cmd_getenforce(sh: Shell, io: CmdIO) -> int:
    io.write("Permissive\n")
    return 0


def cmd_groups(sh: Shell, io: CmdIO) -> int:
    io.write("root input log adb sdcard_rw sdcard_r inet\n")
    return 0


def _with(io: CmdIO, flag: str) -> CmdIO:
    io.args.insert(0, flag)
    return io


_KEEP = (
    "cd pwd cat mkdir touch rm rmdir chmod chown chgrp mv cp echo printf grep egrep fgrep head "
    "tail wc cut sort uniq tr awk sed tee xargs base64 md5sum sha1sum sha256sum test [ true : "
    "false hostname export env printenv unset exit logout clear date sleep nohup setsid nice time "
    "timeout exec kill killall pkill sync alias umask sh ash"
).split()

COMMANDS: dict[str, Command] = {name: SSH_COMMANDS[name] for name in _KEEP if name in SSH_COMMANDS}
COMMANDS.update(
    {
        "[[": cmd_text.cmd_test,
        "ls": cmd_ls,
        "stat": cmd_stat,
        "id": cmd_id,
        "whoami": cmd_whoami,
        "uname": cmd_uname,
        "uptime": cmd_uptime,
        "ps": cmd_ps,
        "free": cmd_free,
        "df": cmd_df,
        "mount": cmd_mount,
        "ifconfig": cmd_ifconfig,
        "netstat": cmd_netstat,
        "ip": cmd_ip,
        "dmesg": cmd_dmesg,
        "which": cmd_which,
        "getprop": cmd_getprop,
        "setprop": cmd_setprop,
        "pm": cmd_pm,
        "am": cmd_am,
        "cmd": cmd_cmd,
        "dumpsys": cmd_dumpsys,
        "settings": cmd_settings,
        "wm": cmd_wm,
        "logcat": cmd_logcat,
        "su": cmd_su,
        "reboot": cmd_reboot,
        "ping": cmd_ping,
        "nc": cmd_nc,
        "netcat": cmd_nc,
        "input": cmd_nothing,
        "svc": cmd_nothing,
        "screencap": cmd_nothing,
        "monkey": cmd_nothing,
        "start": cmd_nothing,
        "stop": cmd_nothing,
        "setenforce": cmd_nothing,
        "usleep": cmd_nothing,
        "getenforce": cmd_getenforce,
        "egrep": lambda sh, io: cmd_text.cmd_grep(sh, _with(io, "-E")),
        "mksh": SSH_COMMANDS["sh"],
        "groups": cmd_groups,
    }
)
# Direct use of these needs the busybox applets to be installed (checked by the shell).
BUSYBOX_ONLY: dict[str, Command] = {
    "wget": cmd_wget,
    "tftp": cmd_tftp,
    "ftpget": cmd_ftpget,
    "telnet": cmd_nc,
    "busybox": cmd_busybox,
}
