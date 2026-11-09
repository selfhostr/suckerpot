"""System-information and process commands with canned, plausible output."""

from __future__ import annotations

import time

from ssh_sensor.shell import baseimage as bi
from ssh_sensor.shell.core import CmdIO, ShellExit, parse_flags, parse_int, parse_uint
from ssh_sensor.shell.fs import FSError
from ssh_sensor.shell.interp import Shell
from ssh_sensor.shell.util import MAX_LINE_CHARS, fmt_date, human_size, read_text

MAX_DATE_FORMAT = 128
MAX_DATE_OUTPUT = 1024

# A worker spawned when the load rose, some days after boot (clamped to the uptime).
_WORKER_START = 3 * 86400

# user, pid, %cpu, %mem, vsz, rss, tty, stat, start (seconds after boot), time, command
_PROCS: tuple[tuple[str, int, float, float, int, int, str, str, int, str, str], ...] = (
    ("root", 1, 0.0, 0.3, 22560, 13408, "?", "Ss", 0, "0:07", "/sbin/init"),
    ("root", 2, 0.0, 0.0, 0, 0, "?", "S", 0, "0:00", "[kthreadd]"),
    (
        "root",
        412,
        0.0,
        0.5,
        66232,
        20328,
        "?",
        "S<s",
        5,
        "0:03",
        "/lib/systemd/systemd-journald",
    ),
    ("root", 689, 0.0, 0.1, 6600, 4096, "?", "Ss", 9, "0:00", "/usr/sbin/cron -f -P"),
    ("root", 702, 0.0, 0.3, 15432, 9216, "?", "Ss", 11, "0:01", "/usr/sbin/sshd -D"),
    ("mysql", 811, 0.3, 9.8, 1791260, 394688, "?", "Ssl", 14, "21:44", "/usr/sbin/mysqld"),
    (
        "root",
        903,
        0.0,
        0.7,
        207356,
        28852,
        "?",
        "Ss",
        16,
        "0:19",
        "/usr/sbin/apache2 -k start",
    ),
    (
        "www-data",
        1105,
        0.0,
        0.5,
        209268,
        21404,
        "?",
        "S",
        _WORKER_START,
        "0:02",
        "/usr/sbin/apache2 -k start",
    ),
    (
        "www-data",
        1106,
        0.0,
        0.5,
        209268,
        21380,
        "?",
        "S",
        _WORKER_START,
        "0:02",
        "/usr/sbin/apache2 -k start",
    ),
    (
        "root",
        1311,
        0.0,
        0.2,
        14912,
        7936,
        "?",
        "Ss",
        6,
        "0:00",
        "/lib/systemd/systemd-logind",
    ),
)


def _uptime(sh: Shell) -> int:
    return max(0, int(sh.now()) - sh.profile.boot_epoch)


def _stime(sh: Shell, offset: int) -> str:
    """ps START/STIME of a process started ``offset`` seconds after boot: the clock time if it
    started today, else ``MonDD``, else the year."""
    now = int(sh.now())
    ts = min(sh.profile.boot_epoch + offset, now - 60 * (offset > 0))
    t, n = time.gmtime(ts), time.gmtime(now)
    if (t.tm_year, t.tm_yday) == (n.tm_year, n.tm_yday):
        return f"{t.tm_hour:02d}:{t.tm_min:02d}"
    if now - ts < 365 * 86400:
        return f"{bi_mon(t.tm_mon)}{t.tm_mday:02d}"
    return str(t.tm_year)


def _uptime_str(sh: Shell) -> str:
    up = _uptime(sh)
    days, rem = divmod(up, 86400)
    hours, minutes = divmod(rem // 60, 60)
    t = time.gmtime(sh.now())
    when = f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"
    span = f"{days} days, {hours:2d}:{minutes:02d}" if days else f"{hours:2d}:{minutes:02d}"
    return f" {when} up {span},  1 user,  load average: 0.08, 0.05, 0.01"


def cmd_whoami(sh: Shell, io: CmdIO) -> int:
    io.write(sh.user.name + "\n")
    return 0


def _groups(sh: Shell) -> str:
    if sh.user.uid == 0:
        return "0(root)"
    name = sh.user.name
    base = f"{sh.user.gid}({name})"
    if name == "ubuntu":
        return base + ",4(adm),24(cdrom),27(sudo),46(plugdev)"
    return base


def cmd_id(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    if "u" in flags:
        io.write((sh.user.name if "n" in flags else str(sh.user.uid)) + "\n")
    elif "g" in flags:
        io.write((sh.user.name if "n" in flags else str(sh.user.gid)) + "\n")
    else:
        io.write(
            f"uid={sh.user.uid}({sh.user.name}) gid={sh.user.gid}({sh.user.name}) groups={_groups(sh)}\n"
        )
    return 0


def cmd_groups(sh: Shell, io: CmdIO) -> int:
    io.write(" ".join(g.split("(")[1].rstrip(")") for g in _groups(sh).split(",")) + "\n")
    return 0


def cmd_uname(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    host = sh.profile.hostname
    parts = {
        "s": "Linux",
        "n": host,
        "r": sh.profile.kernel,
        "v": sh.profile.kernel_build,
        "m": "x86_64",
        "p": "x86_64",
        "i": "x86_64",
        "o": "GNU/Linux",
    }
    if "a" in flags or "all" in flags:
        io.write(" ".join(parts[k] for k in "snrvmpio") + "\n")
        return 0
    long = {"kernel-name": "s", "nodename": "n", "kernel-release": "r", "machine": "m"}
    chosen = [k for k in "snrvmpio" if k in flags] + [long[k] for k in long if k in flags]
    io.write(" ".join(parts[k] for k in chosen or ["s"]) + "\n")
    return 0


def cmd_arch(sh: Shell, io: CmdIO) -> int:
    io.write("x86_64\n")
    return 0


def cmd_hostname(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    if "I" in flags or "i" in flags:
        io.write(sh.profile.ip + " \n")
    elif "f" in flags:
        io.write(sh.profile.hostname + "\n")
    else:
        io.write(sh.profile.hostname + "\n")
    return 0


def cmd_uptime(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    if "p" in flags:
        up = _uptime(sh)
        io.write(f"up {up // 86400} days, {up % 86400 // 3600} hours, {up % 3600 // 60} minutes\n")
    elif "s" in flags:
        io.write(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(sh.profile.boot_epoch)) + "\n")
    else:
        io.write(_uptime_str(sh) + "\n")
    return 0


def _login_time(sh: Shell) -> str:
    t = time.gmtime(sh.started)
    return f"{t.tm_hour:02d}:{t.tm_min:02d}"


def cmd_w(sh: Shell, io: CmdIO) -> int:
    io.write(_uptime_str(sh) + "\n")
    io.write("USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n")
    io.write(
        f"{sh.user.name:<8} pts/0    {sh.client_ip:<16} {_login_time(sh):<8} 0.00s  0.02s  0.00s w\n"
    )
    return 0


def cmd_who(sh: Shell, io: CmdIO) -> int:
    t = time.strftime("%Y-%m-%d %H:%M", time.gmtime(sh.started))
    io.write(f"{sh.user.name:<8} pts/0        {t} ({sh.client_ip})\n")
    return 0


def cmd_last(sh: Shell, io: CmdIO) -> int:
    t = time.gmtime(sh.started)
    stamp = f"{bi_day(t.tm_wday)} {bi_mon(t.tm_mon)} {t.tm_mday:2d} {t.tm_hour:02d}:{t.tm_min:02d}"
    io.write(f"{sh.user.name:<8} pts/0        {sh.client_ip:<16} {stamp}   still logged in\n")
    b = time.gmtime(sh.profile.boot_epoch)
    boot = f"{bi_day(b.tm_wday)} {bi_mon(b.tm_mon)} {b.tm_mday:2d} {b.tm_hour:02d}:{b.tm_min:02d}"
    io.write(f"reboot   system boot  {sh.profile.kernel:<16} {boot}   still running\n\n")
    io.write(
        f"wtmp begins {bi_day(b.tm_wday)} {bi_mon(b.tm_mon)} {b.tm_mday:2d} "
        f"{b.tm_hour:02d}:{b.tm_min:02d}:{b.tm_sec:02d} {b.tm_year}\n"
    )
    return 0


def bi_day(i: int) -> str:
    return ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[i]


def bi_mon(i: int) -> str:
    return ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")[
        i - 1
    ]


def _session_procs(sh: Shell) -> list[tuple[str, int, str, str]]:
    return [
        (sh.user.name, sh.pid, "pts/0", f"sshd: {sh.user.name}@pts/0"),
        (sh.user.name, sh.pid + 1, "pts/0", "-bash"),
    ]


def cmd_ps(sh: Shell, io: CmdIO) -> int:
    args = io.args
    flags, _, _ = parse_flags([a if a.startswith("-") else "-" + a for a in args])
    me = sh.pid + 12
    if flags & {"a", "e", "A", "x"} or "ef" in args or "aux" in args:
        if "f" in flags and "u" not in flags and "aux" not in args:
            io.write("UID          PID    PPID  C STIME TTY          TIME CMD\n")
            for user, pid, _c, _m, _v, _r, _t, _s, start, _x, cmd in _PROCS:
                ppid = 0 if pid <= 2 else 1
                io.write(
                    f"{user[:8]:<8} {pid:>7} {ppid:>7}  0 {_stime(sh, start):<5} ?        00:00:00 {cmd}\n"
                )
            io.write(
                f"{sh.user.name[:8]:<8} {sh.pid + 1:>7} {sh.pid:>7}  0 {_login_time(sh)} pts/0    00:00:00 -bash\n"
            )
            io.write(
                f"{sh.user.name[:8]:<8} {me:>7} {sh.pid + 1:>7}  0 {_login_time(sh)} pts/0    00:00:00 ps {' '.join(args)}\n"
            )
            return 0
        io.write("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
        for user, pid, cpu, mem, vsz, rss, tty, stat, start, cputime, cmd in _PROCS:
            io.write(
                f"{user[:8]:<8} {pid:>7} {cpu:>4.1f} {mem:>4.1f} {vsz:>6} {rss:>5} {tty:<8} {stat:<4} {_stime(sh, start):<5} {cputime:>5} {cmd}\n"
            )
        t = _login_time(sh)
        io.write(
            f"{sh.user.name[:8]:<8} {sh.pid:>7}  0.0  0.4  17000  11000 ?        S    {t}   0:00 sshd: {sh.user.name}@pts/0\n"
        )
        io.write(
            f"{sh.user.name[:8]:<8} {sh.pid + 1:>7}  0.0  0.1   8392   5120 pts/0    Ss   {t}   0:00 -bash\n"
        )
        io.write(
            f"{sh.user.name[:8]:<8} {me:>7}  0.0  0.1  10072   3584 pts/0    R+   {t}   0:00 ps {' '.join(args)}\n"
        )
        return 0
    io.write("    PID TTY          TIME CMD\n")
    io.write(f"{sh.pid + 1:>7} pts/0    00:00:00 bash\n{me:>7} pts/0    00:00:00 ps\n")
    return 0


def cmd_top(sh: Shell, io: CmdIO) -> int:
    t = bi.MEM_TOTAL_KB / 1024
    free = bi.MEM_FREE_KB / 1024
    cache = bi.MEM_BUFFCACHE_KB / 1024
    used = t - free - cache
    avail = bi.MEM_AVAILABLE_KB / 1024
    io.write(
        _uptime_str(sh).replace(" 1 user", "  1 user").replace(" up", "top - up", 0) + "\n"
        if False
        else "top -" + _uptime_str(sh) + "\n"
    )
    io.write(
        f"Tasks: {len(_PROCS) + 98:>3} total,   1 running, {len(_PROCS) + 97:>3} sleeping,   0 stopped,   0 zombie\n"
    )
    io.write("%Cpu(s):  1.3 us,  0.7 sy,  0.0 ni, 97.7 id,  0.0 wa,  0.0 hi,  0.3 si,  0.0 st\n")
    io.write(
        f"MiB Mem : {t:8.1f} total, {free:8.1f} free, {used:8.1f} used, {cache:8.1f} buff/cache\n"
    )
    io.write(f"MiB Swap:      0.0 total,      0.0 free,      0.0 used. {avail:8.1f} avail Mem \n\n")
    io.write("    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n")
    for user, pid, cpu, mem, vsz, rss, _tty, stat, _s, cputime, cmd in sorted(
        _PROCS, key=lambda p: -p[2]
    )[:8]:
        name = cmd.split()[0].rsplit("/", 1)[-1]
        io.write(
            f"{pid:>7} {user[:8]:<9} 20   0 {vsz:>7} {rss:>6} {rss // 3:>6} {stat[0]} {cpu:>5.1f} {mem:>5.1f}  {cputime}.00 {name}\n"
        )
    return 0


def cmd_free(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    total, free_, avail = bi.MEM_TOTAL_KB, bi.MEM_FREE_KB, bi.MEM_AVAILABLE_KB
    cache = bi.MEM_BUFFCACHE_KB
    used = total - free_ - cache
    shared = 1_236

    def fmt(kb: int) -> str:
        if "h" in flags or "human" in flags:
            return human_size(kb).replace("K", "Ki").replace("M", "Mi").replace("G", "Gi")
        if "m" in flags:
            return str(kb // 1024)
        if "g" in flags:
            return str(kb // 1048576)
        return str(kb)

    head = ("total", "used", "free", "shared", "buff/cache", "available")
    mem = (total, used, free_, shared, cache, avail)
    io.write(" " * 8 + "".join(f" {h:>11}" for h in head) + "\n")
    io.write(f"{'Mem:':<8}" + "".join(f" {fmt(v):>11}" for v in mem) + "\n")
    io.write(f"{'Swap:':<8}" + "".join(f" {fmt(0):>11}" for _ in range(3)) + "\n")
    return 0


def cmd_df(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    if "h" in flags:
        io.write(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "tmpfs           392M  1.1M  391M   1% /run\n"
            "/dev/root        39G   12G   28G  30% /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            "/dev/xvda16     881M   76M  744M  10% /boot\n"
            "/dev/xvda15     105M  6.1M   99M   6% /boot/efi\n"
            "tmpfs           392M   12K  392M   1% /run/user/1000\n"
        )
    else:
        used, total = bi.DISK_USED_KB, bi.DISK_TOTAL_KB
        io.write(
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "tmpfs             401584     1096    400488   1% /run\n"
            f"/dev/root       {total:>9} {used:>8} {total - used - 1_200_000:>9}  30% /\n"
            "tmpfs            2007928        0   2007928   0% /dev/shm\n"
            "tmpfs               5120        0      5120   0% /run/lock\n"
        )
    return 0


def cmd_nproc(sh: Shell, io: CmdIO) -> int:
    io.write("2\n")
    return 0


def cmd_lscpu(sh: Shell, io: CmdIO) -> int:
    io.write(
        "Architecture:                         x86_64\n"
        "CPU op-mode(s):                       32-bit, 64-bit\n"
        "Address sizes:                        46 bits physical, 48 bits virtual\n"
        "Byte Order:                           Little Endian\n"
        "CPU(s):                               2\n"
        "On-line CPU(s) list:                  0,1\n"
        "Vendor ID:                            GenuineIntel\n"
        "Model name:                           Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
        "CPU family:                           6\n"
        "Model:                                85\n"
        "Thread(s) per core:                   2\n"
        "Core(s) per socket:                   1\n"
        "Socket(s):                            1\n"
        "Stepping:                             7\n"
        "BogoMIPS:                             4999.99\n"
        "Hypervisor vendor:                    KVM\n"
        "Virtualization type:                  full\n"
        "L1d cache:                            32 KiB (1 instance)\n"
        "L2 cache:                             1 MiB (1 instance)\n"
        "L3 cache:                             35.8 MiB (1 instance)\n"
        "NUMA node(s):                         1\n"
    )
    return 0


def cmd_ifconfig(sh: Shell, io: CmdIO) -> int:
    p = sh.profile
    io.write(
        f"ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
        f"        inet {p.ip}  netmask 255.255.240.0  broadcast {p.broadcast}\n"
        f"        inet6 fe80::{p.mac[3:5]}{p.mac[6:8]}:{p.mac[9:11]}ff:fe{p.mac[12:14]}:{p.mac[15:17]}  prefixlen 64  scopeid 0x20<link>\n"
        f"        ether {p.mac}  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 2154310  bytes 1873645912 (1.8 GB)\n"
        "        RX errors 0  dropped 0  overruns 0  frame 0\n"
        "        TX packets 1432871  bytes 291834011 (291.8 MB)\n"
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
        "        loop  txqueuelen 1000  (Local Loopback)\n"
        "        RX packets 18211  bytes 1459026 (1.4 MB)\n"
        "        RX errors 0  dropped 0  overruns 0  frame 0\n"
        "        TX packets 18211  bytes 1459026 (1.4 MB)\n"
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
    )
    return 0


def cmd_ip(sh: Shell, io: CmdIO) -> int:
    p = sh.profile
    words = [a for a in io.args if not a.startswith("-")]
    sub = words[0] if words else "addr"
    if sub in ("r", "route", "ro"):
        io.write(
            f"default via {p.gateway} dev ens5 proto dhcp src {p.ip} metric 100\n"
            f"{'.'.join(p.ip.split('.')[:2])}.0.0/20 dev ens5 proto kernel scope link src {p.ip} metric 100\n"
        )
        return 0
    link = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP mode DEFAULT group default qlen 1000\n"
        f"    link/ether {p.mac} brd ff:ff:ff:ff:ff:ff\n"
    )
    if sub in ("l", "link"):
        io.write(link)
        return 0
    io.write(
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n"
        "2: ens5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000\n"
        f"    link/ether {p.mac} brd ff:ff:ff:ff:ff:ff\n"
        f"    inet {p.ip}/20 metric 100 brd {p.broadcast} scope global dynamic ens5\n"
        "       valid_lft 2514sec preferred_lft 2514sec\n"
    )
    return 0


_LISTEN = (
    ("tcp", "0.0.0.0:22", "0.0.0.0:*", "702/sshd: /usr/sbin"),
    ("tcp", "0.0.0.0:80", "0.0.0.0:*", "903/apache2"),
    ("tcp", "0.0.0.0:443", "0.0.0.0:*", "903/apache2"),
    ("tcp", "127.0.0.1:3306", "0.0.0.0:*", "811/mysqld"),
    ("tcp", "127.0.0.53:53", "0.0.0.0:*", "540/systemd-resolve"),
    ("udp", "127.0.0.53:53", "0.0.0.0:*", "540/systemd-resolve"),
)


def cmd_netstat(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    io.write(
        "Active Internet connections (only servers)\n"
        if "a" not in flags
        else "Active Internet connections (servers and established)\n"
    )
    io.write(
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
    )
    for proto, local, remote, prog in _LISTEN:
        state = "LISTEN" if proto == "tcp" else ""
        io.write(
            f"{proto:<5}       0      0 {local:<23} {remote:<23} {state:<11} {prog if 'p' in flags else ''}\n"
        )
    if "a" in flags or ("t" not in flags and "l" not in flags):
        io.write(
            f"tcp        0      0 {sh.profile.ip}:22{'':<{max(1, 23 - len(sh.profile.ip) - 3)}}"
            f"{sh.client_ip}:{sh.client_port:<{max(1, 22 - len(sh.client_ip) - 6)}} ESTABLISHED {sh.pid}/sshd\n"
        )
    return 0


def cmd_ss(sh: Shell, io: CmdIO) -> int:
    io.write("Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n")
    for proto, local, remote, prog in _LISTEN:
        name = prog.split("/")[1].split(":")[0]
        pid = prog.split("/")[0]
        io.write(
            f"{proto:<6}{'LISTEN' if proto == 'tcp' else 'UNCONN':<7}0      {'4096' if proto == 'tcp' else '0':<6} "
            f'{local:<19} {remote.replace("0.0.0.0:*", "0.0.0.0:*"):<18} users:(("{name}",pid={pid},fd=3))\n'
        )
    return 0


def cmd_history(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    if "c" in flags:
        sh.clear_history()
        return 0
    for i, line in enumerate(sh.history, 1):
        if io.full:
            break
        io.write(f"{i:>5}  {line[:MAX_LINE_CHARS]}\n")
    return 0


def cmd_export(sh: Shell, io: CmdIO) -> int:
    for arg in io.args:
        if arg.startswith("-"):
            continue
        name, eq, value = arg.partition("=")
        if eq and name.replace("_", "a").isalnum() and name.isascii():
            if not sh.set_var(name, value, export=True):
                io.error(f"{sh.error_prefix()}export: cannot allocate memory\n")
                return 1
    return 0


def cmd_env(sh: Shell, io: CmdIO) -> int:
    io.write("".join(f"{k}={v}\n" for k, v in sh.env.items()))
    return 0


def cmd_printenv(sh: Shell, io: CmdIO) -> int:
    if not io.args:
        return cmd_env(sh, io)
    status = 0
    for name in io.args:
        if name in sh.env:
            io.write(sh.env[name] + "\n")
        else:
            status = 1
    return status


def cmd_unset(sh: Shell, io: CmdIO) -> int:
    for name in io.args:
        sh.env.pop(name, None)
        sh.shell_vars.pop(name, None)
    return 0


_BUILTINS = frozenset(
    "cd echo pwd export exit logout history type unset alias test [ true false :".split()
)


def cmd_which(sh: Shell, io: CmdIO) -> int:
    status = 0
    for name in parse_flags(io.args)[2]:
        if name in sh.base.binaries:
            io.write(f"/usr/bin/{name}\n")
        else:
            status = 1
    return status


def cmd_type(sh: Shell, io: CmdIO) -> int:
    status = 0
    for name in io.args:
        if name.startswith("-"):
            continue
        if name in _BUILTINS:
            io.write(f"{name} is a shell builtin\n")
        elif name in sh.base.binaries:
            io.write(f"{name} is /usr/bin/{name}\n")
        else:
            io.error(f"{sh.error_prefix()}type: {name}: not found\n")
            status = 1
    return status


def cmd_command(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args)
    if flags & {"v", "V"}:
        status = 0
        for name in operands:
            if name in _BUILTINS:
                io.write(name + "\n")
            elif name in sh.base.binaries:
                io.write(f"/usr/bin/{name}\n")
            else:
                status = 1
        return status
    return sh.run_argv(operands, io)


def cmd_crontab(sh: Shell, io: CmdIO) -> int:
    flags, _, operands = parse_flags(io.args, "u")
    if "l" in flags:
        if not sh.crontab:
            io.error(f"no crontab for {sh.user.name}\n")
            return 1
        io.write("\n".join(sh.crontab) + "\n")
        return 0
    if "r" in flags:
        sh.crontab.clear()
        return 0
    if "e" in flags:
        io.error(f"no crontab for {sh.user.name} - using an empty one\n")
        io.write("No modification made\n")
        return 0
    source: str | None = None
    if operands:
        if operands[0] == "-":
            source = io.stdin or ""
        else:
            try:
                source = read_text(sh, sh.abspath(operands[0]))
            except FSError as exc:
                io.error(f"{operands[0]}: {exc}\n")
                return 1
    elif io.stdin:
        source = io.stdin
    if source is not None:
        sh.crontab = [ln for ln in source.splitlines()[:50]]
        return 0
    io.error("usage: crontab [-u user] file\n")
    return 1


def cmd_passwd(sh: Shell, io: CmdIO) -> int:
    io.write("New password: \nRetype new password: \nSorry, passwords do not match.\n")
    io.write("passwd: Authentication token manipulation error\npasswd: password unchanged\n")
    return 10


def _switch(sh: Shell, name: str, login: bool) -> bool:
    previous = sh.user
    if not sh.set_user(name):
        return False
    sh.user_stack.append(previous)
    if login:
        sh.set_cwd(sh.user.home)
        sh.env["PWD"] = sh.cwd
    return True


def cmd_sudo(sh: Shell, io: CmdIO) -> int:
    args = list(io.args)
    target = "root"
    login = shell_mode = list_mode = False
    while args and args[0].startswith("-"):
        flag = args.pop(0)
        if flag == "--":
            break
        if flag in ("-u", "--user") and args:
            target = args.pop(0)
        elif flag.startswith("-u") and len(flag) > 2:
            target = flag[2:]
        elif flag == "-i":
            login = True
        elif flag == "-s":
            shell_mode = True
        elif flag == "-l":
            list_mode = True
    if list_mode:
        io.write(
            f"Matching Defaults entries for {sh.user.name} on {sh.profile.hostname}:\n"
            "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n"
            f"User {sh.user.name} may run the following commands on {sh.profile.hostname}:\n"
            "    (ALL : ALL) NOPASSWD: ALL\n"
        )
        return 0
    if not args and (login or shell_mode):
        if not _switch(sh, target, login):
            io.error(f"sudo: unknown user {target}\n")
            return 1
        return 0
    if not args:
        io.error("usage: sudo -h | -K | -k | -V\n")
        return 1
    previous = sh.user
    if not sh.set_user(target):
        io.error(f"sudo: unknown user {target}\n")
        return 1
    try:
        return sh.run_argv(args, io)
    finally:
        sh.user = previous
        sh.env.update(USER=previous.name, LOGNAME=previous.name, HOME=previous.home)


def cmd_su(sh: Shell, io: CmdIO) -> int:
    login = any(a in ("-", "-l", "--login") for a in io.args)
    names = [a for a in io.args if not a.startswith("-") and a != "-"]
    target = names[0] if names else "root"
    if not sh.is_root:
        io.write("Password: ")
        io.error("\nsu: Authentication failure\n")
        return 1
    if not _switch(sh, target, login):
        io.error(
            f"su: user {target} does not exist or the user entry does not contain all the required fields\n"
        )
        return 1
    return 0


def cmd_exit(sh: Shell, io: CmdIO) -> int:
    if sh.user_stack:
        prev = sh.user_stack.pop()
        sh.set_user(prev.name)
        if sh.interactive:
            io.write("exit\n")
        return 0
    code = parse_int(io.args[0]) if io.args else None
    if io.args and code is None:
        io.error(f"{sh.error_prefix()}exit: {io.args[0][:64]}: numeric argument required\n")
        raise ShellExit(2)
    raise ShellExit(code & 255 if code is not None else sh.last_status)


def cmd_clear(sh: Shell, io: CmdIO) -> int:
    io.write("\x1b[H\x1b[2J\x1b[3J" if sh.tty else "")
    return 0


def cmd_date(sh: Shell, io: CmdIO) -> int:
    fmt = next((a for a in io.args if a.startswith("+")), "")
    if fmt:
        # A directive expands to at most a few dozen characters, so capping the format bounds
        # the output before strftime builds it; the result is capped again for safety.
        spec = fmt[1 : 1 + MAX_DATE_FORMAT]
        try:
            text = time.strftime(spec, time.gmtime(sh.now()))
        except ValueError:  # embedded NUL and similar: GNU date prints the format verbatim
            text = spec.replace("\0", "")
        io.write(text[:MAX_DATE_OUTPUT] + "\n")
    else:
        io.write(fmt_date(sh.now()) + "\n")
    return 0


def cmd_sleep(sh: Shell, io: CmdIO) -> int:
    try:
        seconds = float(io.args[0]) if io.args else 0.0
    except ValueError:
        io.error(f"sleep: invalid time interval '{io.args[0]}'\n")
        return 1
    if sh.cfg.command_delay:
        sh.delay += max(0.0, min(seconds, 2.0))
    return 0


def cmd_passthrough(sh: Shell, io: CmdIO) -> int:
    """nohup, setsid, nice, time, timeout, exec, env-with-command: run the inner command."""
    args = [a for a in io.args]
    while args and args[0].startswith("-"):
        args.pop(0)
    if io.cmdline.startswith("timeout") and args:
        args.pop(0)  # the duration
    return sh.run_argv(args, io)


def cmd_kill(sh: Shell, io: CmdIO) -> int:
    status = 0
    for arg in io.args:
        if arg.startswith("-"):
            continue
        pid = parse_uint(arg)
        if pid is None:
            io.error(f"{sh.error_prefix()}kill: {arg[:64]}: arguments must be process or job IDs\n")
            status = 1
        elif pid not in (1, sh.pid, sh.pid + 1):
            io.error(f"{sh.error_prefix()}kill: ({pid}) - No such process\n")
            status = 1
    return status


def cmd_killall(sh: Shell, io: CmdIO) -> int:
    names = [a for a in io.args if not a.startswith("-")]
    known = {c.split()[0].rsplit("/", 1)[-1] for *_x, c in _PROCS}
    status = 0
    for name in names:
        if name not in known:
            io.error(
                f"{io.cmdline.split()[0]}: {name}: no process found\n"
                if io.cmdline.startswith("killall")
                else ""
            )
            status = 1
    return status


def cmd_apt(sh: Shell, io: CmdIO) -> int:
    name = io.cmdline.split()[0]
    words = [a for a in io.args if not a.startswith("-")]
    sub = words[0] if words else ""
    if not sh.is_root and sub in (
        "install",
        "update",
        "upgrade",
        "remove",
        "purge",
        "dist-upgrade",
    ):
        io.error(
            "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
            "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"
        )
        return 100
    if sub == "update":
        ip = sh.profile.resolve("archive.ubuntu.com")
        io.write(
            f"Err:1 http://archive.ubuntu.com/ubuntu noble InRelease\n"
            f"  Could not connect to archive.ubuntu.com:80 ({ip}), connection timed out\n"
            "Reading package lists... Done\n"
            f"W: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease  Could not connect to archive.ubuntu.com:80 ({ip}), connection timed out\n"
            "W: Some index files failed to download. They have been ignored, or old ones used instead.\n"
        )
        sh.delay += 1.0
        return 0
    if sub == "install":
        pkgs = words[1:]
        io.write(
            "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\n"
        )
        if pkgs:
            io.error(f"E: Unable to locate package {pkgs[0]}\n")
            return 100
        return 0
    if sub in ("upgrade", "dist-upgrade"):
        io.write(
            "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nCalculating upgrade... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
        )
        return 0
    if name == "dpkg":
        return 0
    return 0


_UNITS = {
    "ssh": "OpenBSD Secure Shell server",
    "apache2": "The Apache HTTP Server",
    "mysql": "MySQL Community Server",
    "cron": "Regular background program processing daemon",
}


def cmd_systemctl(sh: Shell, io: CmdIO) -> int:
    words = [a for a in io.args if not a.startswith("-")]
    if len(words) < 2:
        return 0
    action, unit = words[0], words[1].removesuffix(".service")
    if action in ("status", "is-active", "is-enabled", "show") and unit in _UNITS:
        if action == "is-active":
            io.write("active\n")
        elif action == "is-enabled":
            io.write("enabled\n")
        else:
            io.write(
                f"● {unit}.service - {_UNITS[unit]}\n"
                f"     Loaded: loaded (/usr/lib/systemd/system/{unit}.service; enabled; preset: enabled)\n"
                f"     Active: active (running) since Sun 2026-10-12 06:11:30 UTC; 12 days ago\n"
                f"   Main PID: 702 ({unit})\n"
            )
        return 0
    if unit not in _UNITS:
        io.error(f"Unit {unit}.service could not be found.\n")
        return 4 if action in ("status", "is-active") else 5
    if not sh.is_root and action in ("start", "stop", "restart", "reload", "enable", "disable"):
        io.error(
            "Failed to %s %s.service: Interactive authentication required.\nSee system logs and 'systemctl status %s.service' for details.\n"
            % (action, unit, unit)
        )
        return 1
    return 0


def cmd_lsb_release(sh: Shell, io: CmdIO) -> int:
    flags, _, _ = parse_flags(io.args)
    if flags & {"a", "all"}:
        io.write(
            "No LSB modules are available.\nDistributor ID:\tUbuntu\n"
            f"Description:\t{sh.profile.os_pretty}\nRelease:\t24.04\nCodename:\tnoble\n"
        )
    elif "d" in flags:
        io.write(f"Description:\t{sh.profile.os_pretty}\n")
    else:
        io.write("No LSB modules are available.\n")
    return 0


_STDLIB = frozenset(
    "os sys socket subprocess pty time json base64 urllib re random string struct "
    "threading hashlib platform shutil tempfile select signal itertools collections".split()
)


def _literal_print(code: str) -> str | None:
    """Output of ``print("text")`` / ``print('text')`` / ``print(123)``; None otherwise."""
    code = code.strip().rstrip(";").strip()
    if not (code.startswith("print(") and code.endswith(")")):
        return None
    inner = code[6:-1].strip()
    if (
        len(inner) >= 2
        and inner[0] == inner[-1]
        and inner[0] in "\"'"
        and inner[0] not in inner[1:-1]
    ):
        return inner[1:-1] + "\n"
    number = parse_int(inner)
    return f"{number}\n" if number is not None else None


def cmd_python(sh: Shell, io: CmdIO) -> int:
    args = io.args
    if args and args[0] in ("--version", "-V"):
        io.write("Python 3.12.3\n")
        return 0
    if args and args[0] == "-c" and len(args) > 1:
        code = args[1][:512]
        text = _literal_print(code)
        if text is not None:
            io.write(text)
            return 0
        first = code.strip().split(";")[0].split()
        if len(first) >= 2 and first[0] == "import":
            module = first[1].split(".")[0].split(",")[0]
            if module and module not in _STDLIB:
                io.error(
                    "Traceback (most recent call last):\n"
                    '  File "<string>", line 1, in <module>\n'
                    f"ModuleNotFoundError: No module named '{module[:64]}'\n"
                )
                return 1
        return 0
    script = next((a for a in args if not a.startswith("-")), "")
    if script and not sh.fs.exists(sh.abspath(script)):
        io.error(
            f"python3: can't open file '{sh.abspath(script)}': [Errno 2] No such file or directory\n"
        )
        return 2
    return 0


def cmd_perl(sh: Shell, io: CmdIO) -> int:
    args = io.args
    if args and args[0] == "-v":
        io.write(
            "\nThis is perl 5, version 38, subversion 2 (v5.38.2) built for x86_64-linux-gnu-thread-multi\n"
        )
        return 0
    if args and args[0] == "-e" and len(args) > 1:
        code = args[1][:512].strip().rstrip(";").strip()
        if code.startswith("print ") and len(code) > 8 and code[6] in "\"'" and code[-1] == code[6]:
            body = code[7:-1]
            io.write(body.replace("\\n", "\n") if code[6] == '"' else body)
        return 0
    script = next((a for a in args if not a.startswith("-")), "")
    if script and not sh.fs.exists(sh.abspath(script)):
        io.error(f'Can\'t open perl script "{script[:128]}": No such file or directory\n')
        return 2
    return 0


def cmd_reboot(sh: Shell, io: CmdIO) -> int:
    if not sh.is_root:
        io.error(
            "Failed to set wall message, ignoring: Interactive authentication required.\nFailed to reboot system via logind: Interactive authentication required.\nFailed to open initctl fifo: Permission denied\nFailed to talk to init daemon.\n"
        )
        return 1
    raise ShellExit(0)


def cmd_ping(sh: Shell, io: CmdIO) -> int:
    hosts = [a for a in io.args if not a.startswith("-") and parse_uint(a) is None]
    if not hosts:
        io.error("ping: usage error: Destination address required\n")
        return 2
    host = hosts[0]
    io.write(f"PING {host} ({sh.profile.resolve(host)}) 56(84) bytes of data.\n")
    if sh.cfg.command_delay:
        sh.delay += 1.0
    io.write(
        f"\n--- {host} ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss, time 0ms\n\n"
    )
    return 1


def cmd_nc(sh: Shell, io: CmdIO) -> int:
    words = [a for a in io.args if not a.startswith("-")]
    if len(words) >= 2:
        io.error(f"nc: connect to {words[0]} port {words[1]} (tcp) failed: Connection timed out\n")
        if sh.cfg.command_delay:
            sh.delay += 2.0
        return 1
    io.error("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n")
    return 1


def cmd_nothing(sh: Shell, io: CmdIO) -> int:
    return 0
