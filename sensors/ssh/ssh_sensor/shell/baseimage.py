"""Declarative description of the fake host: an Ubuntu 24.04 web server.

Everything here is data. ``build_base_image`` turns it into an immutable ``BaseImage`` shared
by all sessions. Nothing is read from the real host.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ssh_sensor.shell.fs import BaseImage, Node
from ssh_sensor.shell.payload import system_binary

BASE_MTIME = 1_752_000_000
MEM_TOTAL_KB = 4_015_860
MEM_FREE_KB = 1_204_312
MEM_AVAILABLE_KB = 3_102_448
MEM_BUFFCACHE_KB = 1_903_220
SWAP_TOTAL_KB = 0
DISK_TOTAL_KB = 40_470_732
DISK_USED_KB = 11_906_124
DEFAULT_OS_VERSION = "24.04.4"
DEFAULT_KERNEL = "6.8.0-100-generic"
DEFAULT_KERNEL_BUILD = "#100-Ubuntu SMP PREEMPT_DYNAMIC Tue Sep  8 15:11:32 UTC 2026"

_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_DAY = 86400
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_PACKAGE_EPOCH = 1_711_929_600  # 2024-04-01: Ubuntu 24.04 packages are built after this date
_KEY_COMMENTS = (
    "deploy@build01",
    "admin@jump01",
    "ci@gitlab-runner",
    "ubuntu@bastion",
    "sysadmin@ops-ws",
    "backup@nas01",
)
_DB_WORDS = ("Wb4pp", "Intr4net", "Sunr1se", "Blu3fish", "Cl0udy", "Gr33nlnd", "Pa1nter", "Tr1dent")


@dataclass(frozen=True)
class Profile:
    """Per-deployment identity of the fake host. Derived from a private random secret."""

    hostname: str
    ip: str
    boot_epoch: int
    seed: str = field(default="", repr=False)  # private secret: never in a repr or a log
    os_version: str = DEFAULT_OS_VERSION
    kernel: str = DEFAULT_KERNEL
    kernel_build: str = DEFAULT_KERNEL_BUILD

    @property
    def os_pretty(self) -> str:
        return f"Ubuntu {self.os_version} LTS"

    def _digest(self, label: str) -> bytes:
        return hashlib.sha256(f"{self.seed}|{label}".encode()).digest()

    @property
    def mac(self) -> str:
        digest = self._digest("mac")
        return "02:%02x:%02x:%02x:%02x:%02x" % tuple(digest[:5])

    @property
    def gateway(self) -> str:
        return ".".join(self.ip.split(".")[:3] + ["1"])

    @property
    def broadcast(self) -> str:
        return ".".join(self.ip.split(".")[:2] + ["255", "255"])

    def _public_ip(self, label: str) -> str:
        d = self._digest(label)
        first = (3, 13, 18, 34, 35, 44, 52, 54, 63, 76, 85, 91, 104, 138, 157, 185)[d[0] % 16]
        return f"{first}.{d[1]}.{d[2]}.{1 + d[3] % 253}"

    @property
    def public_ip(self) -> str:
        """The address the fake host appears to have on the internet (curl ifconfig.me)."""
        return self._public_ip("public")

    @property
    def last_login_ip(self) -> str:
        return self._public_ip("last-login")

    @property
    def last_login_age(self) -> int:
        """Seconds since the fake previous login (1 to 6 days)."""
        return 86400 + int.from_bytes(self._digest("last-login-age")[:4], "big") % (5 * 86400)

    def _num(self, label: str, modulo: int) -> int:
        """A stable number in ``range(modulo)`` for this install and ``label``."""
        return int.from_bytes(self._digest(label)[:8], "big") % modulo

    @property
    def install_epoch(self) -> int:
        """When the fake host was installed: 40 to 400 days before the base image date."""
        return BASE_MTIME - (40 + self._num("install", 360)) * _DAY - self._num("install-sec", _DAY)

    @property
    def user_hash(self) -> str:
        """A yescrypt-shaped ``/etc/shadow`` hash: ``$y$j9T$<22 char salt>$<43 char hash>``."""
        salt = _crypt64(self._digest("shadow-salt")[:16], 22)
        digest = _crypt64(self._digest("shadow-hash"), 43)
        return f"$y$j9T${salt}${digest}"

    @property
    def ssh_key_line(self) -> str:
        """An ``authorized_keys`` line holding a well-formed ed25519 public key."""
        comment = _KEY_COMMENTS[self._num("key-comment", len(_KEY_COMMENTS))]
        return f"ssh-ed25519 {_authorized_key_blob(self)} {comment}\n"

    @property
    def ssh_key_fingerprint(self) -> str:
        """``SHA256:...`` fingerprint of the key in :attr:`ssh_key_line`, as sshd logs it."""
        blob = base64.b64decode(_authorized_key_blob(self))
        return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")

    @property
    def db_password(self) -> str:
        """The password left in the fake ``config.php``: a word, a year and a symbol."""
        word = _DB_WORDS[self._num("db-word", len(_DB_WORDS))]
        year = 2022 + self._num("db-year", 4)
        sep = "-_.@"[self._num("db-sep", 4)]
        tail = "!#$%"[self._num("db-tail", 4)]
        return f"{word}{sep}{year}{tail}"

    def resolve(self, host: str) -> str:
        """Stable fake DNS: literal IPs resolve to themselves, names to a hashed address."""
        if host and host.replace(".", "").isascii() and host.replace(".", "").isdigit():
            return host
        return self._public_ip("dns:" + host.lower())


def _crypt64(raw: bytes, chars: int) -> str:
    """The first ``chars`` characters of crypt(3)'s base64 (little-endian 6-bit groups)."""
    value = int.from_bytes(raw, "little")
    return "".join(_CRYPT_ALPHABET[(value >> (6 * i)) & 63] for i in range(chars))


def _authorized_key_blob(profile: Profile) -> str:
    """Base64 body of a real ed25519 public key derived from the install secret."""
    private = Ed25519PrivateKey.from_private_bytes(profile._digest("authorized-key"))
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", len(raw)) + raw
    return base64.b64encode(blob).decode()


def derive_profile(
    seed: str,
    hostname: str,
    fake_ip: str = "",
    *,
    os_version: str = DEFAULT_OS_VERSION,
    kernel: str = DEFAULT_KERNEL,
    kernel_build: str = DEFAULT_KERNEL_BUILD,
) -> Profile:
    """Deterministic fake identity from ``seed``, which must be a private random secret."""
    digest = hashlib.sha256(f"{seed}|profile".encode()).digest()
    ip = fake_ip or f"10.{digest[0] % 64}.{digest[1]}.{2 + digest[2] % 250}"
    uptime_days = 3 + digest[3] % 40
    boot = int(time.time()) - uptime_days * 86400 - digest[4] * 97
    return Profile(
        hostname=hostname,
        ip=ip,
        boot_epoch=boot,
        seed=seed,
        os_version=os_version,
        kernel=kernel,
        kernel_build=kernel_build,
    )


_PASSWD = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:996:996:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""

_GROUP = """root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:ubuntu
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
cdrom:x:24:ubuntu
floppy:x:25:
sudo:x:27:ubuntu
audio:x:29:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:ubuntu
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
ubuntu:x:1000:
mysql:x:105:
"""

_SHADOW = """root:*:{chg}:0:99999:7:::
daemon:*:{chg}:0:99999:7:::
bin:*:{chg}:0:99999:7:::
sys:*:{chg}:0:99999:7:::
www-data:*:{chg}:0:99999:7:::
sshd:*:{chg}:0:99999:7:::
mysql:!:{chg}::::::
ubuntu:{hash}:{chg}:0:99999:7:::
"""

_BASH_HISTORY_ROOT = """apt update
apt upgrade -y
systemctl status apache2
tail -f /var/log/apache2/error.log
cd /var/www/html
ls -la
nano index.php
systemctl restart apache2
mysql -u root -p
df -h
free -m
crontab -l
exit
"""

_BASH_HISTORY_UBUNTU = """ls
cd /var/www/html
sudo systemctl status apache2
git pull
htop
sudo tail /var/log/auth.log
exit
"""

_AUTH_LOG = """{d1} 06:25:01 {h} CRON[1423]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
{d1} 06:25:01 {h} CRON[1423]: pam_unix(cron:session): session closed for user root
{d1} 08:02:44 {h} sshd[1601]: Accepted publickey for ubuntu from {ip} port {port} ssh2: ED25519 {fp}
{d1} 08:02:44 {h} sshd[1601]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)
{d1} 08:41:09 {h} sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl restart apache2
"""

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{h}</title></head>
<body>
<h1>It works!</h1>
<p>This is the default web page for this server.</p>
</body>
</html>
"""

_INDEX_PHP = """<?php
// Landing page
require_once __DIR__ . '/config.php';
echo '<h1>Welcome to ' . SITE_NAME . '</h1>';
"""

_CONFIG_PHP = """<?php
define('SITE_NAME', 'Intranet');
define('DB_HOST', 'localhost');
define('DB_NAME', 'webapp');
define('DB_USER', 'webapp');
define('DB_PASS', '{dbpass}');
"""

_SSHD_CONFIG = """Include /etc/ssh/sshd_config.d/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem\tsftp\t/usr/lib/openssh/sftp-server
"""

_CRONTAB = """# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly
25 6\t* * *\troot\ttest -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
"""

_BIN_NAMES = (
    "apt apt-get awk base64 basename bash cat chmod chown cp curl cut date dd df dirname dmesg "
    "du echo env false find free gawk gpg grep gzip head hostname id ip kill less ln ls lsb_release "
    "lscpu lsof md5sum mkdir more mount mv nano netstat nice nohup nproc openssl passwd perl "
    "ping ps pwd python3 readlink rm rmdir scp sed seq sh sha256sum sleep sort ss ssh stat su "
    "sudo sync tail tar tee top touch tr true uname uniq unzip uptime vi vim w wc wget which "
    "who whoami xargs zip crontab free id busybox systemctl service git ifconfig tftp"
).split()
_SBIN_NAMES = "ifconfig iptables reboot shutdown sshd useradd userdel usermod fdisk ip".split()


def _cpuinfo() -> str:
    block = """processor\t: {i}
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz
stepping\t: 7
microcode\t: 0x5003801
cpu MHz\t\t: 2499.998
cache size\t: 36608 KB
physical id\t: 0
siblings\t: 2
core id\t\t: 0
cpu cores\t: 1
apicid\t\t: {i}
initial apicid\t: {i}
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 13
wp\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves ida arat pku ospke avx512_vnni
bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit mmio_stale_data retbleed
bogomips\t: 4999.99
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 46 bits physical, 48 bits virtual
power management:

"""
    return "".join(block.format(i=i) for i in range(2))


def _meminfo() -> str:
    rows = [
        ("MemTotal", MEM_TOTAL_KB),
        ("MemFree", MEM_FREE_KB),
        ("MemAvailable", MEM_AVAILABLE_KB),
        ("Buffers", 187_652),
        ("Cached", MEM_BUFFCACHE_KB - 187_652),
        ("SwapCached", 0),
        ("Active", 1_204_116),
        ("Inactive", 1_332_540),
        ("SwapTotal", SWAP_TOTAL_KB),
        ("SwapFree", SWAP_TOTAL_KB),
        ("Dirty", 312),
        ("Slab", 214_872),
    ]
    return "".join(f"{k + ':':<16}{v:>8} kB\n" for k, v in rows)


def build_base_image(profile: Profile) -> BaseImage:
    h = profile.hostname
    nodes: dict[str, Node] = {}
    now = int(time.time())
    install = profile.install_epoch
    boot = profile.boot_epoch
    last_login = now - profile.last_login_age

    def mtime(path: str) -> int:
        """Deterministic per-install modification time, by kind of file.

        Packages predate the install (a ninth of them were upgraded since); configuration
        dates from the install, a few files changed later; logs and temp files are recent."""
        n = profile._num("mtime|" + path, 1 << 30)
        span = max(1, boot - install)
        if path.startswith(("/usr/bin/", "/usr/sbin/")):
            if n % 9 == 0:
                return install + n % span
            return _PACKAGE_EPOCH + n % max(1, install - _PACKAGE_EPOCH)
        if path.startswith(("/var/log", "/tmp", "/var/tmp", "/dev/shm", "/var/backups")):
            return now - n % 7200
        if path.startswith(("/proc", "/sys", "/dev", "/run")):
            return boot + n % 90
        if path.endswith(".bash_history"):
            return last_login + n % 3600
        if n % 7 == 0:
            return install + n % span
        return install + n % 21600

    def d(path: str, mode: int = 0o755, owner: str = "root") -> None:
        nodes[path] = Node("d", mode=mode, owner=owner, group=owner, mtime=mtime(path))

    def f(
        path: str,
        content: str | bytes,
        mode: int = 0o644,
        owner: str = "root",
        group: str = "",
        size: int = 0,
    ) -> None:
        data = content.encode() if isinstance(content, str) else content
        nodes[path] = Node(
            "f",
            mode=mode,
            owner=owner,
            group=group or owner,
            mtime=mtime(path),
            content=data,
            size=size,
        )

    def link(path: str, target: str) -> None:
        nodes[path] = Node("l", mode=0o777, mtime=mtime(path), target=target)

    def log_date(ts: int) -> str:
        t = time.gmtime(ts)
        return f"{_MONTHS[t.tm_mon - 1]} {t.tm_mday:2d}"

    d("/")
    for p in (
        "/boot /dev /etc /home /media /mnt /opt /proc /run /srv /sys /usr /var /usr/bin /usr/sbin "
        "/usr/lib /usr/lib64 /usr/local /usr/local/bin /usr/share /etc/ssh /etc/apt /etc/cron.d "
        "/etc/cron.daily /etc/apache2 /etc/default /var/lib /var/log /var/log/apache2 /var/www "
        "/var/www/html /var/backups /var/spool /var/spool/cron /var/spool/cron/crontabs "
        "/var/cache /var/mail /var/tmp /dev/shm /home/ubuntu /home/ubuntu/.ssh /root/.ssh"
    ).split():
        d(p)
    d("/root", 0o700)
    d("/tmp", 0o1777)
    d("/var/tmp", 0o1777)
    d("/dev/shm", 0o1777)
    d("/home/ubuntu", 0o750, "ubuntu")
    d("/home/ubuntu/.ssh", 0o700, "ubuntu")
    d("/root/.ssh", 0o700)
    d("/var/spool/cron/crontabs", 0o1730)
    d("/var/www/html", 0o755, "www-data")
    d("/proc/net")
    d("/proc/sys")
    link("/bin", "usr/bin")
    link("/sbin", "usr/sbin")
    link("/lib", "usr/lib")
    link("/lib64", "usr/lib64")
    link("/var/run", "/run")

    for name in dict.fromkeys(_BIN_NAMES):
        head, size = system_binary(name)
        f(f"/usr/bin/{name}", head, 0o755, size=size)
    for name in dict.fromkeys(_SBIN_NAMES):
        head, size = system_binary(name)
        f(f"/usr/sbin/{name}", head, 0o755, size=size)

    f("/etc/passwd", _PASSWD)
    f("/etc/group", _GROUP)
    f(
        "/etc/shadow",
        _SHADOW.format(chg=install // _DAY + profile._num("shadow-chg", 5), hash=profile.user_hash),
        0o640,
        "root",
        "shadow",
    )
    f("/etc/hostname", h + "\n")
    f("/etc/hosts", f"127.0.0.1 localhost\n127.0.1.1 {h}\n\n::1 ip6-localhost ip6-loopback\n")
    f(
        "/etc/os-release",
        f'PRETTY_NAME="{profile.os_pretty}"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
        f'VERSION="{profile.os_version} LTS (Noble Numbat)"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        "UBUNTU_CODENAME=noble\nLOGO=ubuntu-logo\n",
    )
    f(
        "/etc/lsb-release",
        "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=24.04\nDISTRIB_CODENAME=noble\n"
        f'DISTRIB_DESCRIPTION="{profile.os_pretty}"\n',
    )
    f("/etc/issue", f"{profile.os_pretty} \\n \\l\n\n")
    f("/etc/issue.net", profile.os_pretty + "\n")
    f(
        "/etc/resolv.conf",
        "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
    )
    f("/etc/fstab", "LABEL=cloudimg-rootfs\t/\text4\tdiscard,errors=remount-ro\t0 1\n")
    f("/etc/ssh/sshd_config", _SSHD_CONFIG)
    f("/etc/crontab", _CRONTAB)
    f("/etc/timezone", "Etc/UTC\n")
    f("/etc/shells", "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n")
    f("/etc/apache2/apache2.conf", '# Apache2 main configuration\nServerRoot "/etc/apache2"\n')
    f("/proc/cpuinfo", _cpuinfo())
    f("/proc/meminfo", _meminfo())
    f(
        "/proc/version",
        f"Linux version {profile.kernel} (buildd@lcy02-amd64-103) (x86_64-linux-gnu-gcc-13 (Ubuntu "
        f"13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) {profile.kernel_build}\n",
    )
    f("/proc/mounts", "/dev/root / ext4 rw,relatime,discard,errors=remount-ro 0 0\n")
    f("/proc/uptime", "0.00 0.00\n")
    f("/proc/loadavg", "0.00 0.00 0.00 1/120 1\n")
    f("/dev/null", b"", 0o666)
    f(
        "/boot/vmlinuz-" + profile.kernel,
        b"MZ\x00\x00",
        0o600,
        size=14_000_000 + profile._num("vmlinuz", 900_000),
    )
    f(
        "/var/log/auth.log",
        _AUTH_LOG.format(
            h=h,
            ip=profile.last_login_ip,
            d1=log_date(last_login),
            port=32768 + profile._num("login-port", 28000),
            fp=profile.ssh_key_fingerprint,
        ),
        0o640,
        "syslog",
        "adm",
    )
    f(
        "/var/log/syslog",
        f"{log_date(now)} 00:00:01 {h} systemd[1]: Starting logrotate.service...\n",
        0o640,
    )
    f("/var/log/apache2/access.log", "", 0o640, "root", "adm")
    f("/var/log/apache2/error.log", "", 0o640, "root", "adm")
    f("/var/www/html/index.html", _INDEX_HTML.format(h=h), 0o644, "www-data")
    f("/var/www/html/index.php", _INDEX_PHP, 0o644, "www-data")
    f("/var/www/html/config.php", _CONFIG_PHP.format(dbpass=profile.db_password), 0o640, "www-data")
    f("/root/.bash_history", _BASH_HISTORY_ROOT, 0o600)
    f("/root/.bashrc", "# ~/.bashrc: executed by bash(1) for non-login shells.\n", 0o644)
    f("/root/.profile", "# ~/.profile\n", 0o644)
    f("/home/ubuntu/.bash_history", _BASH_HISTORY_UBUNTU, 0o600, "ubuntu")
    f(
        "/home/ubuntu/.bashrc",
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
        0o644,
        "ubuntu",
    )
    f(
        "/home/ubuntu/.ssh/authorized_keys",
        profile.ssh_key_line,
        0o600,
        "ubuntu",
    )
    f("/home/ubuntu/notes.txt", "TODO: rotate db password, renew certificates\n", 0o644, "ubuntu")

    boot = profile.boot_epoch

    def uptime() -> bytes:
        up = max(0, int(time.time()) - boot)
        return f"{up}.{up % 97:02d} {up * 2 - up // 9}.{up % 89:02d}\n".encode()

    def loadavg() -> bytes:
        return b"0.08 0.05 0.01 1/164 8123\n"

    binaries = tuple(sorted(set(_BIN_NAMES)))
    return BaseImage.build(nodes, {"/proc/uptime": uptime, "/proc/loadavg": loadavg}, binaries)
