"""The fake device: a cheap Android TV box with adbd listening on TCP and no authentication.

Everything here is data. ``build_base_image`` turns it into an immutable ``BaseImage`` (the type
of the SSH sensor's emulated shell) shared by all sessions. The identity (model, serial,
addresses, uptime) is derived from the private deployment secret. Nothing is read from the real
host.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from ssh_sensor.shell.baseimage import Profile, derive_profile
from ssh_sensor.shell.fs import BaseImage, Node

# 52-byte ARM ELF header, limited to bytes below 0x80 so it survives the text round trip of the
# emulated shell (`cat /system/bin/toybox | head -c 4` shows ELF).
ELF_ARM = (
    b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x28\x00\x01\x00\x00\x00\x40\x4d\x00\x00"
    b"\x34\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x05\x34\x00\x20\x00\x02\x00\x28\x00\x00\x00\x00\x00"
)

SHELL_UID = 2000

TOYBOX = (
    "acpi base64 basename blockdev cal cat chcon chgrp chmod chown chroot clear cmp comm cp cpio "
    "cut date dd df diff dirname dmesg dos2unix du echo env expand expr fallocate false file find "
    "flock free fsync getenforce getprop groups head hostname hwclock id ifconfig inotifyd insmod "
    "install ionice kill killall ln load_policy log logname losetup ls lsmod lsof lsusb md5sum "
    "microcom mkdir mkfifo mknod mkswap mktemp modinfo more mount mountpoint mv nc netcat netstat "
    "nice nl nohup od paste patch pgrep pidof ping ping6 pkill printenv printf ps pwd readlink "
    "realpath renice restorecon rm rmdir rmmod runcon sed sendevent seq setenforce setprop setsid "
    "sha1sum sha256sum sha512sum sleep sort split start stat stop strings swapoff swapon sync "
    "sysctl tac tail tar taskset tee time timeout top touch tr true truncate tty ulimit umount "
    "uname uniq unix2dos uptime usleep uudecode uuencode vmstat watch wc which whoami xargs xxd yes"
).split()
# Not toybox: dedicated Android binaries (all "work", a few have real output).
ANDROID_BINS = (
    "am app_process cmd dumpsys input ip iptables logcat monkey pm reboot run-as screencap "
    "screenrecord sdcard service settings sh svc toolbox vdc wm netcfg ndc ime content bugreport"
).split()
BUSYBOX_APPLETS = (
    "[ [[ ash awk basename cat chmod chown cp cut date dd df dirname du echo egrep env expr "
    "fgrep find free ftpget ftpput grep gunzip gzip head hostname id ifconfig kill killall ln "
    "ls md5sum mkdir mv nc netstat nslookup ping ps pwd rm rmdir sed sh sleep sort stat "
    "sync tail tar tee telnet tftp touch tr traceroute uname uniq unzip uptime vi wc wget "
    "which whoami xargs zcat"
).split()


@dataclass(frozen=True)
class Model:
    key: str
    product_name: str
    model: str
    device: str
    manufacturer: str
    brand: str
    board: str  # ro.board.platform
    hardware: str
    android: str
    sdk: int
    kernel: str
    kernel_released: date  # release date of that kernel: no build of the box can be older
    cpu_abi: str
    density: int
    features: str  # adbd features advertised in CNXN
    soc_serial_prefix: str

    @property
    def version(self) -> int:
        """Protocol version adbd announces: Android 7 is 0x01000000 (checksummed messages)."""
        return 0x01000000 if self.sdk <= 25 else 0x01000001

    @property
    def banner_nul(self) -> bool:
        """Android 7/8 adbd counts the trailing NUL in the CNXN banner length; newer does not."""
        return self.sdk <= 25

    @property
    def prompt_with_user(self) -> bool:
        return self.sdk <= 25  # Android 7 prints user@device, 8+ prints device only

    @property
    def not_found(self) -> str:
        return "not found" if self.sdk <= 25 else "inaccessible or not found"


# AOSP build ids with the security patch level they shipped: (build id, patch level), oldest
# first, per SDK level. A box carries one of these, never an id from a later patch than its date.
_BUILDS: dict[int, tuple[tuple[str, date], ...]] = {
    25: (
        ("NHG47K", date(2017, 12, 5)),
        ("N2G47H", date(2018, 1, 5)),
        ("N2G47O", date(2018, 3, 5)),
        ("N2G47T", date(2018, 5, 5)),
        ("N2G48C", date(2018, 6, 5)),
        ("N2G48H", date(2018, 9, 5)),
    ),
    28: (
        ("PPR1.180610.011", date(2018, 8, 5)),
        ("PPR2.180905.005", date(2018, 9, 5)),
        ("PPR2.181005.003", date(2018, 10, 5)),
        ("PQ1A.181105.017", date(2018, 11, 5)),
        ("PQ1A.190105.004", date(2019, 1, 5)),
        ("PQ2A.190305.002", date(2019, 3, 5)),
        ("PQ3A.190505.002", date(2019, 5, 5)),
        ("PQ3A.190705.003", date(2019, 7, 5)),
    ),
}
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_CST = timedelta(hours=8)  # these boxes are built by Shenzhen vendors


@dataclass(frozen=True)
class Build:
    """Build facts that must agree with each other: id, patch level, dates, kernel build."""

    build_id: str
    security_patch: str  # YYYY-MM-DD
    date_text: str  # "Wed Mar 20 16:44:02 CST 2019"
    date_utc: int
    incremental: str  # eng.root.YYYYMMDD.HHMMSS, the build timestamp
    kernel_build: str  # "#12 SMP PREEMPT Wed Mar 20 15:58:30 CST 2019"
    first_boot_ms: int


def _stamp(local: datetime) -> str:
    return (
        f"{_DAYS[local.weekday()]} {_MONTHS[local.month - 1]} {local.day:2d}"
        f" {local:%H:%M:%S} CST {local.year}"
    )


def derive_build(digest: bytes, m: Model) -> Build:
    """Pick a coherent build for ``m``: date after its kernel's release, patch level just
    before the date, kernel built shortly before the system image."""
    start = m.kernel_released + timedelta(days=5 + digest[0] % 20)
    day = start + timedelta(days=int.from_bytes(digest[1:3], "big") % 330)
    local = datetime(
        day.year, day.month, day.day, 9 + digest[3] % 11, digest[4] % 60, digest[5] % 60
    )
    eligible = [b for b in _BUILDS[m.sdk] if b[1] <= day - timedelta(days=15)] or [
        _BUILDS[m.sdk][0]
    ]
    build_id, patch = eligible[-1 - digest[6] % min(3, len(eligible))]
    kernel_local = local - timedelta(minutes=20 + int.from_bytes(digest[7:9], "big") % 600)
    utc = int((local - _CST).replace(tzinfo=UTC).timestamp())
    return Build(
        build_id=build_id,
        security_patch=patch.isoformat(),
        date_text=_stamp(local),
        date_utc=utc,
        incremental=f"eng.root.{local:%Y%m%d.%H%M%S}",
        kernel_build=f"#{1 + digest[9] % 60} SMP PREEMPT {_stamp(kernel_local)}",
        first_boot_ms=(utc + 86400 * (2 + digest[10] % 60) + digest[11] * 97) * 1000,
    )


MODELS = (
    Model(
        key="rk3229",
        product_name="rk3229",
        model="MXQ_PRO_4K",
        device="rk3229",
        manufacturer="rockchip",
        brand="rockchip",
        board="rk322x",
        hardware="rk30board",
        android="7.1.2",
        sdk=25,
        kernel="4.9.113",
        kernel_released=date(2018, 8, 22),
        cpu_abi="armeabi-v7a",
        density=240,
        features="shell_v2,cmd",
        soc_serial_prefix="a2",
    ),
    Model(
        key="p212",
        product_name="p212",
        model="X96_mini",
        device="p212",
        manufacturer="Amlogic",
        brand="Amlogic",
        board="gxl",
        hardware="amlogic",
        android="7.1.2",
        sdk=25,
        kernel="4.9.113",
        kernel_released=date(2018, 8, 22),
        cpu_abi="armeabi-v7a",
        density=240,
        features="shell_v2,cmd",
        soc_serial_prefix="08",
    ),
    Model(
        key="q201",
        product_name="q201",
        model="H96_Max",
        device="q201",
        manufacturer="Amlogic",
        brand="Amlogic",
        board="g12a",
        hardware="amlogic",
        android="9",
        sdk=28,
        kernel="4.9.148",
        kernel_released=date(2019, 1, 9),
        cpu_abi="armeabi-v7a",
        density=213,
        features="shell_v2,cmd,stat_v2,fixed_push_mkdir",
        soc_serial_prefix="3c",
    ),
)
MODEL_BY_KEY = {m.key: m for m in MODELS}


def self_identity(*names: str) -> dict[str, list[str]]:
    """The ``data.self_identity`` block of a ``connect`` event (up to 4 names, 64 chars each).

    Only this sensor's own configured or derived names, never anything from a client. Ingest
    uses them to keep the deployment's identity out of anonymous abuse reports.
    """
    out: list[str] = []
    for name in names:
        clipped = name[:64]
        if clipped and clipped not in out:
            out.append(clipped)
    return {"names": out[:4]}


@dataclass(frozen=True)
class Device:
    """Everything that makes this deployment's box unique."""

    model: Model
    build: Build
    profile: Profile
    serial: str
    mac: str
    android_id: str
    busybox: bool
    root: bool

    def self_identity(self) -> dict[str, list[str]]:
        """Per-install names a client can read: serial, host name, net.hostname, Android ID."""
        host = self.profile.hostname
        return self_identity(
            self.serial,
            "" if host == "localhost" else host,
            f"{self.model.product_name}-{self.serial[-4:]}",
            self.android_id,
        )

    @property
    def kernel_build(self) -> str:
        return self.build.kernel_build

    @property
    def fingerprint(self) -> str:
        m, b = self.model, self.build
        return (
            f"{m.brand}/{m.product_name}/{m.device}:{m.android}/{b.build_id}/"
            f"{b.incremental}:userdebug/test-keys"
        )

    @property
    def banner_props(self) -> str:
        m = self.model
        return (
            f"ro.product.name={m.product_name};ro.product.model={m.model};"
            f"ro.product.device={m.device};features={m.features}"
        )

    def getprop(self) -> dict[str, str]:
        m = self.model
        p = self.profile
        b = self.build
        display = f"{m.product_name}-userdebug {m.android} {b.build_id} {b.incremental} test-keys"
        props = {
            "ro.product.name": m.product_name,
            "ro.product.model": m.model,
            "ro.product.device": m.device,
            "ro.product.brand": m.brand,
            "ro.product.manufacturer": m.manufacturer,
            "ro.product.board": m.board,
            "ro.product.cpu.abi": m.cpu_abi,
            "ro.product.cpu.abi2": "armeabi",
            "ro.product.cpu.abilist": f"{m.cpu_abi},armeabi",
            "ro.product.cpu.abilist32": f"{m.cpu_abi},armeabi",
            "ro.product.cpu.abilist64": "",
            "ro.product.locale": "en-US",
            "ro.board.platform": m.board,
            "ro.hardware": m.hardware,
            "ro.bootloader": "unknown",
            "ro.bootmode": "unknown",
            "ro.serialno": self.serial,
            "ro.boot.serialno": self.serial,
            "ro.boot.hardware": m.hardware,
            "ro.build.id": b.build_id,
            "ro.build.display.id": display,
            "ro.build.version.release": m.android,
            "ro.build.version.sdk": str(m.sdk),
            "ro.build.version.codename": "REL",
            "ro.build.version.incremental": b.incremental,
            "ro.build.version.security_patch": b.security_patch,
            "ro.build.date": b.date_text,
            "ro.build.date.utc": str(b.date_utc),
            "ro.build.type": "userdebug",
            "ro.build.user": "root",
            "ro.build.host": "android-build",
            "ro.build.tags": "test-keys",
            "ro.build.flavor": f"{m.product_name}-userdebug",
            "ro.build.product": m.device,
            "ro.build.description": display,
            "ro.build.fingerprint": self.fingerprint,
            "ro.build.characteristics": "tv,nosdcard" if m.sdk >= 28 else "mbx,nosdcard",
            "ro.secure": "0" if self.root else "1",
            "ro.debuggable": "1",
            "ro.adb.secure": "0",
            "ro.allow.mock.location": "0",
            "ro.kernel.qemu": "0",
            "ro.sf.lcd_density": str(m.density),
            "ro.opengles.version": "196609",
            "ro.zygote": "zygote32",
            "ro.runtime.firstboot": str(b.first_boot_ms),
            "persist.sys.usb.config": "adb",
            "persist.service.adb.enable": "1",
            "persist.sys.timezone": "Asia/Shanghai",
            "persist.sys.language": "en",
            "persist.sys.country": "US",
            "service.adb.tcp.port": "5555",
            "sys.usb.config": "adb",
            "sys.usb.state": "adb",
            "sys.boot_completed": "1",
            "sys.boot.reason": "reboot",
            "init.svc.adbd": "running",
            "init.svc.zygote": "running",
            "init.svc.surfaceflinger": "running",
            "net.hostname": f"{m.product_name}-{self.serial[-4:]}",
            "net.dns1": p.gateway,
            "net.eth0.dns1": p.gateway,
            "dhcp.eth0.ipaddress": p.ip,
            "dhcp.eth0.gateway": p.gateway,
            "dhcp.eth0.mask": "255.255.255.0",
            "dhcp.eth0.leasetime": "86400",
            "dhcp.eth0.pid": "1214",
            "wifi.interface": "wlan0",
            "gsm.version.baseband": "unknown",
            "dalvik.vm.heapsize": "256m",
            "dalvik.vm.dexopt-flags": "m=y",
            "dalvik.vm.isa.arm.variant": "cortex-a7" if m.key == "rk3229" else "cortex-a53",
            "ro.crypto.state": "unencrypted",
            "ro.com.google.clientidbase": "android-tv",
            "ro.config.low_ram": "false",
        }
        return props

    @property
    def settings_android_id(self) -> str:
        return self.android_id


def derive_device(seed: str, cfg_hostname: str, busybox_mode: str, root: bool) -> Device:
    digest = hashlib.sha256(f"{seed}|adb-device".encode()).digest()
    model = MODELS[digest[0] % len(MODELS)]
    build = derive_build(hashlib.sha256(f"{seed}|adb-build".encode()).digest(), model)
    serial = model.soc_serial_prefix + digest[1:8].hex()
    ip = f"192.168.{1 + digest[8] % 20}.{20 + digest[9] % 200}"
    profile = derive_profile(
        seed + "|adb",
        cfg_hostname or "localhost",
        ip,
        kernel=model.kernel,
        kernel_build=build.kernel_build,
    )
    mac = ":".join(f"{b:02x}" for b in (0x00, 0x1E, 0x06, digest[10], digest[11], digest[12]))
    busybox = {"yes": True, "no": False}.get(busybox_mode, digest[13] % 2 == 0)
    return Device(
        model=model,
        build=build,
        profile=profile,
        serial=serial,
        mac=mac,
        android_id=digest[14:22].hex(),
        busybox=busybox,
        root=root,
    )


def elf_stub(size: int = 512) -> bytes:
    return ELF_ARM + b"\x00" * max(0, size - len(ELF_ARM))


def _meminfo() -> str:
    rows = [
        ("MemTotal", 1_866_428),
        ("MemFree", 214_312),
        ("MemAvailable", 903_700),
        ("Buffers", 14_208),
        ("Cached", 704_432),
        ("SwapCached", 0),
        ("Active", 912_340),
        ("Inactive", 508_116),
        ("SwapTotal", 0),
        ("SwapFree", 0),
        ("Dirty", 24),
        ("Writeback", 0),
        ("Mapped", 351_216),
        ("Shmem", 18_456),
        ("Slab", 78_332),
    ]
    return "".join(f"{k + ':':<16}{v:>8} kB\n" for k, v in rows)


def _cpuinfo(m: Model) -> str:
    cores = 4
    out = ""
    for i in range(cores):
        out += (
            f"processor\t: {i}\nmodel name\t: ARMv7 Processor rev 5 (v7l)\nBogoMIPS\t: 48.00\n"
            "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm\n"
            "CPU implementer\t: 0x41\nCPU architecture: 7\nCPU variant\t: 0x0\n"
            f"CPU part\t: {'0xc07' if m.key == 'rk3229' else '0xd03'}\nCPU revision\t: 5\n\n"
        )
    return (
        out + f"Hardware\t: {m.hardware.upper()}\nRevision\t: 0000\nSerial\t\t: 0000000000000000\n"
    )


def build_props_file(dev: Device) -> str:
    return "".join(f"{k}={v}\n" for k, v in sorted(dev.getprop().items()) if k.startswith("ro."))


def build_base_image(dev: Device) -> BaseImage:
    m = dev.model
    nodes: dict[str, Node] = {}
    base_mtime = 1_553_071_481

    def d(path: str, mode: int = 0o755, owner: str = "root", group: str = "") -> None:
        nodes[path] = Node("d", mode=mode, owner=owner, group=group or owner, mtime=base_mtime)

    def f(
        path: str, content: str | bytes, mode: int = 0o644, owner: str = "root", group: str = ""
    ) -> None:
        data = content.encode() if isinstance(content, str) else content
        nodes[path] = Node(
            "f", mode=mode, owner=owner, group=group or owner, mtime=base_mtime, content=data
        )

    def link(path: str, target: str) -> None:
        nodes[path] = Node("l", mode=0o777, mtime=base_mtime, target=target)

    d("/", 0o755)
    for path in (
        "/acct /cache /config /d /data /dev /dev/pts /mnt /oem /proc /proc/net /storage /sys "
        "/system /system/app /system/bin /system/etc /system/fonts /system/framework /system/lib "
        "/system/priv-app /system/xbin /vendor /vendor/lib /sbin /data/app /data/data "
        "/data/local /data/misc /data/system /data/media /storage/emulated /storage/emulated/0 "
        "/storage/emulated/0/Android /storage/emulated/0/DCIM /storage/emulated/0/Download "
        "/storage/emulated/0/Movies /storage/emulated/0/Music /storage/emulated/0/Pictures "
        "/mnt/runtime /mnt/media_rw"
    ).split():
        d(path)
    d("/data", 0o771, "system")
    d("/data/local", 0o751, "shell")
    d("/data/local/tmp", 0o771, "shell")
    d("/data/data", 0o771, "system")
    d("/cache", 0o770, "system", "cache")
    d("/storage/emulated/0", 0o770, "root", "sdcard_rw")
    link("/sdcard", "/storage/self/primary")
    d("/storage/self", 0o755)
    link("/storage/self/primary", "/storage/emulated/0")
    link("/etc", "/system/etc")
    link("/bin", "/system/bin")
    link("/vendor/etc", "/system/etc")
    link("/mnt/sdcard", "/storage/self/primary")
    link("/init.rc", "/system/etc/init.rc")
    f("/init", elf_stub(2_000_000), 0o750)
    f(
        "/default.prop",
        "ro.secure=0\nro.adb.secure=0\nro.debuggable=1\npersist.sys.usb.config=adb\n",
    )
    f("/system/build.prop", build_props_file(dev))
    f("/system/etc/init.rc", "# Android init script\nimport /init.${ro.hardware}.rc\n")
    f("/system/etc/hosts", "127.0.0.1       localhost\n")
    f("/system/etc/mkshrc", "# mksh startup\n")
    f("/system/xbin/su", elf_stub(20_000), 0o6755)
    f("/system/bin/toybox", elf_stub(560_000), 0o755)
    f("/system/bin/sh", elf_stub(300_000), 0o755)
    for name in TOYBOX:
        if name != "sh":
            link(f"/system/bin/{name}", "toybox")
    for name in ANDROID_BINS:
        if name not in ("sh",):
            f(f"/system/bin/{name}", elf_stub(18_000), 0o755)
    if dev.busybox:
        f("/system/xbin/busybox", elf_stub(1_100_000), 0o755)
    f("/proc/cpuinfo", _cpuinfo(m), 0o444)
    f("/proc/meminfo", _meminfo(), 0o444)
    f(
        "/proc/version",
        f"Linux version {m.kernel} (root@android-build) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) "
        f"{dev.kernel_build}\n",
        0o444,
    )
    f(
        "/proc/mounts",
        "rootfs / rootfs ro,seclabel,relatime 0 0\n"
        "tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0\n"
        "devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0\n"
        "proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0\n"
        "sysfs /sys sysfs rw,seclabel,relatime 0 0\n"
        "/dev/block/system /system ext4 ro,seclabel,relatime,data=ordered 0 0\n"
        "/dev/block/data /data ext4 rw,seclabel,nosuid,nodev,noatime,data=ordered 0 0\n"
        "/dev/block/cache /cache ext4 rw,seclabel,nosuid,nodev,noatime,data=ordered 0 0\n"
        "/data/media /storage/emulated sdcardfs rw,nosuid,nodev,relatime 0 0\n",
        0o444,
    )
    f(
        "/proc/cmdline",
        f"console=ttyS2,115200n8 androidboot.hardware={m.hardware} androidboot.serialno={dev.serial}\n",
        0o444,
    )
    f("/proc/uptime", "0.00 0.00\n", 0o444)
    f("/proc/loadavg", "0.25 0.30 0.28 2/812 9211\n", 0o444)
    f(
        "/proc/net/tcp",
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        0o444,
    )
    for dev_node in ("null", "zero", "random", "urandom", "tty", "ttyS2", "binder", "ion"):
        f(f"/dev/{dev_node}", b"", 0o666)
    f(
        "/data/system/packages.list",
        "com.android.settings 1000 0 /data/user/0/com.android.settings default:targetSdkVersion=25 3003\n",
        0o640,
        "system",
    )
    boot = dev.profile.boot_epoch

    def uptime() -> bytes:
        up = max(0, int(time.time()) - boot)
        return f"{up}.{up % 97:02d} {up - up // 40}.{up % 89:02d}\n".encode()

    dynamic: dict[str, Callable[[], bytes]] = {"/proc/uptime": uptime}
    binaries = tuple(sorted(set(TOYBOX) | set(ANDROID_BINS)))
    return BaseImage.build(nodes, dynamic, binaries)
