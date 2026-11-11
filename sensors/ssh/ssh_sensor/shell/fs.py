"""In-memory fake filesystem: an immutable base image plus a per-session copy-on-write overlay."""

from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Callable
from dataclasses import dataclass, field, replace

ROOT = "/"
MAX_PATH = 1024
MAX_SYMLINKS = 8
_WRITABLE_PREFIXES = ("/tmp", "/var/tmp", "/dev/shm", "/dev/null")
# A file may declare a size larger than the bytes it stores (a binary: header + filler). The
# filler is generated on read and never stored; a read never builds more than this many bytes.
MAX_VIRTUAL_READ = 2 * 1024 * 1024


class FSError(Exception):
    """Filesystem error carrying a strerror-style message (e.g. 'No such file or directory')."""


@dataclass(frozen=True, slots=True)
class Node:
    kind: str  # "d" directory, "f" file, "l" symlink
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"
    mtime: int = 1_726_000_000
    content: bytes = b""
    target: str = ""
    tag: str = ""  # "" | "elf" | "dropped-script": marks files created by fake downloads
    size: int = 0  # declared size when larger than ``content`` (0: the content is the file)

    @property
    def length(self) -> int:
        """Size in bytes as ``ls`` and ``stat`` report it."""
        return max(self.size, len(self.content))


def pad_content(key: bytes, node: Node, limit: int = MAX_VIRTUAL_READ) -> bytes:
    """The bytes of ``node``: its stored content, then filler up to its size.

    The filler depends on the install secret ``key``, the stored header and the size, not on
    the path, so a copy of a file reads back identical bytes. At most ``limit`` bytes are
    generated."""
    stored = len(node.content)
    want = min(node.size, MAX_VIRTUAL_READ, limit) - stored
    if want <= 0:
        return node.content
    seed = key + node.content[:64] + node.size.to_bytes(8, "big")
    return node.content + hashlib.shake_128(seed).digest(want)


@dataclass(frozen=True)
class BaseImage:
    """Immutable filesystem image shared by all sessions."""

    nodes: dict[str, Node]
    children: dict[str, tuple[str, ...]]
    dynamic: dict[str, Callable[[], bytes]] = field(default_factory=dict)
    binaries: tuple[str, ...] = ()
    secret: bytes = b""  # install secret: keys the filler of virtual files

    @staticmethod
    def build(
        nodes: dict[str, Node],
        dynamic: dict[str, Callable[[], bytes]],
        binaries: tuple[str, ...],
        secret: bytes = b"",
    ) -> BaseImage:
        kids: dict[str, set[str]] = {}
        for path in nodes:
            if path == ROOT:
                continue
            parent, name = posixpath.split(path)
            kids.setdefault(parent or ROOT, set()).add(name)
        return BaseImage(
            nodes=nodes,
            children={k: tuple(sorted(v)) for k, v in kids.items()},
            dynamic=dynamic,
            binaries=binaries,
            secret=secret,
        )


class FakeFS:
    """Per-session view: reads fall through to the base image, writes go to the overlay."""

    def __init__(self, base: BaseImage, *, max_bytes: int, max_nodes: int, now: int) -> None:
        self._base = base
        self._added: dict[str, Node] = {}
        self._extra: dict[str, Node] = {}  # per-session read-only nodes (/proc/self...)
        self._extra_kids: dict[str, set[str]] = {}
        self._deleted: set[str] = set()
        self._max_bytes = max_bytes
        self._max_nodes = max_nodes
        self._bytes = 0
        self._now = now

    @property
    def used_bytes(self) -> int:
        return self._bytes

    @property
    def free_bytes(self) -> int:
        return max(0, self._max_bytes - self._bytes)

    @property
    def base(self) -> BaseImage:
        return self._base

    # ---- path handling -------------------------------------------------------------------
    def normalize(self, cwd: str, path: str) -> str:
        """Absolute, normalised path (``..`` and ``.`` resolved, symlinks not followed)."""
        if len(path) > MAX_PATH:
            raise FSError("File name too long")
        if not path.startswith("/"):
            path = posixpath.join(cwd, path)
        norm = posixpath.normpath(path)
        return "/" + norm.lstrip("/") if norm.startswith("//") else norm

    def resolve(self, cwd: str, path: str, *, follow_last: bool = True) -> str:
        """Like :meth:`normalize` but follows symlinks (bounded)."""
        current = self.normalize(cwd, path)
        for _ in range(MAX_SYMLINKS + 1):
            parts = [p for p in current.split("/") if p]
            built = ""
            changed = False
            for i, part in enumerate(parts):
                built = f"{built}/{part}"
                last = i == len(parts) - 1
                node = self._raw(built)
                if node is not None and node.kind == "l" and (follow_last or not last):
                    rest = "/".join(parts[i + 1 :])
                    target = posixpath.join(posixpath.dirname(built), node.target)
                    current = posixpath.normpath(posixpath.join(target, rest))
                    changed = True
                    break
            if not changed:
                return current or ROOT
        raise FSError("Too many levels of symbolic links")

    def _raw(self, path: str) -> Node | None:
        if path in self._deleted:
            return None
        node = self._added.get(path)
        if node is not None:
            return node
        node = self._extra.get(path)
        if node is not None:
            return node
        return self._base.nodes.get(path)

    def seed(self, nodes: dict[str, Node]) -> None:
        """Add per-session nodes that are not charged to the session's budget (``/proc/<pid>``).

        Paths must be absolute; their parent directories must be in the base image or listed
        here. A later write to the same path lands in the overlay as usual."""
        for path, node in nodes.items():
            self._extra[path] = node
            parent, name = posixpath.split(path)
            self._extra_kids.setdefault(parent or ROOT, set()).add(name)

    # ---- queries -------------------------------------------------------------------------
    def stat(self, path: str) -> Node | None:
        return self._raw(path)

    def exists(self, path: str) -> bool:
        return self._raw(path) is not None

    def is_dir(self, path: str) -> bool:
        node = self._raw(path)
        return node is not None and node.kind == "d"

    def read(self, path: str, limit: int = MAX_VIRTUAL_READ) -> bytes:
        """File content; a file with a declared size is generated up to ``limit`` bytes."""
        node = self._raw(path)
        if node is None:
            raise FSError("No such file or directory")
        if node.kind == "d":
            raise FSError("Is a directory")
        dyn = self._base.dynamic.get(path)
        if dyn is not None and path not in self._added:
            return dyn()
        if node.size > len(node.content):
            return pad_content(self._base.secret, node, limit)
        return node.content

    def listdir(self, path: str) -> list[str]:
        node = self._raw(path)
        if node is None:
            raise FSError("No such file or directory")
        if node.kind != "d":
            raise FSError("Not a directory")
        names = set(self._base.children.get(path, ())) | self._extra_kids.get(path, set())
        prefix = "/" if path == ROOT else path + "/"
        for p in self._added:
            if p != path and p.startswith(prefix) and "/" not in p[len(prefix) :]:
                names.add(p[len(prefix) :])
        return sorted(n for n in names if (prefix + n) not in self._deleted)

    # ---- mutations -----------------------------------------------------------------------
    @staticmethod
    def may_write(path: str, user: str, home: str) -> bool:
        if user == "root":
            return True
        if path == home or path.startswith(home + "/"):
            return True
        return any(path == p or path.startswith(p + "/") for p in _WRITABLE_PREFIXES)

    def _check_parent(self, path: str) -> None:
        parent = posixpath.dirname(path) or ROOT
        pnode = self._raw(parent)
        if pnode is None:
            raise FSError("No such file or directory")
        if pnode.kind != "d":
            raise FSError("Not a directory")

    def _put(self, path: str, node: Node) -> None:
        old = self._raw(path)
        if old is None and len(self._added) >= self._max_nodes:
            raise FSError("No space left on device")
        delta = len(node.content) - (len(old.content) if old and path in self._added else 0)
        if self._bytes + delta > self._max_bytes:
            raise FSError("No space left on device")
        self._bytes += delta
        self._deleted.discard(path)
        self._added[path] = node

    def write(
        self,
        path: str,
        data: bytes,
        *,
        append: bool,
        owner: str,
        mode: int = 0o644,
        tag: str = "",
        size: int = 0,
    ) -> None:
        self._check_parent(path)
        old = self._raw(path)
        if old is not None and old.kind == "d":
            raise FSError("Is a directory")
        if path == "/dev/null":
            return
        appending = append and old is not None
        # Check the projected size BEFORE concatenating: `>>` on a large file must not build
        # a copy that would then be refused.
        base = self.read(path, self._max_bytes + 1) if appending else b""
        old_len = len(base)
        held = len(old.content) if old is not None and path in self._added else 0
        if self._bytes + old_len + len(data) - held > self._max_bytes:
            raise FSError("No space left on device")
        node = Node(
            "f",
            mode=old.mode if old is not None else mode,
            owner=old.owner if old is not None else owner,
            group=old.group if old is not None else owner,
            mtime=self._now,
            content=(base + data),
            tag=tag if old is None or tag else old.tag,
            size=0 if appending else size,
        )
        self._put(path, node)

    def mkdir(self, path: str, owner: str, mode: int = 0o755) -> None:
        if self._raw(path) is not None:
            raise FSError("File exists")
        self._check_parent(path)
        self._put(path, Node("d", mode=mode, owner=owner, group=owner, mtime=self._now))

    def touch(self, path: str, owner: str) -> None:
        node = self._raw(path)
        if node is None:
            self.write(path, b"", append=False, owner=owner)
        else:
            self._added[path] = replace(node, mtime=self._now)

    def chmod(self, path: str, mode: int) -> None:
        node = self._raw(path)
        if node is None:
            raise FSError("No such file or directory")
        self._added[path] = replace(node, mode=mode)

    def remove(self, path: str) -> None:
        node = self._raw(path)
        if node is None:
            raise FSError("No such file or directory")
        if node.kind == "d" and self.listdir(path):
            raise FSError("Directory not empty")
        if path in self._added:
            self._bytes -= len(self._added[path].content)
            del self._added[path]
        if path in self._base.nodes or path in self._extra:
            self._deleted.add(path)

    def remove_tree(self, path: str, limit: int = 5000) -> None:
        """Remove ``path`` and everything under it (bounded)."""
        stack = [path]
        order: list[str] = []
        while stack and len(order) < limit:
            cur = stack.pop()
            order.append(cur)
            node = self._raw(cur)
            if node is not None and node.kind == "d":
                prefix = "/" if cur == ROOT else cur + "/"
                stack.extend(prefix + n for n in self.listdir(cur))
        for cur in reversed(order):
            if self._raw(cur) is not None:
                self.remove(cur)

    def copy(self, src: str, dst: str, owner: str) -> None:
        node = self._raw(src)
        if node is None:
            raise FSError("No such file or directory")
        if node.kind == "d":
            raise FSError("omitting directory")
        self._check_parent(dst)
        # a file with a declared size is copied as header + size: the filler is regenerated
        content = node.content if node.size > len(node.content) else self.read(src)
        self._put(dst, replace(node, content=content, owner=owner, mtime=self._now))

    def rename(self, src: str, dst: str) -> None:
        node = self._raw(src)
        if node is None:
            raise FSError("No such file or directory")
        if node.kind == "d":
            raise FSError("Operation not permitted")
        self._check_parent(dst)
        content = node.content if node.size > len(node.content) else self.read(src)
        if dst == src:
            return
        self._put(dst, replace(node, content=content, mtime=self._now))  # quota check first
        self.remove(src)
