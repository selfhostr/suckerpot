"""Per-install identity: the SSH KEXINIT must look like a stock OpenSSH 9.6p1 on Ubuntu 24.04."""

from __future__ import annotations

import asyncio
import struct
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

import asyncssh
import pytest
from conftest import Harness


async def _read_kexinit(port: int) -> list[list[str]]:
    """Connect with a raw socket and return the ten name-lists of the server's KEXINIT."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
        await writer.drain()
        await reader.readuntil(b"\n")
        head = await reader.readexactly(5)
        length, pad = struct.unpack(">IB", head)
        body = await reader.readexactly(length - 1)
    finally:
        writer.close()
    payload = body[: len(body) - pad]
    assert payload[0] == 20
    pos = 17  # message type + 16 byte cookie
    lists: list[list[str]] = []
    for _ in range(10):
        (n,) = struct.unpack(">I", payload[pos : pos + 4])
        pos += 4
        lists.append(payload[pos : pos + n].decode().split(",") if n else [])
        pos += n
    return lists


async def test_kexinit_matches_stock_openssh(
    make_harness: Callable[..., AbstractAsyncContextManager[Harness]],
) -> None:
    async with make_harness() as h:
        kex, hostkey, enc_c, enc_s, mac_c, mac_s, comp_c, comp_s, _, _ = await _read_kexinit(h.port)
    assert kex[0] == "curve25519-sha256"
    assert "ext-info-s" in kex
    assert "kex-strict-s-v00@openssh.com" in kex
    assert "diffie-hellman-group1-sha1" not in kex
    assert hostkey[:2] == ["rsa-sha2-512", "rsa-sha2-256"]
    assert enc_c == enc_s and mac_c == mac_s
    assert enc_c[0] == "chacha20-poly1305@openssh.com"
    assert comp_c == comp_s == ["none"]


async def test_keyboard_interactive_is_not_offered(
    make_harness: Callable[..., AbstractAsyncContextManager[Harness]],
) -> None:
    async with make_harness() as h:
        with pytest.raises(asyncssh.PermissionDenied):
            await h.connect(preferred_auth="keyboard-interactive", password="root")


async def test_advertised_auth_methods_are_publickey_and_password(
    make_harness: Callable[..., AbstractAsyncContextManager[Harness]],
) -> None:
    async with make_harness() as h:
        methods = await asyncssh.get_server_auth_methods("127.0.0.1", h.port, "root")
    assert ",".join(methods) == "publickey,password"
