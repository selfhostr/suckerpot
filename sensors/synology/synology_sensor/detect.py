"""Request analysis: parameters, flags, CVE hints and URLs. Pure functions, no regexes.

Nothing in here executes, evaluates or fetches anything. Every loop is bounded by a constant
(parameters, values, URLs), so the cost of a request is bounded as well.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote

from synology_sensor.httpio import Request

CVES = ["CVE-2026-13639", "CVE-2026-13684"]
MAX_PARAMS = 64
MAX_VALUE = 4096  # characters of one value that are looked at
MAX_URLS = 4
MAX_URL = 2048

_SID_PARAMS = frozenset({"_sid", "sid", "synotoken", "syno_token"})
_SID_COOKIES = frozenset({"id", "sid", "_sid", "synotoken"})
_SID_HEADERS = frozenset({"x-syno-token"})

_CGI_NAMES = (
    "CONTENT_LENGTH", "SCGI", "REQUEST_METHOD", "REQUEST_URI", "QUERY_STRING", "SCRIPT_NAME",
    "PATH_INFO", "REMOTE_ADDR", "REMOTE_USER", "SERVER_NAME", "SERVER_PORT", "DOCUMENT_ROOT",
    "HTTP_COOKIE", "HTTP_HOST", "HTTP_X_",
)  # fmt: skip
_HEADER_LIKE = (
    "content-length:", "transfer-encoding:", "set-cookie:", "x-accel-redirect:", "x-sendfile:",
    "x-forwarded-for:", "x-real-ip:", "x-original-uri:", "x-syno-token:", "content-type:",
)  # fmt: skip

_FS_WRITE_APIS = frozenset(
    {"upload", "rename", "delete", "copymove", "compress", "extract", "createfolder"}
)
_FS_READ_METHODS = frozenset({"status", "stop", "list", "getinfo", "get"})
_PACKAGE_APIS = frozenset({"installation", "uninstallation", "upload"})
_TASK_WRITE = frozenset({"create", "set", "run", "delete", "save", "start"})
_VERSION_APIS = frozenset({"syno.api.info", "syno.dsm.info", "syno.core.system"})
_VERSION_PATHS = frozenset({"/webman/info.cgi", "/webman/get_status.cgi"})
_SECRET_KEYS = frozenset({"passwd", "password", "pass", "pwd", "__ciphertext"})  # login events
_RANSOM = (".l0ck3d", "read-me3.txt")
_SCHEMES = ("http://", "https://", "ftp://", "ftps://", "tftp://", "sftp://")
_URL_END = frozenset("\"'<>\\ \t\r\n,;|^`{}[]()\x00")


@dataclass
class Analysis:
    api: str = ""
    api_method: str = ""
    api_version: str = ""
    params: list[tuple[str, str]] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    urls: list[tuple[str, str]] = field(default_factory=list)  # (parameter, url)
    uploads: list[str] = field(default_factory=list)  # multipart file names

    def get(self, *names: str) -> str:
        for key in names:
            for k, v in self.params:
                if k == key:
                    return v
        return ""


def has_control(text: str) -> bool:
    """CR, LF, NUL or any other control character except a tab."""
    return any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in text)


def _netstring(text: str) -> bool:
    """``<digits>:`` framing followed by SCGI-ish content (variable names or NUL bytes)."""
    body = text.lstrip()
    i = 0
    while i < len(body) and i < 8 and "0" <= body[i] <= "9":
        i += 1
    if i == 0 or i > 6 or body[i : i + 1] != ":":
        return False
    rest = body[i + 1 :]
    return "\x00" in rest or "CONTENT_LENGTH" in rest or "SCGI" in rest


def scgi_shape(text: str) -> bool:
    """Does a value carry the shape of a header / SCGI injection (CWE-116 style abuse)?"""
    text = text[:MAX_VALUE]
    if has_control(text):
        return True
    low = text.lower()
    if "%0d" in low or "%0a" in low or "%00" in low or "\\r\\n" in low:
        return True  # a second layer of encoding survived the first decode
    if any(name in text for name in _CGI_NAMES):
        return True
    if any(h in low for h in _HEADER_LIKE):
        return True
    return _netstring(text)


def _multipart(body: bytes, boundary: str, out: Analysis) -> None:
    marker = b"--" + boundary.encode("latin-1", "replace")[:200]
    for part in body.split(marker, 24)[1:24]:
        head, sep, value = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        name = filename = ""
        for line in head.split(b"\r\n")[:8]:
            text = line.decode("utf-8", "replace")
            if text.lower().startswith("content-disposition"):
                for item in text.split(";")[1:8]:
                    key, _, val = item.strip().partition("=")
                    val = val.strip('"')
                    if key == "name":
                        name = val[:128]
                    elif key == "filename":
                        filename = val[:256]
        if filename:
            if len(out.uploads) < 8:
                out.uploads.append(filename)
        elif name and len(out.params) < MAX_PARAMS:
            out.params.append(
                (
                    name,
                    value[: MAX_VALUE + 2].rstrip(b"\r\n-").decode("utf-8", "replace")[:MAX_VALUE],
                )
            )


def _json_params(body: bytes, out: Analysis) -> None:
    try:
        doc = json.loads(body[:65536])
    except ValueError, RecursionError:
        return
    if not isinstance(doc, dict):
        return
    for key, value in doc.items():
        if len(out.params) >= MAX_PARAMS:
            break
        text = value if isinstance(value, str) else json.dumps(value)[:MAX_VALUE]
        out.params.append((str(key)[:128], text[:MAX_VALUE]))


def collect(req: Request) -> Analysis:
    """Parameters from the query string and the body (form, multipart or JSON)."""
    out = Analysis()
    try:
        pairs = parse_qsl(req.query_raw, keep_blank_values=True, max_num_fields=MAX_PARAMS)
    except ValueError:
        pairs = []
    out.params = [(k[:128], v[:MAX_VALUE]) for k, v in pairs]
    body = req.body
    if body and len(out.params) < MAX_PARAMS:
        ctype = (req.header("content-type") or "").lower()
        if "multipart/form-data" in ctype:
            _, _, rest = (req.header("content-type") or "").partition("boundary=")
            boundary = rest.split(";")[0].strip().strip('"')
            if boundary:
                _multipart(body, boundary, out)
        elif "json" in ctype or body[:1] in (b"{",):
            _json_params(body, out)
        else:
            try:
                form = parse_qsl(
                    body[:65536].decode("utf-8", "replace"),
                    keep_blank_values=True,
                    max_num_fields=MAX_PARAMS,
                )
            except ValueError:
                form = []
            room = MAX_PARAMS - len(out.params)
            out.params += [(k[:128], v[:MAX_VALUE]) for k, v in form[:room]]
    out.api = out.get("api")[:128]
    out.api_method = out.get("method")[:64]
    out.api_version = out.get("version")[:16]
    return out


def find_urls(value: str) -> list[str]:
    """URLs inside a parameter value (plain, or inside a JSON list / quoted string)."""
    found: list[str] = []
    low = value[:MAX_VALUE].lower()
    pos = 0
    while len(found) < MAX_URLS and pos < len(low):
        hits = [(low.find(s, pos), s) for s in _SCHEMES]
        hits = [(i, s) for i, s in hits if i >= 0]
        if not hits:
            break
        start = min(hits)[0]
        end = start
        while end < len(value) and end - start < MAX_URL and value[end] not in _URL_END:
            end += 1
        url = value[start:end]
        if len(url) > 8:
            found.append(url)
        pos = max(end, start + 1)
    return found


def _api_flags(a: Analysis, flags: set[str]) -> None:
    api = a.api.lower()
    method = a.api_method.lower()
    parts = api.split(".")
    if api == "syno.api.auth" and method == "login":
        flags.add("dsm_login")
    if api in _VERSION_APIS or (api == "syno.core.desktop.initdata"):
        flags.add("dsm_version_probe")
    if api.startswith("syno.filestation."):
        sub = parts[2] if len(parts) > 2 else ""
        if sub in _FS_WRITE_APIS and method not in _FS_READ_METHODS:
            flags.add("file_write")
    elif api.startswith("syno.core.taskscheduler") and method in _TASK_WRITE:
        flags.add("file_write")
    elif api.startswith("syno.core.package."):
        sub = parts[3] if len(parts) > 3 else ""
        if sub in _PACKAGE_APIS and method not in _FS_READ_METHODS:
            flags.add("file_write")


def _sid_forge(req: Request, a: Analysis) -> bool:
    """A session id presented to a DSM web API call that is not itself the login.

    The id is ours to judge because the sensor never issues one. A session cookie or id on an
    ordinary page, and a login (with or without a password), are everyday traffic: not flagged.
    """
    if not req.path.lower().startswith("/webapi/"):
        return False
    if a.api.lower() == "syno.api.auth" and a.api_method.lower() == "login":
        return False
    if any(k.lower() in _SID_PARAMS for k, _ in a.params):
        return True
    if any(h.lower() in _SID_HEADERS for h, _ in req.headers):
        return True
    cookie = ";".join(v for k, v in req.headers if k.lower() == "cookie")[:4096]
    for item in cookie.split(";")[:32]:
        name, sep, value = item.strip().partition("=")
        if sep and name.lower() in _SID_COOKIES and value:
            return True
    return False


def analyse(req: Request, a: Analysis, *, is_login_path: bool = False) -> set[str]:
    """Flags for one request (``a`` comes from :func:`collect`)."""
    flags: set[str] = set()
    path = req.path
    low_path = path.lower()
    if low_path.startswith("/webapi/"):
        flags.add("dsm_api")
    if low_path in _VERSION_PATHS:
        flags.add("dsm_version_probe")
    _api_flags(a, flags)
    if is_login_path:
        flags.add("dsm_login")

    if not (req.header("user-agent") or "").strip():
        flags.add("no_user_agent")
    if req.body_truncated or req.body_len > 1024 * 1024:
        flags.add("oversized_body")

    if _sid_forge(req, a):
        flags.add("sid_forge")

    decoded_path = unquote(path[:MAX_VALUE])
    texts = [decoded_path, *(v for _, v in a.params[:MAX_PARAMS])]
    texts += [v[:MAX_VALUE] for _, v in req.headers[:64]]
    texts += [k for k, _ in a.params[:MAX_PARAMS] if len(k) > 0]
    if any(scgi_shape(t) for t in texts):
        flags.add("scgi_injection")

    haystack = " ".join(
        [low_path, unquote(req.query_raw[:MAX_VALUE]).lower()]
        + [u.lower() for u in a.uploads]
        + [v.lower() for _, v in a.params]
        + [v[:MAX_VALUE].lower() for _, v in req.headers[:64]]
    )
    raw = req.body[:65536].lower()
    if any(m in haystack or m.encode() in raw for m in _RANSOM):
        flags.add("ransom_indicator")
    return flags


def login_fields(a: Analysis) -> tuple[str, str, bool, bool]:
    """(username, password, otp_present, encrypted) of a login request."""
    user = a.get("account", "username", "user", "login")
    cipher = a.get("__cIpHeRtExT")
    password = cipher if cipher else a.get("passwd", "password", "pass", "pwd")
    otp = bool(a.get("otp_code", "otp", "otp_token"))
    return user[:256], password[:512], otp, bool(cipher)


def request_urls(a: Analysis) -> list[tuple[str, str]]:
    """URLs found in parameters, with the parameter they came from (bounded)."""
    out: list[tuple[str, str]] = []
    for key, value in a.params:
        if key.lower() in _SECRET_KEYS:
            continue
        for url in find_urls(value):
            if (key, url) not in out:
                out.append((key, url))
            if len(out) >= MAX_URLS:
                return out
    return out
