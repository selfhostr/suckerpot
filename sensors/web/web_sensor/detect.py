"""Request analysis: exploit flags, PHP2Shell (upload progress) detection, download extraction.

Everything here is passive pattern matching on bytes with ``in`` / ``find`` (linear time, no
regular expressions) over a bounded slice of the request. Nothing in a request is ever executed
or fetched: URLs found in payloads are only reported.
"""

from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote_to_bytes

from web_sensor.config import Config
from web_sensor.httpio import Request, to_text

CVES = ["CVE-2026-109618", "CVE-2026-109619"]

_BLOB_CAP = 24 * 1024
_HEADER_BLOB_CAP = 32 * 1024
_MAX_DOWNLOADS = 8
_MAX_SESSIDS = 10_000

# Flags that mark a request as an exploit attempt: their events get the guaranteed quota.
SEVERE = frozenset(
    {
        "php2shell", "upload_progress", "rce", "php_code", "rfi", "log4shell", "shellshock",
        "phpunit_rce", "laravel_rce", "router_exploit", "webshell_probe", "session_include",
    }
)  # fmt: skip

_PATH_SIGNATURES: list[tuple[bytes, str]] = [
    (b"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", "phpunit_rce"),
    (b"/_ignition/execute-solution", "laravel_rce"),
    (b"/cgi-bin/luci", "router_probe"),
    (b"/boaform/", "router_exploit"),
    (b"/gponform/", "router_exploit"),
    (b"/hnap1", "router_probe"),
    (b"/setup.cgi", "router_probe"),
    (b"/actuator", "spring_probe"),
    (b"/manager/html", "tomcat_probe"),
    (b"/solr/", "solr_probe"),
    (b"/containers/json", "docker_api_probe"),
    (b"/remote/login", "vpn_probe"),
    (b"/+cscoe+/", "vpn_probe"),
    (b"/mgmt/tm/", "f5_probe"),
    (b"/owa/", "exchange_probe"),
    (b"/autodiscover/", "exchange_probe"),
    (b"/console/", "console_probe"),
    (b"/jenkins", "jenkins_probe"),
    (b"/geoserver", "geoserver_probe"),
    (b"/vendor/phpunit", "phpunit_probe"),
    (b"/telescope", "laravel_probe"),
    (b"/.well-known/security.txt", "recon"),
    (b"/server-status", "recon"),
    (b"/server-info", "recon"),
    (b"/wp-config", "config_leak"),
    (b"/config.php", "config_leak"),
    (b"/configuration.php", "config_leak"),
    (b"/backup", "backup_probe"),
    (b"/dump.sql", "backup_probe"),
    (b"/adminer", "db_admin_probe"),
    (b"/phpmyadmin", "phpmyadmin"),
    (b"/pma", "phpmyadmin"),
    (b"/myadmin", "phpmyadmin"),
    (b"/pmd", "phpmyadmin"),
    (b"/wp-login", "wordpress"),
    (b"/wp-admin", "wordpress"),
    (b"/wp-content", "wordpress"),
    (b"/wp-includes", "wordpress"),
    (b"/wp-json", "wordpress"),
    (b"/xmlrpc.php", "wordpress"),
    (b"/info.php", "phpinfo_probe"),
    (b"/phpinfo", "phpinfo_probe"),
    (b"/cgi-bin/", "cgi_probe"),
]
_SHELL_NAMES = (
    b"shell.php", b"c99.php", b"r57.php", b"wso.php", b"b374k", b"alfa.php", b"cmd.php",
    b"webshell", b"up.php", b"uploader.php", b"xmrlpc.php", b"wp-content/uploads/",
    b"China.php", b"mini.php", b"sh.php", b"eval.php",
)  # fmt: skip

_BODY_PATTERNS: list[tuple[bytes, str]] = [
    # PHP code / RCE
    (b"<?php", "php_code"),
    (b"<?=", "php_code"),
    (b"eval(", "rce"),
    (b"system(", "rce"),
    (b"passthru(", "rce"),
    (b"shell_exec(", "rce"),
    (b"popen(", "rce"),
    (b"proc_open(", "rce"),
    (b"base64_decode(", "php_code"),
    (b"file_put_contents(", "php_code"),
    (b"assert(", "php_code"),
    (b"/bin/sh", "rce"),
    (b"/bin/bash", "rce"),
    (b"cmd.exe", "rce"),
    (b"powershell", "rce"),
    (b"wget http", "rce"),
    (b"wget -", "rce"),
    (b"curl http", "rce"),
    (b"curl -", "rce"),
    (b"tftp -", "rce"),
    (b"busybox", "rce"),
    (b"nc -e", "rce"),
    (b"bash -i", "rce"),
    (b"/dev/tcp/", "rce"),
    (b"chmod +x", "rce"),
    (b"chmod 777", "rce"),
    (b"uname -a", "rce"),
    (b"cat /etc/", "rce"),
    (b"${ifs}", "rce"),
    (b";id;", "rce"),
    (b"|id|", "rce"),
    (b"$(id)", "rce"),
    (b"`id`", "rce"),
    (b"whoami", "rce"),
    # SQL injection
    (b"union select", "sqli"),
    (b"union all select", "sqli"),
    (b"' or '1'='1", "sqli"),
    (b"' or 1=1", "sqli"),
    (b" or 1=1", "sqli"),
    (b"sleep(", "sqli"),
    (b"benchmark(", "sqli"),
    (b"information_schema", "sqli"),
    (b"waitfor delay", "sqli"),
    (b"extractvalue(", "sqli"),
    (b"updatexml(", "sqli"),
    # XSS
    (b"<script", "xss"),
    (b"javascript:", "xss"),
    (b"onerror=", "xss"),
    (b"onload=", "xss"),
    # Traversal and file inclusion
    (b"../", "path_traversal"),
    (b"..\\", "path_traversal"),
    (b"/etc/passwd", "lfi"),
    (b"/etc/shadow", "lfi"),
    (b"/proc/self/", "lfi"),
    (b"win.ini", "lfi"),
    (b"boot.ini", "lfi"),
    (b"php://filter", "lfi"),
    (b"php://input", "lfi"),
    (b"php://", "php_wrapper"),
    (b"data://", "php_wrapper"),
    (b"data:text/plain", "php_wrapper"),
    (b"expect://", "php_wrapper"),
    (b"zip://", "php_wrapper"),
    (b"phar://", "php_wrapper"),
    (b"file://", "lfi"),
    # Misc
    (b"169.254.169.254", "ssrf"),
    (b"metadata.google.internal", "ssrf"),
]
_SCANNER_UAS = (
    b"nikto", b"sqlmap", b"nmap", b"masscan", b"zgrab", b"nuclei", b"wpscan", b"dirbuster",
    b"gobuster", b"feroxbuster", b"ffuf", b"wfuzz", b"acunetix", b"nessus", b"openvas", b"burp",
    b"zmeu", b"censys", b"expanse", b"shodan", b"netcraft", b"fuzz faster",
)  # fmt: skip

_LFI_PARAMS = frozenset(
    {
        "file", "page", "include", "inc", "path", "template", "load", "view", "document", "doc",
        "dir", "conf", "lang", "content", "module", "theme", "plugin", "folder", "pg", "style",
        "pdf", "action", "cat", "name", "f", "p", "url", "src", "source", "layout",
    }
)  # fmt: skip

_SESS_DIRS = (b"/tmp/sess_", b"/var/lib/php/sessions/sess_", b"/var/lib/php5/sess_",
              b"/var/lib/php/session/sess_", b"/var/tmp/sess_", b"\\tmp\\sess_")  # fmt: skip
_SID_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,-")

_DOWNLOAD_TOOLS = (
    b"wget", b"curl", b"tftp", b"ftpget", b"fetch", b"lwp-download", b"certutil", b"bitsadmin",
    b"invoke-webrequest", b"downloadfile", b"downloadstring", b"start-bitstransfer",
)  # fmt: skip
_SEPARATORS = b"\t\r\n;|&'\"()<>{}`\\^,"
_SEP_TABLE = bytes.maketrans(_SEPARATORS, b" " * len(_SEPARATORS))
_URL_SCHEMES = ("http://", "https://", "ftp://", "tftp://")


@dataclass
class Analysis:
    flags: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    php2shell: dict[str, Any] | None = None
    basic_auth: tuple[str, str] | None = None

    @property
    def severe(self) -> bool:
        return any(f in SEVERE for f in self.flags)


def decode_bytes(raw: str, rounds: int = 2, cap: int = 4096) -> bytes:
    """Percent-decode a latin-1 view of wire bytes (twice, to see double-encoding)."""
    data = raw[:cap].encode("latin-1", "replace")
    for _ in range(rounds):
        if b"%" not in data:
            break
        data = unquote_to_bytes(data)
    return data


def cookie_value(cookie: str | None, name: str) -> str | None:
    if not cookie:
        return None
    want = name.lower()
    for part in cookie.split(";")[:64]:
        k, sep, v = part.partition("=")
        if sep and k.strip().lower() == want:
            return v.strip()[:256]
    return None


def _sid_after(data: bytes, start: int) -> str:
    end = start
    while end < len(data) and end - start < 128 and data[end] in _SID_CHARS:
        end += 1
    return data[start:end].decode("ascii")


def _query_pairs(query: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for item in query.split("&")[:64]:
        k, _, v = item.partition("=")
        key = decode_bytes(k, 1).decode("latin-1").lower()
        pairs.append((key, decode_bytes(v).decode("latin-1")))
    return pairs


def _extract_url(tokens: list[bytes], start: int) -> str | None:
    for tok in tokens[start : start + 24]:
        text = tok.decode("latin-1")
        low = text.lower()
        for scheme in _URL_SCHEMES:
            idx = low.find(scheme)
            if idx != -1:
                url = text[idx:]
                if len(url) > len(scheme) + 1:
                    return url[:2048]
    return None


def extract_downloads(orig: bytes, low: bytes, query: str) -> list[dict[str, Any]]:
    """Find download commands (wget, curl, tftp, ...) and payload URLs. Never fetches."""
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(url: str, tool: str, command: bytes, via: str) -> None:
        if url in seen or len(found) >= _MAX_DOWNLOADS:
            return
        seen.add(url)
        found.append(
            {
                "url": url,
                "tool": tool,
                "command": command[:256].decode("utf-8", "replace"),
                "via": via,
            }
        )

    for tool in _DOWNLOAD_TOOLS:
        pos = 0
        for _ in range(8):
            idx = low.find(tool, pos)
            if idx == -1:
                break
            pos = idx + len(tool)
            segment = orig[idx : idx + 600]
            for ifs in (b"${IFS}", b"${ifs}", b"$IFS", b"$ifs"):
                segment = segment.replace(ifs, b" ")
            tokens = segment.translate(_SEP_TABLE).split()
            if not tokens:
                continue
            if tool == b"tftp":
                host = next((t for t in tokens[1:] if b"." in t and not t.startswith(b"-")), None)
                fname = None
                for i, t in enumerate(tokens):
                    if t == b"-r" and i + 1 < len(tokens):
                        fname = tokens[i + 1]
                if host is not None:
                    path = fname.decode("latin-1") if fname else ""
                    add(f"tftp://{host.decode('latin-1')}/{path}", "tftp", segment, "payload")
                continue
            url = _extract_url(tokens, 1)
            if url:
                add(url, tool.decode("ascii"), segment, "payload")
    # Log4Shell style callbacks.
    pos = 0
    for _ in range(4):
        idx = low.find(b"${jndi:", pos)
        if idx == -1:
            break
        pos = idx + 7
        end = orig.find(b"}", idx, idx + 600)
        ref = orig[idx + 7 : end if end != -1 else idx + 300]
        if b"://" in ref:
            add(ref.decode("latin-1")[:1024], "jndi", orig[idx : idx + 300], "payload")
    # Remote file inclusion: a URL as the value of a file-like parameter.
    for key, value in _query_pairs(query):
        if key in _LFI_PARAMS and value.lower().startswith(("http://", "https://", "ftp://")):
            add(value[:2048], "rfi", f"{key}={value}".encode("latin-1", "replace"), "query")
    return found


class Detector:
    """Stateful analyser. State: which PHP session IDs recent upload-progress requests used."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._field = cfg.upload_progress_name.lower().encode()
        self._sessids: OrderedDict[str, str] = OrderedDict()

    def _remember_sid(self, sid: str, ip: str) -> None:
        if not sid:
            return
        self._sessids[sid] = ip
        self._sessids.move_to_end(sid)
        while len(self._sessids) > _MAX_SESSIDS:
            self._sessids.popitem(last=False)

    def analyze(self, req: Request, src_ip: str) -> Analysis:
        out = Analysis()
        flags: set[str] = set()
        path_dec = decode_bytes(req.path)
        query_dec = decode_bytes(req.query)
        body_dec = decode_bytes(req.body[:16384].decode("latin-1"), cap=16384) if req.body else b""
        header_blob = bytearray()
        for k, v in req.headers:
            if len(header_blob) > _HEADER_BLOB_CAP:
                break
            header_blob += k.encode("latin-1", "replace")[:128] + b": "
            header_blob += v.encode("latin-1", "replace")[:1024] + b"\n"
        orig = path_dec + b"?" + query_dec + b"\n" + body_dec
        orig = orig[:_BLOB_CAP]
        low = orig.lower()
        raw_low = (req.path + "?" + req.query).encode("latin-1", "replace")[:4096].lower()
        hdr_low = bytes(header_blob).lower()

        for needle, flag in _BODY_PATTERNS:
            if needle in low or (needle in (b"../", b"..\\") and (b"%2e%2e" in raw_low)):
                flags.add(flag)
        path_low = path_dec.lower()
        for needle, flag in _PATH_SIGNATURES:
            if needle in path_low:
                flags.add(flag)
        for name in _SHELL_NAMES:
            if name.lower() in path_low and (b".php" in path_low):
                flags.add("webshell_probe")
        self._dotfiles(path_dec, flags)
        if b"${jndi:" in hdr_low or b"${jndi:" in low or b"${${" in low or b"${lower:" in low:
            flags.add("log4shell")
        if b"() {" in hdr_low or b"() {" in low:
            flags.add("shellshock")
        ua = (req.header("user-agent") or "").encode("latin-1", "replace").lower()
        if any(s in ua for s in _SCANNER_UAS):
            flags.add("scanner_ua")
        if not ua:
            flags.add("no_user_agent")
        # Parameter-based file inclusion.
        for key, value in _query_pairs(req.query):
            if key in _LFI_PARAMS and (
                value.startswith(("/", "..")) or "://" in value or "sess_" in value
            ):
                flags.add("lfi")
        self._php2shell(req, src_ip, low, flags, out)

        out.downloads = extract_downloads(orig, low, req.query)
        if b"${jndi:" in hdr_low:
            for dl in extract_downloads(bytes(header_blob), hdr_low, ""):
                if all(dl["url"] != d["url"] for d in out.downloads):
                    dl["via"] = "header"
                    out.downloads.append(dl)
        if any(d["tool"] == "rfi" for d in out.downloads):
            flags.add("rfi")
        out.basic_auth = _basic_auth(req.header("authorization"))
        # CVE-specific claim: PHP code inside the value of the upload-progress field (not
        # elsewhere in the request), or the include of a
        # session file this sensor saw created through that field. Touching the feature, or a
        # bare session-file include, stays a probe (`upload_progress` / `session_include`).
        in_field = bool(out.php2shell and out.php2shell.get("code_in_field"))
        if in_field or "session_ref_match" in flags:
            flags.add("php2shell")
            out.cve = list(CVES)
        out.flags = sorted(flags)
        return out

    @staticmethod
    def _dotfiles(path: bytes, flags: set[str]) -> None:
        for seg in path.split(b"/")[:32]:
            if seg.startswith(b".") and seg not in (b".", b"..", b".well-known"):
                flags.add("recon_dotfile")
                if seg in (b".env", b".aws", b".ssh", b".htpasswd", b".npmrc", b".git", b".svn"):
                    flags.add("config_leak")
        for ext in (b".bak", b".old", b".sql", b".zip", b".tar.gz", b".swp", b".orig", b"~"):
            if path.lower().endswith(ext):
                flags.add("backup_probe")

    def _php2shell(
        self, req: Request, src_ip: str, low: bytes, flags: set[str], out: Analysis
    ) -> None:
        field_name = self._field
        ctype = (req.header("content-type") or "").lower()
        body = req.body
        body_low = body.lower()
        query_low = decode_bytes(req.query).lower()
        sid = cookie_value(req.header("cookie"), "PHPSESSID")
        info: dict[str, Any] = {}

        pos = -1
        for marker in (b'name="' + field_name, b"name='" + field_name, b"name=" + field_name):
            pos = body_low.find(marker)
            if pos != -1:
                break
        in_body = pos != -1
        if not in_body:
            pos = body_low.find(field_name + b"=") if "x-www-form-urlencoded" in ctype else -1
        in_query = field_name + b"=" in query_low
        if pos != -1 or in_query or b"upload_progress_" in low:
            flags.add("upload_progress")
            info["field"] = self._cfg.upload_progress_name
            info["multipart"] = "multipart/form-data" in ctype
            info["where"] = "body" if pos != -1 else ("query" if in_query else "payload")
            value = ""
            if pos != -1:
                value = _field_value(body, pos, multipart=in_body)
                info["value_preview"] = value
            elif in_query:
                value = _query_field_value(query_low, field_name)
            info["code_in_field"] = _has_code(value)
            if pos != -1:
                fname = body_low.find(b"filename=")
                info["progress_before_file"] = fname == -1 or fname > pos
            if req.content_length is not None:
                info["content_length"] = req.content_length
                if req.content_length >= 64 * 1024:
                    flags.add("oversized_upload")
            if req.body_truncated:
                flags.add("oversized_upload")
            if req.body_seconds >= 5.0:
                flags.add("slow_upload")
            if sid:
                flags.add("session_cookie")
            if sid is not None:
                info["phpsessid"] = sid[:128]
                self._remember_sid(sid, src_ip)
        # Follow-up: including the session file through a file-inclusion parameter.
        for directory in _SESS_DIRS:
            at = low.find(directory)
            if at != -1:
                ref = _sid_after(low, at + len(directory))
                flags.update({"lfi", "session_include"})
                info["session_ref"] = ref
                info["session_dir"] = directory[:-5].decode("ascii")
                owner = self._sessids.get(ref)
                if owner is not None:
                    flags.add("session_ref_match")
                    info["session_ref_same_ip"] = owner == src_ip
                break
        else:
            at = low.find(b"sess_")
            if at != -1 and (b"../" in low or b"php://" in low or b"/tmp" in low):
                ref = _sid_after(low, at + 5)
                flags.update({"lfi", "session_include"})
                info["session_ref"] = ref
        if info:
            out.php2shell = info


_CODE_NEEDLES = tuple(n for n, f in _BODY_PATTERNS if f in ("php_code", "rce"))


def _has_code(value: str) -> bool:
    """PHP code or a command in the (already capped) value of the upload-progress field."""
    low = value[:512].encode("latin-1", "replace").lower()
    return any(n in low for n in _CODE_NEEDLES)


def _query_field_value(query_low: bytes, field_name: bytes) -> str:
    start = query_low.find(field_name + b"=")
    if start == -1:
        return ""
    start += len(field_name) + 1
    end = query_low.find(b"&", start, start + 1024)
    raw = unquote_to_bytes(query_low[start : end if end != -1 else start + 1024])
    return raw.decode("latin-1")[:512]


def _field_value(body: bytes, pos: int, *, multipart: bool) -> str:
    """The value of the upload-progress field, as text (for the event; capped)."""
    if multipart:
        start = body.find(b"\r\n\r\n", pos, pos + 1024)
        if start == -1:
            start = body.find(b"\n\n", pos, pos + 1024)
            skip = 2
        else:
            skip = 4
        if start == -1:
            return ""
        start += skip
        end = body.find(b"\r\n--", start, start + 1024)
        raw = body[start : end if end != -1 else start + 1024]
    else:
        start = body.find(b"=", pos, pos + 128)
        if start == -1:
            return ""
        end = body.find(b"&", start, start + 1024)
        raw = unquote_to_bytes(body[start + 1 : end if end != -1 else start + 1024])
    return to_text(raw.decode("latin-1"))[:512]


def _basic_auth(value: str | None) -> tuple[str, str] | None:
    if not value or not value.lower().startswith("basic "):
        return None
    token = value[6:].strip()
    if not token or len(token) > 1024:
        return None
    try:
        decoded = base64.b64decode(token, validate=True)
    except ValueError:
        return None
    user, sep, password = decoded.decode("utf-8", "replace").partition(":")
    return (user[:256], password[:256]) if sep else None
