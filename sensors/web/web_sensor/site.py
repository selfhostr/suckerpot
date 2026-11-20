"""The fake site: routing and handlers for the Apache + mod_php + WordPress stack.

Nothing here executes request data. Handlers return canned or templated output and a list of
captured credentials; the server turns those into events.
"""

from __future__ import annotations

import html
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, quote

from suckerpot_common import traps as fmt

from web_sensor import apache, xmlrpc
from web_sensor.assets import css, jquery, js, png
from web_sensor.config import Config
from web_sensor.content import phpinfo, pma, wordpress
from web_sensor.detect import Analysis, _query_pairs
from web_sensor.httpio import HttpError, Request, to_text
from web_sensor.profile import Profile
from web_sensor.response import Response
from web_sensor.traps import Hit, RenderValues, render_template, specificity

NOCACHE = [
    ("Expires", "Wed, 11 Jan 1984 05:00:00 GMT"),
    ("Cache-Control", "no-cache, must-revalidate, max-age=0, no-store, private"),
]
KERNEL = "6.8.0-100-generic"
KERNEL_BUILD = "#100-Ubuntu SMP PREEMPT_DYNAMIC Tue Sep  8 15:11:32 UTC 2026"
_HEX = frozenset("0123456789abcdefABCDEF")
_MIME = {
    ".css": "text/css",
    ".js": "text/javascript",
    ".png": "image/png",
    ".txt": "text/plain",
    ".html": "text/html",
    ".xml": "text/xml",
    ".ico": "image/vnd.microsoft.icon",
    ".gif": "image/gif",
    ".jpg": "image/jpeg",
    ".json": "application/json",
}
_ICON = {
    ".txt": ("text.gif", "TXT"),
    ".png": ("image2.gif", "IMG"),
    ".jpg": ("image2.gif", "IMG"),
    ".gif": ("image2.gif", "IMG"),
}


@dataclass
class Ctx:
    src_ip: str
    src_port: int
    tls: bool
    public_port: int
    now: float
    max_response: int = 8 * 1024 * 1024  # body bytes a handler may build (memory budget)


@dataclass
class Outcome:
    resp: Response
    app: str = "apache"
    route: str = ""
    logins: list[dict[str, Any]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticFile:
    body: bytes
    mtime: float


def normalize_path(raw: str) -> str:
    """Percent-decode and clean a request path like Apache does. Raises HttpError."""
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] == "%":
            if i + 2 >= n or raw[i + 1] not in _HEX or raw[i + 2] not in _HEX:
                raise HttpError(400)
            i += 3
        else:
            i += 1
    from urllib.parse import unquote_to_bytes

    if "%2f" in raw.lower():
        raise HttpError(404, close=False)
    data = unquote_to_bytes(raw.encode("latin-1", "replace"))
    if b"\x00" in data:
        raise HttpError(404, close=False)
    parts: list[str] = []
    for seg in data.decode("latin-1").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                raise HttpError(400)
            parts.pop()
            continue
        parts.append(seg)
    trailing = raw.endswith("/") or raw.rsplit("/", 1)[-1] in (".", "..") or data.endswith(b"/")
    path = "/" + "/".join(parts)
    if trailing and not path.endswith("/"):
        path += "/"
    return path


_EXTRA_DIRS = frozenset(
    {"/wp-content/", "/wp-content/plugins/", "/wp-content/themes/", "/wp-admin/", "/wp-includes/"}
)


class Site:
    def __init__(self, cfg: Config, profile: Profile, started: str) -> None:
        self.cfg = cfg
        self.p = profile
        self.started = started
        self.static: dict[str, StaticFile] = {}
        self.dirs: dict[str, list[tuple[str, bool, int, float]]] = {}
        self.multicall = xmlrpc.MulticallLimiter()
        self._build_static()

    # -- content registry ------------------------------------------------------------------

    def _build_static(self) -> None:
        p = self.p
        wp = self.cfg.wp_version
        t0 = p.install_ts
        add = self._add
        add("/readme.html", wordpress.readme_html(wp).encode(), t0 + 60)
        add("/license.txt", wordpress.LICENSE_TXT.encode(), t0 + 60)
        base = "/wp-content/themes/twentytwentyfour"
        add(f"{base}/style.css", wordpress.THEME_STYLE_CSS.encode(), t0 + 120)
        add(f"{base}/readme.txt", wordpress.THEME_README.encode(), t0 + 120)
        add("/wp-content/plugins/akismet/readme.txt", wordpress.AKISMET_README.encode(), t0 + 180)
        add("/wp-includes/images/w-logo-blue-white-bg.png", png(32, 32, (33, 117, 155)), t0 + 60)
        add(
            "/wp-includes/css/dist/block-library/style.min.css", css("block-library", 6000), t0 + 60
        )
        add("/wp-includes/css/dashicons.min.css", css("dashicons", 3000), t0 + 60)
        add("/wp-includes/css/buttons.min.css", css("buttons", 1800), t0 + 60)
        add("/wp-admin/css/forms.min.css", css("forms", 2400), t0 + 60)
        add("/wp-admin/css/l10n.min.css", css("l10n", 700), t0 + 60)
        add("/wp-admin/css/login.min.css", css("login", 2200), t0 + 60)
        add("/wp-admin/css/install.css", css("install", 1500), t0 + 60)
        add("/wp-includes/js/jquery/jquery.min.js", jquery(), t0 + 60)
        add("/wp-includes/js/wp-emoji-release.min.js", js("wp-emoji-release", 1600), t0 + 60)
        for pma_base in ("/phpmyadmin", "/pma"):
            add(f"{pma_base}/themes/pmahomme/css/theme.css", css("pmahomme", 5000), t0 + 90)
            add(f"{pma_base}/js/vendor/jquery/jquery.min.js", jquery(), t0 + 90)
            add(
                f"{pma_base}/README",
                (
                    f"phpMyAdmin - Readme\n===================\n\nVersion {self.cfg.pma_version}\n\n"
                    "A web interface for MySQL and MariaDB.\n\nhttps://www.phpmyadmin.net/\n"
                ).encode(),
                t0 + 90,
            )
        # uploads: a plausible media tree
        rng = p.rng("uploads")
        import datetime as _dt

        first = _dt.datetime.fromtimestamp(p.install_ts, _dt.UTC)
        last = _dt.datetime.fromtimestamp(p.created, _dt.UTC)
        years: dict[int, set[int]] = {}
        y, m = first.year, first.month
        while (y, m) <= (last.year, last.month):
            if rng.random() < 0.55 or (y, m) == (first.year, first.month):
                years.setdefault(y, set()).add(m)
            m += 1
            if m == 13:
                y, m = y + 1, 1
        up = "/wp-content/uploads/"
        self.dirs[up] = []
        for year, months in sorted(years.items()):
            ydir = f"{up}{year}/"
            self.dirs[up].append((f"{year}/", True, 0, p.install_ts + 400))
            self.dirs[ydir] = []
            for month in sorted(months):
                mdir = f"{ydir}{month:02d}/"
                self.dirs[ydir].append((f"{month:02d}/", True, 0, p.install_ts + 500 + month))
                self.dirs[mdir] = []
                for k in range(rng.randrange(1, 3)):
                    fname = f"{rng.choice(['image', 'banner', 'photo', 'logo', 'team'])}-{rng.randrange(1, 40)}.png"
                    data = png(
                        rng.choice([64, 96, 120]), rng.choice([64, 80]), (rng.randrange(256),) * 3
                    )
                    mt = p.install_ts + 600 + month * 3600 + k
                    self.static[f"{mdir}{fname}"] = StaticFile(data, mt)
                    self.dirs[mdir].append((fname, False, len(data), mt))
        self.dirs["/wp-includes/"] = [
            ("ID3/", True, 0, t0 + 60),
            ("PHPMailer/", True, 0, t0 + 60),
            ("assets/", True, 0, t0 + 60),
            ("blocks/", True, 0, t0 + 60),
            ("css/", True, 0, t0 + 60),
            ("fonts/", True, 0, t0 + 60),
            ("images/", True, 0, t0 + 60),
            ("js/", True, 0, t0 + 60),
            ("version.php", False, 8710, t0 + 60),
        ]

    def _add(self, path: str, body: bytes, mtime: float) -> None:
        self.static[path] = StaticFile(body, mtime)

    # -- Apache building blocks ------------------------------------------------------------

    def sig_host(self, req: Request | None, ctx: Ctx) -> tuple[str, int]:
        if req is not None and req.host:
            return req.host, req.host_port or ctx.public_port
        return self.p.server_ip, ctx.public_port

    def error(
        self,
        status: int,
        req: Request | None,
        ctx: Ctx,
        *,
        method: str = "",
        url: str = "",
        extra: str = "",
        headers: list[tuple[str, str]] | None = None,
        close: bool = False,
    ) -> Response:
        host, port = self.sig_host(req, ctx)
        body = apache.error_page(
            status,
            server=self.cfg.server_token,
            host=host,
            port=port,
            method=method,
            url=url,
            extra=extra,
        )
        return Response(
            status=status,
            body=body,
            content_type="text/html; charset=iso-8859-1",
            headers=headers or [],
            kind="error",
            close=close,
        )

    def error_for(self, err: HttpError, req: Request | None, ctx: Ctx) -> Response:
        method = req.method if req else ""
        if not err.host:
            req = None
        headers: list[tuple[str, str]] = []
        if err.status == 501:
            headers = [("Allow", apache.ALLOW_DEFAULT)]
        resp = self.error(
            err.status, req, ctx, method=method, extra=err.extra, headers=headers, close=err.close
        )
        if err.status == 413:
            resp.no_length = True
        return resp

    def base_url(self, req: Request, ctx: Ctx) -> str:
        scheme = "https" if ctx.tls else "http"
        if req.host:
            hp = req.host + (f":{req.host_port}" if req.host_port else "")
        else:
            hp = self.p.server_ip
        return f"{scheme}://{hp}"

    def php(
        self,
        body: str | bytes,
        ctype: str = "text/html; charset=UTF-8",
        *,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
        close: bool = False,
    ) -> Response:
        data = body.encode() if isinstance(body, str) else body
        return Response(
            status=status,
            body=data,
            content_type=ctype,
            headers=headers or [],
            kind="php",
            close=close,
        )

    # -- trap packs ------------------------------------------------------------------------

    def serves(self, path: str) -> bool:
        """A path the built-in site answers itself: a trap needs more than a path there."""
        low = path.lower()
        return fmt.is_reserved_path(low) or path in self.static or path in self.dirs

    def trap_active(self, hit: Hit, groups: dict[str, tuple[str, ...]]) -> bool:
        """Whether this install answers as the pack's product (presence and persona group).
        Detection never depends on it."""
        pack = hit.pack
        if pack.presence < 1.0 and self.p.rng(f"trap:presence:{pack.id}").random() >= pack.presence:
            return False
        if pack.group:
            members = groups.get(pack.group, (pack.id,))
            label = f"trap:group:{pack.group}:"
            return max(members, key=lambda m: self.p.derive(label + m, 32)) == pack.id
        return True

    def trap_outcome(
        self, req: Request, ctx: Ctx, hits: list[Hit], groups: dict[str, tuple[str, ...]]
    ) -> Outcome | None:
        """The fake answer of the most specific responding trap, or None (the site answers)."""
        if not hits or req.method not in apache.KNOWN_METHODS or req.target == "*":
            return None
        candidates = [h for h in hits if h.trap.respond is not None]
        if not candidates:
            return None
        try:
            path = normalize_path(req.path)
        except HttpError:
            return None
        reserved = self.serves(path)
        usable = [
            h
            for h in candidates
            if (not reserved or fmt.may_answer_on_reserved_path(h.trap))
            and self.trap_active(h, groups)
        ]
        if not usable:
            return None
        hit = min(usable, key=specificity)
        route = f"trap:{hit.pack.id}/{hit.trap.id}"
        return Outcome(self._trap_response(hit, req, ctx), app="trap", route=route)

    def _trap_response(self, hit: Hit, req: Request, ctx: Ctx) -> Response:
        r = hit.trap.respond
        if r is None:  # checked by the caller
            raise ValueError("trap without respond")
        p = self.p
        query: dict[str, str] = {}
        for key, value in _query_pairs(req.query):
            query.setdefault(key, value)
        values = RenderValues(
            self.cfg.hostname,
            p.server_ip,
            p.site_title,
            self.base_url(req, ctx),
            self.cfg.server_token,
            self.cfg.php_version,
            ctx.now,
            p.install_ts,
            query,
        )
        # One variant per install and pack: the probe and exploit answers of a pack agree.
        idx = p.rng(f"trap:{hit.pack.id}").randrange(65536) % len(r.variants)
        label = f"trap:{hit.pack.id}:{hit.trap.id}"
        text = render_template(r.variants[idx], values, p.derive, p.rng, label)
        body = text.encode("utf-8")[: fmt.MAX_BODY].decode("utf-8", "ignore").encode("utf-8")
        headers: list[tuple[str, str]] = []
        if r.kind == "static":
            headers += [
                ("Last-Modified", apache.http_date(p.install_ts)),
                ("ETag", apache.etag(len(body), p.install_ts)),
                ("Accept-Ranges", "bytes"),
            ]
        for name, tpl in r.headers:
            value = render_template(tpl, values, p.derive, p.rng, f"{label}:{name}")
            headers.append((name, "".join(c for c in value if " " <= c <= "~")[:512]))
        return Response(
            status=r.status,
            body=body,
            content_type=r.content_type,
            headers=headers,
            kind="php" if r.kind == "php" else ("static" if r.kind == "static" else "error"),
            app="trap",
            route=f"trap:{hit.pack.id}/{hit.trap.id}",
        )

    def _wp_link(self, base: str) -> tuple[str, str]:
        return ("Link", f'<{base}/wp-json/>; rel="https://api.w.org/"')

    # -- entry point -----------------------------------------------------------------------

    def handle(self, req: Request, ctx: Ctx, analysis: Analysis) -> Outcome:
        method = req.method
        if method not in apache.KNOWN_METHODS:
            return Outcome(self.error_for(HttpError(501), req, ctx), route="unknown-method")
        if method == "TRACE":
            return Outcome(
                self.error(405, req, ctx, method=method, headers=[("Allow", "")]), route="trace"
            )
        if method == "CONNECT":
            return Outcome(
                self.error(405, req, ctx, method=method, headers=[("Allow", apache.ALLOW_DEFAULT)]),
                route="connect",
            )
        if req.target == "*":
            return Outcome(Response(status=200, kind="error"), route="options-star")
        try:
            path = normalize_path(req.path)
        except HttpError as err:
            return Outcome(self.error_for(err, req, ctx), route="bad-path")
        out = self._route(req, ctx, path, analysis)
        if (
            out.resp.status == 404
            and out.resp.kind == "error"
            and method not in ("GET", "POST", "HEAD")
        ):
            pass
        return out

    # -- routing ---------------------------------------------------------------------------

    def _static_method_gate(self, req: Request, ctx: Ctx) -> Response | None:
        """Methods the default (static) handler refuses or answers itself."""
        m = req.method
        if m == "OPTIONS":
            return Response(status=200, headers=[("Allow", apache.ALLOW_DEFAULT)], kind="error")
        if m not in ("GET", "HEAD", "POST"):
            return self.error(405, req, ctx, method=m, headers=[("Allow", apache.ALLOW_DEFAULT)])
        return None

    def _route(self, req: Request, ctx: Ctx, path: str, analysis: Analysis) -> Outcome:
        segs = [s for s in path.split("/") if s]
        # Hidden files and directories: .htaccess & friends are denied, everything else is 404.
        for seg in segs:
            if seg.startswith(".") and seg != ".well-known":
                gate = self._static_method_gate(req, ctx)
                if gate is not None:
                    return Outcome(gate, route="dotfile")
                status = 403 if seg.startswith(".ht") else 404
                return Outcome(self.error(status, req, ctx), route="dotfile")
        # PHP scripts (the .php handler also serves PATH_INFO after the script name).
        for i, seg in enumerate(segs):
            if seg.endswith(".php"):
                script = "/" + "/".join(segs[: i + 1])
                info = "/" + "/".join(segs[i + 1 :]) if i + 1 < len(segs) else ""
                return self._php_script(req, ctx, script, info, analysis)
        for root in ("/phpmyadmin", "/pma"):
            if path == root or path.startswith(root + "/"):
                return self._pma(req, ctx, root, path, analysis)
        if path == "/server-status" or path.startswith("/server-status/"):
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(403, req, ctx), route="server-status")
        if path.startswith("/cgi-bin"):
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(404, req, ctx), route="cgi-bin")
        if path == "/icons/":
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(403, req, ctx), route="icons")
        if path.startswith("/icons/"):
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(404, req, ctx), route="icons")
        # Directories.
        if path in self.dirs:
            return self._autoindex(req, ctx, path)
        if path in ("/wp-content/", "/wp-content/plugins/", "/wp-content/themes/"):
            return Outcome(self.php(b""), app="wordpress", route="silence")
        if not path.endswith("/") and (path + "/") in (self.dirs.keys() | _EXTRA_DIRS):
            return Outcome(self._dir_redirect(req, ctx, path), route="dir-redirect")
        if path in self.static:
            return self._serve_static(req, ctx, path)
        return self._wordpress(req, ctx, path, analysis)

    def _dir_redirect(self, req: Request, ctx: Ctx, path: str) -> Response:
        host, port = self.sig_host(req, ctx)
        scheme = "https" if ctx.tls else "http"
        shown = host + (f":{req.host_port}" if req.host and req.host_port else "")
        if not req.host:
            shown = self.p.server_ip
        url = f"{scheme}://{shown}{path}/" + (f"?{req.query}" if req.query else "")
        _ = port
        return self.error(301, req, ctx, url=url, headers=[("Location", url)])

    # -- static files ----------------------------------------------------------------------

    def _serve_static(self, req: Request, ctx: Ctx, path: str) -> Outcome:
        gate = self._static_method_gate(req, ctx)
        if gate is not None:
            return Outcome(gate, route="static")
        f = self.static[path]
        ext = path[path.rfind(".") :].lower() if "." in path.rsplit("/", 1)[-1] else ""
        ctype = _MIME.get(
            ext, "text/plain" if path.endswith("README") else "application/octet-stream"
        )
        etag = apache.etag(len(f.body), f.mtime)
        headers = [
            ("Last-Modified", apache.http_date(f.mtime)),
            ("ETag", etag),
            ("Accept-Ranges", "bytes"),
        ]
        # Conditional requests.
        inm = req.header("if-none-match")
        ims = req.header("if-modified-since")
        not_modified = False
        if inm is not None:
            not_modified = (
                any(t.strip().removeprefix("W/") == etag for t in inm.split(",")[:8])
                or inm.strip() == "*"
            )
        elif ims is not None:
            when = apache.parse_http_date(ims)
            not_modified = when is not None and when >= int(f.mtime) and when <= ctx.now
        if not_modified:
            return Outcome(Response(status=304, headers=headers, kind="static"), route="static")
        body = f.body
        status = 200
        rng = req.header("range")
        gzip_ok = True
        content_range = None
        if rng and req.method in ("GET", "HEAD"):
            parsed = _parse_range(rng, len(body))
            if parsed == "bad":
                err416 = self.error(416, req, ctx)
                err416.chunked = True
                return Outcome(err416, route="static")
            if isinstance(parsed, tuple):
                a, b = parsed
                content_range = f"bytes {a}-{b}/{len(body)}"
                body = body[a : b + 1]
                status = 206
                gzip_ok = False
        resp = Response(
            status=status,
            body=body,
            content_type=ctype,
            headers=headers,
            kind="static",
            last_modified=f.mtime,
            gzip_ok=gzip_ok,
            content_range=content_range,
            full_len=len(f.body),
        )
        return Outcome(resp, app="wordpress" if "/wp-" in path else "apache", route="static")

    def _autoindex(self, req: Request, ctx: Ctx, path: str) -> Outcome:
        gate = self._static_method_gate(req, ctx)
        if gate is not None:
            return Outcome(gate, route="autoindex")
        host, port = self.sig_host(req, ctx)
        rows = []
        parent = path.rstrip("/").rsplit("/", 1)[0] + "/"
        rows.append(
            '<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td>'
            f'<td><a href="{parent}">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>\n'
        )
        for name, is_dir, size, mtime in sorted(self.dirs[path], key=lambda e: e[0]):
            if is_dir:
                icon, alt, shown = "folder.gif", "DIR", "  - "
            else:
                ext = name[name.rfind(".") :].lower()
                icon, alt = _ICON.get(ext, ("unknown.gif", "   "))
                shown = _fmt_size(size)
            stamp = _fmt_time(mtime)
            rows.append(
                f'<tr><td valign="top"><img src="/icons/{icon}" alt="[{alt}]"></td><td><a href="{html.escape(name)}">'
                f'{html.escape(name)}</a></td><td align="right">{stamp}  </td><td align="right">{shown}</td><td>&nbsp;</td></tr>\n'
            )
        shown_path = html.escape(path.rstrip("/") or "/")
        body = (
            '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">\n<html>\n <head>\n'
            f"  <title>Index of {shown_path}</title>\n </head>\n <body>\n<h1>Index of {shown_path}</h1>\n"
            '  <table>\n   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th>'
            '<th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th>'
            '<th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>\n'
            '   <tr><th colspan="5"><hr></th></tr>\n'
            + "".join(rows)
            + '   <tr><th colspan="5"><hr></th></tr>\n</table>\n'
            f"<address>{self.cfg.server_token} Server at {html.escape(host)} Port {port}</address>\n"
            "</body></html>\n"
        )
        resp = Response(
            status=200,
            body=body.encode(),
            content_type="text/html;charset=UTF-8",
            kind="php",
            xpb=False,
        )
        return Outcome(resp, route="autoindex", flags=["directory_listing"])

    # -- PHP scripts -----------------------------------------------------------------------

    def _php_script(
        self, req: Request, ctx: Ctx, script: str, info: str, analysis: Analysis
    ) -> Outcome:
        if script.startswith(("/phpmyadmin/", "/pma/")):
            root = "/phpmyadmin" if script.startswith("/phpmyadmin/") else "/pma"
            return self._pma(req, ctx, root, script, analysis)
        base = self.base_url(req, ctx)
        wp = self.cfg.wp_version
        if script in ("/info.php", "/phpinfo.php"):
            page = phpinfo.render(
                req,
                php_version=self.cfg.php_version,
                hostname=self.cfg.hostname,
                kernel=KERNEL,
                kernel_build=KERNEL_BUILD,
                server_ip=self.p.server_ip,
                server_token=self.cfg.server_token,
                public_port=ctx.public_port,
                remote_ip=ctx.src_ip,
                remote_port=ctx.src_port,
                scheme="https" if ctx.tls else "http",
                started=self.started,
                expose=self.cfg.expose_php,
                now=ctx.now,
                script=script,
            )
            return Outcome(self.php(page), app="phpinfo", route="phpinfo", flags=["phpinfo_probe"])
        if script == "/wp-login.php":
            return self._wp_login(req, ctx, base)
        if script == "/xmlrpc.php":
            return self._xmlrpc(req, ctx, base)
        if script == "/index.php":
            return self._wordpress(req, ctx, "/" if not info else info, analysis)
        if script in (
            "/wp-admin/index.php",
            "/wp-admin/admin.php",
            "/wp-admin/profile.php",
            "/wp-admin/users.php",
            "/wp-admin/plugins.php",
            "/wp-admin/themes.php",
            "/wp-admin/options-general.php",
            "/wp-admin/edit.php",
            "/wp-admin/upload.php",
            "/wp-admin/plugin-install.php",
            "/wp-admin/theme-editor.php",
            "/wp-admin/plugin-editor.php",
            "/wp-admin/update-core.php",
        ):
            return Outcome(
                self._auth_redirect(base, ctx, base + script), app="wordpress", route="wp-admin"
            )
        if script == "/wp-admin/admin-ajax.php":
            h = [*NOCACHE, ("X-Robots-Tag", "noindex"), ("X-Content-Type-Options", "nosniff")]
            return Outcome(
                self.php("0", status=400, headers=h), app="wordpress", route="admin-ajax"
            )
        if script == "/wp-admin/install.php":
            body = (
                '<!DOCTYPE html>\n<html lang="en-US">\n<head>\n<meta name="viewport" content="width=device-width" />\n'
                '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />\n'
                '<meta name="robots" content="noindex,nofollow" />\n<title>WordPress &rsaquo; Installation</title>\n'
                f"<link rel='stylesheet' id='install-css' href='{base}/wp-admin/css/install.css?ver={wp}' media='all' />\n</head>\n"
                '<body class="wp-core-ui">\n<p id="logo"><a href="https://wordpress.org/">WordPress</a></p>\n'
                "<h1>Already Installed</h1><p>You appear to have already installed WordPress. To reinstall please clear your old database tables first.</p>"
                f'<p class="step"><a href="{base}/wp-login.php" class="button button-large">Log In</a></p></body></html>'
            )
            return Outcome(self.php(body, headers=[*NOCACHE]), app="wordpress", route="install")
        if script in ("/wp-cron.php",):
            return Outcome(self.php(b"", headers=list(NOCACHE)), app="wordpress", route="wp-cron")
        if script in ("/wp-config.php", "/wp-load.php", "/wp-settings.php", "/wp-blog-header.php"):
            return Outcome(self.php(b""), app="wordpress", route="wp-internal")
        if script in ("/wp-signup.php", "/wp-activate.php"):
            loc = f"{base}/wp-login.php?action=register"
            return Outcome(self._wp_redirect(302, loc), app="wordpress", route="wp-signup")
        if script == "/wp-trackback.php":
            body = '<?xml version="1.0" encoding="utf-8"?>\n<response>\n<error>1</error>\n<message>I really need an ID for this to work.</message>\n</response>\n'
            return Outcome(
                self.php(body, "text/xml; charset=UTF-8"), app="wordpress", route="trackback"
            )
        if script == "/wp-comments-post.php":
            if req.method != "POST":
                return Outcome(
                    self.php(b"", "text/plain", status=405, headers=[("Allow", "POST")]),
                    app="wordpress",
                    route="comments-post",
                )
            return Outcome(
                self.php(
                    b"", "text/html; charset=UTF-8", status=302, headers=[("Location", base + "/")]
                ),
                app="wordpress",
                route="comments-post",
            )
        if script in (
            "/wp-content/index.php",
            "/wp-content/plugins/index.php",
            "/wp-content/themes/index.php",
        ):
            return Outcome(self.php(b""), app="wordpress", route="silence")
        # Not a script we know: the same 404 the rest of the site gives.
        return self._wordpress(
            req, ctx, "/" + "/".join([script.strip("/")]), analysis, missing=True
        )

    def _wp_redirect(
        self, status: int, location: str, extra: list[tuple[str, str]] | None = None
    ) -> Response:
        headers = [*(extra or []), ("X-Redirect-By", "WordPress"), ("Location", location)]
        return self.php(b"", status=status, headers=headers)

    def _auth_redirect(self, base: str, ctx: Ctx, target: str) -> Response:
        loc = f"{base}/wp-login.php?redirect_to={quote(target, safe='')}&reauth=1"
        return self._wp_redirect(302, loc, list(NOCACHE))

    def _wp_login(self, req: Request, ctx: Ctx, base: str) -> Outcome:
        wp = self.cfg.wp_version
        cookie = "wordpress_test_cookie=WP%20Cookie%20check; path=/" + (
            "; secure" if ctx.tls else ""
        )
        headers = [
            ("Set-Cookie", cookie),
            *NOCACHE,
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ]
        out = Outcome(self.php("", headers=headers), app="wordpress", route="wp-login")
        qs = dict(_qsl(req.query))
        action = qs.get("action", "login")
        if req.method == "POST" and action in ("login", ""):
            form = dict(
                _qsl(req.body[:16384].decode("latin-1"))
                if "urlencoded" in (req.header("content-type") or "").lower()
                or not req.header("content-type")
                else []
            )
            user = to_text(form.get("log", ""))[:256]
            pwd = to_text(form.get("pwd", ""))[:256]
            if user or pwd:
                out.logins.append(
                    {"username": user, "password": pwd, "success": False, "method": "wp-login"}
                )
            if not user and not pwd:
                err = (
                    "<strong>Error:</strong> The username field is empty.<br />\n"
                    "<strong>Error:</strong> The password field is empty.<br />\n"
                )
            else:
                err = wordpress.login_error(base, self.p, user, pwd)
            out.resp = self.php(
                wordpress.login_page(base, self.p, wp, error=err, user=user), headers=headers
            )
            return out
        if action == "lostpassword":
            out.resp = self.php(wordpress.lost_password_page(base, self.p, wp), headers=headers)
            return out
        if action == "register":
            out.resp = self.php(
                wordpress.login_page(
                    base,
                    self.p,
                    wp,
                    error="<strong>Error:</strong> User registration is currently not allowed.",
                ),
                headers=headers,
            )
            return out
        out.resp = self.php(wordpress.login_page(base, self.p, wp), headers=headers)
        return out

    def _xmlrpc(self, req: Request, ctx: Ctx, base: str) -> Outcome:
        out = Outcome(self.php(b""), app="wordpress", route="xmlrpc")
        if req.method != "POST":
            if req.method == "GET" and "rsd" in dict(_qsl(req.query)):
                out.resp = self.php(
                    wordpress.rsd_xml(base, self.cfg.wp_version), "text/xml; charset=UTF-8"
                )
                out.route = "xmlrpc-rsd"
                return out
            out.resp = self.php(
                "XML-RPC server accepts POST requests only.",
                "text/plain",
                status=405,
                headers=[("Allow", "POST")],
            )
            return out
        out.flags.append("xmlrpc")
        # Multicalls are the expensive ones (parse, build, gzip): rate-limited before parsing.
        if b"system.multicall" in req.body and not self.multicall.allow(ctx.src_ip):
            out.flags += ["xmlrpc_multicall", "rate_limited"]
            out.resp = self.error(503, req, ctx, close=True)
            return out
        try:
            call = xmlrpc.parse_call(req.body)
        except xmlrpc.XmlRpcError as err:
            out.resp = self._xml(xmlrpc.fault(err.code, err.message))
            return out
        out.extra["xmlrpc_method"] = call.method
        if call.method == "system.multicall":
            entries: list[tuple[bool, Any]] = []
            calls = call.params[0] if call.params and isinstance(call.params[0], list) else []
            out.extra["xmlrpc_calls"] = len(calls)
            for item in calls:
                if not isinstance(item, dict):
                    entries.append((True, (-32600, "server error. invalid method request")))
                    continue
                name = item.get("methodName")
                params = item.get("params")
                if not isinstance(name, str) or not isinstance(params, list):
                    entries.append((True, (-32600, "server error. invalid method request")))
                    continue
                if name == "system.multicall":
                    entries.append(
                        (True, (-32600, "Recursive calls to system.multicall are forbidden"))
                    )
                    continue
                entries.append(self._xmlrpc_one(xmlrpc.Call(name, params), out))
            out.flags.append("xmlrpc_multicall")
            # Every entry is answered, like WordPress does; the size is known before anything
            # is built, and a response the memory budget cannot hold is a 503 instead.
            if xmlrpc.multicall_size(entries) > ctx.max_response:
                out.flags.append("oversized_response")
                out.resp = self.error(503, req, ctx, close=True)
                return out
            body = xmlrpc.multicall(entries)
            packed: bytes | None = None
            if apache.accepts_gzip(req.header("accept-encoding")):
                packed = self.multicall.gzip(body)
                if packed is None:  # compression budget spent: overloaded
                    out.flags.append("rate_limited")
                    out.resp = self.error(503, req, ctx, close=True)
                    return out
            out.resp = self._xml(body)
            out.resp.packed = packed
            return out
        is_fault, value = self._xmlrpc_one(call, out)
        out.resp = self._xml(xmlrpc.fault(*value) if is_fault else xmlrpc.success(value))
        return out

    def _xml(self, body: bytes) -> Response:
        return self.php(body, "text/xml", close=True)

    def _xmlrpc_one(self, call: xmlrpc.Call, out: Outcome) -> tuple[bool, Any]:
        creds = xmlrpc.credentials(call)
        if creds is not None:
            # Every call is answered, but only the first ``xmlrpc_max_calls`` are recorded.
            if len(out.logins) < self.cfg.xmlrpc_max_calls:
                out.logins.append(
                    {
                        "username": creds[0],
                        "password": creds[1],
                        "success": False,
                        "method": "xmlrpc",
                    }
                )
            return True, (403, "Incorrect username or password.")
        if call.method == "system.listMethods":
            return False, xmlrpc.LIST_METHODS
        if call.method == "demo.sayHello":
            return False, "Hello!"
        if call.method == "demo.addTwoNumbers":
            a, b = [*call.params, 0, 0][:2]
            if isinstance(a, int) and isinstance(b, int):
                return False, a + b
            return False, 0
        if call.method == "pingback.ping":
            if call.params and isinstance(call.params[0], str) and "://" in call.params[0]:
                out.downloads.append(
                    {
                        "url": call.params[0][:2048],
                        "tool": "xmlrpc-pingback",
                        "command": "pingback.ping",
                        "via": "body",
                    }
                )
            return True, (0, "The source URL does not exist.")
        if call.method == "system.getCapabilities":
            return False, {"xmlrpc": {"specUrl": "http://www.xmlrpc.com/spec", "specVersion": 1}}
        if xmlrpc.is_known(call.method):
            return True, (403, "You are not allowed to access this resource.")
        return True, (-32601, f"server error. requested method {call.method} does not exist.")

    # -- phpMyAdmin ------------------------------------------------------------------------

    def _pma(self, req: Request, ctx: Ctx, root: str, path: str, analysis: Analysis) -> Outcome:
        rel = path[len(root) :]
        if rel == "":
            return Outcome(
                self._dir_redirect(req, ctx, root), app="phpmyadmin", route="dir-redirect"
            )
        if rel.startswith("/setup"):
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(404, req, ctx), app="phpmyadmin", route="setup")
        if rel != "/" and not rel.endswith(".php") and not rel.endswith("/"):
            if path in self.static:
                return self._serve_static(req, ctx, path)
            gate = self._static_method_gate(req, ctx)
            return Outcome(gate or self.error(404, req, ctx), app="phpmyadmin", route="static")
        https = ctx.tls
        cookie_name = "phpMyAdmin_https" if https else "phpMyAdmin"
        sid = secrets.token_hex(16)
        token = secrets.token_hex(16)
        stamp = apache.http_date(ctx.now)
        headers: list[tuple[str, str]] = [
            (
                "Set-Cookie",
                f"{cookie_name}={sid}; path={root}/; {'secure; ' if https else ''}HttpOnly",
            ),
            (
                "Set-Cookie",
                f"pma_lang=en; expires={apache.http_date(ctx.now + 2592000)}; Max-Age=2592000; path={root}/; {'secure; ' if https else ''}HttpOnly",
            ),
            *pma.security_headers(stamp),
        ]
        out = Outcome(self.php(""), app="phpmyadmin", route="login")
        error = ""
        if req.method == "POST":
            form = (
                dict(_qsl(req.body[:16384].decode("latin-1")))
                if b"pma_username" in req.body[:16384]
                else {}
            )
            if "pma_username" in form:
                user = to_text(form.get("pma_username", ""))[:256]
                pwd = to_text(form.get("pma_password", ""))[:256]
                out.logins.append(
                    {"username": user, "password": pwd, "success": False, "method": "phpmyadmin"}
                )
                using = "YES" if pwd else "NO"
                error = f"mysqli::real_connect(): (HY000/1045): Access denied for user '{user}'@'localhost' (using password: {using})"
                if not user:
                    error = "Login without a password is forbidden by configuration (see AllowNoPassword)"
        out.resp = self.php(
            pma.login_page(self.cfg.pma_version, token, error=error),
            "text/html; charset=utf-8",
            headers=headers,
        )
        return out

    # -- WordPress front end ---------------------------------------------------------------

    def _wordpress(
        self, req: Request, ctx: Ctx, path: str, analysis: Analysis, *, missing: bool = False
    ) -> Outcome:
        base = self.base_url(req, ctx)
        wp = self.cfg.wp_version
        p = self.p
        link = self._wp_link(base)
        qs = dict(_qsl(req.query))

        def page(
            body: str, status: int = 200, route: str = "wp", ctype: str = "text/html; charset=UTF-8"
        ) -> Outcome:
            return Outcome(
                self.php(body, ctype, status=status, headers=[link]), app="wordpress", route=route
            )

        def not_found() -> Outcome:
            return page(wordpress.not_found_page(base, p, wp), 404, "wp-404")

        if missing:
            return not_found()
        if path.startswith("/wp-json") or "rest_route" in qs:
            return self._rest(req, ctx, base, path, qs)
        if path == "/robots.txt":
            return Outcome(
                self.php(
                    wordpress.robots_txt(base),
                    "text/plain; charset=utf-8",
                    headers=[],
                ),
                app="wordpress",
                route="robots",
            )
        if path == "/favicon.ico":
            return Outcome(
                self._wp_redirect(302, f"{base}/wp-includes/images/w-logo-blue-white-bg.png"),
                app="wordpress",
                route="favicon",
            )
        if path in ("/feed/", "/feed", "/index.php/feed/", "/comments/feed/"):
            return page(
                wordpress.feed_xml(base, p, wp), 200, "feed", "application/rss+xml; charset=UTF-8"
            )
        if path in ("/wp-sitemap.xml",):
            return page(
                wordpress.sitemap_xml(base, p), 200, "sitemap", "application/xml; charset=UTF-8"
            )
        if path in ("/wp-admin/", "/wp-admin/index.php"):
            return Outcome(
                self._auth_redirect(base, ctx, base + "/wp-admin/"),
                app="wordpress",
                route="wp-admin",
            )
        if path.startswith("/wp-admin/"):
            return not_found() if path not in self.static else self._serve_static(req, ctx, path)
        # canonical-redirect behaviour for ?author=N (user enumeration) and ?p=N
        if path == "/" and "author" in qs:
            for u in p.users:
                if qs["author"] == str(u.id):
                    return Outcome(
                        self._wp_redirect(301, f"{base}/author/{u.login}/"),
                        app="wordpress",
                        route="author-enum",
                        flags=["wp_user_enum"],
                    )
            return not_found()
        if path == "/" and "p" in qs:
            for post in p.posts:
                if qs["p"] == str(post.id):
                    return Outcome(
                        self._wp_redirect(301, f"{base}/{post.slug}/"),
                        app="wordpress",
                        route="post-id",
                    )
            return not_found()
        if path == "/" and "s" in qs:
            term = to_text(qs["s"])[:200]
            needle = term.lower()
            hits = [x for x in p.posts if needle and needle in (x.title + " " + x.body).lower()]
            return page(
                wordpress.listing_page(
                    base,
                    f"Search Results for: {html.escape(term)}",
                    p,
                    wp,
                    hits,
                    "search search-results",
                ),
                200,
                "search",
            )
        if path == "/":
            return page(wordpress.home_page(base, p, wp), 200, "home")
        segs = [s for s in path.split("/") if s]
        if len(segs) == 2 and segs[0] == "author":
            for u in p.users:
                if u.login == segs[1]:
                    if not path.endswith("/"):
                        return Outcome(
                            self._wp_redirect(301, f"{base}/author/{u.login}/"),
                            app="wordpress",
                            route="author",
                        )
                    posts = list(p.posts) if u.id == 1 else []
                    return page(
                        wordpress.listing_page(
                            base,
                            f"Posts by {html.escape(u.display)}",
                            p,
                            wp,
                            posts,
                            "archive author",
                        ),
                        200,
                        "author",
                    )
            return not_found()
        if segs == ["category", "uncategorized"]:
            return page(
                wordpress.listing_page(
                    base, "Category: Uncategorized", p, wp, list(p.posts), "archive category"
                ),
                200,
                "category",
            )
        if len(segs) == 1:
            for post in p.posts:
                if post.slug == segs[0]:
                    if not path.endswith("/"):
                        return Outcome(
                            self._wp_redirect(301, f"{base}/{post.slug}/"),
                            app="wordpress",
                            route="post",
                        )
                    return page(wordpress.post_page(base, post, p, wp), 200, "post")
            if segs[0] == "sample-page":
                if not path.endswith("/"):
                    return Outcome(
                        self._wp_redirect(301, f"{base}/sample-page/"),
                        app="wordpress",
                        route="page",
                    )
                from web_sensor.profile import Post

                sample = Post(
                    2,
                    "sample-page",
                    "Sample Page",
                    p.install_ts,
                    "This is an example page. It&#8217;s different from a blog post because it will stay in one place and will show up in your site navigation.",
                )
                return page(wordpress.post_page(base, sample, p, wp), 200, "page")
        return not_found()

    def _rest(self, req: Request, ctx: Ctx, base: str, path: str, qs: dict[str, str]) -> Outcome:
        p = self.p
        route = qs.get("rest_route", "")
        if not route:
            route = path[len("/wp-json") :] or "/"
        route = route.rstrip("/") or "/"
        headers = [
            self._wp_link(base),
            ("X-Robots-Tag", "noindex"),
            ("X-Content-Type-Options", "nosniff"),
            ("Access-Control-Expose-Headers", "X-WP-Total, X-WP-TotalPages, Link"),
            (
                "Access-Control-Allow-Headers",
                "Authorization, X-WP-Nonce, Content-Disposition, Content-MD5, Content-Type",
            ),
            ("Allow", "GET"),
        ]
        ctype = "application/json; charset=UTF-8"
        flags: list[str] = []
        extra_headers: list[tuple[str, str]] = []
        status = 200
        if route == "/":
            body = wordpress.rest_index(base, p, self.cfg.wp_version)
        elif route == "/wp/v2/users":
            body = wordpress.rest_users(base, p)
            flags.append("wp_user_enum")
            extra_headers = [("X-WP-Total", str(len(p.users))), ("X-WP-TotalPages", "1")]
        elif route.startswith("/wp/v2/users/"):
            ident = route.rsplit("/", 1)[1]
            user = next((u for u in p.users if str(u.id) == ident), None)
            flags.append("wp_user_enum")
            if user is None:
                body = wordpress.php_json(
                    {
                        "code": "rest_user_invalid_id",
                        "message": "Invalid user ID.",
                        "data": {"status": 404},
                    }
                )
                status = 404
            else:
                body = wordpress.rest_user(base, user)
        elif route == "/wp/v2/posts":
            body = wordpress.posts_json(base, p)
            extra_headers = [("X-WP-Total", str(len(p.posts))), ("X-WP-TotalPages", "1")]
        else:
            body = wordpress.rest_404()
            status = 404
        resp = self.php(
            body,
            ctype,
            status=status,
            headers=[*headers[:1], *headers[1:4], *extra_headers, *headers[4:]],
        )
        return Outcome(resp, app="wordpress", route="wp-json", flags=flags)


def _qsl(raw: str) -> list[tuple[str, str]]:
    try:
        first = "&".join(raw[:16384].split("&")[:100])  # lenient: extra fields are ignored
        return parse_qsl(first, keep_blank_values=True, errors="replace")
    except ValueError:
        return []


def _parse_range(value: str, size: int) -> tuple[int, int] | str | None:
    """Single byte range -> (first, last); 'bad' if unsatisfiable; None to ignore the header."""
    v = value.strip().lower()
    if not v.startswith("bytes=") or "," in v:
        return None
    spec = v[6:].strip()
    a, sep, b = spec.partition("-")
    if not sep:
        return None
    try:
        if a == "":
            n = int(b)
            if n <= 0:
                return "bad"
            return max(0, size - n), size - 1
        first = int(a)
        last = int(b) if b else size - 1
    except ValueError:
        return None
    if first >= size or first > last:
        return "bad" if first >= size else None
    return first, min(last, size - 1)


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n:3d} "
    k = n / 1024
    if k < 10:
        return f"{k:.1f}K"
    if k < 1024:
        return f"{k:3.0f}K"
    m = k / 1024
    return f"{m:.1f}M" if m < 10 else f"{m:3.0f}M"


def _fmt_time(ts: float) -> str:
    import datetime as _dt

    return _dt.datetime.fromtimestamp(ts, _dt.UTC).strftime("%Y-%m-%d %H:%M")
