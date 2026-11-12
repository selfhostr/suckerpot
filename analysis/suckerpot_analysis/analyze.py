"""Top-level analysis: one pure function from bytes to an `AnalysisResult`."""

from __future__ import annotations

from .deob import deobfuscate_shell
from .digests import digests
from .identify import identify
from .iocs import extract_iocs, mirai_table_iocs
from .models import WEB_KINDS, AnalysisResult, Ioc, Limits, Severity
from .rules import CompiledRules, scan
from .strings import printable_strings
from .weblinks import ASSET_KINDS, asset_links

_ORDER: tuple[Severity, ...] = ("info", "notice", "warning", "severe")
_TEXT_KINDS = frozenset({"script", "text"})


def _severity(value: object) -> Severity | None:
    return value if value in _ORDER else None


def analyze(data: bytes, *, rules: CompiledRules, limits: Limits = Limits()) -> AnalysisResult:  # noqa: B008
    """Analyse a sample statically. Never executes, never touches the network or disk."""
    errors: list[str] = []
    if len(data) > limits.max_input:
        data = data[: limits.max_input]
        errors.append("input_truncated")

    info = identify(data)
    hashes = digests(data)
    hits, scan_errors = scan(data, rules, limits)
    errors.extend(scan_errors)

    family: str | None = None
    # Web content starts at the lowest level; any rule that matches raises it to at least
    # "notice", so a web sample at "info" with no family is one that no rule matched.
    severity: Severity = "info" if info.kind in WEB_KINDS else "notice"
    tags: list[str] = []
    for hit in hits:
        fam = hit.meta.get("family")
        if family is None and isinstance(fam, str):
            family = fam
        sev = _severity(hit.meta.get("severity"))
        if sev is not None and _ORDER.index(sev) > _ORDER.index(severity):
            severity = sev
        for tag in hit.tags:
            if tag not in tags:
                tags.append(tag)
    if hits and severity == "info":
        severity = "notice"

    strings = printable_strings(data, max_count=limits.max_strings, max_len=limits.string_max_len)
    iocs: list[Ioc] = []
    deobfuscated: str | None = None
    deob_steps = []
    # Web content (WEB_KINDS) is read like any text: its links are extracted. Whether they are
    # followed is the collector's decision, which knows how the file was reached. A link that a
    # page or a style sheet names only as an asset (a markup attribute, a style sheet url() or
    # @import) is labelled "web_asset": the file it points at may be plain web content. Any other
    # link, in the text of a page or in a script, stays "script_url".
    if (info.kind in _TEXT_KINDS or info.kind in WEB_KINDS) and len(data) <= limits.deob_max_input:
        text = data.decode("utf-8", errors="replace")
        result = deobfuscate_shell(
            text,
            max_passes=limits.deob_max_passes,
            max_out=limits.deob_max_out,
            max_in=limits.deob_max_input,
        )
        deobfuscated, deob_steps = result.text, result.steps
        if result.truncated:
            errors.append("deob_truncated")
        iocs = extract_iocs([result.text], source="script_url", max_iocs=limits.max_iocs)
        if info.kind in ASSET_KINDS and iocs:
            assets = asset_links(text, info.kind)
            iocs = [
                i.model_copy(update={"source": "web_asset"})
                if i.kind == "next_url" and i.value in assets
                else i
                for i in iocs
            ]
    elif info.kind in {"elf", "pe", "macho"}:
        iocs = extract_iocs(
            strings, source="binary_string", trusted=bool(hits), max_iocs=limits.max_iocs
        )
        for ioc in mirai_table_iocs(data):
            if len(iocs) < limits.max_iocs and all(
                (i.kind, i.value) != (ioc.kind, ioc.value) for i in iocs
            ):
                iocs.append(ioc)
    return AnalysisResult(
        file=info,
        digests=hashes,
        yara=hits,
        family=family,
        tags=tags,
        severity=severity,
        strings=strings,
        deobfuscated=deobfuscated,
        deob_steps=deob_steps,
        iocs=iocs,
        errors=errors,
    )
