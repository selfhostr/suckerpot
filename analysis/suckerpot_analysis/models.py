"""Shared pydantic models: the contract between the analysis library and the collector."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Bump it when a change to the analysis should reach samples already analysed: the analyzer
# re-runs every `done` sample whose stored version is lower. 2: web content kinds.
ANALYSIS_VERSION = 2

# File kinds for ordinary web content (pages, images, style sheets, scripts of a web page, data
# documents), with the severity "info" unless a detection rule matched. A file only gets one of
# these when it plausibly is that format and its whole input holds no shell command, downloader,
# code runner or active content (see `identify._identify_web`); anything else keeps the `script` or
# `text` kind. The kind alone never spares a file: the collector skips the links and the hash of a
# web sample only when no rule matched it AND it was reached by following links found in other
# web content, never when an attacker asked for it (`suckerpot_db.sample_kinds`).
WEB_KINDS: frozenset[str] = frozenset({"html", "svg", "xml", "css", "json", "javascript"})

IocKind = Literal["next_url", "c2_ip", "c2_domain", "c2_url"]
# "web_asset": a next URL that a page or a style sheet only names as an asset (a markup attribute
# such as href or src, a style sheet url() or @import). Every other next URL is "script_url".
IocSource = Literal["script_url", "web_asset", "binary_ip_port", "binary_string", "mirai_table"]
Confidence = Literal["high", "low"]
Severity = Literal["info", "notice", "warning", "severe"]


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Limits(_Model):
    """Hard bounds. Every parser honours these; none is ever exceeded silently."""

    max_input: int = 16 * 1024 * 1024
    string_scan_bytes: int = 16 * 1024 * 1024
    max_strings: int = 500
    string_max_len: int = 120
    yara_timeout_s: int = 10
    max_headers: int = 256
    deob_max_input: int = 1024 * 1024
    deob_max_passes: int = 5
    deob_max_out: int = 256 * 1024
    max_iocs: int = 200
    max_yara_hits: int = 50


class FileInfo(_Model):
    # elf, pe, macho, script, gzip, zip, tar, xz, 7z, bzip2, text, data, or a WEB_KINDS member
    kind: str = "unknown"
    arch: str | None = None
    bits: int | None = None
    endian: Literal["little", "big"] | None = None
    linking: Literal["static", "dynamic"] | None = None
    stripped: bool | None = None
    is_dll: bool | None = None
    packer: str | None = None
    interpreter: str | None = None  # script shebang, e.g. "sh"


class Digests(_Model):
    sha256: str
    sha1: str
    md5: str
    tlsh: str | None = None


class YaraHit(_Model):
    rule: str
    namespace: str
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, str | int | bool] = Field(default_factory=dict)


class DeobStep(_Model):
    kind: str
    count: int


class Deobfuscation(_Model):
    text: str
    steps: list[DeobStep] = Field(default_factory=list)
    truncated: bool = False


class Ioc(_Model):
    kind: IocKind
    value: str = Field(max_length=1024)
    port: int | None = None
    source: IocSource
    confidence: Confidence


class AnalysisResult(_Model):
    version: int = ANALYSIS_VERSION
    file: FileInfo
    digests: Digests
    yara: list[YaraHit] = Field(default_factory=list, max_length=50)
    family: str | None = None
    tags: list[str] = Field(default_factory=list)
    severity: Severity = "notice"
    strings: list[str] = Field(default_factory=list, max_length=500)
    deobfuscated: str | None = Field(default=None, max_length=262144)
    deob_steps: list[DeobStep] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list, max_length=200)
    errors: list[str] = Field(default_factory=list)
