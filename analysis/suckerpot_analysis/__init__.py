"""SuckerPot static analysis library: pure functions over bytes. Never executes a sample."""

from .analyze import analyze
from .deob import deobfuscate_shell
from .digests import digests
from .identify import identify
from .iocs import extract_iocs, mirai_table_iocs
from .models import (
    ANALYSIS_VERSION,
    WEB_KINDS,
    AnalysisResult,
    Deobfuscation,
    DeobStep,
    Digests,
    FileInfo,
    Ioc,
    Limits,
    YaraHit,
)
from .rules import CompiledRules, compile_rules
from .strings import printable_strings

__all__ = [
    "ANALYSIS_VERSION",
    "WEB_KINDS",
    "AnalysisResult",
    "CompiledRules",
    "DeobStep",
    "Deobfuscation",
    "Digests",
    "FileInfo",
    "Ioc",
    "Limits",
    "YaraHit",
    "analyze",
    "compile_rules",
    "deobfuscate_shell",
    "digests",
    "extract_iocs",
    "identify",
    "mirai_table_iocs",
    "printable_strings",
]
