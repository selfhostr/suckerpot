"""Anonymous abuse reporting: pure functions, no I/O (design M22).

Used by ingest (drafts) and the API (renders, downloads, exports). Every artefact returned to
a person must pass ``guard`` first.
"""

from __future__ import annotations

from .bundle import (
    ARCHIVE_PASSWORD,
    BundleResult,
    BundleSample,
    build_encrypted_zip,
    build_sample_bundle,
    hashes_csv,
)
from .errors import BundleLimitError, GuardFailed, RenderUnavailable, ReportingError
from .evidence import (
    DEFAULT_SUBJECT,
    DEFAULT_XARF_USER_AGENT,
    Activity,
    Evidence,
    ExportData,
    ExportItem,
    RedactionStats,
    ReportOptions,
    ReportSettings,
    SampleRef,
    Subject,
    Technique,
    export_from_evidence,
    missing_settings,
)
from .guard import GuardContext, GuardResult, guard, guard_parts, scan_binary
from .ids import (
    cluster_label,
    derive_id,
    export_names,
    new_public_id,
    new_reply_token,
    new_seed,
    report_stem,
    stix_id,
)
from .message import (
    REFERENCE_STYLES,
    Attachment,
    Layout,
    ReferenceStyle,
    RenderedMessage,
    guard_message,
    message_subject,
    new_boundary,
    render_csv,
    render_eml,
    render_mail,
    render_text,
    require_ok,
)
from .misp import render_misp
from .redact import Redacted, RedactionContext, defang, redact
from .stix import dumps as stix_dumps
from .stix import render_stix
from .terms import SelfTermRow, SelfTerms, load_self_terms, mask_value
from .xarf import XARF_VERSION, new_xarf_id, render_xarf_v4, schema_errors

__all__ = [
    "ARCHIVE_PASSWORD",
    "DEFAULT_SUBJECT",
    "DEFAULT_XARF_USER_AGENT",
    "REFERENCE_STYLES",
    "XARF_VERSION",
    "Activity",
    "Attachment",
    "BundleLimitError",
    "BundleResult",
    "BundleSample",
    "Evidence",
    "ExportData",
    "ExportItem",
    "GuardContext",
    "GuardFailed",
    "GuardResult",
    "Layout",
    "Redacted",
    "RedactionContext",
    "RedactionStats",
    "ReferenceStyle",
    "RenderUnavailable",
    "RenderedMessage",
    "ReportOptions",
    "ReportSettings",
    "ReportingError",
    "SampleRef",
    "SelfTermRow",
    "SelfTerms",
    "Subject",
    "Technique",
    "build_encrypted_zip",
    "build_sample_bundle",
    "cluster_label",
    "defang",
    "derive_id",
    "export_from_evidence",
    "export_names",
    "guard",
    "guard_message",
    "guard_parts",
    "hashes_csv",
    "load_self_terms",
    "mask_value",
    "message_subject",
    "missing_settings",
    "new_boundary",
    "new_public_id",
    "new_reply_token",
    "new_seed",
    "new_xarf_id",
    "redact",
    "render_csv",
    "render_eml",
    "render_mail",
    "render_misp",
    "render_stix",
    "render_text",
    "render_xarf_v4",
    "report_stem",
    "require_ok",
    "scan_binary",
    "schema_errors",
    "stix_dumps",
    "stix_id",
]
