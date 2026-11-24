"""How many form reports wait to be submitted (M38, docs/dev/design/m38.md section 6).

The same rule as the queue of ``GET /api/v1/abuse/forms``: a form report that is still a draft or
reviewed, not demo data, to a recipient that is not muted, with at least one source. The API's
Today page and the ingest weekly report both count with this, so the numbers agree.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

FORM_QUEUE_COUNT_SQL = """
SELECT count(*) AS reports, count(DISTINCT r.recipient_id) AS providers
FROM abuse_reports r
JOIN abuse_recipients c ON c.id = r.recipient_id
WHERE r.channel = 'form' AND r.status IN ('draft', 'reviewed') AND NOT r.demo AND NOT c.muted
  AND EXISTS (SELECT 1 FROM abuse_report_subjects s WHERE s.report_id = r.id)
"""


@dataclass(frozen=True, slots=True)
class FormQueueCount:
    """Form reports still to submit, and the number of providers they go to."""

    reports: int
    providers: int


async def form_queue_count(session: AsyncSession) -> FormQueueCount:
    row = (await session.execute(text(FORM_QUEUE_COUNT_SQL))).one()
    return FormQueueCount(reports=int(row.reports or 0), providers=int(row.providers or 0))


def form_queue_sentence(count: FormQueueCount) -> str:
    """``"3 reports to submit by web form, for 2 providers"``, or "" when the queue is empty."""
    if count.reports <= 0:
        return ""
    reports = f"{count.reports:,} report{'' if count.reports == 1 else 's'}"
    providers = f"{count.providers:,} provider{'' if count.providers == 1 else 's'}"
    return f"{reports} to submit by web form, for {providers}"


__all__ = ["FORM_QUEUE_COUNT_SQL", "FormQueueCount", "form_queue_count", "form_queue_sentence"]
