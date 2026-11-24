"""The form queue count's sentence and its SQL rule (M38), without a database."""

from suckerpot_db.form_queue import FORM_QUEUE_COUNT_SQL, FormQueueCount, form_queue_sentence


def test_the_sentence() -> None:
    assert form_queue_sentence(FormQueueCount(reports=0, providers=0)) == ""
    assert form_queue_sentence(FormQueueCount(reports=1, providers=1)) == (
        "1 report to submit by web form, for 1 provider"
    )
    assert form_queue_sentence(FormQueueCount(reports=1200, providers=3)) == (
        "1,200 reports to submit by web form, for 3 providers"
    )


def test_the_rule_matches_the_queue() -> None:
    # The same filter as GET /abuse/forms: open form reports with a source, no demo, no muted desk.
    sql = " ".join(FORM_QUEUE_COUNT_SQL.split())
    for part in (
        "r.channel = 'form'",
        "r.status IN ('draft', 'reviewed')",
        "NOT r.demo",
        "NOT c.muted",
        "EXISTS (SELECT 1 FROM abuse_report_subjects s WHERE s.report_id = r.id)",
    ):
        assert part in sql
