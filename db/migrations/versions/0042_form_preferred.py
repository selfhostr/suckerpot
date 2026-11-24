"""A desk that reads mail but suggests its web form (form preferred).

Revision ID: 0042
Revises: 0041

Some desks answer "we accept email reports, but we encourage you to use our form". That is an
acknowledgement, not a refusal: mail keeps going there. Ingest remembers it on the recipient so
the report page can show the form as an optional hint.

* ``abuse_recipients.form_preferred``: set by ingest from a reply matched to a report (rule
  ``form-preferred``). It never stops a send and never routes to the form queue. The form link,
  when a verified reply on the provider's own domain carries one, goes in the existing
  ``form_url`` column.

No data is changed: a desk that an earlier version flagged form-only from such a reply stays
flagged until the owner clears the flag ("Clear this flag" on the report page).

Safe on a large database: one small table, a boolean column with a constant default (no rewrite).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN form_preferred boolean NOT NULL DEFAULT false"
    )


def downgrade() -> None:
    # The form link of a form-preferred desk is shown only with the flag; older code shows it only
    # on a form-only desk, so it can stay.
    op.execute("ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS form_preferred")
