"""What the replies taught us about a recipient: web form only, or a dead address.

Revision ID: 0035
Revises: 0034

Some abuse desks answer every report with "use our web form" and some addresses bounce for good.
Both facts belong to the recipient, so the node stops sending automatic mail there and the owner
can act by hand.

* ``form_only`` and ``form_url``: set by ingest when a verified reply from the desk says it takes
  reports only through a web form. The URL is the first ``https`` link of the reply, bounded.
* ``undeliverable`` and ``hard_bounces``: set by ingest after a hard bounce (5.x.x) of a report
  sent to the address: one for "user unknown", two for any other permanent failure.

Ingest writes the four columns; the API may write them too, so the owner can clear a flag.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE abuse_recipients ADD COLUMN form_only boolean NOT NULL DEFAULT false")
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN form_url text "
        "CONSTRAINT ck_abuse_recipients_form_url CHECK (form_url IS NULL OR "
        "(char_length(form_url) <= 500 AND form_url LIKE 'https://%'))"
    )
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN undeliverable boolean NOT NULL DEFAULT false"
    )
    op.execute(
        "ALTER TABLE abuse_recipients ADD COLUMN hard_bounces smallint NOT NULL DEFAULT 0 "
        "CONSTRAINT ck_abuse_recipients_hard_bounces CHECK (hard_bounces BETWEEN 0 AND 100)"
    )


def downgrade() -> None:
    for column in ("hard_bounces", "undeliverable", "form_url", "form_only"):
        op.execute(f"ALTER TABLE abuse_recipients DROP COLUMN IF EXISTS {column}")
