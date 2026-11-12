"""Files the analyzer spared, analysed again once an attacker asks for them.

A file is spared when the analyzer did not act on it (plain web content, or a network
verification fetch): no hash indicator, no link followed (``samples.spared``). When an attacker
later asks for it (a typed URL serves it, an attacker types the URL that served it, or a script
or a binary links to that URL), it goes back to ``pending`` and is analysed as attacker content.
The collector and the analyzer both run this, after the change, with the target as ``:t``.
"""

from __future__ import annotations

from suckerpot_db.sample_kinds import reopened_sample

REOPEN_TARGET = f"""
    UPDATE samples s SET analysis_status = 'pending'
    WHERE s.sha256 IN (SELECT x.sha256 FROM sample_sources x WHERE x.target_id = :t)
      AND {reopened_sample("s")}
"""  # noqa: S608  (constant fragment only)
