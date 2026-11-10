"""Site copy differs per install, is plausible, and is stable for one install."""

from __future__ import annotations

import re

from web_sensor.profile import Profile, build_profile


def _fleet(n: int = 40) -> list[Profile]:
    return [build_profile(bytes([i + 1]) * 32, 1_790_000_000.0) for i in range(n)]


def test_profile_is_stable_for_one_secret() -> None:
    assert build_profile(b"s" * 32, 1_790_000_000.0) == build_profile(b"s" * 32, 1_790_000_000.0)


def test_titles_taglines_and_posts_vary() -> None:
    fleet = _fleet()
    assert len({p.site_title for p in fleet}) > 30
    assert len({p.tagline for p in fleet}) > 20
    assert {len(p.posts) for p in fleet} == {3, 4, 5, 6}
    for p in fleet:
        assert p.site_title and p.tagline
        slugs = [x.slug for x in p.posts]
        assert len(slugs) == len(set(slugs))
        assert all(x.ts <= p.created for x in p.posts)


def test_no_long_sentence_is_shared_by_the_fleet() -> None:
    fleet = _fleet()
    sentence_sets = []
    for p in fleet:
        sentences: set[str] = set()
        for post in p.posts:
            sentences.update(s.strip() for s in re.split(r"(?<=[.!?])\s+", post.body))
        sentence_sets.append({s for s in sentences if len(s.split()) > 4})
    assert set.intersection(*sentence_sets) == set()
    # The old constant body is gone.
    assert not any("Stop by during opening hours" in x.body for p in fleet for x in p.posts)
    # Bodies stay short enough for a small business blog.
    assert all(40 < len(x.body) < 700 for p in fleet for x in p.posts if x.slug != "hello-world")
