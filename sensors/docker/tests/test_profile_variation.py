"""The fake host differs per install and stays stable for one install."""

from __future__ import annotations

from docker_sensor.api import DockerApi
from docker_sensor.config import Config
from docker_sensor.profile import _OS_RELEASES, Profile, build_profile


def _fleet(n: int = 24) -> list[Profile]:
    return [build_profile(bytes([i + 1]) * 32, 1_790_000_000.0) for i in range(n)]


def test_container_set_varies_per_install_and_is_stable() -> None:
    fleet = _fleet()
    assert [p.containers for p in fleet] == [p.containers for p in _fleet()]
    sets = {tuple((c.name, c.image) for c in p.containers) for p in fleet}
    assert len(sets) == len(fleet)
    counts = {len(p.containers) for p in fleet}
    assert counts <= set(range(2, 7)) and len(counts) > 2
    # No fixed name is shared by the whole fleet.
    assert not all(any(c.name == "edge-proxy" for c in p.containers) for p in fleet)
    for p in fleet:
        names = [c.name for c in p.containers]
        assert len(names) == len(set(names))
        refs = {img[0]: img[1] for img in p.images}
        assert len(refs) == len(p.images)
        for c in p.containers:
            assert refs[c.image] == c.image_id


def test_os_release_matches_kernel() -> None:
    fleet = _fleet()
    for p in fleet:
        assert any(p.os_name == name and p.kernel in kernels for name, kernels in _OS_RELEASES)
    assert len({p.os_name for p in fleet}) > 1


def test_list_inspect_and_info_agree() -> None:
    p = build_profile(b"z" * 32, 1_790_000_000.0)
    api = DockerApi(Config(), p)
    listed = {c.id: api._list_entry(c) for c in p.containers}
    assert len(listed) == len(p.containers) == api._info()["Containers"]
    for c in p.containers:
        doc = api._inspect(c)
        assert doc["Image"] == listed[c.id]["ImageID"] == c.image_id
        assert doc["Name"] == "/" + c.name == listed[c.id]["Names"][0]
        mac = doc["NetworkSettings"]["MacAddress"]
        assert mac == listed[c.id]["NetworkSettings"]["Networks"]["bridge"]["MacAddress"]
        assert mac.endswith(f"{int(c.ip.split('.')[-1]):02x}")


def test_images_predate_their_containers() -> None:
    for p in _fleet():
        created = {img[0]: img[3] for img in p.images}
        for c in p.containers:
            assert created[c.image] < c.created


def test_compose_labels_follow_the_name_in_list_and_inspect() -> None:
    seen_compose = seen_plain = False
    for p in _fleet():
        api = DockerApi(Config(), p)
        for c in p.containers:
            listed = api._list_entry(c)["Labels"]
            inspected = api._inspect(c)["Config"]["Labels"]
            assert listed == inspected == dict(c.labels)
            if not c.labels:
                seen_plain = True
                continue
            seen_compose = True
            lab = dict(c.labels)
            proj = lab["com.docker.compose.project"]
            svc = lab["com.docker.compose.service"]
            num = lab["com.docker.compose.container-number"]
            assert c.name in (f"{proj}-{svc}-{num}", f"{proj}_{svc}_{num}")
            assert lab["com.docker.compose.oneoff"] == "False"
            assert lab["com.docker.compose.project.working_dir"] == f"/srv/{proj}"
            assert lab["com.docker.compose.project.config_files"].startswith(f"/srv/{proj}/")
            assert len(lab["com.docker.compose.config-hash"]) == 64
            assert lab["com.docker.compose.version"]
    assert seen_compose and seen_plain
