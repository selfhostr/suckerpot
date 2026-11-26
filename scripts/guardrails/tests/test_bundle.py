"""The node bundle (scripts/make-bundle.sh), the bootstrap (scripts/get.sh) and the layouts without
git: install.sh, update.sh and rollback.sh on a bundle install.

The downloads are served by a fake curl from files in the sandbox; cosign is a stub (the real one
is checked by its pinned SHA-256, which the test mode replaces with the stub's own). Nothing here
touches the network.
"""

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_install import add_participant_files, wrap_docker

COMMIT = "b" * 40
GH = "https://gh.test"
CODELOAD = "https://codeload.test"
REPO = "selfhostr/suckerpot"

CURL_WEB = r"""#!/bin/sh
# Fake curl: the URL (last argument) is a file under $SHIM_DIR/web; -o writes it there, -w
# %{url_effective} on .../releases/latest answers the tag in $SHIM_DIR/web/latest.
echo "curl $*" >> "$SHIM_LOG"
out="" fmt="" url=""
while [ $# -gt 0 ]; do
  case $1 in
    -o) out=$2; shift ;;
    -w) fmt=$2; shift ;;
    --max-time | --proto | --retry | --proto-redir | --max-filesize) shift ;;
    -*) ;;
    *) url=$1 ;;
  esac
  shift
done
case $url in
  */releases/latest)
    [ -f "$SHIM_DIR/web/latest" ] || exit 22
    printf '%s/releases/tag/%s' "${url%/releases/latest}" "$(cat "$SHIM_DIR/web/latest")"
    exit 0 ;;
esac
f="$SHIM_DIR/web/$(printf '%s' "$url" | sed 's|^https://||')"
[ -f "$f" ] || exit 22
if [ -n "$out" ]; then cp "$f" "$out"; else cat "$f"; fi
[ -z "$fmt" ] || printf '200'
exit 0
"""

COSIGN_STUB = '#!/bin/sh\necho "cosign $*" >> "$SHIM_LOG"\nexit "${SHIM_COSIGN_RC:-0}"\n'


def make_bundle(out: Path, version: str = "v9.9.9", commit: str = COMMIT) -> str:
    proc = subprocess.run(  # noqa: S603
        ["bash", str(ROOT / "scripts/make-bundle.sh"), version, str(out)],  # noqa: S607
        env={"PATH": "/usr/bin:/bin", "SOURCE_DATE_EPOCH": "1700000000", "BUNDLE_COMMIT": commit},
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return hashlib.sha256(out.read_bytes()).hexdigest()


def names(path: Path) -> set[str]:
    with tarfile.open(path) as t:
        return {m.name.removeprefix("./") for m in t.getmembers() if m.isfile()}


def test_the_bundle_is_reproducible_and_holds_a_node(tmp_path: Path) -> None:
    a, b = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    assert make_bundle(a) == make_bundle(b)
    files = names(a)
    for need in (
        "suckerpot.sh",
        "scripts/get.sh",
        "scripts/install.sh",
        "scripts/lib/ask.sh",
        "docker-compose.yml",
        "config/network-defaults.env",
        ".suckerpot-bundle",
        "vpn/entrypoint.sh",
        "netproto/suckerpot_netproto/data/pseudonym_words.txt",
    ):
        assert need in files, need
    assert not [f for f in files if f.startswith(("scripts/guardrails", "ingest/", "web/", "api/"))]
    with tarfile.open(a) as t:
        info = t.extractfile("./.suckerpot-bundle")
        assert info is not None
        text = info.read().decode()
    assert f"commit={COMMIT}" in text and "signed=1" in text and "version=v9.9.9" in text


def test_every_script_a_node_runs_is_in_the_bundle(tmp_path: Path) -> None:
    """A bundled script that calls another script of the repository finds it in the bundle."""
    out = tmp_path / "n.tar.gz"
    make_bundle(out)
    files = names(out)
    dev_only = {
        "scripts/install-hooks.sh",
        "scripts/test-backup-restore.sh",
        "scripts/ssh-test.sh",
        "scripts/e2e/participant.sh",
    }
    missing = set()
    for f in files:
        if not f.endswith(".sh") or not f.startswith("scripts/"):
            continue
        text = (ROOT / f).read_text()
        for ref in re.findall(
            r"\bscripts/[A-Za-z0-9_./-]+\.(?:sh|py|nft|service|slice|conf)\b", text
        ):
            if ref not in files and ref not in dev_only and "*" not in ref:
                missing.add(f"{f}: {ref}")
    assert not missing, sorted(missing)


# ------------------------------------------------------------------ get.sh


class Web:
    """The files the fake curl serves, and a run of get.sh against them."""

    def __init__(self, sb: Sandbox, tmp_path: Path) -> None:
        self.sb = sb
        self.web = sb.shim / "web"
        self.web.mkdir()
        (sb.shim / "curl").write_text(CURL_WEB)
        (sb.shim / "curl").chmod(0o755)
        self.cosign = tmp_path / "cosign-stub"
        self.cosign.write_text(COSIGN_STUB)
        self.cosign.chmod(0o755)
        self.dest = tmp_path / "home" / "suckerpot"
        self.get = ROOT / "scripts/get.sh"

    def release(
        self, version: str = "v9.9.9", sha: str | None = None, commit: str = COMMIT
    ) -> Path:
        rel = self.web / f"gh.test/{REPO}/releases/download/{version}"
        rel.mkdir(parents=True, exist_ok=True)
        bundle = rel / f"suckerpot-node-{version}.tar.gz"
        real = make_bundle(bundle, version, commit)
        manifest = {
            "schema": "selfhostr-release/1",
            "version": version,
            "commit": COMMIT,
            "node_bundle_sha256": sha or real,
        }
        (rel / "release-manifest.json").write_text(json.dumps(manifest))
        (rel / "release-manifest.json.sigstore.json").write_text("{}")
        (self.web / "latest").write_text(version)
        return bundle

    def run(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            ["sh", str(self.get), "--dir", str(self.dest), "--no-menu", *args],  # noqa: S607
            env={
                **self.sb.env,
                "HOME": str(self.dest.parent),
                "SELFHOSTR_TEST_INSTALL": "1",
                "SELFHOSTR_GET_GH": GH,
                "SELFHOSTR_GET_CODELOAD": CODELOAD,
                "SELFHOSTR_GET_COSIGN": str(self.cosign),
                **env,
            },
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            stdin=subprocess.DEVNULL,
        )


@pytest.fixture
def web(sandbox: Sandbox, tmp_path: Path) -> Web:
    return Web(sandbox, tmp_path)


def test_get_installs_the_signed_bundle_of_the_newest_release(web: Web) -> None:
    web.release()
    proc = web.run("--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert out.index("This will:") < out.index("Downloading the node bundle of v9.9.9")
    assert "is signed by the release workflow of selfhostr/suckerpot for v9.9.9" in out
    assert (web.dest / "suckerpot.sh").is_file() and (web.dest / "scripts/install.sh").is_file()
    assert "signed=1" in (web.dest / ".suckerpot-bundle").read_text()
    assert not (web.dest / ".git").exists() and not (web.dest / "scripts/guardrails").exists()
    cos = [c for c in web.sb.calls() if c.startswith("cosign verify-blob")]
    assert cos and "release\\.yml@refs/tags/v9\\.9\\.9$" in cos[0]
    assert not [c for c in web.sb.calls() if c.startswith("sudo")]


def test_get_refuses_a_bundle_that_is_not_the_signed_one(web: Web) -> None:
    web.release(sha="0" * 64)
    proc = web.run("--yes")
    assert proc.returncode == 1
    assert "does not have the SHA-256 of the signed manifest: refused" in proc.stderr
    assert not web.dest.exists()


def test_get_refuses_an_unsigned_manifest(web: Web) -> None:
    web.release()
    proc = web.run("--yes", SHIM_COSIGN_RC="1")
    assert proc.returncode == 1
    assert "is NOT signed by the release workflow: refused" in proc.stderr
    assert not web.dest.exists()


def test_get_refuses_a_bundle_with_another_commit(web: Web) -> None:
    web.release(commit="c" * 40)
    proc = web.run("--yes")
    assert proc.returncode == 1 and "another commit than the signed manifest" in proc.stderr
    assert not web.dest.exists()


def test_get_refuses_links_in_the_bundle(web: Web, tmp_path: Path) -> None:
    bundle = web.release()
    evil = tmp_path / "evil"
    with tarfile.open(bundle) as t:
        t.extractall(evil, filter="tar")
    (evil / "link").symlink_to("/etc/passwd")
    with tarfile.open(bundle, "w:gz") as t:
        t.add(evil, arcname=".")
    sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    manifest = bundle.parent / "release-manifest.json"
    doc = json.loads(manifest.read_text())
    doc["node_bundle_sha256"] = sha
    manifest.write_text(json.dumps(doc))
    proc = web.run("--yes")
    assert proc.returncode == 1 and "links or special files: refused" in proc.stderr
    assert not web.dest.exists()


def test_get_never_writes_over_an_install(web: Web) -> None:
    web.release()
    web.dest.mkdir(parents=True)
    (web.dest / ".env").write_text("x=1\n")
    proc = web.run("--yes")
    assert proc.returncode == 1 and "already holds a SuckerPot node" in proc.stderr
    assert (web.dest / ".env").read_text() == "x=1\n"
    assert not [c for c in web.sb.calls() if c.startswith("curl")]


def test_get_asks_first_and_needs_yes_without_a_terminal(web: Web) -> None:
    web.release()
    proc = web.run()
    if proc.returncode == 0:
        pytest.skip("this test run has a terminal")
    assert "no terminal to ask on: add --yes" in proc.stderr
    assert not web.dest.exists()


def test_get_ref_takes_only_the_bundle_files_of_a_branch(web: Web, tmp_path: Path) -> None:
    (web.web / "latest").write_text("v9.9.9")
    tree = tmp_path / "suckerpot-dev"
    bundle = tmp_path / "b.tar.gz"
    make_bundle(bundle)
    with tarfile.open(bundle) as t:
        t.extractall(tree, filter="tar")
    (tree / ".suckerpot-bundle").unlink()
    (tree / "notes-only-in-the-repo.txt").write_text("not for a node\n")
    arch = web.web / f"codeload.test/{REPO}/tar.gz/refs/heads"
    arch.mkdir(parents=True)
    with tarfile.open(arch / "dev", "w:gz") as t:
        t.add(tree, arcname="suckerpot-dev")
    proc = web.run("--ref", "dev", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TESTING BUILD, NOT SIGNED" in proc.stdout
    assert (web.dest / "scripts/install.sh").is_file()
    assert not (web.dest / "notes-only-in-the-repo.txt").exists()
    meta = (web.dest / ".suckerpot-bundle").read_text()
    assert "signed=0" in meta and "ref=dev" in meta and "latest=v9.9.9" in meta
    assert not [c for c in web.sb.calls() if c.startswith("cosign")]


# ------------------------------------------------------------------ the scripts on a bundle install


def as_bundle(sb: Sandbox, signed: str = "1", version: str = "v0.9.0") -> None:
    add_participant_files(sb)
    (sb.root / "config").mkdir(exist_ok=True)
    shutil.copy2(ROOT / "config/node-bundle.list", sb.root / "config/node-bundle.list")
    (sb.root / ".suckerpot-bundle").write_text(
        f"version={version}\nref={version if signed == '1' else 'dev'}\ncommit={'a' * 40}\n"
        f"signed={signed}\nlatest=v0.9.0\n"
    )


def test_install_takes_the_release_of_its_bundle(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    as_bundle(sandbox)
    proc = sandbox.run("scripts/install.sh", "--participant", "--yes", "--sensors", "ssh")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    env = parse_env(sandbox.root / ".env")
    assert (env["SUCKERPOT_INSTALL_MODE"], env["SUCKERPOT_VERSION"]) == ("images", "v0.9.0")
    assert "could not find the top of the checkout" not in proc.stdout + proc.stderr


def test_a_bundle_cannot_build_from_source(sandbox: Sandbox) -> None:
    as_bundle(sandbox)
    proc = sandbox.run("scripts/install.sh", "--participant", "--yes", "--source")
    assert proc.returncode != 0 and "a node bundle holds no sources" in proc.stderr


def test_a_testing_bundle_runs_the_images_of_the_newest_release(
    sandbox: Sandbox, parse_env: Callable[[Path], dict[str, str]]
) -> None:
    as_bundle(sandbox, signed="0", version="unknown")
    proc = sandbox.run("scripts/install.sh", "--participant", "--yes", "--sensors", "ssh")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "testing scripts of dev (not signed), with the signed images of v0.9.0" in proc.stdout
    assert parse_env(sandbox.root / ".env")["SUCKERPOT_VERSION"] == "v0.9.0"


def test_update_and_rollback_of_a_bundle_install(sandbox: Sandbox, tmp_path: Path) -> None:
    from test_update import ENV, RELEASE_STUB

    as_bundle(sandbox, version="v0.8.0")
    for name in ("update.sh", "rollback.sh", "verify-release.sh"):
        shutil.copy2(ROOT / "scripts" / name, sandbox.root / "scripts" / name)
    stub = sandbox.root / "scripts" / "verify-release.sh"
    stub.write_text(RELEASE_STUB)
    stub.chmod(0o755)
    sandbox.write_env(ENV.replace("demo", "suckerpot") + "SUCKERPOT_STACK_MODE=participant\n")
    sandbox.env["SHIM_RUNNING_VERSION"] = "v0.9.0"
    sandbox.env["SHIM_EXISTING_VOLUMES"] = "suckerpot_backups"
    web = sandbox.shim / "web"
    rel = web / f"github.com/{REPO}/releases/download/v0.9.0"
    rel.mkdir(parents=True)
    make_bundle(rel / "suckerpot-node-v0.9.0.tar.gz", "v0.9.0", COMMIT)
    (web / "latest").write_text("v0.9.0")
    (sandbox.shim / "curl").write_text(CURL_WEB)
    wrap_docker(
        sandbox,
        '  "compose exec -T ingest printenv SUCKERPOT_RUNNING_VERSION") echo v0.9.0; exit 0 ;;',
    )
    proc = sandbox.run("scripts/update.sh", "--yes")
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "the scripts come from the signed node bundle of v0.9.0" in out
    assert any(
        c.startswith("verify-release --bundle .suckerpot-state/suckerpot-node-v0.9.0.tar.gz v0.9.0")
        for c in sandbox.calls()
    )
    assert "version=v0.9.0" in (sandbox.root / ".suckerpot-bundle").read_text()
    assert not [c for c in sandbox.calls() if c.startswith("git checkout")]
    state = (sandbox.root / ".suckerpot-state/last-update.json").read_text()
    assert '"layout": "bundle"' in state
    proc = sandbox.run("scripts/rollback.sh", "--yes", "--keep-db")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "version=v0.8.0" in (sandbox.root / ".suckerpot-bundle").read_text()
