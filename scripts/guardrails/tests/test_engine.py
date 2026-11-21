"""scripts/lib/engine.sh: the container engine abstraction (docs/dev/design/podman.md, phase 1).

- On Docker, the scripts call exactly the same docker commands as before the abstraction. The
  calls of a set of runs are compared with fixtures/docker_calls.json, recorded with the scripts
  of v0.12.1 (before engine.sh). Set SUCKERPOT_RECORD_DOCKER_CALLS=1 to record them again.
- `dc` and `ctr` call podman and docker-compose (on the Podman socket) when the engine is Podman.
- Until Podman support is finished, every script that installs, updates or starts the stack
  refuses Podman, before it calls any engine.
- No script calls `docker` directly any more, outside scripts/lib/engine.sh and the developer
  recipes of the justfile.
"""

import difflib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT, Sandbox
from test_auto_update import stage
from test_env_set import BASE_ENV
from test_install import PASSWORD, add_participant_files
from test_status import Status
from test_update import ENV as UPDATE_ENV
from test_update import prepare, write_state

FIXTURE = Path(__file__).parent / "fixtures" / "docker_calls.json"
UNREADY = "Podman support is not ready yet"
SOCK = "unix:///run/podman/podman.sock"


def _norm(sb: Sandbox, calls: list[str]) -> list[str]:
    out = []
    for c in calls:
        c = c.replace(str(sb.root), "<root>").replace(str(sb.shim), "<shim>")
        out.append(c.replace(str(sb.root.parent), "<tmp>"))
    return out


def _install_images(sb: Sandbox) -> int:
    return sb.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh,web"),
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    ).returncode


def _install_source(sb: Sandbox) -> int:
    return sb.run(
        "scripts/install.sh",
        *("--yes", "--source", "--sensors", "ssh", "--admin-password-stdin"),
        stdin=PASSWORD + "\n",
    ).returncode


def _install_participant(sb: Sandbox) -> int:
    add_participant_files(sb)
    return sb.run(
        "scripts/install.sh",
        *("--participant", "--yes", "--version", "v0.8.0", "--sensors", "ssh,web"),
    ).returncode


def _update_images(sb: Sandbox) -> int:
    prepare(sb)
    return sb.run("scripts/update.sh", "--yes").returncode


def _update_unhealthy(sb: Sandbox) -> int:
    prepare(sb)
    sb.env["SHIM_UP_RC"] = "1"
    sb.env["SHIM_MIGRATE_STATE"] = "exited 0"
    return sb.run("scripts/update.sh", "--yes").returncode


def _rollback(sb: Sandbox) -> int:
    prepare(sb)
    sb.write_env(UPDATE_ENV.replace("v0.8.0", "v0.9.0"))
    write_state(sb)
    (sb.root / "scripts" / "restore-db.sh").write_text('echo "restore-db $*" >> "$SHIM_LOG"\n')
    return sb.run("scripts/rollback.sh", stdin="rollback\n").returncode


def _compose_fresh(sb: Sandbox) -> int:
    sb.write_env(BASE_ENV + "SENSOR_WEB=0\nSENSOR_SSH=1\n")
    return sb.run("scripts/compose-fresh.sh", "up", "-d", "--wait").returncode


def _compose_fresh_images(sb: Sandbox) -> int:
    sb.write_env(BASE_ENV + "SUCKERPOT_INSTALL_MODE=images\nSENSOR_WEB=0\n")
    return sb.run("scripts/compose-fresh.sh", "up", "-d", "--wait").returncode


def _ensure_volumes(sb: Sandbox) -> int:
    sb.env["SUCKERPOT_VOLUME_PREFIX"] = "demo"
    sb.env["SHIM_EXISTING_VOLUMES"] = "demo_backups"
    return sb.run("scripts/ensure-volumes.sh").returncode


def _update_source(sb: Sandbox) -> int:
    prepare(sb, mode="source", branch="main")
    sb.env["SHIM_RUNNING_VERSION"] = "v0.8.0"
    return sb.run("scripts/update.sh", "--yes").returncode


def _status(sb: Sandbox) -> int:
    return Status(sb).run()[0]


def _participant_status(sb: Sandbox) -> int:
    Status(sb)
    return sb.run("scripts/participant.sh", "status").returncode


def _restore_latest(sb: Sandbox) -> int:
    sb.write_env(BASE_ENV)
    sb.env["SUCKERPOT_VOLUME_PREFIX"] = "demo"
    sb.env["SHIM_EXISTING_VOLUMES"] = "demo_backups"
    return sb.run("scripts/restore-db.sh", "--yes", "latest").returncode


SCENARIOS = {
    "install_images": _install_images,
    "install_source": _install_source,
    "install_participant": _install_participant,
    "update_images": _update_images,
    "update_unhealthy": _update_unhealthy,
    "update_source": _update_source,
    "status": _status,
    "participant_status": _participant_status,
    "rollback": _rollback,
    "compose_fresh": _compose_fresh,
    "compose_fresh_images": _compose_fresh_images,
    "ensure_volumes": _ensure_volumes,
    "restore_latest": _restore_latest,
}


def _record(sb: Sandbox, name: str) -> tuple[int, list[str]]:
    rc = SCENARIOS[name](sb)
    return rc, _norm(sb, sb.docker_calls())


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_docker_command_lines_are_unchanged(sandbox: Sandbox, name: str) -> None:
    rc, calls = _record(sandbox, name)
    assert calls, "the scenario made no docker call: it proves nothing"
    if os.environ.get("SUCKERPOT_RECORD_DOCKER_CALLS") == "1":
        data = json.loads(FIXTURE.read_text()) if FIXTURE.exists() else {}
        data[name] = {"rc": rc, "calls": calls}
        FIXTURE.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
        return
    want = json.loads(FIXTURE.read_text())[name]
    assert rc == want["rc"]
    # Sorted: the two sides of a pipeline (`dc exec db ... | dc exec ingest ...`) log in any order.
    old, new = sorted(want["calls"]), sorted(calls)
    assert new == old, "\n".join(difflib.unified_diff(old, new, "v0.12.1", "now", lineterm=""))


def test_every_scenario_has_a_recorded_fixture() -> None:
    assert sorted(json.loads(FIXTURE.read_text())) == sorted(SCENARIOS)


# ------------------------------------------------------------------ dc and ctr


def _engine_calls(sb: Sandbox) -> list[str]:
    return [c for c in sb.calls() if c.split(" ", 1)[0] in ("docker", "podman", "docker-compose")]


def _source_and_run(sb: Sandbox, body: str, extra_env: dict[str, str] | None = None) -> str:
    script = sb.root / "engine-probe.sh"
    script.write_text(
        "set -euo pipefail\n"
        'cd "$(dirname "$0")"\n'
        ". scripts/lib/engine.sh\n"
        'echo "engine=$SUCKERPOT_ENGINE from=$ENGINE_FROM name=$(engine_name)"\n' + body
    )
    proc = sb.run("engine-probe.sh", extra_env=extra_env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


PROBE = """\
dc up -d --wait
ctr volume ls -q
timeout 5 "${ENGINE_DC[@]}" ps
echo demo_x | xargs -r "${ENGINE_CTR[@]}" volume rm
echo "after=${DOCKER_HOST:-unset}"
"""


def test_dc_and_ctr_call_docker_by_default(sandbox: Sandbox) -> None:
    out = _source_and_run(sandbox, PROBE)
    assert "engine=docker from=default name=Docker" in out
    assert _engine_calls(sandbox) == [
        "docker compose up -d --wait",
        "docker volume ls -q",
        "docker compose ps",
        "docker volume rm demo_x",
    ]


def test_dc_and_ctr_call_podman_and_compose_on_the_podman_socket(sandbox: Sandbox) -> None:
    out = _source_and_run(sandbox, PROBE, extra_env={"SUCKERPOT_ENGINE": "podman"})
    assert "engine=podman from=env name=Podman" in out
    sock = "DOCKER_HOST=unix:///run/podman/podman.sock"
    # podman always talks to the root Podman service, never to a rootless one of the caller.
    assert _engine_calls(sandbox) == [
        f"docker-compose up -d --wait {sock}",
        f"podman --url {SOCK} volume ls -q",
        f"docker-compose ps {sock}",
        f"podman --url {SOCK} volume rm demo_x",
    ]
    # The socket is set for the compose call only, never for the script.
    assert f"after={sandbox.env['DOCKER_HOST']}" in out


def test_engine_comes_from_env_file_first_then_the_environment(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\nSUCKERPOT_ENGINE='podman'\n")
    assert "engine=podman from=file" in _source_and_run(sandbox, "")
    out = _source_and_run(sandbox, "", extra_env={"SUCKERPOT_ENGINE": "docker"})
    assert "engine=podman from=file" in out
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\n")
    out = _source_and_run(sandbox, "", extra_env={"SUCKERPOT_ENGINE": "podman"})
    assert "engine=podman from=env" in out
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\n")
    assert "engine=docker from=default" in _source_and_run(sandbox, "")


def test_an_unknown_engine_stops_the_script(sandbox: Sandbox) -> None:
    sandbox.write_env("SUCKERPOT_ENGINE=containerd\n")
    proc = sandbox.run("scripts/update.sh", "--yes")
    assert proc.returncode != 0
    assert "SUCKERPOT_ENGINE must be docker or podman" in proc.stderr
    assert _engine_calls(sandbox) == []


# ------------------------------------------------------------------ Podman is refused for now


def _podman_install(sb: Sandbox) -> subprocess.CompletedProcess[str]:
    return sb.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"),
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
        extra_env={"SUCKERPOT_ENGINE": "podman"},
    )


def _assert_refused(sb: Sandbox, proc: subprocess.CompletedProcess[str]) -> None:
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert UNREADY in proc.stderr
    assert _engine_calls(sb) == [], "no engine may be called before the refusal"


def test_install_refuses_podman_before_anything_runs(sandbox: Sandbox) -> None:
    proc = _podman_install(sandbox)
    _assert_refused(sandbox, proc)
    assert not (sandbox.root / ".env").exists()
    assert not list(sandbox.root.glob(".env.*.tmp*"))


def test_install_dry_run_refuses_podman_too(sandbox: Sandbox) -> None:
    out = sandbox.root / "out.env"
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--dry-run", "--env-out", str(out), "--admin-password-stdin"),
        stdin=PASSWORD + "\n",
        extra_env={"SUCKERPOT_ENGINE": "podman"},
    )
    _assert_refused(sandbox, proc)
    assert not out.exists()


def test_install_repair_refuses_an_env_that_says_podman(sandbox: Sandbox) -> None:
    sandbox.write_env(UPDATE_ENV + "SUCKERPOT_ENGINE=podman\n")
    proc = sandbox.run("scripts/install.sh", "--repair", "--yes")
    _assert_refused(sandbox, proc)


def _path_without_docker(sb: Sandbox) -> str:
    """A PATH with the sandbox's tools and the fake podman, and no docker command at all.

    The tools are links to what the sandbox PATH finds after the fakes, first match wins, so a
    folder that appears twice (/bin -> /usr/bin on a merged /usr) or a dangling link is harmless.
    """
    tools = sb.shim.parent / "tools"
    tools.mkdir()
    seen: set[str] = set()
    for d in sb.env["PATH"].split(":"):
        real = os.path.realpath(d)
        if d == str(sb.shim) or real in seen or not os.path.isdir(real):
            continue
        seen.add(real)
        for entry in sorted(Path(real).iterdir()):
            link = tools / entry.name
            if entry.name in ("docker", "docker-compose", "podman") or os.path.lexists(link):
                continue
            link.symlink_to(entry)
    nodocker = sb.shim.parent / "nodocker"
    nodocker.mkdir()
    for name in ("podman", "git", "curl", "ss", "sleep"):
        (nodocker / name).symlink_to(sb.shim / name)
    return f"{nodocker}:{tools}"


def test_install_detects_a_podman_only_host_and_refuses(sandbox: Sandbox) -> None:
    sandbox.env["PATH"] = _path_without_docker(sandbox)
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"),
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    )
    _assert_refused(sandbox, proc)


def test_install_refuses_a_docker_command_that_is_podman(sandbox: Sandbox) -> None:
    """The podman-docker package: `docker` answers with the Podman version."""
    shim = sandbox.shim / "docker"
    text = shim.read_text().replace('echo "27.0.1"', 'echo "5.4.2"')
    shim.write_text(
        text.replace("  *) ;;", '  "--version") echo "podman version 5.4.2" ;;\n  *) ;;')
    )
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"),
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert proc.returncode == 1
    assert UNREADY in proc.stderr
    assert "the docker command on this host is Podman 5.4.2" in proc.stderr
    assert not (sandbox.root / ".env").exists()
    assert not [c for c in sandbox.calls() if c.startswith(("docker compose up", "docker run"))]


def test_old_docker_keeps_its_message(sandbox: Sandbox) -> None:
    shim = sandbox.shim / "docker"
    shim.write_text(shim.read_text().replace('echo "27.0.1"', 'echo "20.10.5"'))
    proc = sandbox.run(
        "scripts/install.sh",
        *("--yes", "--images", "--version", "v0.8.0", "--sensors", "ssh"),
        "--admin-password-stdin",
        stdin=PASSWORD + "\n",
    )
    assert proc.returncode == 1
    assert "Docker Engine 24 or newer is required (found 20.10.5)" in proc.stderr
    assert UNREADY not in proc.stderr


def test_update_refuses_podman_before_anything_runs(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(UPDATE_ENV + "SUCKERPOT_ENGINE=podman\n")
    proc = sandbox.run("scripts/update.sh", "--yes")
    _assert_refused(sandbox, proc)
    assert not [c for c in sandbox.calls() if c.startswith("git ")]
    assert not (sandbox.root / ".suckerpot-state").exists()


def test_update_refuses_podman_from_the_environment(sandbox: Sandbox) -> None:
    prepare(sandbox)
    proc = sandbox.run("scripts/update.sh", "--yes", extra_env={"SUCKERPOT_ENGINE": "podman"})
    _assert_refused(sandbox, proc)


@pytest.mark.parametrize(
    ("script", "args"),
    [
        ("scripts/rollback.sh", ()),
        ("scripts/participant.sh", ("status",)),
        ("scripts/compose-fresh.sh", ("up", "-d", "--wait")),
        ("scripts/ensure-volumes.sh", ()),
        ("scripts/restore-db.sh", ("--yes", "latest")),
    ],
)
def test_every_script_that_starts_the_stack_refuses_podman(
    sandbox: Sandbox, script: str, args: tuple[str, ...]
) -> None:
    add_participant_files(sandbox)
    sandbox.write_env(UPDATE_ENV + "SUCKERPOT_ENGINE=podman\n")
    sandbox.env["SUCKERPOT_VOLUME_PREFIX"] = "demo"
    proc = sandbox.run(script, *args, stdin="rollback\n")
    _assert_refused(sandbox, proc)


def test_docker_install_writes_the_engine_and_migrate_adds_it(
    sandbox: Sandbox,
) -> None:
    assert _install_images(sandbox) == 0
    env = (sandbox.root / ".env").read_text()
    assert re.findall(r"^SUCKERPOT_ENGINE=.*$", env, re.M) == ["SUCKERPOT_ENGINE=docker"]
    # An install from before the key gets SUCKERPOT_ENGINE=docker, so it never switches engine.
    sandbox.write_env(UPDATE_ENV)
    proc = sandbox.run("scripts/env-migrate.sh")
    assert proc.returncode == 0, proc.stderr
    env = (sandbox.root / ".env").read_text()
    assert re.findall(r"^SUCKERPOT_ENGINE=.*$", env, re.M) == ["SUCKERPOT_ENGINE=docker"]


# ------------------------------------------------------------------ no literal docker call

ENGINE_LIB = "scripts/lib/engine.sh"
# The developer recipes of the justfile stay on Docker (design decision D8).
DEV_RECIPES = {
    "guardrails",
    "web-dev",
    "trap-check",
    "_trap",
    "hub-integration",
    "test-integration",
    "_cache_vol",
    "_web",
    "_cache",
    "_py",
}
DOCKER_CALL = re.compile(
    r"(?<![\w./-])docker\s+(?:compose|run|volume|network|inspect|image|pull|tag|info|version|ps|"
    r"exec|create|start|stop|rm|rmi|build|kill|logs|login|cp|wait|--version)\b"
)


def _context_at(line: str, pos: int) -> str:
    """'code' when position `pos` of a shell line is outside quotes (or inside $(...))."""
    stack = ["code"]
    i = 0
    while i < pos:
        c, top = line[i], stack[-1]
        if top == "sq":
            if c == "'":
                stack.pop()
        elif c == "\\":
            i += 2
            continue
        elif line.startswith("$(", i):
            stack.append("sub")
            i += 2
            continue
        elif top == "dq":
            if c == '"':
                stack.pop()
        elif c == "'":
            stack.append("sq")
        elif c == '"':
            stack.append("dq")
        elif c == "(":
            stack.append("paren")
        elif c == ")" and top in ("sub", "paren"):
            stack.pop()
        i += 1
    return "code" if stack[-1] in ("code", "sub", "paren") else stack[-1]


def literal_docker_calls(text: str) -> list[str]:
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in DOCKER_CALL.finditer(line):
            if _context_at(line, m.start()) == "code":
                found.append(f"{n}: {line.strip()}")
    return found


def _node_justfile(text: str) -> str:
    """The justfile without the bodies of the developer recipes."""
    keep, skip = [], False
    for line in text.splitlines():
        m = re.match(r"^@?([A-Za-z_][\w-]*)[^:=]*:(?!=)", line)
        if m:
            skip = m.group(1) in DEV_RECIPES
        elif line and not line[0].isspace():
            skip = False
        keep.append("" if skip else line)
    return "\n".join(keep)


def test_the_detector_sees_calls_and_ignores_messages() -> None:
    assert literal_docker_calls("x=$(docker compose ps)\n  docker run --rm a\n")
    assert literal_docker_calls('echo "$(docker inspect -f x c)"\nfoo | docker volume rm\n')
    assert literal_docker_calls("if ! docker network inspect n; then :; fi\n")
    assert not literal_docker_calls('die "run: docker compose pull"\n# docker run\n')
    assert not literal_docker_calls("x=$(dc ps) && ctr run --rm a\n")


def test_no_script_calls_docker_directly() -> None:
    offenders = []
    for path in sorted((ROOT / "scripts").rglob("*.sh")):
        rel = path.relative_to(ROOT).as_posix()
        if rel == ENGINE_LIB:
            continue
        offenders += [f"{rel}:{hit}" for hit in literal_docker_calls(path.read_text())]
    offenders += [
        f"justfile:{hit}"
        for hit in literal_docker_calls(_node_justfile((ROOT / "justfile").read_text()))
    ]
    assert offenders == [], "use dc or ctr (scripts/lib/engine.sh):\n" + "\n".join(offenders)


def test_the_developer_recipes_exist() -> None:
    """A renamed developer recipe must not silently leave the literal-docker check."""
    text = (ROOT / "justfile").read_text()
    for name in DEV_RECIPES:
        assert re.search(rf"^@?{re.escape(name)}\b[^:=]*:(?!=)", text, re.M), name
    assert literal_docker_calls(text), "the developer recipes still call docker"


# ------------------------------------------------------------------ printed commands

HEREDOC = re.compile(r"<<(-?)\s*(['\"]?)(\w+)\2")
SHELL_FN = re.compile(r"(?<![\w$./{-])(dc|ctr)\s+[a-z-]")
MESSAGE_CMD = re.compile(r"^\s*(?:\S+\s*\|\|\s*)?(echo|die|warn|note|fatal|printf|log|fail)\b")


def printed_shell_functions(text: str) -> list[str]:
    """Lines of heredocs and of quoted messages that tell the user to run `dc` or `ctr`.

    Those are shell functions of scripts/lib/engine.sh: a user who copies the line gets "command
    not found" (or GNU dc). Printed commands use ${ENGINE_DC[*]} and ${ENGINE_CTR[*]}.
    """
    found: list[str] = []
    end: str | None = None
    dash = False
    for n, line in enumerate(text.splitlines(), 1):
        if end is not None:
            if (line.strip() if dash else line) == end:
                end = None
            elif SHELL_FN.search(line):
                found.append(f"{n}: {line.strip()}")
            continue
        if line.lstrip().startswith("#"):
            continue
        m = HEREDOC.search(line)
        if m and _context_at(line, m.start()) == "code":
            dash, end = m.group(1) == "-", m.group(3)
        if MESSAGE_CMD.match(line):
            for s in re.finditer(r'"((?:[^"\\]|\\.)*)"', line):
                if SHELL_FN.search(re.sub(r"\$\([^)]*\)", "", s.group(1))):
                    found.append(f"{n}: {line.strip()}")
    return found


def test_the_printed_command_detector() -> None:
    assert printed_shell_functions("cat <<EOF\ndc up -d\nEOF\n")
    assert printed_shell_functions("cat >&2 <<'X'\n  ctr volume rm v\nX\n")
    assert printed_shell_functions('echo "run: dc ps"\n')
    assert printed_shell_functions('cmd || die "then: ctr network rm n"\n')
    assert not printed_shell_functions("cat <<EOF\n${ENGINE_DC[*]} up -d\nEOF\ndc up -d\n")
    assert not printed_shell_functions('echo "$(dc ps)"\nx=$(dc ps)\n')


def test_no_printed_command_names_dc_or_ctr() -> None:
    offenders = []
    for path in sorted((ROOT / "scripts").rglob("*.sh")):
        rel = path.relative_to(ROOT).as_posix()
        if rel == ENGINE_LIB:
            continue
        offenders += [f"{rel}:{hit}" for hit in printed_shell_functions(path.read_text())]
    assert offenders == [], "print ${ENGINE_DC[*]} / ${ENGINE_CTR[*]}:\n" + "\n".join(offenders)


# ------------------------------------------------------------------ .env values and read-only paths


def test_an_inline_comment_after_the_engine_is_ignored(sandbox: Sandbox) -> None:
    sandbox.write_env("COMPOSE_PROJECT_NAME=demo\nSUCKERPOT_ENGINE=docker   # the default\n")
    assert "engine=docker from=file" in _source_and_run(sandbox, "")
    sandbox.write_env('SUCKERPOT_ENGINE="podman" # later\n')
    assert "engine=podman from=file" in _source_and_run(sandbox, "")


def test_update_runs_with_a_commented_engine_line(sandbox: Sandbox) -> None:
    prepare(sandbox)
    sandbox.write_env(UPDATE_ENV + "SUCKERPOT_ENGINE=docker # default\n")
    proc = sandbox.run("scripts/update.sh", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_status_falls_back_to_docker_on_an_unknown_engine(sandbox: Sandbox) -> None:
    st = Status(sandbox)
    with (sandbox.root / ".env").open("a") as f:
        f.write("SUCKERPOT_ENGINE=containerd\n")
    rc, _, err = st.run()
    assert rc == 0, err
    assert "SUCKERPOT_ENGINE must be docker or podman" in err
    assert "using docker for this read-only command" in err
    assert "docker compose exec -T ingest python -m ingest.network.cli status --json" in (
        sandbox.calls()
    )


def test_auto_update_falls_back_to_docker_on_an_unknown_engine(sandbox: Sandbox) -> None:
    stage(sandbox)
    with (sandbox.root / ".env").open("a") as f:
        f.write("SUCKERPOT_ENGINE=containerd\n")
    proc = sandbox.run("scripts/auto-update.sh", extra_env={"AUTO_UPDATE_JITTER_S": "0"})
    assert "using docker for this read-only command" in proc.stderr
    # It went past the library: the tags were fetched.
    assert "git fetch --tags --quiet" in sandbox.calls()


def test_render_firewall_reads_the_env_of_its_checkout(sandbox: Sandbox, tmp_path: Path) -> None:
    add_participant_files(sandbox)
    sandbox.write_env("SUCKERPOT_ENGINE=podman\n")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".env").write_text("SUCKERPOT_ENGINE=docker\n")
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.0.2.53\n")
    subprocess.run(  # noqa: S603
        [  # noqa: S607
            "bash",
            str(sandbox.root / "scripts/host/render-firewall.sh"),
            *("--participant", "--admin-ssh-port", "2200", "--resolv-conf", str(resolv)),
        ],
        cwd=elsewhere,
        env=sandbox.env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    calls = sandbox.calls()
    assert any(c.startswith(f"podman --url {SOCK} network ls") for c in calls), calls
    assert not any(c.startswith("docker network") for c in calls)


# ------------------------------------------------------------------ an update from v0.12.1

OLD_TREE = Path(__file__).parent / "fixtures" / "v0.12.1"

GIT_CHECKOUT_BRINGS_NEW_FILES = """\
case "$*" in "checkout "*) cp -R "$SHIM_DIR/newtree/." . ;; esac
exit 0
"""


def test_an_update_from_v0_12_1_runs_the_same_docker_calls(sandbox: Sandbox) -> None:
    """The v0.12.1 update.sh (still running from memory) checks out this tree and goes on.

    Its git checkout brings the new scripts/lib/env.sh, so the new env-migrate.sh and the other
    new scripts it calls find the engine library. The docker calls are those of a v0.12.1 update.
    """
    prepare(sandbox)
    newtree = sandbox.shim / "newtree" / "scripts" / "lib"
    newtree.mkdir(parents=True)
    (newtree / "env.sh").write_text((sandbox.root / "scripts/lib/env.sh").read_text())
    (sandbox.root / "scripts/update.sh").write_text((OLD_TREE / "update.sh.txt").read_text())
    (sandbox.root / "scripts/lib/env.sh").write_text((OLD_TREE / "env.sh.txt").read_text())
    git = sandbox.shim / "git"
    text = git.read_text()
    assert text.endswith("esac\nexit 0\n")
    git.write_text(text[: -len("exit 0\n")] + GIT_CHECKOUT_BRINGS_NEW_FILES)
    proc = sandbox.run("scripts/update.sh", "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "engine.sh" in (sandbox.root / "scripts/lib/env.sh").read_text()
    want = json.loads(FIXTURE.read_text())["update_images"]["calls"]
    assert sorted(_norm(sandbox, sandbox.docker_calls())) == sorted(want)
    env = (sandbox.root / ".env").read_text()
    assert re.findall(r"^SUCKERPOT_ENGINE=.*$", env, re.M) == ["SUCKERPOT_ENGINE=docker"]


# ------------------------------------------------------------------ sourcing has no side effects

STATE_PROBE = r"""
set -euo pipefail
trap 'true' EXIT
state() { set +o; shopt -p; trap -p; echo "umask=$(umask)"; }
before=$(state)
{prefix}. scripts/lib/engine.sh
rc=$?
after=$(state)
[ "$before" = "$after" ] || { diff <(echo "$before") <(echo "$after") >&2; exit 3; }
echo "rc=$rc env_file=${ENV_FILE-unset} engine=$ENGINE_ID"
rand=$( (set +o pipefail; LC_ALL=C tr -dc 'a-z0-9' < /dev/urandom | head -c 8) )
echo "rand=${#rand}"
"""


@pytest.mark.parametrize(
    ("env", "prefix", "engine"),
    [
        ("", "", "docker"),
        ("", "ENV_FILE=/dev/null ", "docker"),
        ("SUCKERPOT_ENGINE=docker # default\n", "", "docker"),
        ("SUCKERPOT_ENGINE=podman\n", "", "podman"),
    ],
)
def test_sourcing_the_library_keeps_the_shell_state(
    sandbox: Sandbox, env: str, prefix: str, engine: str
) -> None:
    if env:
        sandbox.write_env(env)
    script = sandbox.root / "state-probe.sh"
    script.write_text('cd "$(dirname "$0")"\n' + STATE_PROBE.replace("{prefix}", prefix))
    proc = sandbox.run("state-probe.sh")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"rc=0 env_file=unset engine={engine}" in proc.stdout
    assert "rand=8" in proc.stdout
    assert _engine_calls(sandbox) == []


def test_the_e2e_script_needs_no_work_folder_before_it_exists() -> None:
    """Its own dc and hubdc run in $work: no top-level call before the copy is made."""
    lines = (ROOT / "scripts/e2e/participant.sh").read_text().splitlines()
    start = lines.index('work=""')
    end = next(i for i, line in enumerate(lines) if line.startswith("work=$(mktemp"))
    early = [
        f"{i + 1}: {line}"
        for i, line in enumerate(lines[start:end], start)
        if re.match(r"^(hubdc|dc)\s", line) or re.search(r"^[^\s#].*\$\((hubdc|dc)\s", line)
    ]
    assert early == []


def test_the_docker_free_path_survives_a_merged_usr(sandbox: Sandbox, tmp_path: Path) -> None:
    """/bin -> /usr/bin and dangling links, as on the CI runner."""
    usr = tmp_path / "usr-bin"
    usr.mkdir()
    (usr / "dangling").symlink_to(tmp_path / "nowhere")
    (usr / "docker").write_text("#!/bin/sh\nexit 99\n")
    (tmp_path / "bin").symlink_to(usr)
    sandbox.env["PATH"] = f"{sandbox.shim}:{usr}:{tmp_path / 'bin'}:{usr}:/usr/bin:/bin"
    path = _path_without_docker(sandbox)
    tools = Path(path.split(":")[1])
    assert os.path.islink(tools / "dangling")
    assert not os.path.lexists(tools / "docker")
    assert shutil.which("docker", path=path) is None
