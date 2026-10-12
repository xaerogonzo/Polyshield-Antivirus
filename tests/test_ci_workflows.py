"""The shape of the CI workflows.

A workflow with a syntax error is not one that fails -- it is one that never
runs, and no amount of green elsewhere will say so
(docs/gotchas/ci-green-for-the-wrong-reason.md #3). This file cannot claim CI ran;
it can pin the *shape* the workflows must keep, so that a careless edit that
unwires a gate fails here, in the suite, instead of silently in a workflow nobody
is watching.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML implements YAML 1.1, where a bare `on` is the boolean True.
    return doc.get("on", doc.get(True))


def _steps(doc: dict, job: str) -> list[dict]:
    return doc["jobs"][job]["steps"]


def _step(doc: dict, job: str, name_contains: str) -> dict:
    hits = [s for s in _steps(doc, job) if name_contains in s.get("name", "")]
    assert len(hits) == 1, (
        f"expected exactly one step named like {name_contains!r}, found {len(hits)}")
    return hits[0]


@pytest.mark.parametrize("name", sorted(p.name for p in WORKFLOWS.glob("*.yml")))
def test_every_workflow_parses_and_declares_jobs(name):
    doc = _load(name)
    assert isinstance(doc, dict) and doc.get("jobs"), f"{name} has no jobs"
    assert _triggers(doc), f"{name} has no trigger, so it can never run"


# -- build-smoke ---------------------------------------------------------------

def _relevant_patterns() -> list[str]:
    env = _step(_load("build-smoke.yml"), "changes", "Decide whether")["env"]
    return [ln.strip() for ln in env["RELEVANT"].splitlines() if ln.strip()]


def test_build_smoke_has_no_path_filter_on_its_trigger():
    """A workflow filtered at the trigger does not run at all for a pull request
    that matches nothing, so it reports no check -- and a required check that is
    never reported blocks the merge forever. The filtering is a job instead."""
    pr = _triggers(_load("build-smoke.yml"))["pull_request"]
    assert not (pr and ("paths" in pr or "paths-ignore" in pr)), (
        "a paths filter on the pull_request trigger makes the gate unrequirable")


def test_build_smoke_decides_relevance_when_its_own_definition_changes():
    """Otherwise an edit to the workflow is the one change it does not test."""
    assert ".github/workflows/build-smoke.yml" in _relevant_patterns()


@pytest.mark.parametrize("path", [
    "build.ps1", "installer/*", "requirements.txt", "tools/engine_probe.py",
    "tools/sandbox_verify.ps1",
])
def test_build_smoke_treats_the_files_that_can_break_the_build_as_relevant(path):
    assert path in _relevant_patterns()


def test_build_smoke_also_runs_on_a_schedule_and_on_demand():
    """Most of what rots is outside this repository, so a diff filter alone would
    leave it unwatched between build-file edits."""
    trig = _triggers(_load("build-smoke.yml"))
    assert "schedule" in trig and "workflow_dispatch" in trig


def test_the_build_job_runs_only_when_the_change_detector_says_so():
    build = _load("build-smoke.yml")["jobs"]["build"]
    assert build["needs"] == "changes"
    assert "needs.changes.outputs.relevant == 'true'" in build["if"]


def test_the_gate_always_runs_and_waits_for_both_jobs():
    """`if: always()` is what makes it reportable even when `build` was skipped;
    without it a skipped dependency skips the gate, and a required check that is
    skipped is not a check that passed."""
    gate = _load("build-smoke.yml")["jobs"]["build-smoke-gate"]
    assert gate.get("if") == "always()", (
        "the gate must run with `if: always()`, or a skipped build skips the gate "
        "and the required check never reports")
    assert set(gate["needs"]) == {"changes", "build"}


# The two scripts below are exercised by RUNNING them: a text check on a shell
# script says nothing about what it does with its inputs.

def _bash() -> str | None:
    git = shutil.which("git")
    if git:
        # Git for Windows: ...\cmd\git.exe -> ...\bin\bash.exe. Preferred over a
        # bare `bash` on PATH, which on Windows can be WSL's, with different paths.
        candidate = pathlib.Path(git).resolve().parent.parent / "bin" / "bash.exe"
        if candidate.exists():
            return str(candidate)
    return shutil.which("bash")


needs_bash = pytest.mark.skipif(_bash() is None, reason="no bash available to run the CI scripts")


def _run_script(script: str, env: dict, cwd=None) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as td:
        path = pathlib.Path(td) / "step.sh"
        path.write_text(script, encoding="utf-8", newline="\n")
        return subprocess.run([_bash(), str(path)], env={**os.environ, **env},
                              cwd=cwd, capture_output=True, text=True, timeout=60)


@needs_bash
@pytest.mark.parametrize("relevant,build,expect_pass", [
    ("true", "success", True),      # the build ran and was clean
    ("false", "skipped", True),     # nothing relevant changed; skipping was right
    ("true", "failure", False),     # the build failed
    ("true", "cancelled", False),   # ...or was cancelled
    ("true", "skipped", False),     # the diff said it was needed and it did not run
    ("false", "failure", False),    # cannot happen (build is skipped) -> still red
    ("false", "success", False),    # ...an unreachable state is a bug, not a pass
    ("", "skipped", False),         # no answer from the detector is not "irrelevant"
])
def test_the_gate_passes_only_for_a_clean_build_or_a_correct_skip(relevant, build, expect_pass):
    step = _step(_load("build-smoke.yml"), "build-smoke-gate", "Require a clean build")
    result = _run_script(step["run"], {"CHANGES_RESULT": "success", "RELEVANT": relevant,
                                       "BUILD_RESULT": build})
    assert (result.returncode == 0) is expect_pass, result.stdout + result.stderr


@needs_bash
@pytest.mark.parametrize("changes_result", ["failure", "cancelled", "skipped"])
def test_the_gate_fails_if_the_change_detector_did_not_finish(changes_result):
    """Even a `false`/`skipped` pair must not pass if `changes` itself broke:
    it fails closed."""
    step = _step(_load("build-smoke.yml"), "build-smoke-gate", "Require a clean build")
    result = _run_script(step["run"], {"CHANGES_RESULT": changes_result,
                                       "RELEVANT": "false", "BUILD_RESULT": "skipped"})
    assert result.returncode != 0


def _repo_with_change(files: list[str]) -> tuple[pathlib.Path, str, str, tempfile.TemporaryDirectory]:
    td = tempfile.TemporaryDirectory()
    repo = pathlib.Path(td.name)

    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True,
                       env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})

    git("init", "-q")
    (repo / "README.md").write_text("base\n")
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                          text=True, check=True).stdout.strip()
    for rel in files:
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("changed\n")
    git("add", "-A")
    git("commit", "-q", "-m", "head")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                          text=True, check=True).stdout.strip()
    return repo, base, head, td


def _decide(files, event="pull_request", base=None):
    step = _step(_load("build-smoke.yml"), "changes", "Decide whether")
    repo, real_base, head, td = _repo_with_change(files)
    with td:
        out = repo / "gh_output.txt"
        out.write_text("")
        env = {"EVENT": event, "BASE": base or real_base, "HEAD": head,
               "RELEVANT": step["env"]["RELEVANT"], "GITHUB_OUTPUT": str(out)}
        result = _run_script(step["run"], env, cwd=repo)
        return result, out.read_text()


@needs_bash
@pytest.mark.parametrize("files", [
    ["installer/polyshield.iss"],
    ["installer/sub/dir/nested.ps1"],         # '*' must cross '/'
    ["build.ps1"],
    ["docs/x.md", "tools/sandbox_verify.ps1"],  # one relevant file among others
    [".github/workflows/build-smoke.yml"],
])
def test_the_change_detector_marks_build_files_relevant(files):
    result, output = _decide(files)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "relevant=true" in output


@needs_bash
@pytest.mark.parametrize("files", [
    ["docs/ARCHITECTURE.md"],
    ["CHANGELOG.md", "tests/test_x.py"],
    ["src/ui/views/scan_view.py"],
])
def test_the_change_detector_marks_unrelated_changes_irrelevant(files):
    result, output = _decide(files)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "relevant=false" in output


@needs_bash
@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch"])
def test_outside_a_pull_request_the_build_always_runs(event):
    """Scheduled and manual runs exist to catch what rots outside the repo, so
    they must never be skipped for having an empty diff."""
    result, output = _decide(["docs/ARCHITECTURE.md"], event=event)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "relevant=true" in output


@needs_bash
def test_the_change_detector_fails_closed_when_it_cannot_read_the_diff():
    """An unknown base must be an error, not 'nothing relevant changed' -- the
    latter would let the gate pass without the build ever being considered."""
    result, output = _decide(["docs/x.md"], base="0" * 40)
    assert result.returncode != 0
    assert "relevant=false" not in output


def test_build_smoke_declares_its_shell_explicitly():
    job = _load("build-smoke.yml")["jobs"]["build"]
    assert job["defaults"]["run"]["shell"] == "pwsh", (
        "the default shell changes with the runner; a bash script handed to pwsh "
        "fails at parse time having done nothing")


def test_build_smoke_steps_run_in_the_order_that_makes_them_meaningful():
    names = [s.get("name", "") for s in _steps(_load("build-smoke.yml"), "build")]
    order = ["Build the distribution", "Compile the installer",
             "Run the install cycle", "Fail on any failed check"]
    idx = [next(i for i, n in enumerate(names) if o in n) for o in order]
    assert idx == sorted(idx), f"out of order: {dict(zip(order, idx))}"


def test_build_smoke_verdict_and_upload_run_even_when_an_earlier_step_fails():
    """A red step skips everything behind it, and `skipped` reads as 'not
    applicable' (gotcha #1). The verdict must be able to run on its own, and the
    logs are most needed exactly when something failed."""
    doc = _load("build-smoke.yml")
    for name in ("Fail on any failed check", "Upload logs"):
        assert _step(doc, "build", name).get("if") == "always()", (
            f"step {name!r} must run with `if: always()`, or a red step before it "
            "will skip it and report 'skipped'")


def test_build_smoke_verdict_treats_a_missing_report_as_a_failure():
    """A hung install cycle writes no verify.json. Reading that as 'nothing to
    check' would turn the worst outcome into a green run."""
    script = _step(_load("build-smoke.yml"), "build", "Fail on any failed check")["run"]
    assert "Test-Path" in script and "throw" in script
    assert "verify.json" in script


def test_build_smoke_bounds_the_install_cycle_on_its_own():
    """The first complete run finished every check and then never returned; the
    only limit was the 90-minute job timeout. The cycle needs its own, so a hang
    costs minutes and the steps behind it (verdict, upload) still run."""
    step = _step(_load("build-smoke.yml"), "build", "Run the install cycle")
    assert step.get("timeout-minutes"), "the install cycle has no timeout of its own"
    assert step["timeout-minutes"] <= 45


def test_build_smoke_tells_the_verifier_it_is_not_in_a_sandbox_and_says_what_it_skipped():
    """Two verifier checks describe the Windows Sandbox itself and cannot hold on a
    hosted runner. Skipping them is only honest if the skip is visible: the
    verdict step must print what was skipped."""
    doc = _load("build-smoke.yml")
    cycle = _step(doc, "build", "Run the install cycle")["run"]
    assert "-SkipSandboxPreconditions" in cycle
    assert "-SkipFullReport" in cycle
    verdict = _step(doc, "build", "Fail on any failed check")["run"]
    assert "SKIPPED" in verdict and "skipped" in verdict


def test_build_smoke_uploads_the_verifier_results_so_a_red_run_can_be_diagnosed():
    """The machine is thrown away; the artifact is all that is left."""
    paths = _step(_load("build-smoke.yml"), "build", "Upload logs")["with"]["path"]
    assert "artifacts/ci/" in paths and "verify.log" in paths


def test_build_smoke_builds_unsigned_because_it_runs_on_pull_requests():
    """A signing certificate is a secret. It must never be wired into a workflow
    that pull requests can trigger."""
    text = (WORKFLOWS / "build-smoke.yml").read_text(encoding="utf-8")
    assert "POLYSHIELD_SIGN" not in text and "secrets." not in text
