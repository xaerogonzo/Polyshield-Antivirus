"""The shape of the CI workflows.

A workflow with a syntax error is not one that fails -- it is one that never
runs, and no amount of green elsewhere will say so
(docs/gotchas/ci-green-for-the-wrong-reason.md #3). This file cannot claim CI ran;
it can pin the *shape* the workflows must keep, so that a careless edit that
unwires a gate fails here, in the suite, instead of silently in a workflow nobody
is watching.
"""
from __future__ import annotations

import pathlib

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

def test_build_smoke_runs_when_its_own_definition_changes():
    """Otherwise an edit to the workflow is the one change it does not test."""
    paths = _triggers(_load("build-smoke.yml"))["pull_request"]["paths"]
    assert ".github/workflows/build-smoke.yml" in paths


@pytest.mark.parametrize("path", [
    "build.ps1", "installer/**", "requirements.txt", "tools/engine_probe.py",
])
def test_build_smoke_is_triggered_by_the_files_that_can_break_the_build(path):
    paths = _triggers(_load("build-smoke.yml"))["pull_request"]["paths"]
    assert path in paths


def test_build_smoke_also_runs_on_a_schedule_and_on_demand():
    """Most of what rots is outside this repository, so a path filter alone would
    leave it unwatched between build-file edits."""
    trig = _triggers(_load("build-smoke.yml"))
    assert "schedule" in trig and "workflow_dispatch" in trig


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
