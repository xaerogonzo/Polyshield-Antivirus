"""The PolyBedrock pin, and the compatibility range the pin cannot express.

PolyShield does not start without PolyBedrock (docs/ARCHITECTURE.md, "PolyBedrock
is a hard dependency"), and three separate files declare it: `requirements.txt`
for the source install, `requirements-ci.txt` for the test job, and `build.ps1`
`$RUNTIME_PKGS` for the interpreter that ships inside the installer. Three copies
of one URL is a drift hazard, and drifting quietly is the whole problem: a build
whose runtime resolves a different substrate than the suite tested is a green CI
run sitting on top of a product nobody exercised.

Why the range is asserted here rather than declared
---------------------------------------------------

PolyScour writes `polybedrock-core>=0.1,<0.2` in its `pyproject.toml`. PolyShield
cannot: PolyBedrock is not on PyPI, so it arrives as a PEP 508 *direct reference*
(``name @ url``), and a direct reference may not carry a version specifier --
``polybedrock-core>=0.1,<0.2 @ git+https://...`` is not a parseable requirement.

So the pin and the range answer two different questions and live in two places:

* the **pin** is what the resolver installs, and it is exact;
* the **range** is what PolyShield claims to support, and it is asserted against
  the metadata of whatever actually got installed.

That split is not a workaround, it is the useful shape. PolyBedrock's CI installs
its own working tree over whatever a consumer declared -- deliberately, so a
consumer job cannot go green against the wrong substrate -- which makes the pin
inert there and the range the only thing left that can object. When PolyBedrock
becomes 0.2.0, this file is what turns PolyShield's consumer job red, and
updating it is the act of declaring support rather than discovering the break in
a release.
"""
from __future__ import annotations

import os
import re
import warnings
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet

ROOT = Path(__file__).resolve().parents[1]

#: What PolyShield claims to work against, spelled exactly as PolyScour spells
#: the same claim in its ``pyproject.toml`` -- the two consumers should be
#: readable against each other. The upper bound is here because PolyBedrock's
#: 0.x is where the extraction seams are still moving, not because semver says
#: to write one; raising it means running this suite against that substrate.
#:
#: Parsed by ``packaging`` rather than by splitting on dots, so a pre-release
#: like 0.2.0rc1 is correctly outside the range instead of raising ValueError
#: on int("0rc1") and failing for the wrong reason.
SUPPORTED_RANGE = SpecifierSet(">=0.1,<0.2")

_REPO = "github.com/xaerogonzo/PolyBedrock.git"

#: ``git+https://<repo>@<rev>#subdirectory=<x>``. The revision group is optional
#: on purpose: an unpinned URL must be *matched and then rejected*, not skipped
#: as "no declaration found", which is how a missing pin looks like a pass.
_URL = re.compile(
    re.escape(_REPO) + r"(?:@(?P<rev>[0-9a-fA-F]{7,40}|v[0-9][^#\s\"]*))?"
    r"#subdirectory=(?P<sub>\w+)"
)


def _declarations(name: str) -> list[tuple[str, str | None]]:
    """Every *live* PolyBedrock URL in one file, as ``(subdirectory, revision)``.

    Comment lines are skipped, and that is load-bearing rather than tidiness:
    a commented-out requirement installs nothing, so it must read here as
    absent. Scanning the raw text instead kept every assertion green after the
    real line was commented out -- found by trying it, which is the only way
    this kind of hole is ever found. All three files comment with ``#``, and
    all three carry prose about this dependency directly above the declaration,
    so the distinction is not hypothetical.
    """
    out: list[tuple[str, str | None]] = []
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        out += [(m.group("sub"), m.group("rev")) for m in _URL.finditer(line)]
    return out


#: Which file declares which subdirectories. build.ps1 stages core only -- the
#: service never touches the theme or the capture harness, and -ui would drag
#: customtkinter into a component that must never need a display.
_SITES = {
    "requirements.txt": {"core", "ui"},
    "requirements-ci.txt": {"core", "ui"},
    "build.ps1": {"core"},
}


@pytest.mark.parametrize("filename,expected", sorted(_SITES.items()))
def test_every_declaration_site_names_the_packages_it_should(filename, expected):
    found = _declarations(filename)
    assert found, f"{filename} declares no PolyBedrock dependency at all"
    assert {sub for sub, _ in found} == expected


@pytest.mark.parametrize("filename", sorted(_SITES))
def test_no_declaration_resolves_to_whatever_master_is_today(filename):
    """An unpinned URL is the defect this file exists to catch.

    Not a style rule. `build.ps1` bakes this into the shipped interpreter, so
    unpinned means the same PolyShield tag built on two days is two products.
    """
    unpinned = [sub for sub, rev in _declarations(filename) if rev is None]
    assert not unpinned, (
        f"{filename} declares polybedrock-{{{', '.join(unpinned)}}} without a "
        "revision, so it resolves to whatever master is on build day"
    )


def test_the_three_sites_agree_on_one_revision():
    """Drift between them is silent, and produces a runtime nobody tested."""
    revisions = {
        f"{filename}:{sub}": rev
        for filename in _SITES
        for sub, rev in _declarations(filename)
    }
    assert len(set(revisions.values())) == 1, (
        "the PolyBedrock revision differs between declaration sites; bump them "
        f"together: {revisions}"
    )


@pytest.mark.parametrize("dist", ["polybedrock-core", "polybedrock-ui"])
def test_the_installed_substrate_is_inside_the_supported_range(dist):
    """The compatibility claim, checked against what is actually importable.

    Reads installed metadata rather than a declaration, because the declaration
    is not always what is present: a developer runs an editable install from a
    sibling checkout, and PolyBedrock's own CI overwrites the consumer's pin
    with the substrate under test. Both are the cases worth catching.
    """
    try:
        raw = version(dist)
    except PackageNotFoundError:                      # pragma: no cover
        pytest.fail(f"{dist} is not installed; PolyShield does not start without it")

    assert SUPPORTED_RANGE.contains(raw, prereleases=True), (
        f"{dist} is installed at {raw}, outside the range PolyShield declares "
        f"support for ({SUPPORTED_RANGE}). Not a failure to route around: run "
        "this suite against that substrate, then raise SUPPORTED_RANGE here and "
        "bump the pinned revision in all three declaration sites together."
    )


# ══ The case the pin and the range both miss ═════════════════════════════════
#
# `pip install -e ..\PolyBedrock\core` is the natural thing to do while working
# on both projects at once, and it makes every assertion above vacuous: the pin
# is not what is imported, and the metadata still reports 0.1.0 no matter how far
# the working tree has moved. Measured on a live checkout: the venv resolved
#
#     polybedrock.__path__ = ['D:\...\PolyBedrock\core\src\polybedrock', ...]
#
# ten commits past the revision requirements.txt names -- all of them CI and docs
# commits, so harmless that day, and invisible on any other day too.
#
# Locally that is a warning: it is the correct developer setup and saying so is
# the point. In CI it is a hard failure, because a job that tests a working tree
# nobody declared is the master-vs-master trap PolyBedrock's own CI exists to
# remove.

def _editable_source(dist: str):
    """The checkout an editable install points at, or None if it is a real one."""
    import json
    from importlib.metadata import distribution

    try:
        direct = distribution(dist).read_text("direct_url.json")
    except PackageNotFoundError:
        return None
    if not direct:
        return None
    try:
        info = json.loads(direct)
    except ValueError:
        return None
    if not info.get("dir_info", {}).get("editable"):
        return None
    url = info.get("url", "")
    if not url.startswith("file:"):
        return None
    from urllib.parse import unquote, urlparse

    return Path(unquote(urlparse(url).path).lstrip("/"))


@pytest.mark.parametrize("dist", ["polybedrock-core", "polybedrock-ui"])
def test_an_editable_substrate_is_reported_and_never_silent(dist, request):
    """The pin is inert against an editable install; this is what is left.

    Deliberately not a plain xfail or skip. A developer working on both repos
    should see which tree is actually being imported and how far it is from the
    declared revision -- and CI, where an editable install cannot legitimately
    happen, should stop.
    """
    source = _editable_source(dist)
    if source is None:
        return                      # an ordinary pinned install; the tests above apply

    in_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    detail = f"{dist} is installed EDITABLE from {source}"

    declared = _declared_revisions().get("requirements.txt")
    drift = _commits_ahead(source, declared) if declared else None
    if drift is not None:
        detail += f", {drift} commit(s) past the pinned {declared[:7]}"

    assert not in_ci, (
        detail + ". CI must test the declared revision: an editable install "
        "makes the pin inert and the range unable to object.")

    warnings.warn(UserWarning(
        detail + ". Edits there take effect immediately in PolyShield, and "
        "requirements.txt no longer describes what is running."))


def _declared_revisions() -> dict:
    """Revision each site pins, keyed by filename."""
    out = {}
    for filename in _SITES:
        text = (ROOT / filename).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = _URL.search(line)
            if m and m.group("rev"):
                out[filename] = m.group("rev")
                break
    return out


def _commits_ahead(checkout: Path, revision: str):
    """How far the checkout's HEAD is past `revision`, or None if unanswerable."""
    import subprocess

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(checkout), *args],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    try:
        # The checkout may be core/ or ui/ inside the repo; git resolves that.
        if git("cat-file", "-e", f"{revision}^{{commit}}").returncode != 0:
            return None
        result = git("rev-list", "--count", f"{revision}..HEAD")
        if result.returncode != 0:
            return None
        return int(result.stdout.strip())
    except Exception:
        return None
