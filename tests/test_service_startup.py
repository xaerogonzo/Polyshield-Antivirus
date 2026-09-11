r"""How PolyShield registers its service, and why it kept registering it wrong.

`polyshield_service.PolyShieldService._svc_start_type_` is
`win32service.SERVICE_AUTO_START` and has been since the service was written.
It never took effect.  pywin32 does not read that attribute -- measured in the
installed copy at `win32/lib/win32serviceutil.py`:

    :203  def InstallService(..., startType=None, ...)
    :221      if startType is None:
    :222          startType = win32service.SERVICE_DEMAND_START
    :852      InstallService(..., startType=startup, ...)

`startup` is filled only from an explicit `--startup` option.  So every
`polyshield_service.py install` produced a DEMAND_START service, and two of the
three call sites quietly compensated afterwards with `sc config ... start= auto`
while the third -- the in-app Install button -- did not.  A machine running this
project reported START_TYPE 3 with WIN32_EXIT_CODE 1077: registered, and never
once started.

`_with_startup_flag` is the fix, at the single point all three callers funnel
through.  It is pure, so this file can prove the argv shaping without going
anywhere near the SCM.
"""
from __future__ import annotations

import pathlib

import pytest


def _svc():
    # Imported inside the test, not at module scope: the module pulls in
    # servicemanager and opens no handles, but the existing service tests
    # (test_privilege_boundary, test_service_intel) all do it this way and a
    # collection-time import of a Windows service module is the shape that has
    # broken this project's Linux CI before.
    import polyshield_service

    return polyshield_service


# ── Finding the verb ──────────────────────────────────────────────────────────
#
# The verb is not simply argv[1].  getopt consumes options first, and a long
# option may carry its value inline or in the following token, so
# `--username bob install` has its verb in third place.


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["svc.py", "install"],                                 1),
        (["svc.py", "--startup", "auto", "install"],            3),
        (["svc.py", "--startup=auto", "install"],               2),
        (["svc.py", "--username", "bob", "--password", "x",
          "install"],                                           5),
        (["svc.py", "--interactive", "debug"],                  2),
        (["svc.py", "--", "install"],                           2),
        (["svc.py"],                                            None),
        (["svc.py", "--startup", "auto"],                       None),
    ],
)
def test_the_verb_is_found_the_way_getopt_would(argv, expected):
    assert _svc()._find_verb_index(argv) == expected


# ── Injection ─────────────────────────────────────────────────────────────────


def test_install_is_given_startup_auto():
    """The bug, in one assertion."""
    out = _svc()._with_startup_flag(["svc.py", "install"])
    assert out == ["svc.py", "--startup", "auto", "install"]


def test_the_flag_goes_before_the_verb():
    """getopt stops at the first non-option.

    `install --startup auto` parses as the verb `install` with a leftover
    positional, and the option is never seen -- which would reintroduce the bug
    while looking like the fix.
    """
    out = _svc()._with_startup_flag(["svc.py", "install"])
    assert out.index("--startup") < out.index("install")


def test_update_is_also_a_registering_verb():
    out = _svc()._with_startup_flag(["svc.py", "update"])
    assert out == ["svc.py", "--startup", "auto", "update"]


@pytest.mark.parametrize("verb", ["remove", "start", "stop", "restart", "debug"])
def test_a_non_registering_verb_is_left_alone(verb):
    """pywin32 does not consult startType for these, so touching argv would only
    risk turning a working command into a usage error."""
    argv = ["svc.py", verb]
    assert _svc()._with_startup_flag(argv) == argv


@pytest.mark.parametrize(
    "argv",
    [
        ["svc.py", "--startup", "auto", "install"],
        ["svc.py", "--startup", "manual", "install"],
        ["svc.py", "--startup=delayed", "install"],
        # A spelling pywin32 rejects. `sc config` says "delayed-auto"; pywin32
        # says "delayed". Left alone deliberately: rejected loudly by pywin32 is
        # better than silently rewritten here into something the caller did not
        # ask for.
        ["svc.py", "--startup", "delayed-auto", "install"],
    ],
)
def test_an_explicit_startup_is_never_overridden(argv):
    assert _svc()._with_startup_flag(argv) == argv


def test_no_verb_at_all_is_left_alone():
    assert _svc()._with_startup_flag(["svc.py"]) == ["svc.py"]
    assert _svc()._with_startup_flag(["svc.py", "--interactive"]) == \
        ["svc.py", "--interactive"]


def test_delayed_uses_the_pywin32_spelling():
    """Not "delayed-auto" -- that is the `sc config` spelling and pywin32's
    option map does not contain it."""
    out = _svc()._with_startup_flag(["svc.py", "install"], delayed=True)
    assert out == ["svc.py", "--startup", "delayed", "install"]


def test_the_start_type_attribute_is_what_gets_read():
    """`_svc_start_type_` is load-bearing again, through this function."""
    import win32service

    ps = _svc()
    out = ps._with_startup_flag(
        ["svc.py", "install"], start_type=win32service.SERVICE_DEMAND_START)
    assert out == ["svc.py", "--startup", "manual", "install"]

    out = ps._with_startup_flag(
        ["svc.py", "install"], start_type=win32service.SERVICE_DISABLED)
    assert out == ["svc.py", "--startup", "disabled", "install"]


def test_an_unmapped_start_type_injects_nothing():
    """Better a DEMAND_START service the user can see and fix than an argv built
    from a guess."""
    argv = ["svc.py", "install"]
    assert _svc()._with_startup_flag(argv, start_type=0xDEAD) == argv


def test_options_before_the_verb_survive():
    out = _svc()._with_startup_flag(
        ["svc.py", "--username", "bob", "--password", "hunter2", "install"])
    assert out == ["svc.py", "--username", "bob", "--password", "hunter2",
                   "--startup", "auto", "install"]


def test_the_input_argv_is_not_mutated():
    argv = ["svc.py", "install"]
    _svc()._with_startup_flag(argv)
    assert argv == ["svc.py", "install"]


# ── The class still declares what we inject ───────────────────────────────────


def test_the_service_still_asks_for_auto_start():
    """If someone changes `_svc_start_type_` they are now changing behaviour,
    not documentation. This test is here to make that true rather than to
    restate the assignment."""
    import win32service

    assert _svc().PolyShieldService._svc_start_type_ == \
        win32service.SERVICE_AUTO_START
    assert _svc()._STARTUP_FLAG_BY_TYPE[win32service.SERVICE_AUTO_START] == "auto"


