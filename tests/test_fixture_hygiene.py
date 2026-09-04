"""
No test module may define a fixture that shadows one from conftest.

pytest resolves fixtures by name, innermost scope first, so a fixture defined
in a test module silently replaces the conftest fixture of the same name for
that entire file. Nothing warns, and the call site is unchanged — the test
still reads `def test_x(thing_sandbox)`.

This is not hypothetical. `tests/test_intel_updater.py` defined `yara_sandbox`
redirecting the **publisher** — `tools.update_intelligence`'s output paths —
while `conftest.py` defines `yara_sandbox` redirecting the **reader**,
`ui.core.yara_engine`'s `_USER_DIR` / `_COMMUNITY_DIR` / `_ACTIVE_PTR`. A test
in that module that asked for `yara_sandbox` believed the engine was sandboxed
and was actually reading the developer's real `rules/community/`. It produced
two confident false failures — a "fresh install" that reported YARA rules —
before the shadowing was spotted. The publisher fixture is now
`yara_publish_sandbox`.

The rule this enforces is not "never redefine a name"; it is "if two fixtures
do different things, do not let them share a name". Give the narrower one a
name that says what it narrows.
"""
from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
CONFTEST = TESTS / "conftest.py"


def _fixture_names(source: str) -> set[str]:
    """Names of every @pytest.fixture-decorated function in `source`.

    Matches both `@pytest.fixture` and `@pytest.fixture(scope=...)`, and the
    bare `@fixture` spelling.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name == "fixture":
                names.add(node.name)
    return names


def test_no_test_module_shadows_a_conftest_fixture():
    shared = _fixture_names(CONFTEST.read_text(encoding="utf-8"))
    assert shared, "conftest defines no fixtures — this guard would pass vacuously"

    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        clashes = _fixture_names(path.read_text(encoding="utf-8")) & shared
        for name in sorted(clashes):
            offenders.append(f"{path.name} redefines {name!r}")

    assert not offenders, (
        "a module-local fixture silently replaces the conftest one of the same "
        "name for that whole file; rename it after what it actually sandboxes: "
        + "; ".join(offenders))


def test_the_guard_recognises_a_shadowed_name():
    """A guard that cannot fail is not a guard."""
    conftest_like = "import pytest\n@pytest.fixture\ndef yara_sandbox():\n    return 1\n"
    module_like = (
        "import pytest\n"
        "@pytest.fixture(scope='function')\n"
        "def yara_sandbox():\n"
        "    return 2\n"
        "@pytest.fixture\n"
        "def unrelated():\n"
        "    return 3\n"
    )
    shared = _fixture_names(conftest_like)
    assert shared == {"yara_sandbox"}
    assert _fixture_names(module_like) & shared == {"yara_sandbox"}


def test_the_guard_ignores_plain_functions():
    """Only decorated fixtures shadow; a helper of the same name does not."""
    assert _fixture_names("def yara_sandbox():\n    return 1\n") == set()
