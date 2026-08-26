"""
The user's false-positive whitelist.

Guardian consults contains() on every scanned file, so the cache behaviour is
not an optimisation detail: a stale cache means a file the user explicitly
whitelisted keeps being reported as a threat, or worse, a hash the user
removed stays suppressed.
"""
from __future__ import annotations

from ui.core import ignore_list as il

_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
_OTHER = "0123456789abcdef0123456789abcdef"


def test_add_then_contains(ignore_db):
    assert il.add(_MD5, filename="report.docx") is True
    assert il.contains(_MD5) is True
    assert il.contains(_OTHER) is False


def test_lookups_are_case_insensitive(ignore_db):
    il.add(_MD5.upper())

    assert il.contains(_MD5.lower()) is True
    assert il.contains(_MD5.upper()) is True


def test_empty_hash_is_never_ignored(ignore_db):
    assert il.add("") is False
    assert il.contains("") is False


def test_adding_refreshes_the_cache_without_a_reimport(ignore_db):
    """contains() populates a module-level cache on first call. An add() after
    that must invalidate it, or the whitelist silently does nothing until the
    process restarts."""
    assert il.contains(_MD5) is False        # populates the cache as a miss
    il.add(_MD5)

    assert il.contains(_MD5) is True


def test_removing_refreshes_the_cache(ignore_db):
    il.add(_MD5)
    assert il.contains(_MD5) is True

    assert il.remove(_MD5) is True
    assert il.contains(_MD5) is False


def test_removing_an_absent_hash_reports_no_deletion(ignore_db):
    assert il.remove(_MD5) is False


def test_adding_twice_keeps_the_first_row(ignore_db):
    il.add(_MD5, note="first")
    il.add(_MD5, note="second")

    assert il.count() == 1
    assert il.list_all()[0]["note"] == "first"


def test_clear_all_empties_both_table_and_cache(ignore_db):
    il.add(_MD5)
    il.add(_OTHER)

    assert il.clear_all() == 2
    assert il.count() == 0
    assert il.contains(_MD5) is False


def test_list_all_returns_the_stored_fields(ignore_db):
    il.add(_MD5, hash_type="md5", filename="report.docx",
           note="internal doc", original_reason="Suspicious pattern: Mimikatz credential dump")

    entry = il.list_all()[0]
    assert entry["hash"] == _MD5
    assert entry["hash_type"] == "md5"
    assert entry["filename"] == "report.docx"
    assert entry["note"] == "internal doc"
    assert entry["original_reason"] == "Suspicious pattern: Mimikatz credential dump"
    assert entry["added_utc"]


def test_a_pattern_derived_ignore_feeds_the_false_positive_stats(ignore_db, pattern_db):
    """This is the loop that makes the FP rates in Settings mean anything: the
    user whitelisting a pattern match is the only evidence the tool ever gets
    that the pattern was wrong."""
    from ui.core import pattern_stats as ps

    il.add(_MD5, original_reason="Suspicious pattern: MSHTA remote payload")

    assert ps.get_stats()[0]["pattern"] == "MSHTA remote payload"
    assert ps.get_stats()[0]["ignored"] == 1


def test_a_hash_ignore_does_not_touch_the_pattern_stats(ignore_db, pattern_db):
    """Only heuristic matches are pattern evidence. A signature hit the user
    whitelisted says nothing about any regex."""
    from ui.core import pattern_stats as ps

    il.add(_MD5, original_reason="Known Signature (MD5: d41d8cd98f00…)")

    assert ps.get_stats() == []
