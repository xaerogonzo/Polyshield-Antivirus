"""
The intelligence supply chain — the importers that decide what PolyShield knows.

test_intel_updater.py drives the *scheduler* around these feeds with fake
runners, and covers the YARA publisher in detail.  The three importers that
actually write the detection database had nothing.  That is the wrong half to
leave uncovered: a scheduler bug shows up as "the update did not run", which is
visible, while an importer bug shows up as a database that looks populated and
matches nothing.

Nothing here touches the network.  The feed parsers are pure functions over a
string, and the downloaders are driven through a stubbed `urlopen` in the shape
test_intel_updater.py already established.

pybloom-live is installed on a development machine but deliberately absent from
requirements-ci.txt, so the NSRL tests inject a fake `pybloom_live` rather than
importing the real one -- see docs/TESTING.md, "Engines absent from CI must be
faked, not skipped".  Both `_rebuild_nsrl_bloom` and
`guardian_engine._load_nsrl_bloom` import it *inside* the function, so a
sys.modules entry is enough.
"""
from __future__ import annotations

import hashlib
import io
import sqlite3
import sys
import types
import zipfile

import pytest

from conftest import add_c2_ip, add_malicious


def _md5(path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


# ── Stubbed downloads ─────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _stub_urlopen(upd, monkeypatch, mapping: dict):
    """Route urlopen by URL.  A mapping value may be bytes or an Exception.

    Dispatching on the URL rather than on call order keeps the C2 tests honest:
    import_c2_blocklist fetches two feeds, and a test that says "Feodo is down"
    should still say that if the fetch order ever changes.
    """
    seen: list[str] = []

    def fake_urlopen(req, timeout=None):
        url = getattr(req, "full_url", req)
        seen.append(url)
        if url not in mapping:
            raise AssertionError(f"unexpected fetch: {url}")
        outcome = mapping[url]
        if isinstance(outcome, BaseException):
            raise outcome
        return _FakeResponse(outcome)

    monkeypatch.setattr(upd.urllib.request, "urlopen", fake_urlopen)
    return seen


def _zip_bytes(members: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in members.items():
            zf.writestr(name, body)
    return buf.getvalue()


# ── Fake pybloom-live ─────────────────────────────────────────────────────────

def _install_fake_pybloom(monkeypatch, *, tofile_raises=None, tofile_hook=None):
    """Inject a `pybloom_live` whose filter serialises to a readable format.

    The real one writes a packed bit array; this writes the hashes it was given
    so a test can assert *which* generation of the filter is on disk -- which is
    the whole question when a rebuild fails part-way.
    """
    mod = types.ModuleType("pybloom_live")

    class ScalableBloomFilter:
        def __init__(self, initial_capacity=0, error_rate=0.001):
            self.initial_capacity = initial_capacity
            self.error_rate = error_rate
            self._items: set[str] = set()

        def add(self, item):
            self._items.add(item)

        def __contains__(self, item):
            return item in self._items

        def tofile(self, f):
            if tofile_hook is not None:
                tofile_hook()
            if tofile_raises is not None:
                raise tofile_raises
            f.write(b"BLOOM:" + ",".join(sorted(self._items)).encode())

        @classmethod
        def fromfile(cls, f):
            raw = f.read()
            if not raw.startswith(b"BLOOM:"):
                raise ValueError("not a bloom filter")
            obj = cls()
            body = raw[len(b"BLOOM:"):].decode()
            obj._items = set(body.split(",")) if body else set()
            return obj

    mod.ScalableBloomFilter = ScalableBloomFilter
    monkeypatch.setitem(sys.modules, "pybloom_live", mod)
    return mod


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def feeds(intel_db, hooks, tmp_path, monkeypatch):
    """update_intelligence with every path it *writes* redirected into tmp.

    intel_db covers _DB_PATH.  These two are not covered by it and are both
    real files on a developer's machine: clearing the database rewrites
    known_bad.txt, and an NSRL import publishes nsrl_bloom.bin.
    """
    from tools import update_intelligence as upd

    known_bad = tmp_path / "guardianai" / "data" / "known_bad.txt"
    known_bad.parent.mkdir(parents=True)
    bloom = tmp_path / "intelligence" / "nsrl_bloom.bin"
    bloom.parent.mkdir(parents=True)

    monkeypatch.setattr(upd, "_KNOWN_BAD", known_bad)
    monkeypatch.setattr(upd, "_BLOOM_PATH", bloom)
    return upd


def _meta(db, key: str):
    con = sqlite3.connect(str(db))
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    con.close()
    return row[0] if row else None


def _count(db, table: str) -> int:
    con = sqlite3.connect(str(db))
    n = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    con.close()
    return n


# ══ Feodo parser ══════════════════════════════════════════════════════════════

_FEODO_ROW = "2026-08-01 10:00:00,203.0.113.10,447,online,2026-08-20,Emotet"


def test_feodo_parses_a_record(feeds):
    (ip, tags, port, malware), = feeds._parse_feodo(_FEODO_ROW)
    assert (ip, tags, port, malware) == ("203.0.113.10", "online", 447, "Emotet")


def test_feodo_skips_comments_and_short_lines(feeds):
    raw = "# Feodo Tracker\n\nnot,enough\n" + _FEODO_ROW
    assert [r[0] for r in feeds._parse_feodo(raw)] == ["203.0.113.10"]


def test_feodo_drops_the_uncommented_header_row(feeds):
    """The export carries a bare column header that is not '#'-commented.

    The old truthiness check admitted it, so the literal string "dst_ip" became
    a blocklist entry that network_monitor compared every connection against.
    """
    raw = "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n" + _FEODO_ROW
    ips = [r[0] for r in feeds._parse_feodo(raw)]
    assert ips == ["203.0.113.10"]
    assert "dst_ip" not in ips


def test_feodo_drops_a_row_whose_ip_is_garbage(feeds):
    raw = "2026-08-01,not-an-address,447,online,2026-08-20,Emotet\n" + _FEODO_ROW
    assert [r[0] for r in feeds._parse_feodo(raw)] == ["203.0.113.10"]


def test_feodo_non_numeric_port_becomes_zero(feeds):
    (_ip, _tags, port, _mw), = feeds._parse_feodo(
        "2026-08-01,203.0.113.10,n/a,online,2026-08-20,Emotet")
    assert port == 0


# ══ ThreatFox parser ══════════════════════════════════════════════════════════

_SHA1 = "a" * 40


def _tf_row(ioc: str, malware: str = "Qakbot", confidence: str = "75") -> str:
    return '"1","ip:port","' + ioc + '","' + malware + '","' + confidence + '"'


def test_threatfox_parses_ipv4_with_port(feeds):
    (ip, tags, port, malware), = feeds._parse_threatfox(_tf_row("198.51.100.4:8080"))
    assert (ip, port, malware) == ("198.51.100.4", 8080, "Qakbot")
    assert tags == "threatfox:75%"


def test_threatfox_skips_the_header(feeds):
    header = '"id","ioc_type","ioc_value","malware","confidence_level"'
    raw = header + "\n" + _tf_row("198.51.100.4:8080")
    assert len(feeds._parse_threatfox(raw)) == 1


def test_threatfox_parses_bracketed_ipv6_with_port(feeds):
    (ip, _tags, port, _mw), = feeds._parse_threatfox(_tf_row("[2001:db8::1]:443"))
    assert (ip, port) == ("2001:db8::1", 443)


def test_threatfox_keeps_a_bare_ipv6_address_whole(feeds):
    """The regression the docstring already claimed was handled.

    rsplit(":", 1) treated a port-less IPv6 address as host:port and cut it at
    the last colon, storing the meaningless prefix "2001:db8:" -- an entry that
    can never match a real connection.
    """
    (ip, _tags, port, _mw), = feeds._parse_threatfox(_tf_row("2001:db8::1"))
    assert ip == "2001:db8::1"
    assert port == 0


def test_threatfox_drops_a_garbage_ioc(feeds):
    raw = _tf_row("definitely-not-an-ip") + "\n" + _tf_row("198.51.100.4:8080")
    assert [r[0] for r in feeds._parse_threatfox(raw)] == ["198.51.100.4"]


@pytest.mark.parametrize("value,expected", [
    ("198.51.100.4:8080",      ("198.51.100.4", 8080)),
    ("198.51.100.4",           ("198.51.100.4", 0)),
    ("[2001:db8::1]:443",      ("2001:db8::1", 443)),
    ("[2001:db8::1]",          ("2001:db8::1", 0)),
    ("2001:db8::1",            ("2001:db8::1", 0)),
    # A zone-scoped link-local parses, because ipaddress accepts it and it is a
    # well-formed address.  Kept rather than filtered: a link-local cannot be a
    # C2 endpoint, but network_monitor already skips fe80::/10 as private, so an
    # absurd feed entry is inert rather than something to write more code about.
    ("fe80::1%eth0",           ("fe80::1%eth0", 0)),
    ("198.51.100.4:notaport",  ("198.51.100.4", 0)),
    ("",                       ("", 0)),
    ("garbage",                ("", 0)),
])
def test_split_ioc_endpoint(feeds, value, expected):
    assert feeds._split_ioc_endpoint(value) == expected


# ══ MalwareBazaar ═════════════════════════════════════════════════════════════

_MD5_A = "0" * 31 + "1"
_MD5_B = "0" * 31 + "2"


def test_malwarebazaar_imports_a_plain_text_feed(feeds, intel_db, monkeypatch):
    body = ("# MalwareBazaar\n" + _MD5_A + "\n" + _MD5_B.upper() + "\n").encode()
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: body})

    res = feeds.fetch_malwarebazaar(mode="recent", notify=False)

    assert res["added"] == 2
    assert res["total_db"] == 2
    assert _count(intel_db, "malicious") == 2
    assert _meta(intel_db, "last_mb_update")


def test_malwarebazaar_reports_already_known_hashes_as_skipped(
        feeds, intel_db, monkeypatch):
    add_malicious(intel_db, _MD5_A)
    body = (_MD5_A + "\n" + _MD5_B + "\n").encode()
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: body})

    res = feeds.fetch_malwarebazaar(mode="recent", notify=False)

    assert (res["added"], res["skipped"], res["total_db"]) == (1, 1, 2)


def test_malwarebazaar_reads_the_zipped_full_list(feeds, intel_db, monkeypatch):
    payload = _zip_bytes({"full_md5.txt": _MD5_A + "\n"})
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_FULL_URL: payload})

    assert feeds.fetch_malwarebazaar(mode="full", notify=False)["added"] == 1


def test_malwarebazaar_ignores_lines_that_are_not_md5s(feeds, intel_db, monkeypatch):
    body = ("# header\nnot-a-hash\n" + "z" * 32 + "\n" + _MD5_A + "\n").encode()
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: body})

    assert feeds.fetch_malwarebazaar(mode="recent", notify=False)["added"] == 1


def test_malwarebazaar_fires_the_hashes_hook_once_committed(
        feeds, intel_db, monkeypatch):
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: (_MD5_A + "\n").encode()})

    feeds.fetch_malwarebazaar(mode="recent", notify=True)
    assert fired == ["hashes"]


# ── MalwareBazaar: a bad download must cost the user nothing ───────────────────

@pytest.mark.parametrize("payload,because", [
    (b"",                              "an empty response"),
    (b"<html>rate limited</html>",     "an error page"),
    (b"# only comments\n\n",           "a response with no records"),
    (_zip_bytes({}),                   "an empty archive"),
    (b"PK\x03\x04 truncated garbage",  "a corrupt archive"),
])
def test_malwarebazaar_bad_download_leaves_intelligence_untouched(
        feeds, intel_db, monkeypatch, payload, because):
    """download -> validate -> import -> commit -> freshness.

    Every one of these used to reach the "no hashes" branch and return
    total_db=0 -- describing a table that may hold millions as empty -- or, for
    the empty archive, raise IndexError straight out of a function contracted to
    return a dict.
    """
    add_malicious(intel_db, _MD5_A)
    before_stamp = _meta(intel_db, "last_mb_update")
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: payload})

    res = feeds.fetch_malwarebazaar(mode="recent", notify=False)

    assert res.get("error"), because + " must be reported as an error"
    assert "total_db" not in res, "must not report a total it never measured"
    assert _count(intel_db, "malicious") == 1, "existing intelligence was lost"
    assert _meta(intel_db, "last_mb_update") == before_stamp, (
        "freshness advanced on a failed feed")


def test_malwarebazaar_unreadable_archive_member_is_reported_not_raised(
        feeds, intel_db, monkeypatch):
    """A structurally valid archive whose member will not read.

    zipfile raises RuntimeError for an encrypted member and EOFError for a
    truncated stream -- neither is BadZipFile.  Enumerating the types invites
    the next one to escape through an adapter that only inspects res["error"],
    which is the defect class the empty-archive IndexError belonged to.  The
    failure is injected at zf.read() rather than by fabricating an encrypted
    archive, because the question here is what the handler does with an
    exception, not which byte in the central directory produced it.
    """
    def _boom(self, name, pwd=None):
        raise RuntimeError("File is encrypted, password required for extraction")

    monkeypatch.setattr(zipfile.ZipFile, "read", _boom)
    add_malicious(intel_db, _MD5_A)
    _stub_urlopen(feeds, monkeypatch,
                  {feeds._MB_FULL_URL: _zip_bytes({"md5.txt": _MD5_A + "\n"})})

    res = feeds.fetch_malwarebazaar(mode="full", notify=False)

    assert res.get("error"), "an unreadable member must not escape as an exception"
    assert _count(intel_db, "malicious") == 1


def test_malwarebazaar_http_error_carries_the_status(feeds, intel_db, monkeypatch):
    import urllib.error

    add_malicious(intel_db, _MD5_A)
    exc = urllib.error.HTTPError(feeds._MB_RECENT_URL, 403, "Forbidden", {}, None)
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: exc})

    res = feeds.fetch_malwarebazaar(mode="recent", notify=False)

    assert res["http_status"] == 403
    assert _count(intel_db, "malicious") == 1


def test_malwarebazaar_transport_failure_has_no_status(feeds, intel_db, monkeypatch):
    import urllib.error

    _stub_urlopen(feeds, monkeypatch,
                  {feeds._MB_RECENT_URL: urllib.error.URLError("timed out")})

    res = feeds.fetch_malwarebazaar(mode="recent", notify=False)
    assert res["error"] and res["http_status"] == 0


def test_malwarebazaar_bad_download_does_not_fire_hooks(feeds, intel_db, monkeypatch):
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: b"# nothing here\n"})

    feeds.fetch_malwarebazaar(mode="recent", notify=True)
    assert fired == [], "consumers must not be told to reload after a failed feed"


def test_empty_feed_reaches_the_updater_as_failed_not_unchanged(
        feeds, intel_db, monkeypatch):
    """The reason the empty case returns an error rather than the real total.

    _run_malwarebazaar reads (added=0, total>0) as UNCHANGED, which advances
    freshness.  A feed that returned nothing must never look like a feed that
    had nothing new.
    """
    from ui.core import intel_updater as iu

    add_malicious(intel_db, _MD5_A)
    _stub_urlopen(feeds, monkeypatch, {feeds._MB_RECENT_URL: b"# nothing\n"})

    assert iu._run_malwarebazaar(lambda _m: None)["status"] == iu.FAILED


# ══ C2 blocklist ══════════════════════════════════════════════════════════════

def _c2_urls(feeds, feodo: bytes = b"", threatfox: bytes = b"") -> dict:
    return {feeds._FEODO_IOC_URL: feodo, feeds._THREATFOX_URL: threatfox}


def test_c2_merges_both_feeds(feeds, intel_db, monkeypatch):
    _stub_urlopen(feeds, monkeypatch, _c2_urls(
        feeds,
        feodo=_FEODO_ROW.encode(),
        threatfox=_tf_row("198.51.100.4:8080").encode(),
    ))

    res = feeds.import_c2_blocklist(notify=False)

    assert (res["feodo_count"], res["threatfox_count"]) == (1, 1)
    assert res["added"] == 2
    assert _count(intel_db, "ip_blocklist") == 2
    assert _meta(intel_db, "last_c2_update")


def test_c2_threatfox_wins_when_both_feeds_carry_the_same_ip(
        feeds, intel_db, monkeypatch):
    """Documented dedup rule: last write wins, and ThreatFox is fetched last."""
    shared = "203.0.113.10"
    _stub_urlopen(feeds, monkeypatch, _c2_urls(
        feeds,
        feodo=_FEODO_ROW.encode(),
        threatfox=_tf_row(shared + ":443", malware="Qakbot").encode(),
    ))

    feeds.import_c2_blocklist(notify=False)

    con = sqlite3.connect(str(intel_db))
    tags, malware = con.execute(
        "SELECT tags, malware FROM ip_blocklist WHERE ip=?", (shared,)).fetchone()
    con.close()
    assert tags.startswith("threatfox:") and malware == "Qakbot"


def test_c2_continues_when_one_feed_is_down(feeds, intel_db, monkeypatch):
    import urllib.error

    _stub_urlopen(feeds, monkeypatch, {
        feeds._FEODO_IOC_URL: urllib.error.URLError("takedown"),
        feeds._THREATFOX_URL: _tf_row("198.51.100.4:8080").encode(),
    })

    res = feeds.import_c2_blocklist(notify=False)

    assert res["feodo_count"] == 0
    assert res["threatfox_count"] == 1
    assert _count(intel_db, "ip_blocklist") == 1


def test_c2_refreshes_an_ip_it_already_holds(feeds, intel_db, monkeypatch):
    add_c2_ip(intel_db, "198.51.100.4", tags="stale")
    _stub_urlopen(feeds, monkeypatch, _c2_urls(
        feeds, threatfox=_tf_row("198.51.100.4:8080").encode()))

    res = feeds.import_c2_blocklist(notify=False)

    assert (res["added"], res["updated"]) == (0, 1)
    assert _count(intel_db, "ip_blocklist") == 1


def test_c2_both_feeds_empty_leaves_the_blocklist_untouched(
        feeds, intel_db, monkeypatch):
    """A failed fetch must not cost the user the C2 intelligence they have."""
    add_c2_ip(intel_db, "203.0.113.99")
    before_stamp = _meta(intel_db, "last_c2_update")
    _stub_urlopen(feeds, monkeypatch, _c2_urls(feeds))

    res = feeds.import_c2_blocklist(notify=False)

    assert res.get("error")
    assert "total_db" not in res
    assert _count(intel_db, "ip_blocklist") == 1
    assert _meta(intel_db, "last_c2_update") == before_stamp


def test_c2_fires_the_ips_hook_not_the_hashes_hook(feeds, intel_db, monkeypatch):
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("ips"), domains=("ips",))
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))
    _stub_urlopen(feeds, monkeypatch, _c2_urls(
        feeds, threatfox=_tf_row("198.51.100.4:8080").encode()))

    feeds.import_c2_blocklist(notify=True)
    assert fired == ["ips"]


# ══ clear_malicious_db ════════════════════════════════════════════════════════

def test_clear_deletes_rows_and_the_freshness_stamp(feeds, intel_db):
    add_malicious(intel_db, _MD5_A)
    add_malicious(intel_db, _MD5_B)
    feeds.set_meta("last_mb_update", "2026-08-01T00:00:00")

    res = feeds.clear_malicious_db(notify=False)

    assert res == {"deleted": 2, "ok": True}
    assert _count(intel_db, "malicious") == 0
    assert _meta(intel_db, "last_mb_update") is None


def test_clear_leaves_the_safe_table_alone(feeds, intel_db):
    con = sqlite3.connect(str(intel_db))
    con.execute("INSERT INTO safe (hash, source) VALUES (?, 'nsrl')", (_MD5_A,))
    con.commit()
    con.close()
    add_malicious(intel_db, _MD5_B)

    feeds.clear_malicious_db(notify=False)
    assert _count(intel_db, "safe") == 1


def test_clear_fires_the_hashes_hook(feeds, intel_db):
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))
    add_malicious(intel_db, _MD5_A)

    feeds.clear_malicious_db(notify=True)
    assert fired == ["hashes"]


def test_clear_fires_the_hook_even_when_nothing_was_deleted(feeds, intel_db):
    """The no-op case, and the one that matters most.

    A consumer holding a stale RAM set is *exactly* the situation where the
    table is already empty and the consumer is not.  Gating the hook on
    rowcount would skip the only repair that case has.
    """
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))

    res = feeds.clear_malicious_db(notify=True)

    assert res["deleted"] == 0
    assert fired == ["hashes"]


def test_clear_notify_false_suppresses_the_hook(feeds, intel_db):
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))

    feeds.clear_malicious_db(notify=False)
    assert fired == []


# ── The property the hook exists for, asserted through the consumers ──────────

def test_clearing_stops_guardian_detecting_without_rebuilding_it(
        feeds, intel_db, guardian_sandbox, tmp_path, monkeypatch):
    """Guardian's tier-3 SQLite fallback would mask a stale RAM set, so it is
    disabled here: only a refreshed tier-2 set can change the verdict."""
    from ui.core import guardian_engine as ge
    from ui.core import ignore_list
    from ui.core import intel_db as intel_db_mod
    from ui.core.intel_hooks import register_intel_consumers

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"a file whose hash is about to be revoked\n")
    md5 = _md5(sample)
    add_malicious(intel_db, md5)

    monkeypatch.setattr(intel_db_mod, "lookup_hash", lambda h: None)
    monkeypatch.setattr(intel_db_mod, "is_known_safe", lambda h: False)
    monkeypatch.setattr(ignore_list, "contains", lambda h: False)
    monkeypatch.setattr(ge, "_scanner", None)

    scanner = ge._get_scanner()
    assert scanner.scan_file(str(sample))[0] is True, "precondition: detected"

    register_intel_consumers(force=True)
    feeds.clear_malicious_db(notify=True)

    assert ge._get_scanner() is scanner, "scanner must be reloaded, not replaced"
    infected, _reason, _tier, _ctx = scanner.scan_file(str(sample))
    assert infected is False, (
        "the database says empty but the running scanner still reports a threat")


def test_clearing_stops_the_process_monitor_acting_on_the_hash(
        feeds, intel_db, tmp_path):
    """The consequential half.  ProcessMonitor does not merely report -- when
    the UI is closed the service kills the process tree and quarantines the
    executable.  A stale RAM set here keeps killing on revoked intelligence."""
    from ui.core import process_monitor as pm
    from ui.core.intel_hooks import register_intel_consumers

    sample = tmp_path / "payload.exe"
    sample.write_bytes(b"MZ not-really-an-executable body for polyshield tests\n")
    md5 = _md5(sample)
    add_malicious(intel_db, md5)

    alerts: list[tuple] = []
    monitor = pm.ProcessMonitor(alert_callback=lambda *a: alerts.append(a),
                                known_bad={md5})

    def check():
        monitor._check_process(pid=4242, name="payload.exe",
                               exe_path=str(sample), con=None)

    check()
    assert len(alerts) == 1, "precondition: the monitor acts on this hash"

    register_intel_consumers(force=True)
    feeds.clear_malicious_db(notify=True)

    alerts.clear()
    check()
    assert alerts == [], (
        "the same monitor instance still flags a hash the user deleted")


# ══ NSRL import and bloom publication ═════════════════════════════════════════

_NSRL_HEADER = '"SHA-1","MD5","CRC32","FileName","FileSize"'


def _nsrl_file(tmp_path, *md5s, header: bool = True) -> str:
    lines = [_NSRL_HEADER] if header else []
    for m in md5s:
        lines.append('"' + _SHA1 + '","' + m + '","abcd1234","setup.exe","1024"')
    p = tmp_path / "NSRLFile.txt"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_nsrl_missing_file_touches_nothing_at_all(feeds, intel_db, tmp_path):
    """Pure validation failure -- it happens before any state is written, so
    even the stale flag must be untouched."""
    res = feeds.import_nsrl(str(tmp_path / "no-such-file.txt"), notify=False)

    assert res == {"error": "file not found"}
    assert _count(intel_db, "safe") == 0
    assert _meta(intel_db, "nsrl_bloom_stale") is None


def test_nsrl_import_publishes_a_bloom_and_clears_stale(
        feeds, intel_db, tmp_path, monkeypatch):
    _install_fake_pybloom(monkeypatch)
    path = _nsrl_file(tmp_path, _MD5_A, _MD5_B)

    res = feeds.import_nsrl(path, notify=False)

    assert res == {"added": 2, "total": 2}
    assert _count(intel_db, "safe") == 2
    assert _meta(intel_db, "nsrl_bloom_stale") == "0"
    assert feeds._BLOOM_PATH.exists()
    assert _MD5_A in feeds._BLOOM_PATH.read_text()


def test_nsrl_skips_the_header_row(feeds, intel_db, tmp_path, monkeypatch):
    _install_fake_pybloom(monkeypatch)
    feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    con = sqlite3.connect(str(intel_db))
    rows = [r[0] for r in con.execute("SELECT hash FROM safe")]
    con.close()
    assert rows == [_MD5_A]


def test_nsrl_import_fires_the_hashes_hook(feeds, intel_db, tmp_path, monkeypatch):
    _install_fake_pybloom(monkeypatch)
    fired: list[str] = []
    feeds.register_post_update_hook(lambda: fired.append("hashes"), domains=("hashes",))

    feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=True)
    assert fired == ["hashes"]


def test_stale_is_cleared_only_after_the_filter_is_on_disk(
        feeds, intel_db, tmp_path, monkeypatch):
    """The ordering, not just the outcome.

    Both forbidden states -- a filter advertised as current for a table it does
    not describe, and the reverse -- are ruled out by writing stale=0 last.
    """
    observed: list = []
    _install_fake_pybloom(
        monkeypatch,
        tofile_hook=lambda: observed.append(_meta(intel_db, "nsrl_bloom_stale")))

    feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    assert observed == ["1"], "the filter was written while still marked stale"
    assert _meta(intel_db, "nsrl_bloom_stale") == "0"


def test_a_failed_rebuild_does_not_destroy_the_previous_filter(
        feeds, intel_db, tmp_path, monkeypatch):
    """The defect this fix exists for.

    The previous form opened the live nsrl_bloom.bin "wb", truncating a valid
    ~150-200 MB filter before tofile() had written a byte.  A crash during that
    write left nothing usable, and the only recovery was re-importing a multi-GB
    NSRL file the user may no longer have.
    """
    previous = b"BLOOM:" + _MD5_B.encode()
    feeds._BLOOM_PATH.write_bytes(previous)
    _install_fake_pybloom(monkeypatch, tofile_raises=OSError("disk full"))

    with pytest.raises(OSError):
        feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    assert feeds._BLOOM_PATH.read_bytes() == previous, "the old filter was destroyed"
    assert _meta(intel_db, "nsrl_bloom_stale") == "1", "a failed rebuild was marked fresh"


def test_a_failed_rebuild_leaves_no_temporary_file_behind(
        feeds, intel_db, tmp_path, monkeypatch):
    _install_fake_pybloom(monkeypatch, tofile_raises=OSError("disk full"))

    with pytest.raises(OSError):
        feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    leftovers = list(feeds._BLOOM_PATH.parent.glob(feeds._BLOOM_PATH.name + ".*"))
    assert leftovers == []


def test_a_filter_that_serialises_to_nothing_is_not_published(
        feeds, intel_db, tmp_path, monkeypatch):
    """tofile() returning is the completeness signal; an empty file means it
    did not.  Publishing that would hand the reader a corrupt filter."""
    previous = b"BLOOM:" + _MD5_B.encode()
    feeds._BLOOM_PATH.write_bytes(previous)

    mod = _install_fake_pybloom(monkeypatch)
    monkeypatch.setattr(mod.ScalableBloomFilter, "tofile", lambda self, f: None)

    with pytest.raises(OSError):
        feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    assert feeds._BLOOM_PATH.read_bytes() == previous
    assert _meta(intel_db, "nsrl_bloom_stale") == "1"


def test_no_bloom_library_leaves_the_import_intact(
        feeds, intel_db, tmp_path, monkeypatch):
    """pybloom-live is optional; without it Guardian falls back to SQLite.

    The rows must still land -- the filter is a fast path, not the truth.
    """
    monkeypatch.setitem(sys.modules, "pybloom_live", None)

    res = feeds.import_nsrl(_nsrl_file(tmp_path, _MD5_A), notify=False)

    assert res == {"added": 1, "total": 1}
    assert _count(intel_db, "safe") == 1
    assert not feeds._BLOOM_PATH.exists()
    assert _meta(intel_db, "nsrl_bloom_stale") == "1", (
        "no filter was built, so it cannot be current")


# ── The reader that makes a failed rebuild safe ───────────────────────────────

def test_guardian_ignores_a_bloom_marked_stale(
        feeds, intel_db, guardian_sandbox, tmp_path, monkeypatch):
    """This is the guard the whole failure branch relies on, and it had no test.

    A stale filter can only *omit* entries -- it can never invent them -- so
    falling back to SQLite is correct but slower.  Trusting it would not be.
    """
    from ui.core import guardian_engine as ge

    bloom_path = tmp_path / "nsrl_bloom.bin"
    bloom_path.write_bytes(b"BLOOM:" + _MD5_A.encode())
    monkeypatch.setattr(ge, "_BLOOM_PATH", bloom_path)
    _install_fake_pybloom(monkeypatch)
    feeds.set_meta("nsrl_bloom_stale", "1")

    scanner = ge._EnhancedScanner()
    assert scanner._load_nsrl_bloom() is None

    feeds.set_meta("nsrl_bloom_stale", "0")
    loaded = scanner._load_nsrl_bloom()
    assert loaded is not None and _MD5_A in loaded


def test_guardian_quarantines_a_corrupt_bloom(
        feeds, intel_db, guardian_sandbox, tmp_path, monkeypatch):
    from ui.core import guardian_engine as ge

    bloom_path = tmp_path / "nsrl_bloom.bin"
    bloom_path.write_bytes(b"this is not a bloom filter")
    monkeypatch.setattr(ge, "_BLOOM_PATH", bloom_path)
    _install_fake_pybloom(monkeypatch)
    feeds.set_meta("nsrl_bloom_stale", "0")

    scanner = ge._EnhancedScanner()

    assert scanner._load_nsrl_bloom() is None
    assert not bloom_path.exists(), "a corrupt filter must be removed, not re-read"
    assert _meta(intel_db, "nsrl_bloom_stale") == "1"
