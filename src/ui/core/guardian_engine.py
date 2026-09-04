"""
guardian_engine.py
──────────────────
Wrapper around GuardianAI's scanner that adds:
  - Progress callbacks matching scanner.py's contract
  - Async execution via threading
  - Graceful degradation when guardianai/ is not installed
  - MalwareBazaar hash DB support (loaded from SQLite; known_bad.txt is a legacy fallback)

Phase A: basic dual-scan support
Phase C: SQLite intelligence DB, NSRL allow-list, bloom filter
"""
import os
import hashlib
import re
import threading
from pathlib import Path
from ui.core import paths

_GUARDIAN_DIR = paths.guardian_dir()
_DATA_DIR = _GUARDIAN_DIR / "data"
_KNOWN_BAD_TXT = _DATA_DIR / "known_bad.txt"          # legacy fallback only (v1.8+)
_DB_PATH  = paths.intelligence_dir() / "threat_db.sqlite"
_BLOOM_PATH = paths.intelligence_dir() / "nsrl_bloom.bin"

# If the malicious table exceeds this count, skip loading into RAM entirely.
# The tier-3 SQLite lookup in scan_file() handles all hashes regardless of
# whether the RAM set is populated.  ~50 MB RAM at 500 K entries.
_KNOWN_BAD_RAM_LIMIT = 500_000

# v1.9: minimum file size to scan. Files smaller than this are skipped before
# the MD5 is computed. This eliminates the "null MD5" false-positive class:
# the MalwareBazaar database contains d41d8cd98f00b204e9800998ecf8427e (the MD5
# of any zero-byte file), which would otherwise flag every empty lockfile,
# SQLite WAL/journal, and browser-extension placeholder on the system.
# Default 10 bytes — no modern malicious payload of consequence fits in <10 B.
# Overridden by settings.get("guardian_min_scan_bytes") at scan time.
_DEFAULT_MIN_SCAN_BYTES = 10


# ── Availability ──────────────────────────────────────────────────────────────

def is_available() -> bool:
    """True if the guardianai/ repo has been cloned."""
    return (_GUARDIAN_DIR / "scan" / "scanner.py").exists()


def get_db_stats() -> dict:
    """Return stats about the current signature database."""
    # Prefer SQLite stats (more accurate)
    try:
        from ui.core.intel_db import get_stats as _intel_stats
        s = _intel_stats()
        if s.get("db_exists"):
            return {
                "known_bad":   s["malicious"],
                "known_safe":  s["safe"],
                "last_updated": s["last_update"],
            }
    except Exception:
        pass

    # Fallback: count known_bad.txt
    count = 0
    last_updated = "Never"
    if _KNOWN_BAD_TXT.exists():
        try:
            lines = _KNOWN_BAD_TXT.read_text(
                encoding="utf-8", errors="ignore").splitlines()
            count = sum(1 for ln in lines if len(ln.strip()) in (32, 64))
            import datetime
            mtime = _KNOWN_BAD_TXT.stat().st_mtime
            last_updated = datetime.datetime.fromtimestamp(mtime).strftime(
                "%Y-%m-%d %H:%M")
        except Exception:
            pass
    return {"known_bad": count, "known_safe": 0, "last_updated": last_updated}


# ── Hashing ───────────────────────────────────────────────────────────────────

def hash_file(path: str) -> dict:
    """Return md5 and sha256 of a file. Returns {'error': ...} on failure."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        return {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── Enhanced scanner ──────────────────────────────────────────────────────────

class _EnhancedScanner:
    """
    Compatible with GuardianAI's Scanner interface but loads signatures from
    a plain-text known_bad.txt instead of binary malware sample files.

    Known-bad list format (guardianai/data/known_bad.txt):
      • One MD5 hash per line (32 hex chars)
      • Lines that don't match are silently ignored
      • Comments (#) are supported

    Pattern matching is intentionally restricted to text/script files only.
    Running regex patterns against compiled binaries (.exe, .dll, .sys, etc.)
    produces massive false positives because words like "bitcoin", "wallet",
    and "decrypt" appear legitimately in any large binary.
    """

    # File extensions where heuristic pattern matching makes sense.
    # Compiled binaries are intentionally excluded — patterns are for scripts/docs.
    _PATTERN_EXTENSIONS: frozenset[str] = frozenset({
        # Windows script formats
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".ps1", ".psm1", ".psd1", ".wsf", ".wsh", ".hta",
        ".inf",   # AutoRun.inf
        ".reg",   # Registry scripts
        # General scripting languages
        ".py", ".rb", ".pl", ".lua", ".sh", ".bash",
        # Web scripts (can be dropper vectors)
        ".php", ".asp", ".aspx",
        ".html", ".htm",
        # Text / documents (ransomware notes land here)
        ".txt", ".log", ".xml", ".csv",
    })

    # Heuristic patterns — ONLY applied to text/script files (see above).
    #
    # Design rules that prevent the Steam/LM Studio false-positive class:
    #   • No re.DOTALL on multi-keyword patterns — prevents spanning the whole file
    #   • Use bounded quantifiers (.{0,N}) not unlimited .*
    #   • Require action verbs in payment-demand patterns ("send", "pay", "transfer")
    #   • Keep patterns specific enough that they wouldn't appear in legitimate software
    _PATTERNS: list[tuple[str, re.Pattern, str]] = [
        (
            "AutoRun exploit (AUTORUN.INF)",
            re.compile(r"^\[AutoRun\]", re.IGNORECASE | re.MULTILINE),
            # Secondary check applied separately — both must match in _check_patterns
        ),
        (
            "Script dropper (WScript.Shell.Run)",
            re.compile(r'WScript\.Shell\b.{0,120}\.Run\s*\(', re.IGNORECASE | re.DOTALL),
        ),
        (
            "Encoded PowerShell payload",
            re.compile(
                r'(?:powershell|pwsh)(?:\.exe)?.{0,60}'
                r'-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}',
                re.IGNORECASE),
        ),
        (
            "MSHTA remote payload",
            re.compile(r'mshta(?:\.exe)?\s+https?://', re.IGNORECASE),
        ),
        (
            "Mimikatz credential dump",
            # Extremely specific — this exact string won't appear in legitimate software
            re.compile(r'sekurlsa::logonpasswords', re.IGNORECASE),
        ),
        (
            "Ransomware note (files encrypted)",
            re.compile(
                r'your\s+(?:personal\s+)?files\s+(?:have\s+been\s+)?'
                r'(?:encrypted|locked|compromised)',
                re.IGNORECASE),
        ),
        (
            "Ransomware payment demand",
            # Requires an imperative verb + bitcoin + wallet/address in close proximity.
            # "send X bitcoin to wallet Y" — NOT just any file mentioning all three words.
            re.compile(
                r'(?:send|pay|transfer|deposit)\s.{0,80}'
                r'bitcoin.{0,80}'
                r'(?:wallet|address)',
                re.IGNORECASE),
        ),
    ]

    @classmethod
    def _should_pattern_scan(cls, file_path: str, content: bytes) -> bool:
        """
        Return True only if this file should be checked with heuristic patterns.

        Rules (in order):
          1. If extension is in the script/text allow-list → yes
          2. If the file looks like a compiled binary (null bytes, low ASCII ratio) → no
          3. If the file appears to be plain text → yes
          4. Otherwise → no (safe default)

        This prevents the most common false-positive class: compiled executables
        (.exe, .dll, .sys, .pyd, etc.) that happen to contain words like
        "bitcoin", "wallet", or "decrypt" in their binary data.
        """
        ext = Path(file_path).suffix.lower()

        # Fast path: known script/text extension
        if ext in cls._PATTERN_EXTENSIONS:
            return True

        # Fast path: known binary extension — skip immediately
        _BINARY_EXTENSIONS = frozenset({
            ".exe", ".dll", ".sys", ".drv", ".ocx", ".scr",
            ".pyd", ".so", ".dylib", ".lib", ".obj", ".o",
            ".bin", ".dat", ".db", ".sqlite", ".pak",
            ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
            ".mp3", ".mp4", ".avi", ".wav", ".ogg",
            ".pdf", ".docx", ".xlsx", ".pptx",
            ".pyc", ".pyo", ".pycache",
        })
        if ext in _BINARY_EXTENSIONS:
            return False

        # Heuristic: check first 512 bytes for binary markers
        sample = content[:512]
        if not sample:
            return False
        # Null bytes → binary
        if b'\x00' in sample:
            return False
        # If >20% of bytes are non-printable control chars → binary
        printable = sum(1 for b in sample
                        if b >= 0x20 or b in (0x09, 0x0a, 0x0d))  # tab, LF, CR
        return (printable / len(sample)) > 0.80

    def __init__(self):
        self.virus_db: set[str] = self._load_sigs()
        self._nsrl_bloom = self._load_nsrl_bloom()
        # v1.10: per-scan circuit-breaker state. Reset at the start of each
        # scan_async() pass via reset_scan_session() (called from scan_view).
        # If pattern_hit_count exceeds the configured threshold the pattern
        # tier is short-circuited for the rest of the scan; tiers 1-3 keep
        # running normally.
        self._pattern_hit_count: int = 0
        self._circuit_tripped:   bool = False
        self._circuit_threshold: int  = 0     # cached at scan start

    def reset_scan_session(self) -> None:
        """Called at the start of each scan to reset circuit-breaker counters."""
        from ui.core import settings as _cfg
        try:
            self._circuit_threshold = int(_cfg.get("guardian_circuit_breaker_threshold") or 0)
        except Exception:
            self._circuit_threshold = 0
        self._pattern_hit_count = 0
        self._circuit_tripped = False

    def get_circuit_state(self) -> dict:
        """Return circuit-breaker state for UI banner consumption."""
        return {
            "tripped":   self._circuit_tripped,
            "hit_count": self._pattern_hit_count,
            "threshold": self._circuit_threshold,
        }

    # ── Sensitivity profile resolution ────────────────────────────────────────

    # The Conservative profile disables these two patterns by default — they are
    # natural-language patterns that fire on legitimate security documentation,
    # recovery instructions, and AV tool logs (the chief sources of v1.9 noise).
    _CONSERVATIVE_DISABLED = frozenset({
        "Ransomware note (files encrypted)",
        "Ransomware payment demand",
    })

    @classmethod
    def _pattern_enabled(cls, label: str, profile: str, toggles: dict) -> bool:
        """Resolve whether the named pattern should fire under the current
        profile + user toggle overrides.

        Resolution order:
          1. If a user toggle explicitly mentions this pattern, that wins.
          2. Otherwise apply profile defaults:
             - Conservative: patterns in _CONSERVATIVE_DISABLED are OFF
             - Balanced / Power: all patterns ON
        """
        if isinstance(toggles, dict) and label in toggles:
            return bool(toggles[label])
        if profile == "conservative" and label in cls._CONSERVATIVE_DISABLED:
            return False
        return True

    @staticmethod
    def _severity_for_pattern(profile: str) -> str:
        """Pattern matches are 'suspicious' in Conservative/Balanced (downgraded)
        and 'confirmed' in Power mode (no downgrade). Hash matches are always
        'confirmed' regardless of profile."""
        return "confirmed" if profile == "power" else "suspicious"

    def _load_sigs(self) -> set[str]:
        sigs: set[str] = set()
        # Legacy: hash binary files in data/ (original GuardianAI approach)
        if _DATA_DIR.exists():
            for root, _, files in os.walk(str(_DATA_DIR)):
                for fname in files:
                    if fname in ("known_bad.txt",):
                        continue
                    try:
                        with open(os.path.join(root, fname), "rb") as f:
                            sigs.add(hashlib.md5(f.read()).hexdigest())
                    except Exception:
                        pass
        # MalwareBazaar hashes — load directly from SQLite (canonical source, v1.8+).
        # If the table is very large (> _KNOWN_BAD_RAM_LIMIT), skip RAM loading;
        # tier-3 lookup_hash() in scan_file() handles those hashes via SQLite anyway.
        if _DB_PATH.exists():
            try:
                import sqlite3 as _sqlite3
                _con = _sqlite3.connect(str(_DB_PATH), timeout=3)
                _count = _con.execute(
                    "SELECT COUNT(*) FROM malicious WHERE hash_type='md5'"
                ).fetchone()[0]
                if _count <= _KNOWN_BAD_RAM_LIMIT:
                    for (_h,) in _con.execute(
                        "SELECT hash FROM malicious WHERE hash_type='md5'"
                    ):
                        if _h:
                            sigs.add(_h.lower())
                _con.close()
            except Exception:
                pass
        elif _KNOWN_BAD_TXT.exists():
            # Legacy fallback: SQLite not present but known_bad.txt exists
            try:
                for raw_line in _KNOWN_BAD_TXT.read_text(
                        encoding="utf-8", errors="ignore").splitlines():
                    line = raw_line.strip().lower()
                    if line.startswith("#") or not line:
                        continue
                    if len(line) == 32 and all(c in "0123456789abcdef" for c in line):
                        sigs.add(line)
            except Exception:
                pass
        return sigs

    def reload(self):
        """Reload signatures from SQLite (called automatically after an intelligence update)."""
        self.virus_db = self._load_sigs()
        self._nsrl_bloom = self._load_nsrl_bloom()
        # Also reset the session counters so a circuit-trip from a prior scan
        # doesn't bleed into the next one.
        self._pattern_hit_count = 0
        self._circuit_tripped = False

    def _load_nsrl_bloom(self):
        """
        Load the persisted NSRL Bloom filter from intelligence/nsrl_bloom.bin.

        Returns the bloom object on success, or None if:
          • NSRL is disabled in settings
          • The .bin file doesn't exist yet (NSRL not yet imported)
          • The .bin is marked stale (import in progress or crashed mid-import)
          • The .bin is corrupt (truncated write due to power loss, etc.)

        On corruption: deletes the bad .bin, marks nsrl_bloom_stale=1 in SQLite
        so the next NSRL import will rebuild it, and emits a BLOOM_OFFLINE event
        over IPC so the UI can warn the user.

        When None is returned guardian_engine falls back to per-file SQLite calls
        via is_known_safe() — correct but slower.
        """
        try:
            from ui.core import settings as _cfg
            if not _cfg.get("guardian_use_nsrl"):
                return None
        except Exception:
            pass  # if settings unavailable, proceed and try to load

        if not _BLOOM_PATH.exists():
            return None  # NSRL not yet imported — fall back to SQLite

        # Check stale flag before loading — avoids loading a partial write
        try:
            import sqlite3 as _sqlite3
            if _DB_PATH.exists():
                _con = _sqlite3.connect(str(_DB_PATH))
                _row = _con.execute(
                    "SELECT value FROM meta WHERE key='nsrl_bloom_stale'"
                ).fetchone()
                _con.close()
                if _row and _row[0] == "1":
                    return None  # import in progress or crashed — skip until rebuilt
        except Exception:
            pass

        try:
            from pybloom_live import ScalableBloomFilter
            with open(_BLOOM_PATH, "rb") as f:
                return ScalableBloomFilter.fromfile(f)
        except ImportError:
            return None  # pybloom-live not installed
        except Exception:
            # Corrupt or truncated .bin — mark stale and clean up
            try:
                import sqlite3 as _sqlite3
                if _DB_PATH.exists():
                    _con = _sqlite3.connect(str(_DB_PATH))
                    _con.execute(
                        "INSERT OR REPLACE INTO meta VALUES ('nsrl_bloom_stale', '1')"
                    )
                    _con.commit()
                    _con.close()
            except Exception:
                pass
            try:
                _BLOOM_PATH.unlink(missing_ok=True)
            except Exception:
                pass
            return None  # fall back to per-file SQLite until rebuilt

    def _read_scan_settings(self, use_patterns_override: bool | None):
        """Read the per-scan settings this file will be judged against.

        Read once, here, and passed down to the tiers as parameters rather
        than re-read inside them: a settings write partway through a scan
        must not change the rules halfway down one file.

        Unreadable settings fall back to the permissive defaults -- both
        togglable tiers on -- because failing closed here would silently
        disable detection.
        """
        try:
            from ui.core import settings as _cfg
            use_nsrl     = _cfg.get("guardian_use_nsrl")
            use_patterns = _cfg.get("guardian_use_patterns")
            min_bytes    = _cfg.get("guardian_min_scan_bytes")
            profile      = (_cfg.get("guardian_sensitivity_profile") or "conservative").lower()
            toggles      = _cfg.get("guardian_pattern_toggles") or {}
            if min_bytes is None:
                min_bytes = _DEFAULT_MIN_SCAN_BYTES
        except Exception:
            use_nsrl = use_patterns = True
            min_bytes = _DEFAULT_MIN_SCAN_BYTES
            profile  = "conservative"
            toggles  = {}

        if use_patterns_override is not None:
            use_patterns = bool(use_patterns_override)
        return use_nsrl, use_patterns, min_bytes, profile, toggles

    def _tier_patterns(self, file_path: str, content: bytes, use_patterns: bool,
                       profile: str, toggles: dict) -> tuple[bool, str, str, str] | None:
        """Tier 4 -- heuristic regex patterns, gated by profile and toggles.

        Returns None for "no pattern verdict", which the caller renders as
        Clean.  That covers the tier being off, the file not being worth
        pattern-scanning, and no pattern matching.

        The circuit breaker is the one piece of state here that outlives the
        call: _pattern_hit_count and _circuit_tripped persist across
        scan_file() calls on the same scanner, are reset by
        reset_scan_session() at scan start, and are read by the UI through
        get_circuit_state().  That is why this is a method and not a free
        function.
        """
        # Circuit breaker: if an earlier file in this scan already tripped the
        # threshold, short-circuit the pattern tier entirely.
        if use_patterns and self._circuit_tripped:
            return None

        if use_patterns and self._should_pattern_scan(file_path, content):
            text = content.decode("utf-8", errors="ignore")
            for label, pattern, *_ in self._PATTERNS:
                # v1.10: profile + per-pattern toggle gate
                if not self._pattern_enabled(label, profile, toggles):
                    continue

                matched = False
                match_obj = None
                if label.startswith("AutoRun"):
                    # AutoRun requires BOTH the [AutoRun] section header
                    # AND an open= directive (two separate checks)
                    m1 = pattern.search(text)
                    m2 = re.search(r'^\s*open\s*=\s*\S', text,
                                   re.IGNORECASE | re.MULTILINE)
                    if m1 and m2:
                        matched = True
                        match_obj = m1
                else:
                    match_obj = pattern.search(text)
                    if match_obj:
                        matched = True

                if matched:
                    # Capture a small printable context window for the UI.
                    match_context = self._capture_match_context(text, match_obj)

                    # Telemetry: increment pattern stats.
                    try:
                        from ui.core import pattern_stats as _ps
                        _ps.record_detection(label)
                    except Exception:
                        pass

                    # Circuit breaker: count the hit and trip if over threshold.
                    self._pattern_hit_count += 1
                    if (self._circuit_threshold > 0
                            and self._pattern_hit_count >= self._circuit_threshold):
                        self._circuit_tripped = True

                    return True, f"Suspicious pattern: {label}", "pattern", match_context
        return None

    def _tier_nsrl(self, md5: str, use_nsrl: bool) -> tuple[bool, str, str, str] | None:
        """Tier 1 -- the NSRL known-safe allow-list, when enabled.

        The bloom filter is a pre-filter, never the verdict: a hit still has
        to be confirmed against SQLite, because a bloom filter has false
        positives and calling a file safe on one would be a missed detection.
        A filter that is absent (not built, or quarantined as unparseable)
        means every hash falls through to the SQLite check rather than
        skipping the tier.
        """
        if not use_nsrl:
            return None
        bloom = self._nsrl_bloom
        if bloom is not None and md5 not in bloom:
            return None
        try:
            from ui.core.intel_db import is_known_safe
            if is_known_safe(md5):
                return False, "NSRL (known-safe system file)", "safe", ""
        except ImportError:
            pass
        return None

    @staticmethod
    def _format_hash_reason(meta: dict | None, fallback: str) -> str:
        """Render a hash-tier reason from an intel_db row, else `fallback`.

        Both hash tiers agree on the shape -- family name, with the engine
        count appended when there is one -- and differ only in what they say
        when the row carries neither.  That difference is the fallback.
        """
        if not meta:
            return fallback
        family = meta.get("family", "").strip()
        count  = meta.get("detection_count", 0)
        if family:
            return f"{family}  [{count} engines]" if count else family
        if count:
            return f"Known malware  [{count} engines]"
        return fallback

    def _tier_ram_signature(self, md5: str) -> tuple[bool, str, str, str] | None:
        """Tier 2 -- the in-memory signature set loaded at scan start."""
        if md5 not in self.virus_db:
            return None
        reason = f"Known Signature (MD5: {md5[:12]}…)"
        try:
            from ui.core.intel_db import lookup_hash
            reason = self._format_hash_reason(lookup_hash(md5), reason)
        except ImportError:
            pass
        return True, reason, "hash", ""

    def _tier_sqlite(self, md5: str) -> tuple[bool, str, str, str] | None:
        """Tier 3 -- the malicious table, which carries family and engine count.

        A row that exists but is empty is still a hit: the guard is
        `is not None`, not truthiness, so a bare row does not read as a miss.
        """
        try:
            from ui.core.intel_db import lookup_hash
            meta = lookup_hash(md5)
            if meta is not None:
                return True, self._format_hash_reason(
                    meta, f"Known Signature (DB: MD5 {md5[:12]}…)"), "hash", ""
        except ImportError:
            pass
        return None

    def scan_file(self, file_path: str,
                  use_patterns_override: bool | None = None) -> tuple[bool, str, str, str]:
        """
        Returns (infected, reason, tier, match_context).

        Tier values:
          'safe'    — NSRL allow-list hit (file is known safe, returned with infected=False)
          'hash'    — tier 2 or tier 3 MalwareBazaar / SQLite hash match
          'pattern' — tier 4 heuristic regex match
          'skipped' — pre-MD5 guards (min size, ignore list)
          'clean'   — no detection
          ''        — error or permission denied

        match_context is non-empty only for tier='pattern' — a ~160 char window
        of the file content around the regex match span, with non-printable
        bytes replaced by '·'. Used by the UI's Match Context block.

        ``use_patterns_override`` lets the caller (e.g. the real-time watcher)
        force the pattern tier off even when the global setting has it on.

        Lookup priority:
          0. Min-size guard + user ignore list  → 'skipped'
          1. NSRL allow-list                    → 'safe'        [if guardian_use_nsrl]
          2. RAM signature set                  → 'hash'
          3. SQLite malicious table             → 'hash'
          4. Heuristic pattern matching         → 'pattern'     [if use_patterns + profile/toggle allows]

        Tiers 1 and 4 are togglable; tier 4 is further subject to the
        sensitivity profile (Conservative / Balanced / Power) and the
        per-pattern toggles dict from settings.
        """
        (use_nsrl, use_patterns, min_bytes, profile,
         toggles) = self._read_scan_settings(use_patterns_override)

        try:
            with open(file_path, "rb") as f:
                content = f.read()

            # v1.9: minimum-size guard — skips null-MD5 false positives.
            if len(content) < max(0, int(min_bytes)):
                return False, "Skipped (below minimum scan size)", "skipped", ""

            md5 = hashlib.md5(content).hexdigest()

            # v1.9: user-managed ignore list short-circuit.
            try:
                from ui.core import ignore_list as _ignore
                if _ignore.contains(md5):
                    return False, "User-ignored hash", "skipped", ""
            except Exception:
                pass

            # ── 1. NSRL allow-list ──
            verdict = self._tier_nsrl(md5, use_nsrl)
            if verdict is not None:
                return verdict

            # ── 2. RAM signature set ──
            verdict = self._tier_ram_signature(md5)
            if verdict is not None:
                return verdict

            # ── 3. SQLite malicious table ──
            verdict = self._tier_sqlite(md5)
            if verdict is not None:
                return verdict

            # ── 4. Pattern matching ──
            verdict = self._tier_patterns(file_path, content, use_patterns,
                                          profile, toggles)
            if verdict is not None:
                return verdict

            return False, "Clean", "clean", ""

        except PermissionError:
            return False, "Permission denied", "", ""
        except Exception as exc:
            return False, f"Error: {str(exc)[:60]}", "", ""

    @staticmethod
    def _capture_match_context(text: str, match) -> str:
        """Extract a printable ~160-char window around a regex match span.

        Returns a string like '...some surrounding text including the matched
        phrase...' where non-printable characters become '·'. Empty string on
        failure or if the match is None.
        """
        if not match:
            return ""
        try:
            start = max(0, match.start() - 40)
            end   = min(len(text), match.end() + 40)
            snippet = text[start:end].replace("\n", " ").replace("\r", " ").replace("\t", " ")
            # Trim to printable ASCII for safe display
            snippet = "".join(c if 32 <= ord(c) < 127 else "·" for c in snippet)
            # Truncate hard so we never blow up the detail pane
            if len(snippet) > 160:
                snippet = snippet[:160]
            return f"…{snippet.strip()}…"
        except Exception:
            return ""


# ── Post-update hook registration flag ───────────────────────────────────────
# Registered lazily on the first scan_async() call to avoid import-time side
# effects (all modules are fully initialised by then).
_post_update_hook_registered = False


# ── Module-level scanner singleton (reloaded when needed) ──────────────────

_scanner: _EnhancedScanner | None = None


def _get_scanner() -> _EnhancedScanner:
    global _scanner
    if _scanner is None:
        _scanner = _EnhancedScanner()
    return _scanner


def pattern_labels() -> tuple[str, ...]:
    """The heuristic pattern labels, in the order the engine evaluates them.

    The single source of truth for these strings.  They are not decoration:
    `guardian_pattern_toggles` is a dict *keyed by label*, and
    `_pattern_enabled()` resolves a toggle by looking the label up.  A settings
    screen holding its own copy of the list can therefore drift into writing
    `toggles["old name"] = False` for a pattern the engine now calls something
    else -- the switch reads OFF and the pattern keeps firing, with nothing
    anywhere reporting a mismatch.
    """
    return tuple(p[0] for p in _EnhancedScanner._PATTERNS)


def conservative_disabled() -> frozenset[str]:
    """Labels the conservative profile turns off by default.

    Exposed for the same reason as pattern_labels(): so the Settings screen can
    show what the engine will do rather than a second opinion about it.
    """
    return _EnhancedScanner._CONSERVATIVE_DISABLED


def pattern_enabled(label: str, profile: str, toggles: dict) -> bool:
    """Whether `label` fires under this profile + override set.

    Thin re-export of the scanner's resolver so callers outside this module do
    not have to reach through a private class -- and, more to the point, do not
    reimplement it.
    """
    return _EnhancedScanner._pattern_enabled(label, profile, toggles)


def reload_signatures():
    """Force a reload of MalwareBazaar signatures from SQLite. Call after updating the DB."""
    global _scanner
    if _scanner is not None:
        _scanner.reload()
    else:
        _scanner = _EnhancedScanner()


def register_intel_hooks() -> bool:
    """Register reload_signatures() as this process's "hashes" post-update hook.

    Idempotent, and safe to call from both the eager start-up paths (App
    __init__, the service's SvcDoRun) and the lazy first-scan path in
    scan_async().  Eager registration matters for the service: it can run for
    days without ever entering scan_async(), and an unregistered hook means
    intelligence updates never reach its in-RAM hash set.

    Returns True once registration has succeeded in this process.
    """
    global _post_update_hook_registered
    if _post_update_hook_registered:
        return True
    try:
        from tools.update_intelligence import register_post_update_hook
        register_post_update_hook(reload_signatures, domains=("hashes",))
        _post_update_hook_registered = True
    except Exception:
        pass   # update_intelligence not on path (standalone guardian env)
    return _post_update_hook_registered


# ── Async scan ────────────────────────────────────────────────────────────────

def scan_async(
    paths: list[str],
    on_result,
    on_done,
    on_progress=None,
    cancel_event=None,   # threading.Event | None
    pause_event=None,    # threading.Event | None — cleared while paused
    use_patterns_override: bool | None = None,
    on_error=None,
):
    """
    Scan a list of files/folders asynchronously in a daemon thread.

    Parameters
    ----------
    paths        : list of file or directory paths to scan
    on_result    : callable. Supports two signatures (auto-detected by arity):
                     (fpath, infected, reason)                 — legacy
                     (fpath, infected, reason, tier, context)  — v1.10+
                   Callers that want match-context + tier-aware UI use the 5-arg form.
    on_done      : callable(infected_count: int)
    on_progress  : optional callable(done: int, total: int, current_file: str)
    on_error     : optional callable(message: str), fired at most once and
                   always before on_done. Additive, and present here so the
                   three engines stay drivable through one interface — see
                   tests/test_engine_contract.py. Guardian's per-file verdicts
                   already carry a tier, so this reports only the case where
                   the engine was launched and could not run at all.
    use_patterns_override : if not None, forces the pattern tier on/off for this
                            scan only (used by the real-time watcher to skip
                            patterns by default).
    """
    def _run():
        # Fallback registration for hosts that never called register_intel_hooks()
        # at start-up.  Idempotent — a no-op once the eager path has run.
        register_intel_hooks()

        if not is_available():
            # Launched but unable to run. The watcher only launches Guardian
            # after is_available() says yes, so reaching here means it changed
            # underneath — which must not read as a completed clean scan.
            if on_error:
                on_error("Guardian signatures are unavailable")
            on_done(0)
            return

        scanner = _get_scanner()
        # v1.10: reset circuit-breaker counters at the start of each scan
        scanner.reset_scan_session()

        # Detect on_result signature (legacy 3-arg vs v1.10 5-arg) once.
        import inspect
        try:
            sig = inspect.signature(on_result)
            cb_arity = len([p for p in sig.parameters.values()
                            if p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                          inspect.Parameter.POSITIONAL_ONLY)])
        except (TypeError, ValueError):
            cb_arity = 3   # default to legacy

        # Enumerate all files
        all_files: list[str] = []
        for p in paths:
            path = Path(p)
            try:
                if path.is_file():
                    all_files.append(str(path))
                elif path.is_dir():
                    for item in path.rglob("*"):
                        try:
                            if item.is_file():
                                all_files.append(str(item))
                        except PermissionError:
                            pass
            except PermissionError:
                pass

        total = len(all_files)
        infected_count = 0

        if on_progress:
            on_progress(0, total, "")

        for idx, fpath in enumerate(all_files):
            if cancel_event and cancel_event.is_set():
                break
            if pause_event is not None:
                pause_event.wait()   # blocks while paused; instant if running
                if cancel_event and cancel_event.is_set():
                    break            # cancel issued while we were paused
            infected, reason, tier, ctx = scanner.scan_file(
                fpath, use_patterns_override=use_patterns_override)
            try:
                if cb_arity >= 5:
                    on_result(fpath, infected, reason, tier, ctx)
                else:
                    on_result(fpath, infected, reason)
            except TypeError:
                # If introspection misjudged, fall back to legacy form
                on_result(fpath, infected, reason)
            if infected:
                infected_count += 1
            if on_progress:
                on_progress(idx + 1, total, fpath)

        on_done(infected_count)

    threading.Thread(target=_run, daemon=True).start()
