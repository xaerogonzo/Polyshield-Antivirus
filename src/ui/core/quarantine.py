import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from ui.core import paths

QUARANTINE_DIR = paths.quarantine_dir()
# parents=True because on the first run of a distribution the data root
# itself does not exist yet; a checkout always had one.
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Per-file sidecar suffix
_META_SUFFIX = ".kicometa"


def list_quarantined() -> list[dict]:
    """Return list of quarantined file entries with metadata."""
    entries = []
    for item in sorted(QUARANTINE_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if item.suffix == _META_SUFFIX or item.name.startswith("."):
            continue
        meta = _load_meta(item)
        entries.append({
            "path": item,
            "filename": item.name,
            "original_path": meta.get("original_path", "Unknown"),
            "threat_name": meta.get("threat_name", "Unknown"),
            "date": meta.get("quarantine_date", _mtime_str(item)),
        })
    return entries


def add_file(src_path: str, threat_name: str = "Unknown") -> Path:
    """Move a file into quarantine and write its .kicometa sidecar.

    The origin is recorded as an absolute path. A relative one would be
    resolved at *restore* time against whatever the working directory happens
    to be then — which, for a file that may sit in quarantine for months, is a
    guess rather than a destination.
    """
    src = Path(src_path).resolve()
    dest = _unique_dest(src.name)
    shutil.move(str(src), dest)
    _save_meta(dest, {
        "original_path": str(src),
        "threat_name": threat_name,
        "quarantine_date": datetime.now().isoformat(),
    })
    return dest


def move_to_quarantine(src_path: str, threat_name: str = "Unknown") -> tuple[bool, str]:
    """Quarantine a file, reporting a verdict and a message fit for the UI.

    The view-facing wrapper around add_file(). Every caller is a button
    handler that needs two things add_file() does not give it: a boolean it
    can branch on, and a line it can put in the status bar and the scan log.
    add_file() raises instead, and an exception reaching a Tk command handler
    is invisible to the user — the button simply does nothing.
    """
    name = Path(src_path).name
    try:
        dest = add_file(src_path, threat_name)
    except FileNotFoundError:
        return False, f"Quarantine failed: {name} no longer exists"
    except PermissionError:
        return False, f"Quarantine failed: {name} is locked by another process"
    except Exception as exc:
        return False, f"Quarantine failed: {name} - {exc}"
    return True, f"Quarantined: {name}"


def restore(entry: dict) -> bool:
    """Restore a quarantined file to its original location.

    Refuses rather than overwrites. If something already occupies the original
    path — the user re-created or re-downloaded it while the threat sat in
    quarantine — the restore fails and leaves both the quarantined file and
    its sidecar intact. Losing the file the user kept is worse than declining
    to restore the one they quarantined.
    """
    qpath: Path = entry["path"]
    orig = entry["original_path"]
    if orig == "Unknown":
        return False
    dest = Path(orig)
    if dest.exists():
        return False
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(qpath), dest)
        meta_file = _meta_path(qpath)
        if meta_file.exists():
            meta_file.unlink()
        return True
    except Exception:
        return False


def delete(entry: dict) -> bool:
    """Permanently delete a quarantined file."""
    qpath: Path = entry["path"]
    try:
        qpath.unlink(missing_ok=True)
        meta_file = _meta_path(qpath)
        if meta_file.exists():
            meta_file.unlink()
        return True
    except Exception:
        return False


# ── helpers ──────────────────────────────────────────────────────────────────

def _meta_path(qpath: Path) -> Path:
    return qpath.with_suffix(qpath.suffix + _META_SUFFIX)


def _load_meta(qpath: Path) -> dict:
    meta_file = _meta_path(qpath)
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_meta(qpath: Path, data: dict):
    _meta_path(qpath).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _unique_dest(filename: str) -> Path:
    dest = QUARANTINE_DIR / filename
    if not dest.exists():
        return dest
    stem, suffix = os.path.splitext(filename)
    i = 1
    while True:
        candidate = QUARANTINE_DIR / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def _mtime_str(p: Path) -> str:
    try:
        return datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "Unknown"
