"""Helpers shared by more than one view.

Views must not import each other.  ``scan_view`` imports
``threat_actions_mixin`` to inherit its mixin, so anything the mixin needs from
``scan_view`` would close an import cycle -- which is why ``_human_size`` came
to exist twice, once on each side of that edge.  This module is the third place
both can reach.

Add a helper here when a second view needs it.  Keep it dependency-free: no
widget construction, no ``ui.core`` imports, nothing that needs a Tk root.
"""


def _format_eta(seconds: float) -> str:
    if seconds <= 0:
        return "—"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _human_size(n: int) -> str:
    """Human-readable byte count (1.5 KB, 3.2 MB, etc.)."""
    if n < 1024:
        return f"{n} B"
    units = ["KB", "MB", "GB", "TB"]
    val = float(n) / 1024.0
    for u in units:
        if val < 1024 or u == units[-1]:
            return f"{val:.1f} {u}"
        val /= 1024.0
    return f"{n} B"


def _parse_dnd_paths(raw: str) -> list[str]:
    r"""Split a tkinterdnd2 drop payload into individual paths.

    Tk brace-wraps any path containing a space and separates the rest with
    single spaces, so ``{C:\Program Files.exe} C:	mp.exe`` is two paths,
    not four.  Splitting on whitespace alone silently shreds every path with a
    space in it.
    """
    paths, raw, i = [], raw.strip(), 0
    while i < len(raw):
        if raw[i] == "{":
            end = raw.index("}", i)
            paths.append(raw[i + 1:end])
            i = end + 2
        else:
            end = raw.find(" ", i)
            if end == -1:
                paths.append(raw[i:])
                break
            paths.append(raw[i:end])
            i = end + 1
    return [p for p in paths if p]
