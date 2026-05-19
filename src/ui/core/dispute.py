"""
dispute.py
──────────
Compare k2 engine results against Guardian AI results and find files
where the two engines disagree.

A "dispute" means exactly one engine flagged a file as infected while the
other called it clean — these are the interesting cases that warrant a
human decision.
"""
from __future__ import annotations
from pathlib import Path


def find_disputes(
    k2_infected: list[str],
    guardian_infected: dict[str, str],  # path → reason string
) -> list[dict]:
    """
    Return a list of dispute dicts for files the two engines disagree on.

    Each dict contains:
      path              – original file path (best-case casing)
      k2_verdict        – "Infected" | "Clean"
      guardian_verdict  – "Infected" | "Clean"
      guardian_reason   – reason string from guardian_engine (or "")
      filename          – Path(path).name  (convenience)
    """
    # Normalise to lowercase keys for comparison
    k2_map:  dict[str, str] = {p.lower(): p for p in k2_infected}
    g_map:   dict[str, tuple[str, str]] = {
        p.lower(): (p, reason) for p, reason in guardian_infected.items()
    }

    all_keys = set(k2_map) | set(g_map)
    disputes: list[dict] = []

    for key in all_keys:
        in_k2  = key in k2_map
        in_g   = key in g_map

        if in_k2 == in_g:
            continue  # Both agree — either both clean or both infected

        # Pick best casing: prefer k2's path (comes from a real scan report)
        orig_path      = k2_map.get(key) or g_map[key][0]
        guardian_reason = g_map[key][1] if in_g else ""

        disputes.append({
            "path":             orig_path,
            "filename":         Path(orig_path).name,
            "k2_verdict":       "Infected" if in_k2 else "Clean",
            "guardian_verdict": "Infected" if in_g  else "Clean",
            "guardian_reason":  guardian_reason,
        })

    # Sort: k2-says-infected first (higher confidence), then guardian-only
    disputes.sort(key=lambda d: (0 if d["k2_verdict"] == "Infected" else 1, d["filename"]))
    return disputes
