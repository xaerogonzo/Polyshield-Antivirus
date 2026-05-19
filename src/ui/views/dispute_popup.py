"""
dispute_popup.py — DEPRECATED (v1.9)
─────────────────────────────────────
The DisputePopup class has been retired. Dispute resolution is now handled
inline inside the Scan view's Threat Actions master-detail panel:

  • A banner above the threat list shows the dispute count
  • Disputed files are selectable via the "Dispute" filter chip
  • Selecting a disputed row expands the "Dispute Mode" panel in the detail
    pane, with Trust K2 / Trust Guardian quick-resolve actions
  • Resolved disputes move to a hidden "Resolved" set (visible via the
    Resolved filter chip)

The popup was modal — it froze the rest of the UI while open and forced
the user to manage two windows for a single task. The inline replacement
keeps everything in one coordinate space and lets the user navigate the
main UI while resolving.

See `src/ui/views/scan_view.py`:
  - `_check_disputes()` — populates `self._disputes`
  - `_build_dispute_mode_panel()` — renders the inline dispute UI
  - `_resolve_dispute()` — Trust K2 / Trust Guardian handlers

This file is retained as a stub so that any historical import of
`ui.views.dispute_popup` does not break — it simply has nothing to export.
"""
