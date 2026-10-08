# PolyShield — Basic Instructions

@project-baseline.md

---

## Project Overview

**Name:** PolyShield Security Suite
**Stack:** Python 3.11+, CustomTkinter (dark theme), Windows-only (uses `schtasks`, `MpCmdRun.exe`, `NtSuspendProcess`)
**Entry point:** `launch_ui.vbs` -> `src/ui/app.py` -> `App.mainloop()`
**Purpose:** A Windows antivirus and security suite: scanning (k2, ClamAV, YARA), real-time watching, and a Windows service, with a desktop UI.

The detailed file map, conventions and common edit locations live in `CLAUDE.md`, which is the single place to keep them current. Do not duplicate them here.

---

## Documentation Files

| File | Location | Purpose |
|---|---|---|
| README | `README.md` | User-facing: features, install, usage, troubleshooting |
| Changelog | `CHANGELOG.md` | Per-release changes; `[Unreleased]` is the candidate next version |
| Architecture | `docs/ARCHITECTURE.md` | Detection layers, scan pipelines, DB schema, threading |
| Windows service | `docs/WINDOWS_SERVICE.md` | Service implementation, IPC protocol, crash recovery |
| Testing | `docs/TESTING.md` | Test procedures, sandbox workflow, VM field-test checklist |
| VM setup | `docs/VM_SETUP.md` | Windows 11 VM and snapshot setup |
| Releasing | `docs/RELEASING.md` | Release checklist: pin check, version bump, signing, build, tag |
| Lessons | `docs/LESSONS.md` | Lessons moved out of `CLAUDE.md`, plus `docs/gotchas/` |

---

## Project-Specific Rules

See `CLAUDE.md` ("Key Patterns & Conventions" and "Common Edit Locations").
