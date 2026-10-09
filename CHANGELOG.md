# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/). Each entry says
what changed for someone running or building PolyShield; the reasoning lives in
the commit message and in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

There are **no git tags** yet, so older entries cannot be tied to a commit. The
release checklist ([docs/RELEASING.md](docs/RELEASING.md)) makes tagging a step;
the first tagged release should also fix the date of the entry it closes.

## [Unreleased]

`src/ui/version.py` and `installer/polyshield.iss` still say **1.16.0**. The
login-autostart, tray and uninstall-entry work below is labelled "v1.17" in
`CLAUDE.md`, so this section is the candidate 1.17 notes; whoever cuts the
release decides the number and bumps both files (a test keeps them equal).

### Added
- **Start with Windows (opt-in).** A per-user login entry that launches
  PolyShield minimised to the notification area (`--minimized` / `--tray`), a
  matching *unchecked* installer task, and a setting for a Quick Scan shortly
  after sign-in. Nothing is written to the registry unless the user asked.
- **Add/Remove Programs entry for a source checkout**
  (`scripts/install_dev.bat`, `scripts/uninstall_dev.bat`). It lists as
  *(development install)* and removes registrations, never the checkout.
- **Optional code signing.** `build.ps1` signs `PolyShield.exe`, the setup
  program and the uninstaller when `POLYSHIELD_SIGN_THUMBPRINT` or
  `POLYSHIELD_SIGN_EXTRA_ARGS` is set; `-RequireSigning` fails the build up front
  if neither is. Off by default, and an unsigned build says so in its last lines.
  Verified with a throwaway self-signed certificate only; see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#code-signing-v117).
- **K2 is now checked by detection.** The build's engine probe scans a planted
  sample (K2's own harmless Dummy test signature) and a clean control, and fails
  the build if K2 reports itself available and misses the first or flags the
  second. Previously it only counted loaded plugins.

### Fixed
- **The Windows service never started at boot.** pywin32 ignores
  `_svc_start_type_`, so every install registered a demand-start service. The
  start type is now injected where all three install paths converge.
- **`build.ps1 -BuildRuntime` could not install PolyBedrock** into the staged
  runtime (`Cannot import 'setuptools.build_meta'`): the embeddable Python
  ignores `PYTHONPATH`, which hides pip's isolated build environment. Git-URL
  packages are now built into wheels on the build machine and installed by path.
  No distribution could be built from a clean tree until this.
- **The runtime build failed on any machine that had never run k2.** kicomav's
  `.env` warning on stderr aborted `Test-StagedRuntime` under
  `$ErrorActionPreference = "Stop"`, and its K2 signature floor of 100 needed
  rule archives only a used profile has (a clean machine sees 23). Found by the
  first CI run of the build-smoke workflow.
- **A fresh install of the pinned PolyBedrock raised `ModuleNotFoundError`.**
  `scheduler.py` imports `polybedrock.schtasks_run`, which the pinned revision
  predated. The local editable install hid it; CI and `build.ps1` would not have.

### Changed
- The `schtasks.exe` invocation behind scheduled scans now comes from
  `polybedrock.schtasks_run`, shared with PolyScour. Task naming, elevation and
  error handling are unchanged.
- PolyBedrock pin `3a50288` -> `2801424` (requirements, CI requirements,
  `build.ps1`); `schtasks_run` added to both Nuitka targets.
- `docs/ARCHITECTURE.md` now states that K2 ships in the staged runtime (it has
  since 4c.2) and corrects the signature split: about 23 in the plugins, the rest
  from archives downloaded at install time.

## [1.16.0]

Installer, shared `%ProgramData%\PolyShield` data root, service privilege
boundary, K2 shipped in a self-building runtime, scheduled scans in an installed
copy. The full list is the v1.16 block in
[docs/USAGE.md](docs/USAGE.md#potential-improvements); no release date was
recorded.

## Earlier

v1.0 - v1.15 are described in [docs/USAGE.md](docs/USAGE.md) (feature history)
and in `git log`. They are not repeated here.
