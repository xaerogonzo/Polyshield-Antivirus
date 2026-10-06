# Releasing PolyShield

A checklist, not a script: most of it needs judgement, and the parts that do not
are one command each. Every step names the thing that would otherwise fail
*quietly* -- a release is where a green log and a broken product coincide.

**Do the verification on a throwaway machine, not this one.** Step 6 installs the
product, registers the service and rewrites `%ProgramData%\PolyShield` ACLs.

## 1. Preconditions

- On `master`, working tree clean, CI green on **both** matrix legs (Python 3.11
  and 3.13) for the commit you are releasing.
- **The PolyBedrock pin is a pushed commit that contains everything PolyShield
  imports.** A pin that predates an import passes locally -- the editable install
  hides it -- and raises `ModuleNotFoundError` for everyone else. Check it the way
  a stranger would: in a scratch venv,
  `pip install "polybedrock-core @ git+https://github.com/xaerogonzo/PolyBedrock.git@<sha>#subdirectory=core"`
  and import what PolyShield uses. This happened once (`aab3a72` -> `9c8cc8b`).
- The three pin sites agree: `requirements.txt`, `requirements-ci.txt`,
  `$POLYBEDROCK` in `build.ps1`. `tests/test_substrate_pin.py` asserts it, but
  only against what is installed, so run it in a **non-editable** environment.
- If PolyBedrock changed for this release, its CI pins for PolyShield/PolyScour
  are current: run `python .github/scripts/pin_distance.py` in that repo and
  follow `docs/ECOSYSTEM_HEALTH.md` (one consumer per PR).

## 2. Version and notes

- Bump **both** `__version__` in `src/ui/version.py` and `#define AppVersion` in
  `installer/polyshield.iss`; `tests/test_integration_edges.py` fails if they
  differ.
- Move `CHANGELOG.md`'s `[Unreleased]` block under the new version and **date
  it**. There are no tags yet, so the changelog is the only record of what shipped
  when.

## 3. Signing configuration

Environment variables only -- see *Code signing* in `docs/ARCHITECTURE.md`.

```powershell
$env:POLYSHIELD_SIGN_THUMBPRINT = "<sha-1 of the certificate in your store>"
# or, for non-store providers (Azure Trusted Signing):
# $env:POLYSHIELD_SIGN_EXTRA_ARGS = '/dlib "C:\...\Azure.CodeSigning.Dlib.dll" /dmdf metadata.json'
```

Do **not** set `POLYSHIELD_SIGN_ALLOW_UNTRUSTED` for a release: it exists so a
self-signed development certificate can be used, and it disables the check that
the signature chains to a trusted root.

## 4. Build

Use `build.ps1` directly. `build.bat` ends in `pause`, which hangs an unattended
run.

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1 -BuildRuntime -Onefile -Target all -RequireSigning
powershell -ExecutionPolicy Bypass -File .\build.ps1 -NoClean -Target installer -RequireSigning
```

`-RequireSigning` fails at pre-flight if no certificate is configured, before the
multi-minute compile. The build then gates itself:

- the **path probe** (frozen, data root outside the build);
- the **engine probe** on the *signed* binary, including K2 detecting its Dummy
  test signature and passing a clean control;
- the runtime's own assertions (pywin32 resolved from the runtime, k2 signature
  count).

Read the last line of the log. It must say `Signing: SIGNED`.

## 5. Check the artifacts yourself

The build reads signatures back off the files, but a release deserves one look
that does not trust the build script:

```powershell
Get-AuthenticodeSignature dist\PolyShield.exe, dist\PolyShield-Setup-*.exe |
    Format-List Path, Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid` (not `UnknownError`, which means an untrusted chain) and
`TimeStamperCertificate` must be present -- without a timestamp the signature
stops validating the day the certificate expires.

> **Not yet observed:** a `Valid` status. Signing has only been exercised with a
> self-signed certificate, so the first real release is also the first time this
> check can pass. Treat it as a test of the signing setup, not a formality.

## 6. Verify on a machine that has nothing

On a throwaway VM or in Windows Sandbox -- never on a development machine:

```
kicomav_env\Scripts\python.exe tools\make_sandbox_wsb.py
```

Open the generated `.wsb`. `tools/sandbox_verify.ps1` runs the build checks and
the install/uninstall cycle (about 50 checks); results land in
`artifacts/sandbox/verify.json`, which survives the sandbox. All must pass. Then,
inside it, after the install, check the **uninstaller** that Inno wrote:

```powershell
Get-AuthenticodeSignature "C:\Program Files\PolyShield\unins000.exe"
```

It is the file Windows runs elevated from Settings > Apps, and it only exists
after an install, so nothing at build time can check it. See `docs/TESTING.md`
(*The install cycle*) for what each check replaced.

Also confirm the K2 rule archives arrived: after install, the Update Center's K2
card should report about 1263 signatures. The build machine only sees 23, because
the archives are downloaded at install time and a failed download is not an
install failure.

## 7. Tag and publish (a human step)

The repository's agent rules forbid pushing tags, so this is yours.

```bash
git tag -a vX.Y.Z -m "PolyShield X.Y.Z"
git push origin vX.Y.Z
```

Attach `PolyShield-Setup-X.Y.Z.exe` and its SHA-256
(`Get-FileHash -Algorithm SHA256`) to the release, with the CHANGELOG entry as the
notes. Do not attach `dist\` build scratch.

## 8. After

- Start a fresh `[Unreleased]` block in `CHANGELOG.md`.
- If PolyShield moved while you were releasing, PolyBedrock's CI pin for it is
  stale again; `pin_distance.py` in that repo says by how much.

## What this checklist cannot tell you

SmartScreen weighs *reputation* as well as signatures. An OV certificate removes
"unknown publisher" but a new publisher can still be warned until downloads
accumulate; an EV certificate or Azure Trusted Signing is trusted immediately.
A correctly signed release can therefore still show a warning to its first users.
