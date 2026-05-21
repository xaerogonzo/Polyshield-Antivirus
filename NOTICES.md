# Third-Party Notices

PolyShield is licensed under the MIT License (see [LICENSE](LICENSE)) and bundles, depends on, or invokes the following open-source components. Each retains its own copyright and license. This file lists the licenses we are aware of at the time of writing — if anything is missing or incorrect, please open an issue.

---

## Bundled scanners (invoked via subprocess or imported as Python packages)

### K2 (KicomAV)
- **Project**: [hanul93/kicomav](https://github.com/hanul93/kicomav)
- **License**: MIT
- **Author**: Kei Choi
- **How PolyShield uses it**: K2 ships as part of the `kicomav` PyPI package and is invoked as `k2.exe`, a subprocess. K2 is the primary signature-detection engine.

### Guardian AI
- **Project**: [MattEmilien/GuardianAI](https://github.com/MattEmilien/GuardianAI)
- **License**: MIT
- **Author**: Matt Emilien
- **How PolyShield uses it**: Cloned and installed into its own virtual environment by `scripts/manage.bat`; invoked as a second-opinion scanner with hash DB lookup and 7 heuristic patterns.

### YARA
- **Project**: [VirusTotal/yara](https://github.com/VirusTotal/yara) (via `yara-python`)
- **License**: BSD-3-Clause
- **How PolyShield uses it**: Imported as `yara` via the `yara-python` Python package; used for rule-based scanning.

### Speakeasy
- **Project**: [mandiant/speakeasy](https://github.com/mandiant/speakeasy) (via `speakeasy-emulator` on PyPI)
- **License**: Apache 2.0
- **How PolyShield uses it**: Imported as a Python module; used for PE behavioral emulation at the end of the scan pipeline.

### ClamAV
- **Project**: [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav)
- **License**: GPL-2.0-only
- **How PolyShield uses it**: Invoked as a subprocess (`clamscan` / `clamd`) when available. PolyShield neither bundles nor links against ClamAV source — this is mere aggregation, not derivative use, so PolyShield's MIT license is unaffected.

### Microsoft Defender
- **Component**: Built-in Windows AV (`MpCmdRun.exe`)
- **License**: Proprietary (Microsoft Windows)
- **How PolyShield uses it**: Invoked as a subprocess on systems where Defender is installed. No code from Defender is included in PolyShield.

### VirusTotal
- **Service**: [virustotal.com](https://www.virustotal.com)
- **License**: Service terms apply (no code bundled)
- **How PolyShield uses it**: HTTP API lookups by file hash, optional, requires a user-supplied API key. The API key is stored in user-local config (`config/ui_settings.json`, **never committed**).

---

## Python runtime dependencies (installed via pip)

See [requirements.txt](requirements.txt) for the canonical list. Notable licenses:

| Package | License |
|---|---|
| customtkinter | MIT |
| tkinterdnd2 | Public Domain |
| python-dotenv | BSD-3-Clause |
| requests | Apache 2.0 |
| py7zr | LGPL-2.1-or-later |
| rarfile | ISC |
| pefile | MIT |
| yara-python | BSD-3-Clause |
| speakeasy-emulator | Apache 2.0 |
| unicorn | GPL-2.0 |
| pycryptodome | BSD-2-Clause / Public Domain |
| watchdog | Apache 2.0 |
| psutil | BSD-3-Clause |
| rich | MIT |
| pystray | LGPL-3.0 |
| pywin32 | PSF (Python Software Foundation) + proprietary components |
| pybloom-live | MIT |
| setuptools | MIT |

PolyShield imports these via the standard Python package mechanism. Permissive licenses (MIT/BSD/Apache/ISC) impose no restrictions on PolyShield's own MIT license. LGPL packages (`py7zr`, `pystray`) allow MIT applications to link as long as the LGPL libraries remain replaceable (which they are — they're standard pip installs). The single GPL-2.0 dependency (`unicorn`) is loaded by `speakeasy-emulator`, not PolyShield directly; substitution would require replacing Speakeasy, not PolyShield's own code.

---

## Acknowledgements

PolyShield's value is mostly in **how it combines** these excellent open-source tools — the scan-pipeline architecture, the UI, the Windows service, the threat-intelligence integration, the dispute-resolution system, and the per-engine reordering are PolyShield's own work. The detection engines themselves are the heroes; this project is the conductor.

If you're an author of any component listed here and would like attribution, link, or license details changed, please open an issue or PR.
