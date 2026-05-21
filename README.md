# PolyShield Security Suite

> Multi-engine open-source security suite for Windows — built to **supplement Windows Defender, not replace it.**

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey)
![Python](https://img.shields.io/badge/python-3.11%2B-green)
![Engines](https://img.shields.io/badge/engines-6-orange)

---

PolyShield runs **six security engines in parallel** through a unified UI: K2 (KicomAV), Microsoft Defender, Guardian AI, YARA, ClamAV, and Speakeasy. All five secondary engines are reorderable, individually toggleable, and configurable per-sensitivity. There's a Windows Service for always-on file-watching, a VirusTotal smart-upload flow (hash-first, never uploads what's already known), and a per-pattern false-positive tracking system that learns which heuristics you trust over time.

No telemetry. No cloud upload of your files (unless you opt into VirusTotal with your own API key). No vendor lock-in.

## Screenshots

![Scan view — pipeline, presets, and drop zone](docs/images/scan_view.png)
*Scan view: six-engine pipeline with drag-to-reorder, scan-type tabs, custom path drop zone, and per-engine status badges.*

---

## Why PolyShield?

Commercial AV products have telemetry, ad-ware components, and they replace Defender (which is actually pretty good). The open-source AV world has K2, ClamAV, YARA, and a few others — but each is a CLI tool. **PolyShield is the missing UI** that turns these into a coherent product:

- **Five-engine consensus on every scan** — disagree-and-vote rather than trust one verdict
- **Defender stays your primary** — PolyShield doesn't fight it, just adds layers
- **You see exactly what each engine said** — no black-box "Threat detected" without details
- **Dispute resolution** — when engines conflict, you decide; the system remembers your verdict and tracks each engine's false-positive rate over time

## Key features

- 🔬 **6-engine scan pipeline** — K2 / Defender / Guardian AI / YARA / ClamAV / Speakeasy, fully reorderable
- 🛡️ **Windows Service** — `PolyShield Realtime Protection`; survives logout, starts at boot, low-privilege by design
- 🌐 **VirusTotal smart upload** — hash-first lookup; only uploads if no existing record
- ⚖️ **Dispute resolution** — per-engine false-positive tracking + manual override system
- 🎚️ **Sensitivity profiles** — Conservative / Balanced / Power, plus per-pattern toggles
- 🐉 **Behavioral analysis** — optional Speakeasy PE emulation for unknown executables
- 🔐 **Quarantine kept under Defender's watch** — second line of defense by design (not by accident)
- 🚀 **No telemetry, no cloud-by-default, no API keys required**

## Quick start

**Prerequisites**: Windows 10 / 11, Python 3.11+, administrator rights for the Windows Service install.

```powershell
git clone https://github.com/xaerogonzo/Polyshield-Antivirus.git
cd Polyshield-Antivirus
.\scripts\install.bat
```

The installer creates the portable venvs, installs the engines, and offers to register the Windows Service. The UI launches via `launch_ui.vbs` (or `scripts\dev\launch_ui.bat` for a console window).

Full step-by-step install guide, daily workflow, and troubleshooting → **[docs/USAGE.md](docs/USAGE.md)**

## Detection engines

| Engine | What it does | Author |
|---|---|---|
| **K2** (KicomAV) | Signature-based scanner — primary detection layer | Kei Choi — [hanul93/kicomav](https://github.com/hanul93/kicomav) |
| **Defender** | Microsoft Defender via `MpCmdRun.exe` | Microsoft |
| **Guardian AI** | Hash DB + 7 heuristic patterns; tier-aware verdicts | Matt Emilien — [MattEmilien/GuardianAI](https://github.com/MattEmilien/GuardianAI) |
| **YARA** | Rule-based pattern matching | VirusTotal — [yara](https://github.com/VirusTotal/yara) |
| **ClamAV** | Community signature database | Cisco Talos — [clamav](https://github.com/Cisco-Talos/clamav) |
| **Speakeasy** | Pure-Python PE behavioral emulator (optional) | Mandiant — [mandiant/speakeasy](https://github.com/mandiant/speakeasy) |

Full attribution, license info for every dependency, and acknowledgements → **[NOTICES.md](NOTICES.md)**.

## Documentation

| Document | Covers |
|---|---|
| **[docs/USAGE.md](docs/USAGE.md)** | Install, daily workflow, every feature, troubleshooting (long-form reference) |
| **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Internals: scan pipeline, database schema, threading patterns |
| **[docs/WINDOWS_SERVICE.md](docs/WINDOWS_SERVICE.md)** | Windows Service implementation deep-dive |
| **[docs/TESTING.md](docs/TESTING.md)** | Test procedures, EICAR sprint, service-recovery tests |
| **[docs/VM_SETUP.md](docs/VM_SETUP.md)** | Windows 11 VM setup for safe field testing |

## Contributing

Contributions, bug reports, and engine integrations welcome. See **[docs/USAGE.md → Contributing](docs/USAGE.md#contributing--local-development)** for the local dev workflow.

If you spot an attribution issue in [NOTICES.md](NOTICES.md), open an issue or PR — accurate credit matters.

## License

PolyShield is **MIT-licensed** — see [LICENSE](LICENSE). The bundled engines retain their own licenses; full breakdown in [NOTICES.md](NOTICES.md).

---

<sub>Created by Alexander L Corthell. Engines by their respective authors. The architecture and integration are what PolyShield contributes — the detection work is the heroes of the open-source AV world.</sub>
