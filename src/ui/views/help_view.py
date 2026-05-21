"""
help_view.py
────────────
In-app help panel with collapsible accordion sections.
Plain-English explanations of every major feature — no assumed knowledge.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import customtkinter as ctk
import ui.theme as theme

_CARD  = "#1a1a2e"
_CARD2 = "#12121e"
_BLUE  = "#5294e2"
_DIM   = "#555577"
_TEXT  = "#cdd6f4"
_SUBTEXT = "#888899"

# ── Help content: (key, title, paragraphs) ────────────────────────────────────
_SECTIONS = [
    ("scan_modes", "Scan Modes", [
        ("Quick Scan", "Checks the most common hiding spots for malware — running "
         "processes, Windows startup items, the system drive's root and Windows "
         "directories. Finishes in a minute or two. Good for a fast daily check."),
        ("Smart Scan", "Targeted scan of high-risk locations: every currently running "
         "process, startup items, temp folders, browser extension directories, "
         "PowerShell profile locations, and WindowsApps shims. Deliberately skips "
         "Python/Node/pip caches and other large dev trees that are almost never "
         "malicious. The best everyday balance of speed and coverage."),
        ("Full Scan", "Scans every file on every drive. Thorough but slow — "
         "run overnight or when you suspect something was missed. All engines "
         "in the pipeline run on every file."),
        ("Custom Scan", "Pick exactly which folders or files to scan by dragging "
         "them into the drop zone or using the Browse buttons. You can mix files "
         "and folders freely. Save any custom path set as a named preset (💾 Save) "
         "and reload it in one click from the dropdown — up to 20 presets, "
         "stored across restarts."),
        ("Downloads Folder", "Scans only your Downloads directory — the single "
         "most common malware entry point. Fast and practical after a big download "
         "session or receiving files over email."),
        ("Temp Files", "Scans Windows temporary directories (%TEMP%, %TMP%, "
         "and the system temp folder). Malware frequently unpacks itself here "
         "before executing. Useful after running an installer you weren't sure about."),
        ("Pause & Resume", "Click Pause during any scan to freeze all engines "
         "simultaneously. K2 and ClamAV subprocesses are suspended at the OS level "
         "(NtSuspendProcess) — they don't finish their current file and stop. "
         "Resume continues exactly where each engine left off. You can also cancel "
         "mid-scan and still act on everything found so far."),
    ]),
    ("pipeline", "Scan Pipeline", [
        ("What the pipeline is", "PolyShield runs up to five detection engines "
         "sequentially on each scan: K2, Defender, Guardian AI, YARA, and ClamAV. "
         "Each engine is independent — you can enable or disable any of them, "
         "and reorder them however you like. The pipeline panel is the collapsible "
         "'▼ Scan Pipeline' section below the toolbar in the Scan view."),
        ("Enabling and disabling engines", "Each engine row has a checkbox. "
         "Unchecked engines are skipped entirely — no performance impact. "
         "If an engine isn't installed or available, its row shows a grey "
         "'Not available' badge and stays disabled automatically."),
        ("Reordering engines", "Drag any engine row by its ⠿ handle, or use "
         "the ↑ / ↓ buttons to move it. The order matters: engines earlier in "
         "the list run first. Click ↺ Reset order to restore the default "
         "(K2 → Defender → Guardian AI → YARA → ClamAV). Speakeasy always "
         "runs last as a final behavioral stage."),
        ("What each engine is best at", "K2: fast, reliable signature detection "
         "for known malware families. Defender: Microsoft's threat intel, good "
         "on newly-circulating threats. Guardian AI: catches malware with no "
         "known signature via hash DB and heuristic patterns. YARA: custom rules "
         "you write yourself. ClamAV: broad community-maintained signature library "
         "as a final sweep."),
        ("Recommended configurations", "For most users: K2 + Guardian AI is "
         "sufficient — two complementary approaches with minimal overhead. "
         "Add Defender for broader coverage. Add ClamAV for maximum breadth "
         "at the cost of scan time. YARA is for advanced users with specific "
         "detection targets."),
    ]),
    ("engines", "Detection Engines", [
        ("k2 Engine", "The core signature-based scanner. Matches files against a "
         "database of known malware patterns. Fast and reliable for known threats. "
         "Update signatures via Update Center → K2 Engine Signatures. Results "
         "appear in red in the scan log."),
        ("Windows Defender", "Calls MpCmdRun.exe to run Microsoft Defender's inline "
         "scan on the target files. Uses Microsoft's constantly-updated cloud threat "
         "intelligence. Good at catching newly-circulating threats that haven't made "
         "it into k2's signature DB yet. Results appear in orange."),
        ("Guardian AI", "A second-opinion engine using hash matching and heuristic "
         "pattern analysis. Hash-based detections (file is a known-bad MD5) appear "
         "as red 'Confirmed' results. Heuristic pattern matches appear as amber "
         "'Suspicious' results and are hidden by default — click the 'Suspicious (N)' "
         "filter chip to review them. See 'Guardian AI — How It Works' below for "
         "details on sensitivity profiles, circuit breaker, and per-pattern controls."),
        ("YARA Rules", "A pattern rule engine for advanced users. Drop .yar files "
         "into the rules folder (Settings → YARA → Open Rules Folder) and they run "
         "automatically on every scan. YARA rules describe exact byte patterns, "
         "strings, or code structures — useful for hunting specific malware families "
         "or custom scripts. Results appear in purple."),
        ("ClamAV", "An open-source engine backed by millions of community-maintained "
         "signatures. Catches threats the other engines may miss, especially "
         "document-embedded macros and email-borne malware. Requires a separate "
         "install (clamav.net) — see Settings → ClamAV for the download link "
         "and path configuration. Results appear in cyan."),
        ("VirusTotal", "Sends a file's fingerprint (hash) to VirusTotal's cloud "
         "service, checked against 70+ antivirus engines simultaneously. Requires "
         "a free API key (virustotal.com). By default only the hash is sent — no "
         "file content leaves your machine unless you configure Smart Upload to "
         "upload unknowns. See 'VirusTotal' in this Help section for setup details."),
    ]),
    ("guardian_ai", "Guardian AI — How It Works", [
        ("The four detection tiers", "Guardian AI runs every file through up to four "
         "layers of analysis, stopping as soon as it reaches a verdict. Each tier "
         "adds coverage at the cost of a little more time:\n"
         "  1. NSRL allow-list — if the file is a known-safe system file, skip it instantly.\n"
         "  2. RAM hash set — check against a compact list of known-bad MD5s loaded in memory.\n"
         "  3. SQLite signature lookup — a richer database that also returns malware family "
         "names and detection counts.\n"
         "  4. Heuristic patterns — seven regex patterns that scan the file's content for "
         "suspicious strings (encoded PowerShell, Mimikatz, ransomware notes, etc.).\n"
         "Tiers 1–3 are high-confidence (hash-based). Tier 4 catches zero-day and fileless "
         "threats but produces more false positives — which is why sensitivity profiles exist."),

        ("Conservative profile (default)", "The two noisiest patterns — "
         "'Ransomware note (files encrypted)' and 'Ransomware payment demand' — are "
         "turned off. All remaining pattern matches are treated as 'Suspicious' (shown in "
         "amber) rather than 'Confirmed' (red), and they are hidden by default in the "
         "Threat Actions panel. You only see them when you click the 'Suspicious (N)' "
         "filter chip. Hash-based detections (tiers 2–3) are always shown as Confirmed "
         "regardless of profile. This is the right choice for everyday use: low noise, "
         "high-confidence results front and centre."),

        ("Balanced profile", "All seven patterns are active. Matches are still shown as "
         "'Suspicious' (amber) — they are never automatically quarantined or treated as "
         "confirmed threats. Use this if you want full pattern coverage and are comfortable "
         "reviewing a potentially longer list of heuristic findings after each scan."),

        ("Power profile", "All seven patterns active, and pattern matches carry the same "
         "'Confirmed' (red) weight as a hash detection. This restores the pre-v1.10 "
         "behavior. Intended for security researchers who are deliberately studying "
         "false-positive rates. A warning is shown when you switch to this profile — "
         "expect more noise on legitimate security documentation, recovery guides, "
         "and AV tool log files."),

        ("Per-pattern toggles & statistics", "Open Settings → Guardian AI → "
         "Advanced Guardian Settings to enable or disable any of the seven individual "
         "patterns. Next to each pattern you will see a lifetime detection count and "
         "a false-positive rate — the percentage of detections where you later added "
         "the matched file to the ignore list. A pattern at 90–100% FP rate is a strong "
         "signal to disable it for your environment. You can also click 'Reset to profile "
         "defaults' to undo any manual changes and go back to the current profile's "
         "built-in settings."),

        ("Why was this flagged? (Match Context)", "When a file is flagged by a "
         "heuristic pattern, the detail pane shows a 'Why was this flagged?' block: "
         "the pattern name in amber, and a ~160-character snippet of the file's content "
         "centred on the exact text that triggered the match. This lets you evaluate "
         "the detection in seconds — if the snippet is clearly from a help document or "
         "a legitimate script, you can add the file to the ignore list immediately. "
         "Hash-based detections do not show this block because the file hash is already "
         "the full explanation."),

        ("Consensus badge", "The file detail pane shows how many engines flagged the "
         "same file. When only Guardian's pattern tier fired and K2 + ClamAV both said "
         "clean, the badge reads '⚠ Single-engine heuristic — likely false positive'. "
         "This is statistically the highest-FP scenario (>99% false positive rate when "
         "hash engines disagree). When multiple engines agree, the badge updates to "
         "'Confirmed by N engines' or '🛡 Confirmed by N engines — high confidence'. "
         "The badge is informational only — it does not block any action."),

        ("Circuit breaker", "If Guardian's pattern tier produces more matches than a "
         "configured threshold in a single scan (default: 200), it automatically "
         "disables the pattern tier for the rest of that scan. Hash tiers 1–3 keep "
         "running normally. A prominent red banner appears in the scan view when this "
         "trips, with a button to open Guardian settings. This prevents one noisy scan "
         "from flooding the Threat Actions panel. The threshold (including '0 = off') "
         "is adjustable in Advanced Guardian Settings."),

        ("Ignore list & auto-ignore prompt", "Any file you mark as a false positive "
         "is fingerprinted (MD5) and added to the ignore list. On every future scan "
         "Guardian checks the list before running any tier — if the file is there, "
         "it is skipped entirely. If you ignore three or more files matching the same "
         "pattern in a single scan session, Guardian offers to disable that pattern "
         "automatically. Manage all ignored files in Settings → Guardian AI → Manage…."),

        ("Real-time watcher and patterns", "When the Watcher monitors a folder for "
         "new files, Guardian's pattern tier is OFF by default. The reason: patterns "
         "fire on every new file in Downloads, Desktop, and USB mounts — a false "
         "positive rate that is tolerable in a manual scan becomes overwhelming in "
         "real-time mode. Hash tiers 2–3 still run. You can re-enable patterns for "
         "the watcher in Advanced Guardian Settings → 'Run heuristic patterns at "
         "real-time scanner speed' — useful if you are actively testing heuristic "
         "coverage on a controlled folder."),
    ]),

    ("threat_actions", "Threat Actions Panel", [
        ("What it is", "After any scan that finds threats, a master-detail panel "
         "appears below the scan log. The left side lists every flagged file; the "
         "right side shows details for the selected file and action buttons. "
         "Files stay in their original locations until you explicitly act — "
         "nothing is moved or deleted automatically (unless Auto-quarantine is on)."),
        ("Filter chips", "At the top of the list are filter chips: All, K2, "
         "Guardian, Defender, YARA, ClamAV, and Suspicious. Clicking a chip "
         "filters to only that engine's detections. The Suspicious chip reveals "
         "Guardian's amber heuristic matches, which are hidden from the default "
         "view to keep the list focused on high-confidence results."),
        ("Quarantine", "Moves the file to a locked quarantine folder where it "
         "cannot run. The original path is saved — you can restore it later. "
         "Use for anything you're confident is malicious."),
        ("Ignore (false positive)", "Fingerprints the file (MD5) and adds it to "
         "the ignore list so Guardian skips it on every future scan. Opens a "
         "small dialog so you can add a note. Use for legitimate files incorrectly "
         "flagged by the heuristic engine. Manage all ignored files in "
         "Settings → Guardian AI → Manage Ignored Hashes."),
        ("VirusTotal", "Sends the file's fingerprint to VirusTotal for a second "
         "opinion from 70+ engines simultaneously. Useful when you're unsure "
         "whether a detection is real or a false positive."),
        ("Analyze", "Opens the file in Behavioral Analysis so you can run "
         "Stage 4 (Speakeasy emulation) or Stage 5 (Sandboxie detonation) "
         "before deciding what to do. Use this for high-stakes files where "
         "you want to see what the file actually does."),
        ("Bulk actions", "Check the checkbox on any row (or Shift-click for "
         "a range) to select multiple files. A footer bar appears with "
         "Quarantine Selected and Ignore Selected buttons. Select All / "
         "Deselect All buttons appear in the header when at least one file "
         "is checked. A progress bar shows bulk action progress."),
        ("Keyboard shortcuts", "↑ / ↓ arrows move between files in the list. "
         "Space toggles the checkbox on the highlighted file. "
         "Enter triggers the primary action (Quarantine) on the selected file."),
        ("Detail pane", "Selecting a file expands the right panel showing: "
         "full file path, file size and MD5/SHA-256 hashes (computed in the "
         "background), which engines flagged it, the consensus badge (how "
         "many engines agree), and — for Guardian pattern matches — a 'Why "
         "was this flagged?' block showing the exact text that triggered the "
         "detection. Disputed files show an additional Dispute Mode block "
         "with Trust K2 / Trust Guardian options."),
    ]),
    ("disputes", "Disputes — When Engines Disagree", [
        ("What a dispute is", "If k2 flags a file as malicious but Guardian AI "
         "says it's clean (or vice versa), PolyShield marks the file in the Threat "
         "Actions panel for review instead of acting automatically. This is "
         "intentional — neither engine is perfect, and you get to make the final "
         "call. Select the disputed file and look for the Dispute Mode block in "
         "the detail pane on the right."),
        ("Your options", "✓ Trust K2: accept k2's verdict and quarantine the file. "
         "⚠ Trust Guardian: accept Guardian's verdict and leave the file alone. "
         "VirusTotal: send the file's fingerprint to 70+ cloud engines for a third "
         "opinion before deciding. Analyze: open the file in the Behavioral Analysis "
         "view to run emulation or sandbox testing."),
        ("Why engines disagree", "Signature-based engines (k2) sometimes flag "
         "files that share byte patterns with malware but aren't actually harmful "
         "(false positives). Heuristic engines (Guardian AI) may miss threats "
         "that don't match known patterns. Disagreements are most common with "
         "packed installers, cracks, and custom scripts."),
    ]),
    ("quarantine", "Quarantine", [
        ("What quarantine does", "Quarantined files are moved to a protected "
         "folder inside the PolyShield directory. The file is renamed so it "
         "cannot be executed, and its original path, detection engine, and "
         "reason are saved in a metadata file alongside it."),
        ("Restoring a file", "Open the Quarantine view, find the file, and click "
         "Restore. The file moves back to its original location exactly. "
         "Only restore files you're confident are safe — for example, after "
         "confirming a false positive via VirusTotal or Behavioral Analysis."),
        ("VirusTotal check from quarantine", "Each quarantined entry has a VT "
         "button that hash-checks the file against VirusTotal without restoring "
         "it. The result appears inline: '47/72 ⚠' (likely malicious) or "
         "'0/72 ✓' (all engines say clean). Useful for a second opinion before "
         "deciding whether to restore or permanently delete."),
        ("Deleting permanently", "Click Delete on a quarantined file to remove "
         "it from disk entirely — irreversible. Use only when you're confident "
         "the file is malicious and you don't need it back."),
        ("Bulk actions", "Use the checkbox on each row to select files, or "
         "click Select All. Then click Restore Selected or Delete Selected — "
         "you see a list of all affected files and must confirm once before "
         "the batch runs. Useful for clearing many false positives at once."),
    ]),
    ("watcher", "Real-Time Watcher", [
        ("What it does", "The Watcher monitors one or more folders and scans "
         "every new file the moment it appears — downloads, USB transfers, email "
         "attachments saved to disk, anything written by another program. "
         "Threats are flagged immediately rather than waiting for your next "
         "manual scan."),
        ("Adding folders", "Open the Watcher view and click Add Folder. "
         "You can monitor as many folders as you like. Common choices: "
         "Downloads, Desktop, a USB-mapped drive, or a shared network folder. "
         "Remove a folder by selecting it and clicking Remove."),
        ("In-process mode", "When the Watcher runs inside the PolyShield UI, "
         "monitoring stops when you close the app. Fine for most users — "
         "just leave PolyShield minimized to the tray."),
        ("Service mode", "When the PolyShield Service is installed, the Watcher "
         "runs inside the background service and keeps monitoring after you close "
         "the UI — just like a commercial antivirus. The Watcher view shows a "
         "'Service mode' badge when connected to the service. Install the service "
         "from the Service view (one-time UAC prompt)."),
        ("Auto-quarantine", "When enabled in Watcher Options, any file the "
         "Watcher flags is moved to quarantine automatically with no prompt. "
         "Off by default — enable only if you're comfortable with automatic "
         "action. A threat event entry is still created for review."),
        ("Guardian AI and real-time scanning", "Guardian's pattern tier (the "
         "heuristic regex patterns) is disabled for the Watcher by default. "
         "Hash-based detection still runs. This prevents the pattern engine "
         "from generating too many false positives on every file that lands "
         "in Downloads. You can re-enable patterns for the Watcher in "
         "Settings → Guardian AI → Advanced → Watcher pattern scanning."),
    ]),
    ("behavioral", "Behavioral Analysis", [
        ("Stage 4 — Behavioral Trace (Speakeasy)", "Speakeasy is a pure-Python "
         "Windows PE emulator by Mandiant. It runs the file inside a simulated "
         "Windows environment and records everything it tries to do — without "
         "ever executing it on your real OS. Safe to run on any machine with no "
         "setup beyond the initial install. Load a file and click Emulate."),
        ("API Calls tab", "Shows every Windows API call the file made during "
         "emulation. Dangerous calls — process injection, privilege escalation, "
         "shadow copy deletion — are highlighted in red. This is the most "
         "detailed view of what the file actually does at a code level."),
        ("Network tab", "URLs, domains, and IP addresses the file tried to reach "
         "during emulation. Hardcoded C2 addresses, suspicious TLDs, and "
         "raw-IP connections are the main things to look for."),
        ("Registry tab", "Registry keys the file tried to read or write. "
         "Persistence locations (HKCU\\Run, HKLM\\Run, scheduled task keys) "
         "and sensitive areas (SAM, LSA secrets) are highlighted in red."),
        ("File Ops tab", "Files the file tried to create, modify, rename, or "
         "delete. Malware frequently drops payloads in %TEMP%, writes to "
         "startup folders, or tries to delete shadow copies and backups."),
        ("Indicators tab", "A summary of the most suspicious behaviors detected "
         "during emulation, automatically categorized: Persistence, Injection, "
         "Network, Encryption, Anti-analysis. The indicator count in the toolbar "
         "updates in real time as emulation runs."),
        ("Stage 5 — Sandbox Test (Sandboxie-Plus)", "Sandboxie-Plus runs the "
         "file for real — it actually executes — inside an isolated glass box. "
         "Every file system write, registry change, and network connection is "
         "trapped inside the box and never touches your real OS. When done, "
         "click Wipe Sandbox to discard everything. Requires Sandboxie-Plus to "
         "be installed and configured in Settings → Behavioral Analysis."),
        ("Which should I use?", "Stage 4 (Emulate) first — it's always safe, "
         "requires no sandbox setup, and gives the detailed API trace. Use "
         "Stage 5 (Detonate) when you need to see full runtime behavior or "
         "when the file is packed/obfuscated in a way the emulator doesn't "
         "handle perfectly (e.g. custom unpackers, heavy anti-emulation)."),
        ("Loading a file", "Drag a file into the drop zone, click Browse File, "
         "or use the Analyze button in the Threat Actions panel to pre-load a "
         "flagged file directly."),
    ]),
    ("network_monitor", "Network Monitor", [
        ("What it shows", "The Network view displays all active outbound TCP "
         "connections from every process on your machine, updated live. "
         "Each row shows: the process name, remote IP and port, connection "
         "state, and a status badge (clean / C2 hit / unsigned)."),
        ("C2 IP detection", "When a connection's remote IP matches an entry "
         "in the C2 blocklist (imported from Feodo Tracker and ThreatFox), "
         "the row turns red and an alert is added to the Recent Alerts log. "
         "Keep the C2 blocklist updated via Update Center → C2 Blocklist."),
        ("Unsigned process flag", "Connections from processes whose executable "
         "is not digitally signed are flagged in amber. Legitimate software "
         "(browsers, Steam, Discord) is almost always signed — an unsigned "
         "process phoning home to an external IP is worth investigating."),
        ("Blocking an IP", "Click the Block button on any row to add a Windows "
         "Firewall outbound block rule for that IP, named 'PolyShield-Block-{ip}'. "
         "The button turns red and the connection will be refused from that "
         "point on. Note: blocking requires the app to be running elevated, "
         "or the Service to be installed."),
        ("Recent Alerts", "The alert log below the connections table records "
         "every C2 hit and unsigned-outbound event, with timestamps and process "
         "details. The log persists across navigation but resets when the app "
         "restarts. Use it to review what happened during a scan session."),
        ("Service mode", "When the PolyShield Service is running, the network "
         "monitor runs continuously in the background. When running in-process, "
         "it only monitors while the Network view is open."),
    ]),
    ("process_monitor", "Process Monitor", [
        ("What it does", "The Process Monitor view watches for new processes "
         "being created on your system using WMI (Windows Management "
         "Instrumentation) event subscriptions. Within about one second of any "
         "new executable launching, its file path is hashed (MD5) and checked "
         "against the local threat intelligence database."),
        ("When a match is found", "If the new process matches a known-malicious "
         "hash, it appears in the Processes view with a red alert badge. "
         "If the Windows Service is running, the service automatically kills "
         "the process and moves the executable to quarantine — no user action "
         "needed. If running in-process (no service), it flags the event "
         "for you to review but does not auto-act."),
        ("What the table shows", "Each row in the Processes view shows: "
         "process name, PID, executable path, hash match result, and timestamp. "
         "Known-safe files (NSRL allow-list) are silently skipped and not "
         "shown. Only unknown and flagged processes appear."),
        ("Service vs in-process", "Without the service, monitoring stops when "
         "you close PolyShield. With the service installed, monitoring runs "
         "24/7 and autonomous quarantine is active. This is the main reason "
         "to install the service on a machine you're actively protecting."),
    ]),
    ("scheduler", "Scheduler", [
        ("What it does", "The Scheduler view creates Windows Task Scheduler "
         "jobs that run PolyShield scans automatically — daily or weekly — "
         "without you needing to open the app. Scans run silently in the "
         "background and save results to the scan history."),
        ("Creating a task", "Click Create Task, choose a scan type (Quick, "
         "Smart, Full, Downloads, or Temp), set a frequency (Daily or Weekly), "
         "and pick a time. PolyShield creates a Windows scheduled task named "
         "'PolyShield_ScheduledScan'. Only one task exists at a time — "
         "creating a new one replaces the previous."),
        ("Run Now", "Click Run Now to trigger the scheduled task immediately "
         "without waiting for the scheduled time. Useful to verify the task "
         "is working correctly."),
        ("How scheduled scans work", "When the task fires, Windows launches "
         "scheduled_scan.py using the kicomav_env Python environment. The scan "
         "runs headlessly using whichever engines you had enabled last time you "
         "used the Scan view, and saves a timestamped JSON report to the logs "
         "folder. Open History to review results."),
        ("Deleting the task", "Click Delete Task to remove the scheduled task "
         "from Windows Task Scheduler entirely. PolyShield's files are unaffected."),
    ]),
    ("virustotal", "VirusTotal", [
        ("What it is", "VirusTotal is a free cloud service owned by Google that "
         "checks files and hashes against 70+ antivirus engines simultaneously. "
         "PolyShield integrates with its API for hash lookups and optional "
         "file uploads."),
        ("Getting an API key", "Go to virustotal.com, create a free account, "
         "and copy your API key from your profile page. Paste it into "
         "Settings → VirusTotal → API Key. The free tier allows 4 requests "
         "per minute and 500 requests per day — more than enough for "
         "manual verification use."),
        ("Privacy — what gets sent", "By default, only the file's SHA-256 "
         "hash is sent to VirusTotal. No file content ever leaves your machine "
         "unless you explicitly enable a Smart Upload setting. The hash alone "
         "is enough to check known files in the VT database."),
        ("Smart Upload", "In Settings → VirusTotal you can configure automatic "
         "uploads after a scan. 'Pattern matches & unknowns' uploads files "
         "that Guardian's pattern engine flagged (where certainty is lower) "
         "plus truly unknown files not in the VT database. 'Both engines only' "
         "is more conservative — only uploads files that both K2 and Guardian "
         "agreed are malicious. Off = no automatic uploads, only manual lookups."),
        ("Lookup vs upload", "The VirusTotal view and Threat Actions 'VT' button "
         "always do a hash lookup first — no upload. If the file isn't in the "
         "VT database and Smart Upload is configured, a follow-up upload is made. "
         "You can also drag any file into the VirusTotal view for a direct lookup."),
    ]),
    ("winsec", "Windows Security Score", [
        ("What the score means", "The Security Score (0–100) is a composite of "
         "five Windows security categories: Firewall & Network Protection, "
         "Device Security, Account Protection, App & Browser Control, and "
         "System Health. Each category contributes a weighted portion. "
         "It supplements — but does not replace — Windows Security Center."),
        ("Firewall & Network Protection (20 pts)", "Checks whether the Windows "
         "Firewall is active on all profiles (Domain, Private, Public) and "
         "whether unusual outbound rules are present. Unsigned processes with "
         "external connections count against this score."),
        ("Device Security (20 pts)", "Checks Secure Boot status, TPM presence "
         "and version, Virtualization Based Security (VBS), and kernel DMA "
         "protection. These are hardware-level protections against firmware "
         "and boot-level attacks. Requires admin to read — shows 'Unknown' "
         "if the app isn't elevated."),
        ("Account Protection (15 pts)", "Checks for local accounts without "
         "passwords, whether Windows Hello is configured, and UAC settings. "
         "A passwordless local account is a full compromise if someone gets "
         "physical access."),
        ("App & Browser Control (15 pts)", "Checks SmartScreen status for "
         "apps, Edge/IE, and file downloads separately. Also checks whether "
         "Controlled Folder Access is enabled (ransomware protection)."),
        ("System Health (5 pts)", "Checks Windows Update status and whether "
         "there are any pending critical updates. Out-of-date systems are "
         "the most common attack vector in enterprise environments."),
        ("Why your score might be lower than expected", "The score checks for "
         "hardening settings Windows doesn't show prominently — Secure Boot, "
         "TPM version, passwordless accounts, per-context SmartScreen. "
         "A score of 70–80 is typical on a normal consumer Windows 11 machine. "
         "Anything above 85 is well-hardened."),
        ("Open → links", "Each section has an Open → button that deep-links "
         "directly to the relevant Windows Settings page or management console, "
         "so you can address issues without navigating through menus."),
    ]),
    ("update_center", "Update Center", [
        ("K2 Engine Signatures", "Downloads the latest k2.exe virus signature "
         "database. These are the patterns k2 matches files against. Update "
         "regularly — at least weekly if you scan frequently. The date of the "
         "last successful update is shown next to the button."),
        ("Guardian AI Engine", "Pulls the latest Guardian AI scanner code from "
         "its GitHub repository (git pull on the guardianai/ clone). Updates "
         "the heuristic patterns and hash matching logic. Only needed when "
         "Kei Choi releases a new version — check the date shown."),
        ("Local Intelligence Database", "Two options: 'MalwareBazaar Recent (24h)' "
         "downloads only the last 24 hours of newly-identified malware MD5s — "
         "fast and lightweight, good for daily updates. 'Full MD5 List' downloads "
         "the complete MalwareBazaar corpus — thorough but adds 5–15 seconds to "
         "Guardian scan time. Use Clear DB to reset before switching from Full "
         "to Recent."),
        ("NSRL Import", "Imports the NIST National Software Reference Library "
         "— a list of hashes for known-safe, legitimate software. Importing it "
         "reduces Guardian false positives because Windows system files, common "
         "applications, and game files are instantly recognized as clean. "
         "Takes a few minutes the first time; subsequent updates are incremental."),
        ("Speakeasy Emulator", "Checks PyPI for the latest version of the "
         "speakeasy-emulator package and optionally runs a pip upgrade. "
         "Shows installed vs. latest version. Update when a new version is "
         "available to get the latest emulation improvements from Mandiant."),
        ("C2 Blocklist", "Downloads the Feodo Tracker botnet C2 IP list and "
         "ThreatFox recent C2 infrastructure feed from abuse.ch, merges and "
         "deduplicates them, and imports ~400–600 active C2 IPs into the "
         "threat database. The Network Monitor uses this list in real time. "
         "Update daily — C2 infrastructure changes frequently."),
        ("Update All", "Runs K2 Signatures → Guardian AI → Intelligence DB "
         "(recent) → Speakeasy → C2 Blocklist in sequence. Sandboxie-Plus "
         "is excluded (manual download required). Takes 1–3 minutes. "
         "Recommended as a daily or weekly maintenance step."),
    ]),
]


class HelpView(ctk.CTkScrollableFrame):
    def __init__(self, master, status_callback, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._status_cb = status_callback
        self._open: dict[str, bool] = {key: False for key, _, __ in _SECTIONS}
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 8))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(hdr, text="Help & Feature Guide",
                     font=theme.get("heading")).grid(
            row=0, column=0, sticky="w")

        ctk.CTkLabel(hdr,
                     text="Click any section to expand it.  ·  Full technical docs: docs/ folder or GitHub ↗",
                     font=ctk.CTkFont(size=12), text_color=_SUBTEXT, anchor="w").grid(
            row=1, column=0, sticky="w", pady=(2, 0))

        ctk.CTkButton(
            hdr, text="📄 Full Docs", width=120,
            fg_color="#3a3a4a", hover_color="#4a4a5a",
            command=self._open_readme,
        ).grid(row=0, column=1, padx=(12, 0))

        # Accordion sections
        self._cards: dict[str, dict] = {}
        for i, (key, title, _items) in enumerate(_SECTIONS):
            card, detail = self._make_card(row=i + 1, key=key, title=title, items=_items)
            self._cards[key] = {"card": card, "detail": detail}

    def _make_card(self, row: int, key: str, title: str, items: list):
        outer = ctk.CTkFrame(self, corner_radius=10, fg_color=_CARD)
        outer.grid(row=row, column=0, sticky="ew", padx=24, pady=(0, 6))
        outer.grid_columnconfigure(0, weight=1)

        # Clickable header row
        hdr = ctk.CTkFrame(outer, fg_color="transparent", cursor="hand2")
        hdr.grid(row=0, column=0, sticky="ew", padx=14, pady=10)
        hdr.grid_columnconfigure(0, weight=1)
        hdr.bind("<Button-1>", lambda e, k=key: self._toggle(k))

        title_lbl = ctk.CTkLabel(
            hdr, text=title, font=theme.get("section_title"),
            text_color=_BLUE, anchor="w", cursor="hand2")
        title_lbl.grid(row=0, column=0, sticky="w")
        title_lbl.bind("<Button-1>", lambda e, k=key: self._toggle(k))

        chevron = ctk.CTkLabel(
            hdr, text="▶", font=ctk.CTkFont(size=10),
            text_color=_DIM, cursor="hand2")
        chevron.grid(row=0, column=1, padx=(8, 0))
        chevron.bind("<Button-1>", lambda e, k=key: self._toggle(k))
        outer._chevron = chevron  # type: ignore[attr-defined]

        # Detail area (hidden initially)
        detail = ctk.CTkFrame(outer, fg_color=_CARD2, corner_radius=6)
        detail.grid_columnconfigure(0, weight=1)

        for j, (subtitle, body) in enumerate(items):
            item_frame = ctk.CTkFrame(detail, fg_color="transparent")
            item_frame.grid(row=j, column=0, sticky="ew",
                            padx=14, pady=(10 if j == 0 else 2, 2 if j < len(items) - 1 else 10))
            item_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(item_frame, text=subtitle,
                         font=theme.get("item_title"),
                         text_color=_TEXT, anchor="w").grid(
                row=0, column=0, sticky="w")
            ctk.CTkLabel(item_frame, text=body,
                         font=theme.get("body"), text_color=_SUBTEXT,
                         anchor="w", justify="left", wraplength=680).grid(
                row=1, column=0, sticky="ew", pady=(2, 0))

        return outer, detail

    # ── Toggle ────────────────────────────────────────────────────────────────

    def _toggle(self, key: str):
        self._open[key] = not self._open.get(key, False)
        entry = self._cards[key]
        chevron = entry["card"]._chevron  # type: ignore[attr-defined]
        detail = entry["detail"]

        if self._open[key]:
            chevron.configure(text="▼")
            detail.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        else:
            chevron.configure(text="▶")
            detail.grid_remove()

    # ── README opener ─────────────────────────────────────────────────────────

    def _open_readme(self):
        """Open the full PolyShield documentation from the docs/ folder.

        Resolution order:
          1. docs/README.md        — primary target (full readme moved here)
          2. docs/USAGE.md         — detailed usage guide fallback
          3. GitHub docs URL       — always works; opens in the default browser
        """
        root = Path(__file__).resolve().parents[3]
        for candidate in (
            root / "docs" / "README.md",
            root / "docs" / "USAGE.md",
        ):
            if candidate.exists():
                try:
                    os.startfile(str(candidate))
                    return
                except Exception:
                    pass

        # Final fallback: open the GitHub docs tree in the browser
        try:
            import webbrowser
            webbrowser.open(
                "https://github.com/xaerogonzo/Polyshield-Antivirus/tree/main/docs"
            )
        except Exception:
            self._status_cb("Could not open docs — visit github.com/xaerogonzo/Polyshield-Antivirus")
