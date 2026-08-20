"""
PolyShield Realtime Protection -- Windows Service

Usage (from an elevated prompt):
    python polyshield_service.py install    # register with SCM
    python polyshield_service.py start      # start the service
    python polyshield_service.py stop       # stop the service
    python polyshield_service.py remove     # unregister from SCM

The service uses python.exe as the service binary (not pythonservice.exe),
which is the modern pywin32 approach that works correctly with virtual
environments.
"""

import json
import logging
import os
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

# ── Bootstrap: project root + src/ on sys.path ────────────────────────────────
_SVC_DIR = Path(__file__).resolve().parent          # project root
_SVC_SRC = _SVC_DIR / "src"                         # src/ for ui.core.* imports
if str(_SVC_DIR) not in sys.path:
    sys.path.insert(0, str(_SVC_DIR))
if str(_SVC_SRC) not in sys.path:
    sys.path.insert(0, str(_SVC_SRC))

import servicemanager
import win32event
import win32service
import win32serviceutil

# ── Constants ─────────────────────────────────────────────────────────────────
SERVICE_PORT     = 52614
TOKEN_FILE       = Path(r"C:\ProgramData\PolyShield\service_token.txt")
EVENTS_FILE      = _SVC_DIR / "config" / "service_events.json"
LOG_FILE         = Path(r"C:\ProgramData\PolyShield\service.log")
HEARTBEAT_SECS   = 30
_NET_EVENTS_CAP  = 100    # max network events kept in memory
_EVENTS_CAP      = 2000   # max scan/process-threat events kept in memory
_ALLOWED_CONFIG_KEYS = {"watcher_folders", "watcher_auto_quarantine", "watcher_guardian_scan"}

# ── Logging ────────────────────────────────────────────────────────────────────
log = logging.getLogger("PolyShieldService")
log.setLevel(logging.INFO)
if not log.handlers:
    log.addHandler(logging.NullHandler())


def _setup_logging():
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(LOG_FILE), encoding="utf-8")
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        log.addHandler(fh)
    except Exception:
        log.addHandler(logging.StreamHandler())


# ── Token helpers ──────────────────────────────────────────────────────────────

def _load_or_create_token() -> str:
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if TOKEN_FILE.exists():
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    token = str(uuid.uuid4())
    TOKEN_FILE.write_text(token, encoding="utf-8")
    log.info("Generated new service token.")
    return token


# ── Event store ────────────────────────────────────────────────────────────────

def _load_events() -> list:
    try:
        if EVENTS_FILE.exists():
            return json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return []


def _save_events(events: list):
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = EVENTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(events, indent=2), encoding="utf-8")
    os.replace(tmp, EVENTS_FILE)


# ── Windows Service class ──────────────────────────────────────────────────────

class PolyShieldService(win32serviceutil.ServiceFramework):
    _svc_name_         = "PolyShieldService"
    _svc_display_name_ = "PolyShield Realtime Protection"
    _svc_description_  = (
        "Monitors watched folders for malware; "
        "persists when the PolyShield UI is closed."
    )
    # Start automatically with Windows — users should not need to manually
    # start the service after each reboot.
    _svc_start_type_   = win32service.SERVICE_AUTO_START
    # Use venv python.exe directly — works with virtual environments
    _exe_name_  = sys.executable
    _exe_args_  = f'"{_SVC_DIR / "polyshield_service.py"}"'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self._stop_event   = win32event.CreateEvent(None, 0, 0, None)
        self._running      = False
        self._token        = ""
        self._events: list = []
        self._next_id      = 1
        self._start_time   = time.time()

        # Subscriber sockets (persistent SUBSCRIBE connections)
        self._subscribers: set  = set()
        self._subs_lock         = threading.Lock()
        self._new_event_flag    = threading.Event()

        # Events list lock — guards _events and _next_id across watcher/WMI/IPC threads
        self._events_lock       = threading.Lock()

        # Network monitor event ring buffer
        self._net_events: list  = []
        self._net_monitor       = None

        # Process monitor
        self._proc_monitor      = None

        # Intelligence updater (scheduler thread + on-demand runs)
        self._intel_updater     = None
        self._intel_last_result: dict = {}
        # Guards the on-demand worker thread.  Not the real concurrency
        # guarantee — intel_updater's own process/file locks are — but it lets
        # the service answer "already_running" immediately instead of spawning a
        # thread that would only discover the lock and exit.
        self._intel_run_lock    = threading.Lock()

        # Server socket
        self._server_sock: socket.socket | None = None

    # ── SCM callbacks ──────────────────────────────────────────────────────────

    def SvcStop(self):
        log.info("Service stop requested.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass

    def SvcDoRun(self):
        _setup_logging()
        log.info("Service starting.")
        self._running = True

        try:
            self._token  = _load_or_create_token()
            self._events = _load_events()
            if self._events:
                self._next_id = max(e.get("id", 0) for e in self._events) + 1

            self._bind_socket()
            threading.Thread(target=self._accept_loop, daemon=True).start()
            threading.Thread(target=self._heartbeat_loop, daemon=True).start()

            self._maybe_start_watcher()
            self._start_network_monitor()
            self._start_process_monitor()
            self._register_intel_hooks()
            self._start_intel_updater()

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            log.info(f"Service running on port {SERVICE_PORT}.")

            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
        except Exception as exc:
            log.exception(f"Fatal error in SvcDoRun: {exc}")
            servicemanager.LogErrorMsg(f"PolyShield service error: {exc}")
        finally:
            self._shutdown()

    # ── Socket server ──────────────────────────────────────────────────────────

    def _bind_socket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # SO_EXCLUSIVEADDRUSE (Windows-specific, Python 3.6+) prevents a second
        # process from stealing the port even with SO_REUSEADDR — eliminates the
        # stale-process / token-mismatch problem.
        # Use socket.SO_EXCLUSIVEADDRUSE (Python-exported constant with the correct
        # raw value) rather than a hardcoded literal — Windows defines it as
        # ~SO_REUSEADDR which resolves to a value that varies by platform/Python.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        # If not available (very old Python), the default is already exclusive.
        s.bind(("127.0.0.1", SERVICE_PORT))
        s.listen(10)
        self._server_sock = s
        log.info(f"Socket bound to 127.0.0.1:{SERVICE_PORT}")

    def _accept_loop(self):
        while self._running:
            try:
                conn, _ = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_client, args=(conn,), daemon=True
                ).start()
            except OSError:
                break

    def _handle_client(self, conn: socket.socket):
        conn.settimeout(10)
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                buf += chunk

            line = buf.split(b"\n", 1)[0]
            msg = json.loads(line.decode("utf-8"))

            if msg.get("token") != self._token:
                conn.sendall(
                    json.dumps({"ok": False, "error": "unauthorized"}).encode() + b"\n"
                )
                return

            cmd = msg.get("cmd", "")

            if cmd == "PING":
                self._send(conn, {"ok": True, "msg": "PONG"})

            elif cmd == "STATUS":
                self._send(conn, self._build_status())

            elif cmd == "START_WATCHER":
                ok, err = self._start_watcher()
                resp = {"ok": ok, "watcher_running": ok}
                if not ok:
                    resp["error"] = err
                self._send(conn, resp)

            elif cmd == "STOP_WATCHER":
                self._stop_watcher()
                self._send(conn, {"ok": True, "watcher_running": False})

            elif cmd == "GET_EVENTS":
                since = msg.get("since_id", 0)
                with self._events_lock:
                    subset = [e for e in self._events if e.get("id", 0) > since]
                self._send(conn, {"ok": True, "events": subset})

            elif cmd == "CLEAR_EVENTS":
                with self._events_lock:
                    self._events.clear()
                    self._next_id = 1
                    _save_events(self._events)
                self._send(conn, {"ok": True})

            elif cmd == "SET_CONFIG":
                key = msg.get("key")
                if key not in _ALLOWED_CONFIG_KEYS:
                    self._send(conn, {"ok": False, "error": "Key not allowed"})
                    return
                from ui.core import settings as cfg
                cfg.set_value(key, msg.get("value"))
                if key == "watcher_folders":
                    self._restart_watcher()
                self._send(conn, {"ok": True})

            elif cmd == "GET_NETWORK_EVENTS":
                limit  = int(msg.get("limit", 50))
                subset = self._net_events[-limit:]
                self._send(conn, {"ok": True, "events": subset})

            elif cmd == "BLOCK_IP":
                ip = str(msg.get("ip", "")).strip()
                if not ip:
                    self._send(conn, {"ok": False, "error": "ip required"})
                else:
                    ok, err = self._block_ip(ip)
                    self._send(conn, {"ok": ok, "error": err if not ok else ""})

            elif cmd == "SUBSCRIBE":
                self._send(conn, {"ok": True})
                self._run_event_stream(conn)
                return  # _run_event_stream owns conn from here

            elif cmd == "ALLOW_HASH":
                md5 = str(msg.get("md5", "")).strip().lower()
                if md5 and self._proc_monitor is not None:
                    self._proc_monitor.allow_hash(md5)
                self._send(conn, {"ok": True})

            elif cmd == "START_PROCESS_MONITOR":
                if self._proc_monitor is not None:
                    if not self._proc_monitor.is_running():
                        self._proc_monitor.start()
                    self._send(conn, {"ok": True, "process_monitor_running": True})
                else:
                    self._send(conn, {"ok": False, "error": "Process monitor not available"})

            elif cmd == "GET_INTEL_STATUS":
                self._send(conn, self._build_intel_status())

            elif cmd == "RUN_INTEL_UPDATE":
                feeds = msg.get("feeds") or None
                force = bool(msg.get("force", True))
                started, reason = self._start_intel_update(feeds, force)
                self._send(conn, {
                    "ok": True,
                    "status": "started" if started else "already_running",
                    "error": "" if started else reason,
                })

            elif cmd == "STOP_PROCESS_MONITOR":
                if self._proc_monitor is not None:
                    self._proc_monitor.stop()
                self._send(conn, {"ok": True, "process_monitor_running": False})

            else:
                self._send(conn, {"ok": False, "error": f"Unknown command: {cmd}"})

        except (json.JSONDecodeError, OSError, Exception) as exc:
            log.debug(f"Client error: {exc}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _send(conn: socket.socket, data: dict):
        conn.sendall(json.dumps(data).encode() + b"\n")

    # ── Event stream ───────────────────────────────────────────────────────────

    def _run_event_stream(self, conn: socket.socket):
        conn.settimeout(None)
        with self._subs_lock:
            self._subscribers.add(conn)
        try:
            while self._running:
                triggered = self._new_event_flag.wait(timeout=HEARTBEAT_SECS)
                if not self._running:
                    break
                if triggered:
                    self._new_event_flag.clear()
                try:
                    conn.sendall(
                        json.dumps({"event": "heartbeat"}).encode() + b"\n"
                    )
                except OSError:
                    break
        finally:
            with self._subs_lock:
                self._subscribers.discard(conn)
            try:
                conn.close()
            except Exception:
                pass

    def _push_event(self, event: dict):
        """
        Broadcast an event dict to all SUBSCRIBE clients.
        If the event already has an "event" key (e.g. network_event), it is used as-is.
        Scan result events are tagged "scan_result" if no key is present.
        Network events are also buffered in _net_events (ring buffer, cap _NET_EVENTS_CAP).
        """
        event_type = event.get("event", "scan_result")
        payload    = {"event": event_type, **{k: v for k, v in event.items() if k != "event"}}
        line       = json.dumps(payload).encode() + b"\n"

        # Buffer network events for GET_NETWORK_EVENTS polling
        if event_type == "network_event":
            self._net_events.append(payload)
            if len(self._net_events) > _NET_EVENTS_CAP:
                self._net_events = self._net_events[-_NET_EVENTS_CAP:]

        with self._subs_lock:
            dead = set()
            for conn in self._subscribers:
                try:
                    conn.sendall(line)
                except OSError:
                    dead.add(conn)
            self._subscribers -= dead
            for conn in dead:
                try:
                    conn.close()
                except Exception:
                    pass
        self._new_event_flag.set()

    def _heartbeat_loop(self):
        while self._running:
            time.sleep(HEARTBEAT_SECS)
            self._new_event_flag.set()

    # ── Watcher integration ────────────────────────────────────────────────────

    def _maybe_start_watcher(self):
        from ui.core import settings as cfg
        if cfg.get("watcher_enabled") and cfg.get("watcher_folders"):
            self._start_watcher()

    def _start_watcher(self) -> tuple[bool, str]:
        from ui.core import watcher as wtch
        ok = wtch.start(self._service_scan_callback)
        if ok:
            log.info("Watcher started.")
            self._push_watcher_status(running=True)
        else:
            log.warning("Watcher start failed — no valid folders.")
        return ok, "" if ok else "No valid folders configured"

    def _stop_watcher(self):
        from ui.core import watcher as wtch
        wtch.stop()
        log.info("Watcher stopped.")
        self._push_watcher_status(running=False)

    def _restart_watcher(self):
        from ui.core import watcher as wtch
        if wtch.is_running():
            self._stop_watcher()
        self._start_watcher()

    def _service_scan_callback(self, path: str, entry: dict):
        from ui.core import watcher as wtch
        wtch.scan_new_file(path, entry)

        event = {
            "path":     path,
            "filename": Path(path).name,
            "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status":   entry.get("status", "pending"),
            "source":   "k2",
        }
        with self._events_lock:
            event["id"] = self._next_id
            self._next_id += 1
            self._events.append(event)
            if len(self._events) > _EVENTS_CAP:
                self._events = self._events[-_EVENTS_CAP:]
            _save_events(self._events)
        self._push_event(event)

    def _push_watcher_status(self, running: bool):
        line = json.dumps({"event": "watcher_status", "running": running}).encode() + b"\n"
        with self._subs_lock:
            dead = set()
            for conn in self._subscribers:
                try:
                    conn.sendall(line)
                except OSError:
                    dead.add(conn)
            self._subscribers -= dead
            for conn in dead:
                try:
                    conn.close()
                except Exception:
                    pass

    # ── Status helper ──────────────────────────────────────────────────────────

    def _build_status(self) -> dict:
        from ui.core import watcher as wtch
        from ui.core import settings as cfg
        folders = cfg.get("watcher_folders") or []
        return {
            "ok":                     True,
            "watcher_running":        wtch.is_running(),
            "process_monitor_running": (
                self._proc_monitor is not None
                and self._proc_monitor.is_running()
            ),
            "folders_watched":        folders,
            "events_count":           len(self._events),
            "uptime_seconds":         int(time.time() - self._start_time),
            "intel_updater_running":  (self._intel_updater is not None
                                       and self._intel_updater.is_running()),
            "intel_last_run":         cfg.get("intel_last_auto_run") or "",
        }

    # ── Network monitor ───────────────────────────────────────────────────────

    def _start_network_monitor(self):
        try:
            from ui.core.network_monitor import NetworkMonitorThread
            self._net_monitor = NetworkMonitorThread(self._push_event)
            self._net_monitor.start()
            log.info("Network monitor started.")
        except Exception as exc:
            log.warning(f"Network monitor unavailable: {exc}")

    # ── Intelligence updater ──────────────────────────────────────────────────

    def _start_intel_updater(self):
        """Host the scheduled intelligence refresh.

        The service is the designated writer whenever it is running: a UI-side
        run checks ownership and stands down, so this thread is normally the
        only thing refreshing feeds on the machine.
        """
        try:
            from ui.core.intel_updater import IntelUpdaterThread
            self._intel_updater = IntelUpdaterThread(
                push_event=self._push_event, owner="service",
            )
            if self._intel_updater.start():
                log.info("Intelligence updater started.")
            else:
                log.info("Intelligence updater idle (disabled in settings).")
        except Exception as exc:
            log.warning(f"Intelligence updater unavailable: {exc}")

    def _start_intel_update(self, feeds, force: bool) -> tuple[bool, str]:
        """Kick off an on-demand update on a worker thread.

        Enters the same run_updates() the scheduler uses — there is deliberately
        no second code path for manual runs.  Returns (started, reason).
        """
        if not self._intel_run_lock.acquire(blocking=False):
            return False, "an intelligence update is already running"

        def _work():
            try:
                from ui.core.intel_updater import run_updates, build_update_event
                result = run_updates(
                    feeds=feeds, force=force, owner="service",
                    on_progress=lambda m: log.info("  %s", m),
                )
                self._intel_last_result = result
                log.info(f"Intelligence update finished: {result.get('status')}")
                self._push_event(build_update_event(result))
            except Exception as exc:
                log.exception(f"On-demand intelligence update failed: {exc}")
            finally:
                self._intel_run_lock.release()

        threading.Thread(target=_work, daemon=True, name="IntelUpdateOnDemand").start()
        return True, ""

    def _build_intel_status(self) -> dict:
        try:
            from ui.core import intel_updater as iu
            last = self._intel_last_result
            if not last and self._intel_updater is not None:
                last = self._intel_updater.last_result
            return {
                "ok": True,
                "updater_running": (self._intel_updater is not None
                                    and self._intel_updater.is_running()),
                "running_now":     self._intel_run_lock.locked(),
                "feeds":           iu.get_staleness(),
                "last_result":     last or {},
            }
        except Exception as exc:
            log.warning(f"Could not build intel status: {exc}")
            return {"ok": False, "error": str(exc)}

    # ── Intelligence post-update hooks ────────────────────────────────────────

    def _register_intel_hooks(self):
        """Wire this process's in-memory intelligence consumers to the hook registry.

        Must be eager.  The service can run for days without entering
        guardian_engine.scan_async(), which is the only other place the
        Guardian hook gets registered — so without this, a service that never
        scanned a watched file would never see an intelligence update.
        """
        try:
            from ui.core.intel_hooks import register_intel_consumers
            wired = register_intel_consumers()
            log.info(f"Intelligence hooks wired: {', '.join(wired) or 'none'}")
        except Exception as exc:
            log.warning(f"Intelligence hooks not registered: {exc}")

    # ── Process monitor ───────────────────────────────────────────────────────

    def _start_process_monitor(self):
        try:
            from ui.core.process_monitor import ProcessMonitor
            from ui.core import settings as cfg
            poll = int(cfg.get("process_monitor_poll_interval") or 1)
            self._proc_monitor = ProcessMonitor(
                alert_callback=self._on_process_threat,
                poll_interval=poll,
            )
            self._proc_monitor.start()
            log.info("Process monitor started.")
        except Exception as exc:
            log.warning(f"Process monitor unavailable: {exc}")

    def _on_process_threat(
        self, pid: int, name: str, exe_path: str,
        reason: str, alert_level: str,
    ) -> None:
        """
        Called from the ProcessMonitor thread when a threat is detected.

        Pushes a PROCESS_THREAT event to all SUBSCRIBE clients (UI).
        When the UI is closed (no active subscribers), applies the
        process_monitor_ui_closed_action setting:
          "kill_and_quarantine" — kill process tree + quarantine the .exe
          "kill_only"           — kill only; user reviews quarantine on next open
        """
        from ui.core import settings as cfg

        event = {
            "event":    "process_threat",
            "pid":      pid,
            "name":     name,
            "path":     exe_path,
            "reason":   reason,
            "level":    alert_level,
            "time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self._events_lock:
            event["id"] = self._next_id
            self._next_id += 1
            # Persist to events file so UI can show a banner after reconnect
            self._events.append(event)
            if len(self._events) > _EVENTS_CAP:
                self._events = self._events[-_EVENTS_CAP:]
            _save_events(self._events)
        self._push_event(event)

        # If no UI subscriber is connected, take autonomous action
        with self._subs_lock:
            has_ui = bool(self._subscribers)

        if not has_ui:
            action = cfg.get("process_monitor_ui_closed_action") or "kill_and_quarantine"
            self._autonomous_process_action(pid, exe_path, action, event)

    def _autonomous_process_action(
        self, pid: int, exe_path: str, action: str, event: dict
    ) -> None:
        """
        Kill and optionally quarantine a threat process when the UI is closed.

        LocalService has limited kill rights — SYSTEM/PPL processes will raise
        AccessDenied.  The attempt is always made; failures are logged.
        """
        import psutil, time as _time

        killed    = False
        quarantined = False
        alert_level = "warning"

        # ── Kill process tree ──────────────────────────────────────────────────
        try:
            proc     = psutil.Process(pid)
            children = proc.children(recursive=True)
            failed_children = []
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    failed_children.append((child.pid, str(e)))
            try:
                proc.kill()
                psutil.wait_procs([proc], timeout=2)
                killed = True
            except psutil.NoSuchProcess:
                killed = True   # already exited
            except psutil.AccessDenied:
                alert_level = "critical"
                log.warning(
                    "Process monitor: AccessDenied killing PID %d (%s). "
                    "Process may be running as SYSTEM.",
                    pid, exe_path,
                )
            if failed_children:
                alert_level = "critical"
                log.warning(
                    "Process monitor: partial kill — %d child(ren) not killed: %s",
                    len(failed_children), failed_children,
                )
        except psutil.NoSuchProcess:
            killed = True   # process exited before we got to it

        # ── Quarantine ────────────────────────────────────────────────────────
        if action == "kill_and_quarantine" and exe_path:
            _time.sleep(0.15)   # brief pause to let kernel release file locks
            try:
                from ui.core import quarantine as _q
                _q.add_file(exe_path, threat_name=event.get("reason", "Unknown"))
                quarantined = True
                log.info("Process monitor: quarantined %s", exe_path)
            except Exception as exc:
                log.error(
                    "Process monitor: quarantine failed for %s — %s", exe_path, exc
                )

        # Update persisted event with outcome
        event["killed"]      = killed
        event["quarantined"] = quarantined
        event["level"]       = alert_level
        with self._events_lock:
            _save_events(self._events)

        log.warning(
            "Process monitor: autonomous action on PID=%d name=%s "
            "killed=%s quarantined=%s action=%s",
            pid, event.get("name", ""), killed, quarantined, action,
        )

    def _block_ip(self, ip: str) -> tuple[bool, str]:
        """
        Add a Windows Firewall outbound block rule for the given IP and
        record the block in ip_blocklist so the UI shows it immediately.
        Returns (success, error_message).
        Note: LocalService cannot elevate itself to create firewall rules;
        the UI falls back to a direct ShellExecute runas call when this fails.
        """
        import subprocess, sqlite3 as _sqlite3
        from pathlib import Path as _Path
        from datetime import datetime as _dt

        rule_name = f"PolyShield-Block-{ip}"
        ps_cmd = (
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction Outbound -RemoteAddress '{ip}' "
            f"-Action Block -Profile Any -Enabled True"
        )
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", ps_cmd,
                ],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if result.returncode == 0:
                log.info(f"Firewall rule added: block outbound {ip}")
                # Also write to local ip_blocklist so it shows up immediately
                self._record_manual_block(ip)
                return True, ""
            else:
                err = result.stderr.strip() or result.stdout.strip()
                log.warning(f"Firewall rule failed for {ip}: {err}")
                return False, err
        except Exception as exc:
            return False, str(exc)

    @staticmethod
    def _record_manual_block(ip: str):
        """Persist a manually blocked IP in the intelligence DB."""
        import sqlite3 as _sqlite3
        from datetime import datetime as _dt
        db_path = _SVC_DIR / "intelligence" / "threat_db.sqlite"
        if not db_path.exists():
            return
        try:
            con = _sqlite3.connect(str(db_path), timeout=5)
            con.execute(
                "INSERT OR REPLACE INTO ip_blocklist (ip, tags, port, malware, added_ts) "
                "VALUES (?, 'manual_block', 0, '', ?)",
                (ip, _dt.utcnow().isoformat()),
            )
            con.commit()
            con.close()
        except Exception:
            pass

    # ── Shutdown ───────────────────────────────────────────────────────────────

    def _shutdown(self):
        log.info("Shutting down service.")
        try:
            from ui.core import watcher as wtch
            wtch.stop()
        except Exception:
            pass
        if self._net_monitor is not None:
            try:
                self._net_monitor.stop()
            except Exception:
                pass
        if self._proc_monitor is not None:
            try:
                self._proc_monitor.stop()
            except Exception:
                pass
        if self._intel_updater is not None:
            try:
                # stop() sets the event and joins; the loop sleeps in short
                # slices and every feed HTTP call carries a bounded timeout, so
                # this cannot hold up SCM shutdown indefinitely.
                self._intel_updater.stop()
            except Exception:
                pass
        with self._subs_lock:
            for conn in self._subscribers:
                try:
                    conn.close()
                except Exception:
                    pass
            self._subscribers.clear()
        self._running = False
        log.info("Service stopped.")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No args — started by Windows SCM. Use modern venv-compatible entry point.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PolyShieldService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(PolyShieldService)
