"""
Native log collection from Windows Event Log and Linux auditd.
Linux fallback uses journalctl (Kali does not ship /var/log/syslog).
"""

import platform
import re
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from .config import (
    WINDOWS_HIGH_RISK_EVENT_IDS,
    LINUX_HIGH_RISK_AUDIT_TYPES,
)


class Collector:
    def __init__(self):
        self.os_type = platform.system()

    def collect(self, minutes_back: int = 5) -> List[Dict[str, Any]]:
        if self.os_type == "Windows":
            return self._collect_windows(minutes_back)
        if self.os_type == "Linux":
            logs = self._collect_auditd(minutes_back)
            if logs:
                return logs
            return self._collect_journalctl(minutes_back)
        return []

    # ─── Windows ──────────────────────────────────────────
    def _collect_windows(self, minutes_back: int) -> List[Dict[str, Any]]:
        try:
            import win32evtlog  # type: ignore
            import win32evtlogutil  # type: ignore
        except ImportError:
            print("pywin32 not installed; cannot read Windows Event Log")
            return []

        logs: List[Dict[str, Any]] = []
        threshold = datetime.now(timezone.utc) - timedelta(minutes=minutes_back)

        handle = win32evtlog.OpenEventLog("localhost", "Security")
        flags = (
            win32evtlog.EVENTLOG_BACKWARDS_READ
            | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )

        try:
            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for evt in events:
                    evt_time = datetime.fromtimestamp(
                        evt.TimeGenerated, tz=timezone.utc
                    )
                    if evt_time < threshold:
                        continue
                    if evt.EventID not in WINDOWS_HIGH_RISK_EVENT_IDS:
                        continue
                    try:
                        message = win32evtlogutil.SafeFormatMessage(evt, "Security")
                    except Exception:
                        message = f"Event ID {evt.EventID}"
                    logs.append({
                        "timestamp": evt_time.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        "event_type": f"windows_{evt.EventID}",
                        "source": "windows_security",
                        "content": message,
                    })
        finally:
            win32evtlog.CloseEventLog(handle)

        return logs

    # ─── Linux: auditd ────────────────────────────────────
    def _collect_auditd(self, minutes_back: int) -> List[Dict[str, Any]]:
        """
        ausearch requires a proper start date. We compute it from the current time.
        """
        # ausearch accepts: 'today', 'recent', 'boot', or 'MM/DD/YYYY HH:MM:SS'
        start_dt = datetime.now() - timedelta(minutes=minutes_back)
        start_str = start_dt.strftime("%m/%d/%Y %H:%M:%S")

        try:
            result = subprocess.run(
                ["ausearch", "--start", start_str],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0 or not result.stdout:
            return []

        logs: List[Dict[str, Any]] = []
        wanted = {t.upper() for t in LINUX_HIGH_RISK_AUDIT_TYPES}

        for line in result.stdout.splitlines():
            m = re.search(r"type=(\w+).*msg=audit\(([\d.]+):\d+\)", line)
            if not m:
                continue
            atype, ts = m.group(1), float(m.group(2))
            if atype.upper() not in wanted:
                continue
            ts_str = (
                datetime.fromtimestamp(ts, tz=timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
            logs.append({
                "timestamp": ts_str,
                "event_type": f"audit_{atype}",
                "source": "linux_auditd",
                "content": line.strip(),
            })
        return logs

    # ─── Linux: journalctl fallback ───────────────────────
    def _collect_journalctl(self, minutes_back: int) -> List[Dict[str, Any]]:
        """
        Read recent syslog/SSH/sudo events from journald.
        This is the fallback when auditd has nothing.
        """
        try:
            result = subprocess.run(
                [
                    "journalctl",
                    "--since", f"{minutes_back} minutes ago",
                    "--no-pager",
                    "--output=short-iso",
                ],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        if result.returncode != 0 or not result.stdout:
            return []

        logs: List[Dict[str, Any]] = []
        keywords = ["ssh", "login", "sudo", "auth", "failed", "session"]

        for line in result.stdout.splitlines():
            if not any(k in line.lower() for k in keywords):
                continue
            # journalctl --output=short-iso prefix: 2026-10-06T15:47:16+0000
            m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)", line)
            if not m:
                continue

            # event type from the content
            low = line.lower()
            if "sudo" in low:
                et = "journal_sudo"
            elif "ssh" in low:
                et = "journal_ssh"
            elif "session" in low:
                et = "journal_session"
            elif "auth" in low or "login" in low:
                et = "journal_auth"
            else:
                et = "journal_generic"

            logs.append({
                "timestamp": m.group(1),
                "event_type": et,
                "source": "linux_journald",
                "content": line.strip(),
            })
        return logs
