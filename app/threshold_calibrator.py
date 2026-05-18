"""
threshold_calibrator.py
-----------------------
Runs recalibrate_threshold.py as a background subprocess, streams its output
for live progress tracking, and saves the resulting threshold to the
authenticated user's record in the database.

Calibration duration: 4 minutes (240 s) at 99th percentile.
"""

import os
import re
import sqlite3
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone

DB_PATH = "threat_memory.db"
CALIBRATION_TIMEOUT = 240  # 4 minutes

_active_procs: dict[str, subprocess.Popen] = {}
_procs_lock = threading.Lock()

_FLOW_RE = re.compile(r"Flow\s+(\d+):")
_THRESHOLD_RE = re.compile(r"New threshold\s*:\s*([\d.]+)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_calibration(user_id: str, iface: str | None = None,
                      timeout: int = CALIBRATION_TIMEOUT) -> str:
    """Launch calibration in a background thread. Returns session_id."""
    session_id = str(uuid.uuid4())

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO calibration_sessions
               (session_id, user_id, status, started_at, duration_seconds, sample_count)
               VALUES (?, ?, 'running', ?, ?, 0)""",
            (session_id, user_id, _now(), timeout),
        )

    thread = threading.Thread(
        target=_run,
        args=(session_id, user_id, iface, timeout),
        daemon=True,
        name=f"calib-{session_id[:8]}",
    )
    thread.start()
    return session_id


def stop_calibration(session_id: str) -> bool:
    """Stop a running calibration. Returns False if not found/running."""
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT status FROM calibration_sessions WHERE session_id = ?",
            (session_id,),
        ).fetchone()

    if not row or row[0] != "running":
        return False

    # Mark stopped immediately so the UI updates on next refresh
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE calibration_sessions SET status='stopped', stopped_at=? WHERE session_id=?",
            (_now(), session_id),
        )

    # Terminate the subprocess
    with _procs_lock:
        proc = _active_procs.get(session_id)
    if proc:
        try:
            proc.terminate()
        except Exception:
            pass
    return True


def get_calibration_status(session_id: str) -> dict | None:
    """Return the current state of a calibration session."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                """SELECT session_id, user_id, status, started_at, stopped_at,
                          duration_seconds, sample_count, computed_threshold, error_message
                   FROM calibration_sessions WHERE session_id = ?""",
                (session_id,),
            ).fetchone()
        if row:
            return _row_to_dict(row)
    except Exception:
        pass
    return None


def get_user_latest_calibration(user_id: str) -> dict | None:
    """Return the most recent calibration session for a user."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                """SELECT session_id, user_id, status, started_at, stopped_at,
                          duration_seconds, sample_count, computed_threshold, error_message
                   FROM calibration_sessions
                   WHERE user_id = ?
                   ORDER BY started_at DESC LIMIT 1""",
                (user_id,),
            ).fetchone()
        if row:
            return _row_to_dict(row)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _row_to_dict(row) -> dict:
    keys = [
        "session_id", "user_id", "status", "started_at", "stopped_at",
        "duration_seconds", "sample_count", "computed_threshold", "error_message",
    ]
    return dict(zip(keys, row))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _app_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _run(session_id: str, user_id: str, iface: str | None, timeout: int):
    script = os.path.join(_app_dir(), "recalibrate_threshold.py")
    cmd = [sys.executable, "-u", script, "--timeout", str(timeout)]
    if iface:
        cmd += ["--iface", iface]

    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            bufsize=1,
            cwd=_app_dir(),
            env=env,
        )
        with _procs_lock:
            _active_procs[session_id] = proc

        flow_count = 0
        threshold_from_output = None
        output_lines: list[str] = []

        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            output_lines.append(line)

            m = _FLOW_RE.search(line)
            if m:
                flow_count = int(m.group(1))
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute(
                            "UPDATE calibration_sessions SET sample_count=? WHERE session_id=?",
                            (flow_count, session_id),
                        )
                except Exception:
                    pass

            m = _THRESHOLD_RE.search(line)
            if m:
                threshold_from_output = float(m.group(1))

        proc.wait()

        # If the user already stopped it, do nothing more
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT status FROM calibration_sessions WHERE session_id=?",
                (session_id,),
            ).fetchone()
        if row and row[0] == "stopped":
            return

        if proc.returncode == 0 or threshold_from_output is not None:
            # Prefer artifacts/threshold.pkl (most accurate); fall back to parsed value
            new_threshold = _read_artifact_threshold() or threshold_from_output
            if new_threshold is not None:
                _save_user_threshold(user_id, new_threshold)
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute(
                        """UPDATE calibration_sessions
                           SET status='completed', stopped_at=?, sample_count=?,
                               computed_threshold=?
                           WHERE session_id=?""",
                        (_now(), flow_count, new_threshold, session_id),
                    )
            else:
                _mark_failed(session_id, "No threshold value could be determined from calibration output.")
        else:
            tail = "\n".join(output_lines[-10:]) if output_lines else "(no output)"
            _mark_failed(
                session_id,
                f"Calibration process exited with code {proc.returncode}.\n{tail}",
            )

    except Exception as exc:
        _mark_failed(session_id, str(exc))
    finally:
        with _procs_lock:
            _active_procs.pop(session_id, None)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass


def _read_artifact_threshold() -> float | None:
    path = os.path.join(_app_dir(), "artifacts", "threshold.pkl")
    try:
        import joblib
        return float(joblib.load(path))
    except Exception:
        return None


def _save_user_threshold(user_id: str, threshold: float):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO user_thresholds (user_id, threshold) VALUES (?, ?)",
            (user_id, threshold),
        )
        # Mirror to "current_user" so live_capture.py picks it up on next start
        conn.execute(
            "INSERT OR REPLACE INTO user_thresholds (user_id, threshold) VALUES (?, ?)",
            ("current_user", threshold),
        )


def _mark_failed(session_id: str, error_msg: str):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """UPDATE calibration_sessions
                   SET status='failed', error_message=?, stopped_at=?
                   WHERE session_id=?""",
                (error_msg, _now(), session_id),
            )
    except Exception:
        pass
