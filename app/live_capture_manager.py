"""
live_capture_manager.py
-----------------------
Manages live_capture.py as a background subprocess so the dashboard can
start and stop IDS monitoring with a button click.
"""

import os
import sys
import threading
import subprocess

try:
    from .paths import app_dir
except ImportError:
    from paths import app_dir

_proc: subprocess.Popen | None = None
_lock = threading.Lock()


def _app_dir() -> str:
    """Return the directory containing this module for stable subprocess cwd."""
    return str(app_dir())


def start(iface: str | None = None) -> bool:
    """Launch live_capture.py. Returns False if already running."""
    global _proc
    with _lock:
        if _proc is not None and _proc.poll() is None:
            return False

        script = os.path.join(_app_dir(), "live_capture.py")
        cmd = [sys.executable, "-u", script, "--no-reset", "--no-dashboard"]
        if iface:
            cmd += ["--iface", iface]

        env = os.environ.copy()
        # Keep child output decodable on Windows terminals and Streamlit logs.
        env["PYTHONIOENCODING"] = "utf-8"

        _proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=_app_dir(),
            env=env,
        )
    return True


def stop() -> bool:
    """Stop live_capture.py. Returns False if it was not running."""
    global _proc
    with _lock:
        if _proc is None or _proc.poll() is not None:
            _proc = None
            return False
        try:
            _proc.terminate()
            _proc.wait(timeout=5)
        except Exception:
            try:
                _proc.kill()
            except Exception:
                pass
        _proc = None
    return True


def is_running() -> bool:
    """True if the live_capture subprocess is alive."""
    global _proc
    with _lock:
        if _proc is None:
            return False
        if _proc.poll() is None:
            return True
        _proc = None
        return False


def pid() -> int | None:
    """Return the active child process id, or None when stopped."""
    with _lock:
        return _proc.pid if (_proc is not None and _proc.poll() is None) else None
