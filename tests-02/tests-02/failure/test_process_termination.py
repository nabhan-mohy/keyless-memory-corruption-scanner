"""A target that dies by signal or hangs must be handled cleanly."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from kmcs.analysis.crash_monitor import CrashMonitor, MonitorConfig


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
class TestTermination:
    def test_sigkill_is_detected(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "kill", "#!/bin/sh\nkill -KILL $$\n")
        obs = CrashMonitor().run(
            MonitorConfig(target=target, timeout_seconds=5.0), input_bytes=b""
        )
        assert obs.signal_number == 9
        assert obs.crashed

    def test_sigterm_is_detected(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "term", "#!/bin/sh\nkill -TERM $$\n")
        obs = CrashMonitor().run(
            MonitorConfig(target=target, timeout_seconds=5.0), input_bytes=b""
        )
        assert obs.signal_number == 15
        assert obs.crashed

    def test_hang_triggers_timeout(self, tmp_path: Path) -> None:
        target = _write(tmp_path / "hang", "#!/bin/sh\nsleep 60\n")
        obs = CrashMonitor().run(
            MonitorConfig(target=target, timeout_seconds=0.5), input_bytes=b""
        )
        assert obs.timed_out is True
        assert obs.crashed

    def test_infinite_output_is_bounded(self, tmp_path: Path) -> None:
        # A target that would loop forever printing must be killed by timeout,
        # not allowed to fill the disk.
        target = _write(
            tmp_path / "spam",
            "#!/bin/sh\nwhile true; do echo line; done\n",
        )
        obs = CrashMonitor().run(
            MonitorConfig(
                target=target, timeout_seconds=1.0, file_size_limit_mb=1
            ),
            input_bytes=b"",
        )
        assert obs.timed_out
