"""Regression runner: still-crashing / fixed / different / error."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from kmcs.core.models import Crash
from kmcs.reproduction.regression import (
    RegressionOutcome,
    RegressionRunner,
)


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
class TestOutcomes:
    def test_still_crashing_when_fingerprint_matches(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nkill -SEGV $$\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"x")

        # Compute the fingerprint by running once.
        from kmcs.analysis.crash_monitor import CrashMonitor, MonitorConfig
        from kmcs.analysis.fingerprint import CrashFingerprinter

        obs = CrashMonitor().run(
            MonitorConfig(target=binary), input_bytes=b"x"
        )
        fp = CrashFingerprinter().fingerprint(obs.report)

        crash = Crash(fingerprint=fp.value)

        result = RegressionRunner().run([(crash, inp)], target=binary)
        assert result.cases[0].outcome is RegressionOutcome.STILL_CRASHING
        assert result.still_crashing == 1
        assert result.all_clear is False

    def test_fixed_when_target_no_longer_crashes(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"x")

        crash = Crash(fingerprint="something")
        result = RegressionRunner().run([(crash, inp)], target=binary)
        assert result.cases[0].outcome is RegressionOutcome.FIXED
        assert result.fixed == 1
        assert result.all_clear is True

    def test_different_crash_when_fingerprint_does_not_match(
        self, tmp_path: Path
    ) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nkill -SEGV $$\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"x")

        crash = Crash(fingerprint="this-does-not-match")

        result = RegressionRunner().run([(crash, inp)], target=binary)
        assert result.cases[0].outcome is RegressionOutcome.DIFFERENT_CRASH
        assert result.different == 1

    def test_missing_input_is_error(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        crash = Crash(fingerprint="x")
        result = RegressionRunner().run(
            [(crash, tmp_path / "missing")], target=binary
        )
        assert result.cases[0].outcome is RegressionOutcome.ERROR
        assert result.errored == 1

    def test_empty_case_list(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        result = RegressionRunner().run([], target=binary)
        assert result.cases == []
        assert result.all_clear is False
