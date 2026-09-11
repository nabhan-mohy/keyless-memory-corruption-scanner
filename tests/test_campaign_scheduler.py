"""Scheduler: parallelism, cancellation, and aggregation."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns import scheduler as scheduler_module
from kmcs.campaigns.scheduler import CampaignScheduler, SchedulerConfig
from kmcs.core.models import FuzzerKind
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerConfig,
    FuzzerStats,
)
from kmcs.targets.detector import EnvironmentDetector


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


class _SleepingFuzzerAdapter(FuzzerAdapter):
    """A fake fuzzer that spawns ``sleep 60`` and reports nothing.

    Used to test the scheduler's cancellation logic without requiring a real
    fuzzer to be installed.
    """

    kind = FuzzerKind.AFLPP

    @classmethod
    def check_availability(cls, detector: EnvironmentDetector) -> FuzzerAvailability:
        return FuzzerAvailability(fuzzer=cls.kind, available=True, binary="sleep")

    def plan(self) -> tuple[list[str], dict[str, str]]:
        return ["sleep", "60"], {}

    def stats(self) -> FuzzerStats:
        return FuzzerStats(source="fake")


@pytest.fixture()
def demo(tmp_path: Path) -> tuple[Path, Path]:
    binary = _write_executable(tmp_path / "t", "#!/bin/sh\nkill -SEGV $$\n")
    corpus = tmp_path / "c"
    corpus.mkdir()
    (corpus / "seed").write_bytes(b"x")
    return binary, corpus


@pytest.fixture()
def patch_fuzzer(monkeypatch):
    """Replace the AFL++ adapter class with the fake one for the test."""
    monkeypatch.setitem(
        scheduler_module._FUZZER_CLASSES,
        FuzzerKind.AFLPP,
        _SleepingFuzzerAdapter,
    )


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX shell")
class TestScheduler:
    def test_prepare_creates_workers(self, tmp_path: Path, demo, patch_fuzzer) -> None:
        binary, corpus = demo
        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=tmp_path / "out",
            fuzzer=FuzzerKind.AFLPP,
            workers=3,
        )
        scheduler = CampaignScheduler(config, detector=CrashDetector())
        scheduler.prepare()
        assert len(scheduler._workers) == 3  # noqa: SLF001 - test introspection

    def test_clear_output_root_is_honoured(
        self, tmp_path: Path, demo, patch_fuzzer
    ) -> None:
        binary, corpus = demo
        output = tmp_path / "out"
        output.mkdir()
        (output / "stale").write_text("old")

        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=output,
            fuzzer=FuzzerKind.AFLPP,
            workers=1,
            clear_output_root=True,
        )
        CampaignScheduler(config, detector=CrashDetector()).prepare()
        assert not (output / "stale").exists()

    def test_cancel_stops_workers(
        self, tmp_path: Path, demo, patch_fuzzer
    ) -> None:
        binary, corpus = demo
        config = SchedulerConfig(
            campaign_id="c",
            target_binary=binary,
            corpus_dir=corpus,
            output_root=tmp_path / "out",
            fuzzer=FuzzerKind.AFLPP,
            workers=2,
            poll_interval_seconds=0.05,
        )
        scheduler = CampaignScheduler(config, detector=CrashDetector())
        scheduler.prepare()

        result_holder: dict[str, object] = {}

        def run() -> None:
            result_holder["result"] = scheduler.run()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        # Give workers a moment to enter their polling loop.
        time.sleep(0.5)
        scheduler.cancel()
        thread.join(timeout=15)
        assert not thread.is_alive()

        result = result_holder["result"]
        assert result.cancelled is True
        assert len(result.worker_results) == 2

