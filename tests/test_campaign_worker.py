"""Worker behaviour using a controllable fake fuzzer adapter."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.telemetry import TelemetryAggregator
from kmcs.campaigns.worker import (
    CampaignWorker,
    WorkerConfig,
    WorkerStatus,
)
from kmcs.core import models
from kmcs.core.models import FuzzerKind
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.models import CampaignRow, TargetRow
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerConfig,
    FuzzerStats,
)
from kmcs.targets.detector import EnvironmentDetector


# ---------------------------------------------------------------------- fake adapter


class _FakeFuzzerAdapter(FuzzerAdapter):
    """A test-only adapter that spawns a real sleeping process."""

    kind = FuzzerKind.AFLPP

    def __init__(self, config: FuzzerConfig) -> None:
        super().__init__(config)
        self._crashes_dir = config.output_dir / "crashes"
        self._crashes_dir.mkdir(parents=True, exist_ok=True)
        self._stats = FuzzerStats(source="fake", executions=0, crashes=0)

    @classmethod
    def check_availability(cls, detector: EnvironmentDetector) -> FuzzerAvailability:
        return FuzzerAvailability(fuzzer=cls.kind, available=True, binary="sleep")

    def plan(self) -> tuple[list[str], dict[str, str]]:
        return ["sleep", "60"], {}

    def stats(self) -> FuzzerStats:
        return self._stats

    def artifact_files(self) -> list[Path]:
        if not self._crashes_dir.is_dir():
            return []
        return sorted(p for p in self._crashes_dir.iterdir() if p.is_file())

    # --- test helpers ------------------------------------------------

    def emit_artifact(self, name: str, payload: bytes) -> Path:
        path = self._crashes_dir / name
        path.write_bytes(payload)
        return path

    def set_stats(self, **fields: object) -> None:
        for k, v in fields.items():
            setattr(self._stats, k, v)


# ---------------------------------------------------------------------- fixtures


def _write_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture()
def target_and_corpus(tmp_path: Path) -> tuple[Path, Path]:
    # The "target" here is a shell script that always exits with SIGSEGV.
    binary = _write_executable(
        tmp_path / "target", "#!/bin/sh\nkill -SEGV $$\n"
    )
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed").write_bytes(b"seed")
    return binary, corpus


@pytest.fixture()
def database(tmp_path: Path) -> Database:
    db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
    db.initialize()
    return db


@pytest.fixture()
def seeded_campaign_id(
    database: Database, target_and_corpus: tuple[Path, Path]
) -> str:
    """Persist a target and campaign so worker-recorded crashes can reference them."""
    binary, _corpus = target_and_corpus
    target = models.Target(name="worker-target", executable=binary)
    campaign = models.Campaign(name="worker-campaign", target_id=target.id)

    with database.session() as session:
        session.add(TargetRow.from_domain(target))
        session.flush()
        session.add(CampaignRow.from_domain(campaign))

    return campaign.id


# ---------------------------------------------------------------------- tests


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX shell")
class TestWorkerLifecycle:
    def test_worker_runs_and_records_a_crash(
        self,
        tmp_path: Path,
        target_and_corpus: tuple[Path, Path],
        database: Database,
        seeded_campaign_id: str,
    ) -> None:
        binary, corpus = target_and_corpus
        output = tmp_path / "out"

        config = WorkerConfig(
            campaign_id=seeded_campaign_id,
            worker_index=0,
            target_id=None,
            target_binary=binary,
            corpus_dir=corpus,
            output_dir=output,
            fuzzer=FuzzerKind.AFLPP,
            duration_seconds=None,
            poll_interval_seconds=0.1,
        )
        fuzzer_config = FuzzerConfig(
            target_binary=binary,
            input_dir=corpus,
            output_dir=output,
        )
        fake = _FakeFuzzerAdapter(fuzzer_config)

        detector = CrashDetector(database=database)
        telemetry = TelemetryAggregator(campaign_id=seeded_campaign_id)

        worker = CampaignWorker(
            config,
            fuzzer=fake,
            detector=detector,
            telemetry=telemetry,
            database=database,
        )

        fake.emit_artifact("id:000000,crashed", b"\x00" * 16)

        result_holder: dict[str, object] = {}

        def run_worker() -> None:
            result_holder["result"] = worker.run()

        thread = threading.Thread(target=run_worker, daemon=True)
        thread.start()

        for _ in range(40):
            if worker.crashes_recorded > 0:
                break
            time.sleep(0.1)

        worker.request_stop()
        thread.join(timeout=10)
        assert not thread.is_alive(), "worker did not stop"

        assert worker.crashes_recorded == 1
        assert worker.artifacts_seen == 1

        from sqlalchemy import select

        from kmcs.database.models import CrashRow

        with database.session() as session:
            rows = session.scalars(select(CrashRow)).all()
            assert len(rows) == 1
            assert rows[0].signal == 11
            assert rows[0].campaign_id == seeded_campaign_id

    def test_worker_stop_is_idempotent(
        self,
        tmp_path: Path,
        target_and_corpus: tuple[Path, Path],
    ) -> None:
        binary, corpus = target_and_corpus
        output = tmp_path / "out"

        config = WorkerConfig(
            campaign_id="",
            worker_index=0,
            target_id=None,
            target_binary=binary,
            corpus_dir=corpus,
            output_dir=output,
            fuzzer=FuzzerKind.AFLPP,
            poll_interval_seconds=0.05,
        )
        fake = _FakeFuzzerAdapter(
            FuzzerConfig(target_binary=binary, input_dir=corpus, output_dir=output)
        )
        worker = CampaignWorker(
            config,
            fuzzer=fake,
            detector=CrashDetector(),
            telemetry=TelemetryAggregator(),
        )

        thread = threading.Thread(target=worker.run, daemon=True)
        thread.start()
        time.sleep(0.2)
        worker.request_stop()
        worker.request_stop()
        thread.join(timeout=5)
        assert worker.status in (WorkerStatus.STOPPED, WorkerStatus.FAILED)


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX shell")
class TestWorkerStats:
    def test_stats_flow_into_telemetry(
        self,
        tmp_path: Path,
        target_and_corpus: tuple[Path, Path],
    ) -> None:
        binary, corpus = target_and_corpus
        output = tmp_path / "out"
        config = WorkerConfig(
            campaign_id="",
            worker_index=2,
            target_id=None,
            target_binary=binary,
            corpus_dir=corpus,
            output_dir=output,
            fuzzer=FuzzerKind.AFLPP,
            poll_interval_seconds=0.05,
        )
        fake = _FakeFuzzerAdapter(
            FuzzerConfig(target_binary=binary, input_dir=corpus, output_dir=output)
        )
        fake.set_stats(executions=1234, crashes=5, executions_per_second=42.0)

        telemetry = TelemetryAggregator(campaign_id="c3")
        worker = CampaignWorker(
            config,
            fuzzer=fake,
            detector=CrashDetector(),
            telemetry=telemetry,
        )

        thread = threading.Thread(target=worker.run, daemon=True)
        thread.start()
        time.sleep(0.3)
        worker.request_stop()
        thread.join(timeout=5)

        record = telemetry.worker(2)
        assert record is not None
        assert record.executions == 1234
        assert record.crashes == 5
        assert record.executions_per_second == 42.0
