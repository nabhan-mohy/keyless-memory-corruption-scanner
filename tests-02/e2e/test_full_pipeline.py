"""The full pipeline, once, from corpus to SARIF.

This is the acceptance test for KMCS.  If it passes, the tool works end to
end for the common case.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.analysis.crash_monitor import MonitorConfig
from kmcs.campaigns.manager import CampaignManager
from kmcs.core import models
from kmcs.corpus.manager import CorpusManager
from kmcs.reporting import ReportFormat, ReportGenerator
from kmcs.reporting.base import ReportSection
from kmcs.sanitizers.asan import AddressSanitizerAdapter
from kmcs.targets.manager import TargetManager


class TestDetectBuildDeduplicateReport:
    """No fuzzer required — the crash is triggered directly.

    This exercises every phase from 3 through 6 without needing AFL++.
    """

    def test_heap_overflow_end_to_end(self, workspace, demo_binaries: dict[str, Path]) -> None:
        config, db = workspace
        binary = demo_binaries["heap_overflow"]

        # --- Phase 2: register a target
        target = models.Target(
            name="heap_overflow",
            executable=binary,
            build_configuration=models.BuildConfiguration.ASAN_UBSAN,
            sanitizers=[
                models.SanitizerKind.ADDRESS,
                models.SanitizerKind.UNDEFINED,
            ],
        )
        TargetManager(db).add(target)

        # --- Phase 5: create a corpus and import seed inputs
        corpus_manager = CorpusManager(db, config)
        corpus = corpus_manager.create("seeds", target_id=target.id)
        seed_dir = config.base_dir / "seed-inputs"
        seed_dir.mkdir(parents=True, exist_ok=True)
        (seed_dir / "small").write_bytes(b"AAAA")
        (seed_dir / "medium").write_bytes(b"A" * 32)
        (seed_dir / "large").write_bytes(b"A" * 200)
        corpus_manager.import_files(corpus.id, [seed_dir])

        # --- Phase 3: run the target against each seed and detect crashes
        detector = CrashDetector(database=db)
        env = AddressSanitizerAdapter.build_environment(
            {}, abort_on_error=True, symbolize=True
        )
        recorded: list[models.Crash] = []
        for entry_path in corpus_manager.files(corpus.id):
            obs = detector.run_and_record(
                MonitorConfig(
                    target=binary,
                    timeout_seconds=10.0,
                    environment=env,
                    expected_sanitizers=[models.SanitizerKind.ADDRESS],
                    evidence_dir=config.crashes_path / entry_path.stem,
                ),
                input_path=entry_path,
                input_bytes=entry_path.read_bytes(),
                target_id=target.id,
                persist=True,
            )
            if obs.crash is not None:
                recorded.append(obs.crash)

        assert len(recorded) >= 2, "at least two seeds should crash"

        # --- Phase 4: every crash is classified as heap-buffer-overflow
        for crash in recorded:
            assert crash.classification is models.CrashClassification.HEAP_BUFFER_OVERFLOW
            assert crash.severity is models.Severity.HIGH
            assert crash.fingerprint

        # --- Phase 4: fingerprints collapse the crashes into one finding
        from kmcs.analysis.crash_parser import CrashParser
        from kmcs.analysis.deduplicator import CrashDeduplicator

        parser = CrashParser()
        observations = []
        for crash in recorded:
            assert crash.evidence_path is not None
            stderr = Path(crash.evidence_path).read_text(
                encoding="utf-8", errors="replace"
            )
            report = parser.parse(
                stderr=stderr,
                exit_code=crash.exit_code,
                signal_number=crash.signal,
            )
            observations.append((crash, report))

        result = CrashDeduplicator().deduplicate(observations)
        assert result.total_crashes == len(recorded)
        # All the ASan reports point at the same line in heap_overflow.c, so
        # we expect exactly one finding.
        assert result.total_groups == 1
        assert len(result.findings) == 1

        finding = result.findings[0]
        assert finding.classification is models.CrashClassification.HEAP_BUFFER_OVERFLOW
        assert finding.severity is models.Severity.HIGH
        assert len(finding.crash_ids) == len(recorded)

        # --- Phase 6: render every report format
        from kmcs.database.models import CrashRow, FindingRow

        with db.session() as session:
            for crash in recorded:
                session.add(CrashRow.from_domain(crash))
            session.add(FindingRow.from_domain(finding))

        generator = ReportGenerator(db, config)
        for fmt in (
            ReportFormat.JSON,
            ReportFormat.MARKDOWN,
            ReportFormat.CSV,
            ReportFormat.SARIF,
            ReportFormat.HTML,
        ):
            rendered, written = generator.generate(
                fmt,
                output_dir=config.reports_path,
            )
            assert rendered.content, f"{fmt} produced empty output"
            assert written is not None and written.is_file()

        # --- Verify the JSON report is parseable and correct
        json_reports = sorted(config.reports_path.glob("*.json"))
        assert json_reports
        payload = json.loads(json_reports[-1].read_text())
        assert payload["schema"] == "kmcs.report.v1"
        assert payload["summary"]["findings"] == 1
        assert payload["findings"][0]["classification"] == "heap-buffer-overflow"

        # --- Verify the SARIF report has one rule and one result
        sarif_reports = sorted(config.reports_path.glob("*.sarif"))
        assert sarif_reports
        sarif = json.loads(sarif_reports[-1].read_text())
        run = sarif["runs"][0]
        assert any(r["id"] == "heap-buffer-overflow" for r in run["tool"]["driver"]["rules"])
        assert len(run["results"]) == 1


@pytest.mark.integration
class TestFullPipelineWithAFLpp:
    """Same workflow, but a real AFL++ campaign drives the crashes."""

    def test_afl_campaign_produces_findings(
        self,
        workspace,
        demo_binaries: dict[str, Path],
        aflpp_available: bool,
        tmp_path: Path,
    ) -> None:
        if not aflpp_available:
            pytest.skip("AFL++ is not installed")

        config, db = workspace
        binary = demo_binaries["heap_overflow"]

        from kmcs.targets.detector import EnvironmentDetector

        detector = EnvironmentDetector()
        wrapper_info = detector.detect_all(["afl-clang-fast"]).get("afl-clang-fast")
        assert wrapper_info is not None and wrapper_info.available

        # Build an AFL++-instrumented binary from the demo source.
        from kmcs.core.models import BuildConfiguration, SanitizerKind
        from kmcs.targets.build import BuildManager, BuildRequest

        instrumented = tmp_path / "heap_overflow_afl"
        source = Path(__file__).resolve().parent.parent.parent / "examples" / "vulnerable" / "heap_overflow.c"
        build = BuildManager(detector).build(
            BuildRequest(
                sources=[source],
                output=instrumented,
                compiler=wrapper_info.path,
                configuration=BuildConfiguration.ASAN,
                sanitizers=[SanitizerKind.ADDRESS],
                for_fuzzer=models.FuzzerKind.AFLPP,
            )
        )
        assert build.success, build.stderr

        target = models.Target(
            name="heap_overflow_afl",
            executable=instrumented,
            build_configuration=models.BuildConfiguration.ASAN,
            sanitizers=[models.SanitizerKind.ADDRESS],
        )
        TargetManager(db).add(target)

        corpus_manager = CorpusManager(db, config)
        corpus = corpus_manager.create("seeds", target_id=target.id)
        seed_dir = config.base_dir / "seeds-afl"
        seed_dir.mkdir(parents=True, exist_ok=True)
        (seed_dir / "seed").write_bytes(b"AAAA")
        corpus_manager.import_files(corpus.id, [seed_dir])

        campaign = models.Campaign(
            name="heap-overflow-run",
            target_id=target.id,
            corpus_id=corpus.id,
            fuzzer=models.FuzzerKind.AFLPP,
            sanitizers=[models.SanitizerKind.ADDRESS],
            workers=2,
            duration_seconds=10,
        )
        manager = CampaignManager(db, config, detector=CrashDetector(database=db))
        manager.add(campaign)

        result = manager.run(
            campaign.id,
            target_binary=instrumented,
            corpus_dir=corpus_manager.corpus_directory(corpus.id),
            output_root=tmp_path / "afl-out",
            environment={
                "AFL_SKIP_CPUFREQ": "1",
                "AFL_NO_UI": "1",
                "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            },
            poll_interval_seconds=0.5,
        )

        assert result.campaign.status is models.CampaignStatus.COMPLETED
        assert result.scheduler_result.total_crashes_recorded >= 1
        assert len(result.deduplication.findings) >= 1

        for finding in result.deduplication.findings:
            assert finding.classification is models.CrashClassification.HEAP_BUFFER_OVERFLOW


class TestReproductionAndMinimisation:
    """Verify that a discovered crash can be replayed and shrunk."""

    def test_reproduce_and_minimise(self, workspace, demo_binaries: dict[str, Path]) -> None:
        config, db = workspace
        binary = demo_binaries["heap_overflow"]

        from kmcs.analysis.crash_monitor import CrashMonitor
        from kmcs.corpus.minimizer import CorpusMinimizer, MinimizerConfig
        from kmcs.reproduction.runner import ReproductionOutcome, ReproductionRunner

        # Trigger a crash with a large input.
        big_input = config.base_dir / "big-input"
        big_input.write_bytes(b"A" * 512)

        obs = CrashMonitor().run(
            MonitorConfig(target=binary, timeout_seconds=10.0),
            input_path=big_input,
            input_bytes=big_input.read_bytes(),
        )
        assert obs.crashed

        # Reproduce it three times.
        repro = ReproductionRunner(attempts=3).reproduce(
            target=binary, input_path=big_input
        )
        assert repro.outcome is ReproductionOutcome.REPRODUCED

        # Minimise it.
        def predicate(candidate: bytes) -> bool:
            result = CrashMonitor().run(
                MonitorConfig(target=binary, timeout_seconds=5.0),
                input_bytes=candidate,
            )
            return result.crashed

        minimizer = CorpusMinimizer(MinimizerConfig(max_runs=200))
        outcome = minimizer.minimize(big_input.read_bytes(), predicate)
        assert outcome.success
        assert outcome.minimized_size < outcome.original_size
        assert outcome.minimized_size <= 64  # must still fit the overflow
