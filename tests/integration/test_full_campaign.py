"""The complete pipeline, against a real AFL++ campaign.

This is the acceptance test for KMCS.  It exercises every phase of the
toolchain that matters:

1. Build a small C target with AFL++ instrumentation.
2. Verify by hand that the binary crashes on the trigger input and exits
   cleanly on a benign one.  This is the single most important check in the
   file: a fuzzing campaign cannot find a crash that does not happen.
3. Create a fresh, isolated KMCS workspace.
4. Register the target, create a corpus, import a seed, create a campaign.
5. Run the campaign for a fixed duration.
6. Assert on real telemetry (executions), real crash records, real
   deduplication, and real report generation.

Every assertion is written to fail with a message that names exactly what
went wrong.  Nothing is inferred, and nothing is tolerated that could hide a
broken pipeline.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.manager import CampaignManager
from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.corpus.manager import CorpusManager
from kmcs.database.database import Database
from kmcs.database.models import CrashRow, FindingRow
from kmcs.reporting import ReportFormat, ReportGenerator
from kmcs.targets.manager import TargetManager

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# ---------------------------------------------------------------------- constants


CAMPAIGN_DURATION_SECONDS = 8
MIN_EXPECTED_RUNTIME_SECONDS = 5.0  # tolerates a small startup overhead
POLL_INTERVAL_SECONDS = 0.5


C_TARGET_SOURCE = """\
/*
 * KMCS integration test target.
 *
 * Benign on ordinary input.  Crashes with SIGSEGV when the input contains
 * the byte '!'.  The null pointer is read from an externally visible global
 * so the compiler cannot prove it is NULL at compile time and fold the
 * dereference away.  This is the pattern we converged on while building the
 * demo lab, and it is the pattern a real fuzzing target should follow.
 *
 * DO NOT DEPLOY.
 */
#include <stdio.h>

/* External linkage, not assigned anywhere.  The compiler must load its
 * value at runtime; it cannot substitute a constant. */
int *kmcs_test_pointer;

int main(void) {
    int c;
    int trigger = 0;
    while ((c = getchar()) != EOF) {
        if (c == '!') {
            trigger = 1;
        }
    }
    if (!trigger) {
        return 0;
    }
    return *kmcs_test_pointer;   /* BUG: kmcs_test_pointer is NULL */
}
"""


# ---------------------------------------------------------------------- helpers


def _write_target_source(directory: Path) -> Path:
    """Write the C source into ``directory`` and return its path."""
    source = directory / "target.c"
    source.write_text(C_TARGET_SOURCE, encoding="utf-8")
    return source


def _build_instrumented(
    source: Path, binary: Path, *, afl_compiler: str
) -> None:
    """Compile ``source`` with an AFL++ wrapper and -O1.

    ``-O1`` is required by AFL++'s LLVM LTO pass; without optimisation the
    instrumentation pass does not run and the resulting binary will not
    speak the fork-server protocol AFL++ expects.  No sanitizer flags are
    passed: the target uses a bare SIGSEGV, which is the simplest possible
    crash for the pipeline to detect.
    """
    command = [
        afl_compiler,
        "-g",
        "-O1",
        "-fno-omit-frame-pointer",
        str(source),
        "-o",
        str(binary),
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not binary.is_file():
        pytest.fail(
            "AFL++ build failed.\n"
            f"command: {' '.join(command)}\n"
            f"returncode: {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def _verify_crash_behaviour(binary: Path) -> None:
    """Confirm the binary crashes on '!' and exits 0 on any other input.

    Failure here means the target is not usable and the rest of the test
    would produce a misleading result.  We fail fast with a clear message
    instead of letting the campaign quietly record zero crashes.
    """
    # --- benign input: must exit cleanly ---
    benign = subprocess.run(
        [str(binary)],
        input=b"x",
        capture_output=True,
        timeout=15,
        check=False,
    )
    if benign.returncode != 0:
        pytest.fail(
            "Target does not exit cleanly on a benign input.\n"
            f"input: b'x'\n"
            f"returncode: {benign.returncode}\n"
            f"stderr:\n{benign.stderr.decode(errors='replace')}"
        )

    # --- trigger input: must die from a signal ---
    trigger = subprocess.run(
        [str(binary)],
        input=b"!",
        capture_output=True,
        timeout=15,
        check=False,
    )
    if trigger.returncode == 0:
        pytest.fail(
            "Target does not crash on the trigger input.\n"
            "input: b'!'\n"
            "returncode: 0 (expected a signal)\n"
            "This usually means the compiler optimised the bug away. "
            "Confirm that the source uses an uninitialised global pointer "
            "and that the binary was built at -O1 or higher."
        )


# ---------------------------------------------------------------------- fixtures


@pytest.fixture(scope="session")
def afl_compiler() -> str:
    """Return the path to an AFL++ compiler wrapper, or skip the test."""
    for name in ("afl-clang-lto", "afl-clang-fast"):
        path = shutil.which(name)
        if path:
            return path
    pytest.skip(
        "no AFL++ compiler wrapper found on $PATH "
        "(install afl-clang-lto or afl-clang-fast)"
    )
    raise AssertionError("unreachable")


@pytest.fixture(scope="session")
def afl_fuzzer() -> str:
    """Return the path to afl-fuzz, or skip the test."""
    path = shutil.which("afl-fuzz")
    if not path:
        pytest.skip("afl-fuzz not found on $PATH")
    return path


@pytest.fixture(scope="session")
def instrumented_binary(
    tmp_path_factory: pytest.TempPathFactory,
    afl_compiler: str,
    afl_fuzzer: str,
) -> Path:
    """Build the integration target once per test session.

    The binary is reused across tests because compiling with the AFL++ LTO
    plugin is expensive.  The directory is created under ``tmp_path_factory``
    so it survives across tests and is cleaned up by pytest at the end of the
    session.
    """
    directory = tmp_path_factory.mktemp("kmcs-integration-target")
    source = _write_target_source(directory)
    binary = directory / "target_afl"
    _build_instrumented(source, binary, afl_compiler=afl_compiler)
    _verify_crash_behaviour(binary)
    return binary


@pytest.fixture()
def workspace(tmp_path: Path) -> KMCSConfig:
    """A fresh, isolated KMCS data directory for one test."""
    config = KMCSConfig(base_dir=tmp_path / "kmcs-home")
    config.ensure_directories()
    return config


# ---------------------------------------------------------------------- the test


class TestFullPipeline:
    """The end-to-end acceptance test for KMCS.

    Deliberately one large test rather than a series of small ones: every
    step depends on the previous, and the whole point is to verify that the
    pipeline holds together from end to end.  A failure in any step is
    reported with a message that names the step that failed.
    """

    def test_campaign_finds_and_deduplicates_crashes(
        self,
        tmp_path: Path,
        workspace: KMCSConfig,
        instrumented_binary: Path,
    ) -> None:
        # --- Phase 1: database ------------------------------------------
        database = Database.from_config(workspace)
        database.initialize()

        health = database.health_check()
        assert health.ok, (
            "database health check failed during test setup:\n"
            + "\n".join(health.messages)
        )

        try:
            # --- Phase 2: register the target ---------------------------
            target = models.Target(
                name="integration-null-deref",
                description="Integration test target: null dereference on '!'",
                executable=instrumented_binary,
            )
            TargetManager(database).add(target)

            # --- Phase 5: assemble a corpus ------------------------------
            corpus_manager = CorpusManager(database, workspace)
            corpus = corpus_manager.create(
                "integration-corpus", target_id=target.id
            )

            seeds_dir = tmp_path / "seeds"
            seeds_dir.mkdir()
            (seeds_dir / "seed").write_bytes(b"x")
            corpus_manager.import_files(corpus.id, [seeds_dir / "seed"])

            corpus_dir = corpus_manager.corpus_directory(corpus.id)
            assert corpus_dir.is_dir(), (
                f"corpus directory was not created: {corpus_dir}"
            )
            assert any(corpus_dir.iterdir()), (
                f"corpus directory is empty: {corpus_dir}"
            )

            # --- Phase 5: create and run a campaign ----------------------
            campaign = models.Campaign(
                name="integration-campaign",
                target_id=target.id,
                corpus_id=corpus.id,
                fuzzer=models.FuzzerKind.AFLPP,
                sanitizers=[],
                workers=1,
                duration_seconds=CAMPAIGN_DURATION_SECONDS,
            )
            campaign_manager = CampaignManager(
                database, workspace, detector=CrashDetector(database=database)
            )
            campaign_manager.add(campaign)

            output_root = tmp_path / "campaign-out"
            result = campaign_manager.run(
                campaign.id,
                target_binary=instrumented_binary,
                corpus_dir=corpus_dir,
                output_root=output_root,
                environment={
                    "AFL_SKIP_CPUFREQ": "1",
                    "AFL_NO_UI": "1",
                    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
                },
                poll_interval_seconds=POLL_INTERVAL_SECONDS,
                clear_output_root=True,
            )

            # --- Campaign ran for its full duration ----------------------
            assert result.campaign.status is models.CampaignStatus.COMPLETED, (
                f"campaign finished with status {result.campaign.status.value}, "
                "expected 'completed'"
            )
            assert result.scheduler_result.duration_seconds >= (
                MIN_EXPECTED_RUNTIME_SECONDS
            ), (
                f"campaign ran for only {result.scheduler_result.duration_seconds:.2f}s, "
                f"expected at least {MIN_EXPECTED_RUNTIME_SECONDS}s. "
                "A campaign that exits early usually means the fuzzer failed to start."
            )
            assert not result.scheduler_result.cancelled, (
                "campaign was cancelled unexpectedly"
            )

            # --- AFL++ actually executed the target ----------------------
            telemetry = result.scheduler_result.telemetry
            assert telemetry is not None, "no telemetry was produced"
            assert telemetry.total_executions is not None, (
                "AFL++ did not report execution count; the campaign may not "
                "have started correctly"
            )
            assert telemetry.total_executions > 0, (
                "AFL++ ran zero executions; the campaign did not do any work"
            )

            # --- Crashes were detected and recorded ----------------------
            crashes_recorded = result.scheduler_result.total_crashes_recorded
            assert crashes_recorded >= 1, (
                f"AFL++ ran {telemetry.total_executions} executions but no "
                "crash was recorded.  Check the worker log at "
                f"{output_root}/worker-000/aflpp.log."
            )

            # --- Crashes deduplicated into findings ----------------------
            assert result.deduplication.total_crashes == crashes_recorded, (
                f"deduplication saw {result.deduplication.total_crashes} crashes, "
                f"but {crashes_recorded} were recorded"
            )
            assert result.deduplication.total_groups >= 1, (
                "no crash groups were produced"
            )
            assert len(result.deduplication.findings) >= 1, (
                "no findings were produced"
            )

            finding = result.deduplication.findings[0]
            assert (
                finding.classification
                is models.CrashClassification.SEGMENTATION_FAULT
            ), (
                f"finding classification is {finding.classification.value}, "
                "expected 'segmentation-fault'"
            )
            assert len(finding.crash_ids) == crashes_recorded, (
                f"finding links {len(finding.crash_ids)} crashes, "
                f"expected {crashes_recorded}"
            )

            # --- Persistence: rows exist in the database -----------------
            from sqlalchemy import select

            with database.session() as session:
                crash_rows = list(session.scalars(select(CrashRow)).all())
                finding_rows = list(session.scalars(select(FindingRow)).all())

            assert len(crash_rows) == crashes_recorded, (
                f"database contains {len(crash_rows)} crash rows, "
                f"expected {crashes_recorded}"
            )
            assert len(finding_rows) == len(result.deduplication.findings), (
                f"database contains {len(finding_rows)} finding rows, "
                f"expected {len(result.deduplication.findings)}"
            )

            # --- Phase 6: every report format renders --------------------
            report_dir = tmp_path / "reports"
            generator = ReportGenerator(database, workspace)

            for fmt in (
                ReportFormat.JSON,
                ReportFormat.MARKDOWN,
                ReportFormat.CSV,
                ReportFormat.SARIF,
                ReportFormat.HTML,
            ):
                rendered, written = generator.generate(
                    fmt, output_dir=report_dir
                )
                assert rendered.content, (
                    f"{fmt.value} report rendered empty content"
                )
                assert written is not None, (
                    f"{fmt.value} report was not written to disk"
                )
                assert written.is_file(), (
                    f"{fmt.value} report file does not exist: {written}"
                )

            written_files = sorted(report_dir.iterdir())
            assert len(written_files) == 5, (
                f"expected 5 report files, found {len(written_files)}: "
                f"{[f.name for f in written_files]}"
            )
            extensions = {f.suffix for f in written_files}
            expected_extensions = {".json", ".md", ".csv", ".sarif", ".html"}
            assert extensions == expected_extensions, (
                f"report file extensions are {extensions}, "
                f"expected {expected_extensions}"
            )

            # --- SARIF has the shape CI dashboards expect ----------------
            sarif_file = next(f for f in written_files if f.suffix == ".sarif")
            sarif = json.loads(sarif_file.read_text(encoding="utf-8"))

            assert sarif.get("version") == "2.1.0", (
                f"SARIF version is {sarif.get('version')}, expected '2.1.0'"
            )
            runs = sarif.get("runs")
            assert isinstance(runs, list) and len(runs) >= 1, (
                "SARIF does not contain a 'runs' array"
            )
            driver = runs[0].get("tool", {}).get("driver", {})
            assert driver.get("name") == "KMCS", (
                f"SARIF tool name is {driver.get('name')!r}, expected 'KMCS'"
            )
            results = runs[0].get("results", [])
            assert len(results) >= 1, (
                "SARIF contains no results despite findings existing"
            )

            # --- JSON report declares its schema -------------------------
            json_file = next(f for f in written_files if f.suffix == ".json")
            json_payload = json.loads(json_file.read_text(encoding="utf-8"))
            assert json_payload.get("schema") == "kmcs.report.v1", (
                f"JSON report schema is {json_payload.get('schema')!r}, "
                "expected 'kmcs.report.v1'"
            )
            assert json_payload["summary"]["findings"] >= 1, (
                "JSON report summary reports zero findings"
            )
            assert json_payload["summary"]["crashes"] == crashes_recorded, (
                f"JSON report summary reports "
                f"{json_payload['summary']['crashes']} crashes, "
                f"expected {crashes_recorded}"
            )

        finally:
            database.dispose()
