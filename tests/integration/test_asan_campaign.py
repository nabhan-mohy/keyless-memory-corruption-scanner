"""End-to-end test of the ASan detection path.

The other integration test uses a bare SIGSEGV target: it proves the pipeline
runs, but it does not exercise the sanitizer parsing, classification, or
severity logic against real ASan output.  This test does.

It:

1. Writes a small C target with a heap buffer overflow.
2. Builds it with ``AFL_USE_ASAN=1 afl-clang-lto`` so ASan is linked in and
   the binary is coverage-instrumented.
3. Verifies by hand that the target crashes with the trigger input and exits
   0 on a benign one.
4. Runs a real AFL++ campaign for a few seconds.
5. Asserts the resulting finding is classified as ``heap-buffer-overflow``
   -- a memory-safety class, not ``segmentation-fault`` -- which proves the
   ASan path fired and the classifier understood its output.

This test is marked ``integration`` because it requires clang, AFL++, and a
working ASan runtime.
"""

from __future__ import annotations

import os
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
from kmcs.targets.manager import TargetManager

pytestmark = [pytest.mark.integration, pytest.mark.slow]


CAMPAIGN_DURATION_SECONDS = 8
MIN_EXPECTED_RUNTIME_SECONDS = 5.0


C_SOURCE = """\
/*
 * KMCS ASan integration test target.
 *
 * Benign on inputs shorter than 8 bytes.  Crashes with an ASan
 * heap-buffer-overflow when the input contains more than 8 bytes.
 *
 * There is no null dereference and no sanitizer-visible behaviour on short
 * inputs, so a benign seed exits cleanly and AFL++ can run its dry-run.
 */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *buffer = (char *)malloc(8);
    if (buffer == NULL) {
        return 1;
    }
    int n = 0;
    int c;
    while ((c = getchar()) != EOF && n < 64) {
        buffer[n++] = (char)c;   /* BUG: writes past 8 bytes */
    }
    free(buffer);
    return 0;
}
"""


def _write_source(directory: Path) -> Path:
    source = directory / "target.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    return source


def _build_with_asan(source: Path, binary: Path, afl_compiler: str) -> None:
    """Build with ASan + AFL++ instrumentation.

    ``AFL_USE_ASAN=1`` tells AFL++ to link the ASan runtime.  Passing
    ``-fsanitize=address`` as well would cause linking problems; AFL++ adds
    the flag internally.
    """
    env = dict(os.environ)
    env["AFL_USE_ASAN"] = "1"
    completed = subprocess.run(
        [
            afl_compiler,
            "-g", "-O1", "-fno-omit-frame-pointer",
            str(source), "-o", str(binary),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not binary.is_file():
        pytest.fail(
            "ASan + AFL++ build failed.\n"
            f"command: {' '.join(completed.args)}\n"
            f"returncode: {completed.returncode}\n"
            f"stderr:\n{completed.stderr}"
        )


def _verify_behaviour(binary: Path) -> None:
    """Confirm the target crashes with ASan on >8 bytes, exit 0 on <=8 bytes."""
    benign = subprocess.run(
        [str(binary)], input=b"ab", capture_output=True, timeout=15, check=False,
    )
    if benign.returncode != 0:
        pytest.fail(
            f"Target exited {benign.returncode} on benign input; expected 0.\n"
            f"stderr:\n{benign.stderr.decode(errors='replace')}"
        )

    trigger = subprocess.run(
        [str(binary)],
        input=b"A" * 32,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if trigger.returncode == 0:
        pytest.fail(
            "Target exited 0 on the ASan trigger input.  The sanitizer "
            "runtime is not firing.  Check that ASan works on this system."
        )

    combined = trigger.stdout + trigger.stderr
    if b"AddressSanitizer" not in combined or b"heap-buffer-overflow" not in combined:
        pytest.fail(
            "Target crashed but ASan did not print a heap-buffer-overflow "
            "report.\n"
            f"stderr:\n{trigger.stderr.decode(errors='replace')[:2000]}"
        )


@pytest.fixture(scope="module")
def afl_compiler() -> str:
    for name in ("afl-clang-lto", "afl-clang-fast"):
        path = shutil.which(name)
        if path:
            return path
    pytest.skip("no AFL++ compiler wrapper found on $PATH")
    raise AssertionError("unreachable")


@pytest.fixture(scope="module")
def asan_binary(tmp_path_factory, afl_compiler: str) -> Path:
    directory = tmp_path_factory.mktemp("kmcs-asan-target")
    source = _write_source(directory)
    binary = directory / "target_asan_afl"
    _build_with_asan(source, binary, afl_compiler)
    _verify_behaviour(binary)
    return binary


@pytest.fixture()
def workspace(tmp_path: Path) -> KMCSConfig:
    config = KMCSConfig(base_dir=tmp_path / "kmcs-home")
    config.ensure_directories()
    return config


class TestASanCampaign:
    """Prove that ASan output is parsed and classified correctly end to end."""

    def test_campaign_classifies_heap_buffer_overflow(
        self, tmp_path: Path, workspace: KMCSConfig, asan_binary: Path
    ) -> None:
        database = Database.from_config(workspace)
        database.initialize()

        try:
            target = models.Target(
                name="integration-asan-heap",
                description="Integration: heap overflow under ASan",
                executable=asan_binary,
                sanitizers=[models.SanitizerKind.ADDRESS],
                build_configuration=models.BuildConfiguration.ASAN,
            )
            TargetManager(database).add(target)

            corpus_manager = CorpusManager(database, workspace)
            corpus = corpus_manager.create("asan-corpus", target_id=target.id)

            seeds = tmp_path / "seeds"
            seeds.mkdir()
            (seeds / "seed").write_bytes(b"ab")
            corpus_manager.import_files(corpus.id, [seeds / "seed"])

            corpus_dir = corpus_manager.corpus_directory(corpus.id)

            campaign = models.Campaign(
                name="asan-run",
                target_id=target.id,
                corpus_id=corpus.id,
                fuzzer=models.FuzzerKind.AFLPP,
                sanitizers=[models.SanitizerKind.ADDRESS],
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
                target_binary=asan_binary,
                corpus_dir=corpus_dir,
                output_root=output_root,
                environment={
                    "AFL_SKIP_CPUFREQ": "1",
                    "AFL_NO_UI": "1",
                    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
                },
                poll_interval_seconds=0.5,
                clear_output_root=True,
            )

            assert result.campaign.status is models.CampaignStatus.COMPLETED
            assert (
                result.scheduler_result.duration_seconds
                >= MIN_EXPECTED_RUNTIME_SECONDS
            )

            telemetry = result.scheduler_result.telemetry
            assert telemetry is not None
            assert telemetry.total_executions is not None
            assert telemetry.total_executions > 0

            assert result.scheduler_result.total_crashes_recorded >= 1
            assert len(result.deduplication.findings) >= 1

            finding = result.deduplication.findings[0]

            # This is the assertion that matters: it proves the ASan path
            # fired and the classifier understood the output.
            assert (
                finding.classification
                is models.CrashClassification.HEAP_BUFFER_OVERFLOW
            ), (
                f"Expected 'heap-buffer-overflow', got "
                f"{finding.classification.value!r}.  If this is "
                "'segmentation-fault', ASan did not run.  If this is "
                "'unknown', the parser did not recognise the ASan output."
            )

            assert finding.severity in (
                models.Severity.HIGH,
                models.Severity.MEDIUM,
            ), f"Unexpected severity {finding.severity.value!r}"

            # The ASan report must have been preserved verbatim.
            from sqlalchemy import select

            with database.session() as session:
                crash_rows = list(session.scalars(select(CrashRow)).all())

            assert crash_rows
            any_asan_evidence = False
            for row in crash_rows:
                if row.stderr_excerpt and "AddressSanitizer" in row.stderr_excerpt:
                    any_asan_evidence = True
                    break
            assert any_asan_evidence, (
                "No crash row contains 'AddressSanitizer' in its stderr "
                "excerpt.  The sanitizer output was not preserved."
            )

            with database.session() as session:
                finding_rows = list(session.scalars(select(FindingRow)).all())
            assert finding_rows

        finally:
            database.dispose()
