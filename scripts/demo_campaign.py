#!/usr/bin/env python3
"""Run a complete KMCS campaign against a fresh target.

This is the demonstration a new user runs after cloning the repository:

    python scripts/demo_campaign.py

It builds a small C target with AFL++ instrumentation, verifies that the
target crashes on the trigger input and not on a benign one, creates a
fresh KMCS workspace, registers the target, imports a corpus, runs a
short campaign, and prints the findings and the report paths.

The script exits with status 0 on success and non-zero on any failure.  It
is deliberately self-contained: it does not read from or write to any
existing KMCS workspace.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# --- locate the repository root ---------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


C_SOURCE = """\
/*
 * KMCS demonstration target.
 *
 * Benign on any input that does not contain '!'.  Crashes with SIGSEGV when
 * the input contains '!'.  The pointer is read from an extern global so the
 * compiler cannot fold the null dereference away.
 */
#include <stdio.h>

int *kmcs_demo_pointer;

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
    return *kmcs_demo_pointer;
}
"""


def step(message: str) -> None:
    print(f"\n=== {message} ===", flush=True)


def fail(message: str, code: int = 1) -> "None":
    print(f"\nFAIL: {message}", file=sys.stderr)
    sys.exit(code)


def find_afl_compiler() -> str:
    for name in ("afl-clang-lto", "afl-clang-fast"):
        path = shutil.which(name)
        if path:
            return path
    fail(
        "No AFL++ compiler wrapper found on $PATH.  "
        "Install afl-clang-lto or afl-clang-fast."
    )
    raise AssertionError("unreachable")


def build_target(source: Path, binary: Path, afl_compiler: str) -> None:
    step(f"Building target with {Path(afl_compiler).name}")
    completed = subprocess.run(
        [afl_compiler, "-g", "-O1", "-fno-omit-frame-pointer",
         str(source), "-o", str(binary)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if completed.returncode != 0 or not binary.is_file():
        fail(
            "Target build failed:\n"
            f"  command: {' '.join(completed.args)}\n"
            f"  returncode: {completed.returncode}\n"
            f"  stderr:\n{completed.stderr}"
        )
    print(f"built: {binary}")


def verify_crash_behaviour(binary: Path) -> None:
    step("Verifying the target crashes on '!' and exits 0 on benign input")

    benign = subprocess.run(
        [str(binary)], input=b"x", capture_output=True, timeout=15, check=False,
    )
    if benign.returncode != 0:
        fail(f"target exited {benign.returncode} on benign input; expected 0")

    trigger = subprocess.run(
        [str(binary)], input=b"!", capture_output=True, timeout=15, check=False,
    )
    if trigger.returncode == 0:
        fail("target exited 0 on the trigger input; expected a signal")

    print(f"benign input:  exit {benign.returncode}")
    print(f"trigger input: exit {trigger.returncode} (expected non-zero)")


def main() -> int:
    # --- imports (after sys.path is set) ------------------------------------
    from kmcs.analysis.crash_detector import CrashDetector
    from kmcs.campaigns.manager import CampaignManager
    from kmcs.core import models
    from kmcs.core.config import KMCSConfig
    from kmcs.corpus.manager import CorpusManager
    from kmcs.database.database import Database
    from kmcs.reporting import ReportFormat, ReportGenerator
    from kmcs.targets.manager import TargetManager

    afl_compiler = find_afl_compiler()

    # --- set up an isolated workspace ---------------------------------------
    workspace_root = Path(tempfile.mkdtemp(prefix="kmcs-demo-"))
    print(f"workspace: {workspace_root}")

    config = KMCSConfig(base_dir=workspace_root / "data")
    config.ensure_directories()

    database = Database.from_config(config)
    database.initialize()

    # --- build the target ---------------------------------------------------
    source = workspace_root / "target.c"
    source.write_text(C_SOURCE, encoding="utf-8")
    binary = workspace_root / "target_afl"
    build_target(source, binary, afl_compiler)
    verify_crash_behaviour(binary)

    # --- register the target ------------------------------------------------
    step("Registering the target")
    target = models.Target(
        name="demo-target",
        description="KMCS demonstration target",
        executable=binary,
    )
    TargetManager(database).add(target)
    print(f"target id: {target.id}")

    # --- create a corpus ----------------------------------------------------
    step("Creating the corpus")
    corpus_manager = CorpusManager(database, config)
    corpus = corpus_manager.create("demo-corpus", target_id=target.id)

    seed_dir = workspace_root / "seeds"
    seed_dir.mkdir()
    (seed_dir / "seed").write_bytes(b"x")
    corpus_manager.import_files(corpus.id, [seed_dir / "seed"])

    corpus_dir = corpus_manager.corpus_directory(corpus.id)
    print(f"corpus directory: {corpus_dir}")
    print(f"seed files: {[p.name for p in corpus_dir.iterdir()]}")

    # --- run a campaign -----------------------------------------------------
    step("Running a 10-second campaign")
    campaign = models.Campaign(
        name="demo-campaign",
        target_id=target.id,
        corpus_id=corpus.id,
        fuzzer=models.FuzzerKind.AFLPP,
        sanitizers=[],
        workers=1,
        duration_seconds=10,
    )
    campaign_manager = CampaignManager(
        database, config, detector=CrashDetector(database=database),
    )
    campaign_manager.add(campaign)

    env = dict(os.environ)
    env.update({
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_UI": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    })

    output_root = workspace_root / "campaign-out"
    result = campaign_manager.run(
        campaign.id,
        target_binary=binary,
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

    # --- report the result --------------------------------------------------
    step("Campaign complete")

    telemetry = result.scheduler_result.telemetry
    executions = telemetry.total_executions if telemetry else None

    print(f"  status              : {result.campaign.status.value}")
    print(f"  duration            : {result.scheduler_result.duration_seconds:.1f}s")
    print(f"  executions          : {executions}")
    print(f"  crashes recorded    : {result.scheduler_result.total_crashes_recorded}")
    print(f"  unique fingerprints : {result.deduplication.total_groups}")
    print(f"  findings            : {len(result.deduplication.findings)}")

    if not result.deduplication.findings:
        fail(
            "Campaign did not produce any findings.  "
            "This usually means the target did not crash, or AFL++ did not run."
        )

    step("Findings")
    for i, finding in enumerate(result.deduplication.findings, start=1):
        print(f"  [{i}] {finding.title}")
        print(f"      classification : {finding.classification.value}")
        print(f"      severity       : {finding.severity.value}")
        print(f"      fingerprint    : {finding.fingerprint}")
        print(f"      occurrences    : {len(finding.crash_ids)}")

    # --- generate reports ---------------------------------------------------
    step("Generating reports")
    generator = ReportGenerator(database, config)
    report_dir = workspace_root / "reports"
    for fmt in ReportFormat:
        rendered, written = generator.generate(fmt, output_dir=report_dir)
        print(f"  {fmt.value:<9} {written}")

    step("Demo complete")
    print(f"\nWorkspace is at {workspace_root}")
    print("Inspect it with:")
    print(f"  KMCS_HOME={config.base_dir} kmcs finding list")
    print(f"  KMCS_HOME={config.base_dir} kmcs report generate --format markdown --stdout")

    database.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
