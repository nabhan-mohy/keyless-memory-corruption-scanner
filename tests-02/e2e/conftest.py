"""Fixtures for end-to-end tests.

These fixtures are deliberately heavyweight: they build real targets, create
real corpora, and (optionally) launch real fuzzers.  Tests that need AFL++
skip cleanly when it is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from kmcs.core.config import KMCSConfig
from kmcs.database.database import Database, build_sqlite_url
from kmcs.targets.detector import EnvironmentDetector


DEMO_ROOT = Path(__file__).resolve().parent.parent.parent / "examples" / "vulnerable"


@pytest.fixture(scope="session")
def demo_root() -> Path:
    if not DEMO_ROOT.is_dir():
        pytest.skip(f"demo laboratory not present at {DEMO_ROOT}")
    return DEMO_ROOT


@pytest.fixture(scope="session")
def detector() -> EnvironmentDetector:
    return EnvironmentDetector()


@pytest.fixture(scope="session")
def c_compiler(detector: EnvironmentDetector) -> str:
    report = detector.detect_all(["clang", "gcc", "cc"])
    for name in ("clang", "gcc", "cc"):
        info = report.get(name)
        if info is not None and info.available and info.path:
            return info.path
    pytest.skip("no C compiler on this system")
    raise AssertionError("unreachable")


@pytest.fixture(scope="session")
def aflpp_available(detector: EnvironmentDetector) -> bool:
    report = detector.detect_all(["afl-fuzz", "afl-clang-fast"])
    return bool(
        report.available("afl-fuzz") and report.available("afl-clang-fast")
    )


@pytest.fixture()
def workspace(tmp_path: Path):
    """A fully initialised KMCS workspace plus a database handle."""
    config = KMCSConfig(base_dir=tmp_path / "kmcs-home")
    config.ensure_directories()
    db = Database.from_config(config)
    db.initialize()
    try:
        yield config, db
    finally:
        db.dispose()


@pytest.fixture(scope="session")
def demo_binaries(tmp_path_factory, demo_root: Path, c_compiler: str):
    """Compile every demo target once per session under ASan + UBSan."""
    build_dir = tmp_path_factory.mktemp("demo-binaries")

    from kmcs.core.models import BuildConfiguration, SanitizerKind
    from kmcs.targets.build import BuildManager, BuildRequest

    detector = EnvironmentDetector()
    manager = BuildManager(detector)

    binaries: dict[str, Path] = {}
    for name in (
        "heap_overflow",
        "stack_overflow",
        "global_overflow",
        "use_after_free",
        "double_free",
        "null_deref",
        "oob_read",
        "signed_overflow",
        "memory_leak",
    ):
        source = demo_root / f"{name}.c"
        if not source.is_file():
            continue
        output = build_dir / name
        result = manager.build(
            BuildRequest(
                sources=[source],
                output=output,
                compiler=c_compiler,
                configuration=BuildConfiguration.ASAN_UBSAN,
                sanitizers=[
                    SanitizerKind.ADDRESS,
                    SanitizerKind.UNDEFINED,
                    SanitizerKind.LEAK,
                ],
            )
        )
        if result.success:
            binaries[name] = output
        # A build failure here is a real failure — a demo target must compile.
        else:
            raise AssertionError(
                f"demo target {name} did not build: {result.stderr[-2000:]}"
            )

    return binaries
