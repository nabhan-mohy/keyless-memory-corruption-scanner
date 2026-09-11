"""Reproduction runner: REPRODUCED / NOT_REPRODUCED / INTERMITTENT / ERROR."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from kmcs.reproduction.runner import (
    ReproductionOutcome,
    ReproductionRunner,
)


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
class TestOutcomes:
    def test_deterministic_crash_is_reproduced(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nkill -SEGV $$\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"data")

        runner = ReproductionRunner(attempts=3)
        result = runner.reproduce(target=binary, input_path=inp)
        assert result.outcome is ReproductionOutcome.REPRODUCED
        assert result.crashes == 3
        assert result.crash_rate == 1.0

    def test_clean_exit_is_not_reproduced(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"")

        result = ReproductionRunner(attempts=3).reproduce(
            target=binary, input_path=inp
        )
        assert result.outcome is ReproductionOutcome.NOT_REPRODUCED
        assert result.crashes == 0

    def test_missing_input_is_error(self, tmp_path: Path) -> None:
        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        result = ReproductionRunner().reproduce(
            target=binary, input_path=tmp_path / "nonexistent"
        )
        assert result.outcome is ReproductionOutcome.ERROR

    def test_intermittent_is_detected(self, tmp_path: Path) -> None:
        # Crash on every other invocation by tracking state in a counter file.
        counter = tmp_path / "counter"
        counter.write_text("0")
        binary = _write(
            tmp_path / "t",
            f"""#!/bin/sh
n=$(cat "{counter}")
n=$((n+1))
echo "$n" > "{counter}"
if [ $((n % 2)) -eq 0 ]; then
  exit 0
fi
kill -SEGV $$
""",
        )
        inp = tmp_path / "i"
        inp.write_bytes(b"")

        result = ReproductionRunner(attempts=4).reproduce(
            target=binary, input_path=inp
        )
        assert result.outcome is ReproductionOutcome.INTERMITTENT
        assert 0 < result.crashes < 4


class TestResultHelpers:
    def test_result_is_serialisable(self, tmp_path: Path) -> None:
        import json

        binary = _write(tmp_path / "t", "#!/bin/sh\nexit 0\n")
        inp = tmp_path / "i"
        inp.write_bytes(b"")
        result = ReproductionRunner(attempts=2).reproduce(
            target=binary, input_path=inp
        )
        json.dumps(result.to_dict())
