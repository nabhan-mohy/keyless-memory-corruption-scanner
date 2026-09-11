"""Input minimisation via a delta-debugging variant.

The minimiser is given:

* the original input bytes,
* a *predicate* that returns ``True`` if the crash still occurs with the same
  fingerprint,

and returns the smallest input (by byte count) it found that still satisfies
the predicate.

The algorithm is a byte-level ddmin: at each step the input is divided into
``n`` contiguous chunks, and each chunk is tested *individually* to see whether
removing it still crashes.  If removing any single chunk still crashes, that
chunk is discarded and ``n`` is reduced; if no single removal works, ``n`` is
doubled.  The loop terminates when ``n`` reaches the input size.

The predicate is injected by the caller — this module does not itself run
targets.  That keeps the minimiser pure and easy to test.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "MinimizerConfig",
    "MinimizationResult",
    "CorpusMinimizer",
    "MinimizationPredicate",
    "MinimizationBudgetExceeded",
]

logger = logging.getLogger(__name__)

MinimizationPredicate = Callable[[bytes], bool]


class MinimizationBudgetExceeded(Exception):
    """Raised internally when the run budget is exhausted."""


class MinimizerConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    max_runs: int = Field(default=500, ge=1, le=100_000)
    initial_chunk_count: int = Field(default=2, ge=2, le=1024)
    verify_before_start: bool = True
    """When True, the minimiser first confirms the predicate holds on the
    original input.  This prevents the caller from accidentally minimising a
    non-reproducing input down to an empty file."""


@dataclass(slots=True)
class MinimizationResult:
    original_size: int
    minimized: bytes
    minimized_size: int
    runs: int
    success: bool
    error: str | None = None

    @property
    def reduction_percent(self) -> float:
        if self.original_size == 0:
            return 0.0
        return 100.0 * (1.0 - self.minimized_size / self.original_size)

    def to_dict(self) -> dict[str, object]:
        return {
            "original_size": self.original_size,
            "minimized_size": self.minimized_size,
            "reduction_percent": round(self.reduction_percent, 2),
            "runs": self.runs,
            "success": self.success,
            "error": self.error,
        }


_MIN_CHUNK_SIZE: Final[int] = 1


class CorpusMinimizer:
    """Byte-level ddmin."""

    def __init__(self, config: MinimizerConfig | None = None) -> None:
        self._config = config or MinimizerConfig()

    @property
    def config(self) -> MinimizerConfig:
        return self._config

    # ------------------------------------------------------------------ public

    def minimize(
        self,
        data: bytes,
        predicate: MinimizationPredicate,
    ) -> MinimizationResult:
        """Return the smallest input satisfying ``predicate``.

        The predicate is called with candidate byte strings; it must return
        ``True`` when the candidate still reproduces the target crash.
        """
        original_size = len(data)
        run_counter = _RunCounter(self._config.max_runs)

        if not data:
            return MinimizationResult(
                original_size=0,
                minimized=b"",
                minimized_size=0,
                runs=0,
                success=False,
                error="Input is empty; nothing to minimise",
            )

        if self._config.verify_before_start:
            try:
                if not run_counter.call(predicate, data):
                    return MinimizationResult(
                        original_size=original_size,
                        minimized=data,
                        minimized_size=original_size,
                        runs=run_counter.runs,
                        success=False,
                        error=(
                            "The predicate does not hold on the original input; "
                            "the crash is not reproducible with this input"
                        ),
                    )
            except MinimizationBudgetExceeded:
                return MinimizationResult(
                    original_size=original_size,
                    minimized=data,
                    minimized_size=original_size,
                    runs=run_counter.runs,
                    success=False,
                    error="Run budget exhausted during verification",
                )

        current = data
        chunk_count = self._config.initial_chunk_count
        error: str | None = None

        try:
            while len(current) >= 2 * _MIN_CHUNK_SIZE and chunk_count <= len(current):
                chunks = _split(current, chunk_count)
                if len(chunks) < 2:
                    break

                reduced = False
                for index in range(len(chunks)):
                    candidate = b"".join(chunks[:index] + chunks[index + 1 :])
                    if not candidate:
                        continue
                    if run_counter.call(predicate, candidate):
                        current = candidate
                        chunk_count = max(chunk_count - 1, self._config.initial_chunk_count)
                        reduced = True
                        break

                if not reduced:
                    if chunk_count >= len(current):
                        break
                    chunk_count = min(chunk_count * 2, len(current))
        except MinimizationBudgetExceeded:
            error = (
                f"Run budget of {self._config.max_runs} exhausted before full "
                "minimisation"
            )

        return MinimizationResult(
            original_size=original_size,
            minimized=current,
            minimized_size=len(current),
            runs=run_counter.runs,
            success=True,
            error=error,
        )


# ---------------------------------------------------------------------- helpers


class _RunCounter:
    """Wraps a predicate with a hard run budget."""

    __slots__ = ("_budget", "runs")

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self.runs = 0

    def call(self, predicate: MinimizationPredicate, data: bytes) -> bool:
        if self.runs >= self._budget:
            raise MinimizationBudgetExceeded
        self.runs += 1
        return bool(predicate(data))


def _split(data: bytes, n: int) -> list[bytes]:
    """Split ``data`` into ``n`` contiguous chunks of roughly equal size."""
    if n <= 1 or len(data) <= 1:
        return [data]
    length = len(data)
    base = length // n
    remainder = length % n
    chunks: list[bytes] = []
    cursor = 0
    for index in range(n):
        size = base + (1 if index < remainder else 0)
        if size == 0:
            continue
        chunks.append(data[cursor : cursor + size])
        cursor += size
    return chunks
