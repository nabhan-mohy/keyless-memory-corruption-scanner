"""Fuzzer adapters.

Each adapter wraps one real fuzzing engine.  They share a common interface so
that campaign management (Phase 5) can drive them uniformly, but each one talks
to its engine's actual command line and parses its engine's actual output.
"""

from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerConfig,
    FuzzerError,
    FuzzerStartError,
    FuzzerStats,
    FuzzerStatus,
    FuzzerUnavailableError,
)
from kmcs.fuzzers.aflpp import AFLPlusPlusAdapter
from kmcs.fuzzers.libfuzzer import LibFuzzerAdapter
from kmcs.fuzzers.honggfuzz import HonggfuzzAdapter

__all__ = [
    "FuzzerAdapter",
    "FuzzerAvailability",
    "FuzzerConfig",
    "FuzzerError",
    "FuzzerStartError",
    "FuzzerStats",
    "FuzzerStatus",
    "FuzzerUnavailableError",
    "AFLPlusPlusAdapter",
    "LibFuzzerAdapter",
    "HonggfuzzAdapter",
]
