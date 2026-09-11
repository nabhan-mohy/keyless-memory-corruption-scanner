"""Minimiser: correctness on synthetic predicates, budget handling."""

from __future__ import annotations

from kmcs.corpus.minimizer import (
    CorpusMinimizer,
    MinimizationResult,
    MinimizerConfig,
)


def _predicate_contains(needle: bytes):
    """Return a predicate that holds iff the candidate contains ``needle``."""

    def predicate(candidate: bytes) -> bool:
        return needle in candidate

    return predicate


class TestBasicMinimisation:
    def test_finds_a_minimal_containing_input(self) -> None:
        # The "bug" is triggered by the substring "TRIGGER".  Everything else
        # can go away.
        data = b"\x00" * 50 + b"TRIGGER" + b"\xFF" * 50
        result = CorpusMinimizer(MinimizerConfig(max_runs=5000)).minimize(
            data, _predicate_contains(b"TRIGGER")
        )

        assert result.success is True
        assert b"TRIGGER" in result.minimized
        assert result.minimized_size <= len(b"TRIGGER") + 2  # small slack
        assert result.minimized_size < result.original_size

    def test_trivial_input_is_left_alone(self) -> None:
        result = CorpusMinimizer().minimize(b"T", _predicate_contains(b"T"))
        assert result.success is True
        assert result.minimized == b"T"

    def test_empty_input_returns_error(self) -> None:
        result = CorpusMinimizer().minimize(b"", lambda _: True)
        assert result.success is False
        assert result.error is not None


class TestVerification:
    def test_non_reproducing_input_is_reported(self) -> None:
        result = CorpusMinimizer().minimize(
            b"this does not contain the trigger", _predicate_contains(b"TRIGGER")
        )
        assert result.success is False
        assert "not reproducible" in (result.error or "").lower()

    def test_verification_can_be_skipped(self) -> None:
        # When verification is disabled, the minimiser proceeds even if the
        # predicate never holds; the result is the unmodified input.
        minimizer = CorpusMinimizer(
            MinimizerConfig(verify_before_start=False, max_runs=10)
        )
        result = minimizer.minimize(b"abcdef", lambda _: False)
        assert result.success is True
        assert result.minimized == b"abcdef"


class TestBudget:
    def test_budget_exhaustion_is_reported(self) -> None:
        # A predicate that holds only on the full input forces the minimiser
        # to try many removals before giving up.
        target = b"abcdefghijklmnop"
        minimizer = CorpusMinimizer(MinimizerConfig(max_runs=5))
        result = minimizer.minimize(
            target, lambda candidate: candidate == target
        )
        # The run budget will be exhausted; the result is still valid, just
        # not fully minimal.
        assert isinstance(result, MinimizationResult)
        assert result.runs <= 5
        assert result.error is not None
        assert "budget" in result.error.lower()


class TestReduction:
    def test_single_byte_trigger(self) -> None:
        data = b"A" * 200 + b"!" + b"B" * 200
        result = CorpusMinimizer(MinimizerConfig(max_runs=5000)).minimize(
            data, _predicate_contains(b"!")
        )
        assert b"!" in result.minimized
        assert result.minimized_size <= 3

    def test_two_disjoint_triggers(self) -> None:
        # The predicate requires both "AAA" and "BBB".  Neither can be removed.
        def predicate(candidate: bytes) -> bool:
            return b"AAA" in candidate and b"BBB" in candidate

        data = b"XXXAAAXXXBBBXXX" * 4
        result = CorpusMinimizer(MinimizerConfig(max_runs=10_000)).minimize(
            data, predicate
        )
        assert b"AAA" in result.minimized
        assert b"BBB" in result.minimized
        assert result.minimized_size <= 8


class TestDeterminism:
    def test_same_input_same_result(self) -> None:
        data = b"\x00" * 30 + b"TRIGGER" + b"\xFF" * 30
        cfg = MinimizerConfig(max_runs=2000)
        result_a = CorpusMinimizer(cfg).minimize(data, _predicate_contains(b"TRIGGER"))
        result_b = CorpusMinimizer(cfg).minimize(data, _predicate_contains(b"TRIGGER"))
        assert result_a.minimized == result_b.minimized
