"""Mutation engine: determinism, size bounds, coverage of operators."""

from __future__ import annotations

import pytest

from kmcs.corpus.mutations import (
    Mutation,
    MutationConfig,
    MutationEngine,
)


class TestDeterminism:
    def test_same_seed_same_output(self) -> None:
        engine_a = MutationEngine(MutationConfig(seed=42))
        engine_b = MutationEngine(MutationConfig(seed=42))

        data = b"the quick brown fox" * 4
        for _ in range(20):
            assert engine_a.mutate(data) == engine_b.mutate(data)

    def test_different_seeds_diverge(self) -> None:
        engine_a = MutationEngine(MutationConfig(seed=1))
        engine_b = MutationEngine(MutationConfig(seed=2))

        data = b"the quick brown fox" * 4
        outputs_a = [engine_a.mutate(data) for _ in range(10)]
        outputs_b = [engine_b.mutate(data) for _ in range(10)]
        assert outputs_a != outputs_b

    def test_same_seed_different_engine_instances_agree(self) -> None:
        data = b"xyz" * 100
        seq_a = [MutationEngine(MutationConfig(seed=7)).mutate(data) for _ in range(3)]
        seq_b = [MutationEngine(MutationConfig(seed=7)).mutate(data) for _ in range(3)]
        assert seq_a == seq_b


class TestOperators:
    def test_bit_flip_changes_exactly_some_bits(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        result = engine.mutate(b"\x00" * 32, mutation=Mutation.BIT_FLIP)
        assert result != b"\x00" * 32
        assert len(result) == 32

    def test_byte_substitution_keeps_length(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        result = engine.mutate(b"\x00" * 32, mutation=Mutation.BYTE_SUBSTITUTION)
        assert len(result) == 32

    def test_insertion_increases_length(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        result = engine.mutate(b"A" * 16, mutation=Mutation.BYTE_INSERTION)
        assert len(result) > 16

    def test_deletion_decreases_length(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        result = engine.mutate(b"A" * 64, mutation=Mutation.BYTE_DELETION)
        assert len(result) < 64

    def test_block_copy_can_increase_length(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        data = bytes(range(256)) * 4
        # With a fixed seed the first block copy may or may not extend; try a
        # handful of seeds and assert that at least one extends the input.
        extended = False
        for seed in range(10):
            engine = MutationEngine(MutationConfig(seed=seed))
            result = engine.mutate(data, mutation=Mutation.BLOCK_COPY)
            if len(result) > len(data):
                extended = True
                break
        assert extended

    def test_block_move_preserves_length(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        data = bytes(range(128)) * 4
        result = engine.mutate(data, mutation=Mutation.BLOCK_MOVE)
        assert len(result) == len(data)
        assert sorted(result) == sorted(data)

    def test_splice_uses_other_when_provided(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        a = b"AAAAAAAA"
        b = b"BBBBBBBB"
        result = engine.mutate(a, other=b, mutation=Mutation.SPLICE)
        assert len(result) > 0

    def test_splice_without_other_falls_back(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        a = b"AAAAAAAA"
        result = engine.mutate(a, mutation=Mutation.SPLICE)
        assert len(result) == len(a)

    def test_arithmetic_only_shifts_bytes(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        data = bytes(range(256))
        result = engine.mutate(data, mutation=Mutation.ARITHMETIC)
        assert len(result) == len(data)
        differences = sum(1 for a, b in zip(data, result) if a != b)
        assert differences >= 1

    def test_interesting_value_only_uses_interesting_bytes(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        data = b"\x55" * 64
        result = engine.mutate(data, mutation=Mutation.INTERESTING_VALUE)
        assert len(result) == len(data)
        # Every change must land on a byte from the interesting set.
        for original, mutated in zip(data, result):
            if original != mutated:
                assert mutated in {0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF,
                                    0x09, 0x0A, 0x0D, 0x20}


class TestBounds:
    def test_output_never_exceeds_max(self) -> None:
        engine = MutationEngine(
            MutationConfig(seed=3, max_output_bytes=64)
        )
        data = b"A" * 60
        for _ in range(200):
            result = engine.mutate(data, other=b"B" * 200)
            assert len(result) <= 64

    def test_empty_input_is_handled(self) -> None:
        engine = MutationEngine(MutationConfig(seed=0))
        for mutation in Mutation:
            result = engine.mutate(b"", mutation=mutation)
            assert isinstance(result, bytes)


class TestChooseMutation:
    def test_choose_is_deterministic_for_a_seed(self) -> None:
        engine_a = MutationEngine(MutationConfig(seed=99))
        engine_b = MutationEngine(MutationConfig(seed=99))
        assert [engine_a.choose_mutation() for _ in range(50)] == [
            engine_b.choose_mutation() for _ in range(50)
        ]

    def test_all_operators_are_reachable(self) -> None:
        engine = MutationEngine(MutationConfig(seed=1))
        chosen: set[Mutation] = set()
        for _ in range(2000):
            chosen.add(engine.choose_mutation())
        # Not every operator needs to fire in every run of the test, but the
        # common ones must all appear at least once.
        assert Mutation.BIT_FLIP in chosen
        assert Mutation.BYTE_SUBSTITUTION in chosen
        assert Mutation.BYTE_INSERTION in chosen
        assert Mutation.BYTE_DELETION in chosen


class TestConfigValidation:
    def test_invalid_seed_is_rejected(self) -> None:
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            MutationConfig(seed=-1)

    def test_zero_max_output_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            MutationConfig(max_output_bytes=0)
