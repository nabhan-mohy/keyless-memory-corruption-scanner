"""Deterministic mutation engine.

The engine is a thin layer over :class:`random.Random`.  Given the same seed
and the same input bytes, it produces exactly the same mutated output — which
means a crash found during a campaign can be re-derived by anyone who knows
the seed.

KMCS does **not** replace the fuzzer's own mutation strategies.  AFL++ and
libFuzzer already implement sophisticated, coverage-guided mutation.  This
engine exists for two narrower purposes:

* generating an initial, diverse corpus when the researcher has only a few
  seed files,
* and reproducing a specific mutation for regression testing.

Both use cases require reproducibility above raw power.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Mutation",
    "MutationConfig",
    "MutationEngine",
]


class Mutation(str, Enum):
    BIT_FLIP = "bit-flip"
    BYTE_SUBSTITUTION = "byte-substitution"
    BYTE_INSERTION = "byte-insertion"
    BYTE_DELETION = "byte-deletion"
    ARITHMETIC = "arithmetic"
    INTERESTING_VALUE = "interesting-value"
    BLOCK_COPY = "block-copy"
    BLOCK_MOVE = "block-move"
    SPLICE = "splice"


class MutationConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    seed: int = Field(default=0, ge=0, le=2**63 - 1)
    max_output_bytes: int = Field(default=1 << 20, gt=0)
    bit_flip_max_bits: int = Field(default=8, ge=1, le=64)
    byte_substitution_max: int = Field(default=16, ge=1, le=1024)
    insert_max_bytes: int = Field(default=64, ge=1, le=4096)
    delete_max_bytes: int = Field(default=64, ge=1, le=4096)
    block_max_bytes: int = Field(default=256, ge=1, le=65536)
    arithmetic_max_delta: int = Field(default=16, ge=1, le=4096)


_INTERESTING_BYTES: tuple[int, ...] = (
    0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF,
    0x09, 0x0A, 0x0D, 0x20,
)

# Default weights.  Roughly mirrors the distribution of mutation operators in
# coverage-guided fuzzers: many small flips, some inserts/deletes, occasional
# large structural changes.
_DEFAULT_WEIGHTS: dict[Mutation, int] = {
    Mutation.BIT_FLIP: 30,
    Mutation.BYTE_SUBSTITUTION: 25,
    Mutation.ARITHMETIC: 10,
    Mutation.INTERESTING_VALUE: 10,
    Mutation.BYTE_INSERTION: 8,
    Mutation.BYTE_DELETION: 7,
    Mutation.BLOCK_COPY: 5,
    Mutation.BLOCK_MOVE: 3,
    Mutation.SPLICE: 2,
}


class MutationEngine:
    """A deterministic mutation engine.

    The engine holds one :class:`random.Random` instance, seeded at
    construction.  Every method that consumes randomness advances that single
    stream, so calling ``mutate(data)`` twice in a row produces two different
    (but reproducible) mutations.
    """

    _WEIGHTS: ClassVar[dict[Mutation, int]] = _DEFAULT_WEIGHTS

    def __init__(self, config: MutationConfig | None = None) -> None:
        self._config = config or MutationConfig()
        self._rng = random.Random(self._config.seed)

    @property
    def config(self) -> MutationConfig:
        return self._config

    # ------------------------------------------------------------------ public

    def choose_mutation(self) -> Mutation:
        """Pick a mutation operator by weighted choice."""
        population = list(self._WEIGHTS.keys())
        weights = [self._WEIGHTS[m] for m in population]
        return self._rng.choices(population, weights=weights, k=1)[0]

    def mutate(
        self,
        data: bytes,
        *,
        other: bytes | None = None,
        mutation: Mutation | None = None,
    ) -> bytes:
        """Apply one mutation to ``data``.

        ``other`` is only used by :attr:`Mutation.SPLICE`; when splicing is
        chosen but ``other`` is not provided, the call falls back to a byte
        substitution rather than failing.
        """
        chosen = mutation or self.choose_mutation()

        if chosen is Mutation.BIT_FLIP:
            return self._bit_flip(data)
        if chosen is Mutation.BYTE_SUBSTITUTION:
            return self._byte_substitution(data)
        if chosen is Mutation.ARITHMETIC:
            return self._arithmetic(data)
        if chosen is Mutation.INTERESTING_VALUE:
            return self._interesting_value(data)
        if chosen is Mutation.BYTE_INSERTION:
            return self._byte_insertion(data)
        if chosen is Mutation.BYTE_DELETION:
            return self._byte_deletion(data)
        if chosen is Mutation.BLOCK_COPY:
            return self._block_copy(data)
        if chosen is Mutation.BLOCK_MOVE:
            return self._block_move(data)
        if chosen is Mutation.SPLICE:
            if other is None:
                return self._byte_substitution(data)
            return self._splice(data, other)

        return data  # pragma: no cover - the enum is exhaustive

    # ------------------------------------------------------------------ operators

    def _bit_flip(self, data: bytes) -> bytes:
        if not data:
            return bytes([self._rng.randrange(256)])

        buf = bytearray(data)
        count = self._rng.randint(1, self._config.bit_flip_max_bits)
        for _ in range(count):
            position = self._rng.randrange(len(buf))
            buf[position] ^= 1 << self._rng.randrange(8)
        return bytes(buf)

    def _byte_substitution(self, data: bytes) -> bytes:
        if not data:
            return bytes([self._rng.randrange(256)])

        buf = bytearray(data)
        count = min(self._rng.randint(1, self._config.byte_substitution_max), len(buf))
        for _ in range(count):
            position = self._rng.randrange(len(buf))
            buf[position] = self._rng.randrange(256)
        return bytes(buf)

    def _arithmetic(self, data: bytes) -> bytes:
        if not data:
            return bytes([self._rng.randrange(256)])

        buf = bytearray(data)
        count = min(self._rng.randint(1, 4), len(buf))
        for _ in range(count):
            position = self._rng.randrange(len(buf))
            delta = self._rng.randint(-self._config.arithmetic_max_delta,
                                       self._config.arithmetic_max_delta)
            buf[position] = (buf[position] + delta) & 0xFF
        return bytes(buf)

    def _interesting_value(self, data: bytes) -> bytes:
        if not data:
            return bytes([self._rng.choice(_INTERESTING_BYTES)])

        buf = bytearray(data)
        count = min(self._rng.randint(1, 4), len(buf))
        for _ in range(count):
            position = self._rng.randrange(len(buf))
            buf[position] = self._rng.choice(_INTERESTING_BYTES)
        return bytes(buf)

    def _byte_insertion(self, data: bytes) -> bytes:
        room = self._config.max_output_bytes - len(data)
        if room <= 0:
            return self._byte_substitution(data)

        count = min(self._rng.randint(1, self._config.insert_max_bytes), room)
        position = self._rng.randint(0, len(data))
        blob = bytes(self._rng.randrange(256) for _ in range(count))
        return data[:position] + blob + data[position:]

    def _byte_deletion(self, data: bytes) -> bytes:
        if len(data) <= 1:
            return data

        count = min(self._rng.randint(1, self._config.delete_max_bytes), len(data) - 1)
        position = self._rng.randint(0, len(data) - count)
        return data[:position] + data[position + count:]

    def _block_copy(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._byte_substitution(data)

        room = self._config.max_output_bytes - len(data)
        if room <= 0:
            return self._byte_substitution(data)

        block_size = min(
            self._rng.randint(1, self._config.block_max_bytes),
            len(data),
            room,
        )
        source_start = self._rng.randint(0, len(data) - block_size)
        block = data[source_start:source_start + block_size]
        destination = self._rng.randint(0, len(data))
        return data[:destination] + block + data[destination:]

    def _block_move(self, data: bytes) -> bytes:
        if len(data) < 2:
            return self._byte_substitution(data)

        block_size = min(self._rng.randint(1, self._config.block_max_bytes), len(data) - 1)
        source_start = self._rng.randint(0, len(data) - block_size)
        block = data[source_start:source_start + block_size]
        remainder = data[:source_start] + data[source_start + block_size:]
        destination = self._rng.randint(0, len(remainder))
        return remainder[:destination] + block + remainder[destination:]

    def _splice(self, data: bytes, other: bytes) -> bytes:
        if not data or not other:
            return self._byte_substitution(data or other)

        cut_a = self._rng.randint(1, len(data))
        cut_b = self._rng.randint(0, len(other))
        combined = data[:cut_a] + other[cut_b:]
        if len(combined) > self._config.max_output_bytes:
            combined = combined[: self._config.max_output_bytes]
        return combined
