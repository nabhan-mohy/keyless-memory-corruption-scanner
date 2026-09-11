"""KMCS — Keyless Memory-Corruption Scanner.

A defensive fuzzing and memory-safety research platform.

KMCS orchestrates existing tools (AFL++, libFuzzer, AddressSanitizer, GDB, LLVM).
It does not generate exploits, shellcode, or weaponised payloads, and it must only
ever be pointed at targets the operator is authorised to test.
"""

from __future__ import annotations

__version__ = "0.7.0"
__all__ = ["__version__"]
