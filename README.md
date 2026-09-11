# KMCS — Keyless Memory-Corruption Scanner

KMCS is a **defensive** fuzzing and memory-safety research platform. It orchestrates
existing, well-understood tools (AFL++, libFuzzer, AddressSanitizer, GDB, LLVM) to help
researchers answer one question:

> What crashed, why did it crash, is it reproducible, and how do I document the finding?

KMCS is **not** an exploitation framework. It does not generate exploits, shellcode,
payloads, or persistence mechanisms. See `docs/threat-model.md` (Phase 7).

## Status

Phase 1 — Foundation and Core.

Implemented and testable today:

- portable, environment-driven configuration
- thread-safe internal event bus
- job state machine and registry
- database-independent domain models
- SQLite schema with versioned migrations and a real health check
- a headless startup sequence (`kmcs`)

Not implemented yet (do not expect it to work): fuzzing, sanitizers, crash analysis,
corpus handling, campaigns, reporting.

## Install

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Run

```bash
kmcs                       # human-readable startup report
kmcs --json                # machine-readable startup report
kmcs --base-dir /tmp/kmcs  # use an explicit data directory
python -m kmcs             # equivalent to the `kmcs` entry point
```

Exit code `0` means the workspace and database are ready. Any non-zero code means
startup failed; the reason is printed to stderr.

## Test

```bash
pytest -q
pytest --cov=kmcs --cov-report=term-missing
```

## Data locations

KMCS never writes into your source tree. Resolution order:

1. `--base-dir`
2. `$KMCS_HOME`
3. `$XDG_DATA_HOME/kmcs` (Linux), `~/Library/Application Support/KMCS` (macOS),
   `%LOCALAPPDATA%\KMCS` (Windows)
