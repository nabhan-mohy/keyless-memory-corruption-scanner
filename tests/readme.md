cd /path/to/kmcs

python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# 1. Test suite
pytest -q

# 2. Coverage of the Phase 1 surface
pytest --cov=kmcs --cov-report=term-missing -q

# 3. Real execution — the startup sequence must actually create a workspace
kmcs --base-dir /tmp/kmcs-verify
echo "exit code: $?"

# 4. Verify the artefacts exist on disk
ls -la /tmp/kmcs-verify
sqlite3 /tmp/kmcs-verify/kmcs.sqlite3 ".tables"
sqlite3 /tmp/kmcs-verify/kmcs.sqlite3 "PRAGMA user_version;"

# 5. Machine-readable path
kmcs --base-dir /tmp/kmcs-verify --json | python -m json.tool

# 6. Idempotency — second run must not re-migrate or fail
kmcs --base-dir /tmp/kmcs-verify

# 7. Module invocation must match the console script
python -m kmcs --base-dir /tmp/kmcs-verify --json
