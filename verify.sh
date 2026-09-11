#!/usr/bin/env bash
# Verify KMCS is installed and functional.
set -e
cd "$(dirname "$0")"
source .venv/bin/activate

echo "== KMCS version =="
python -c "import kmcs; print(kmcs.__version__)"

echo
echo "== static test suite =="
pytest tests -m "not integration" -q

echo
echo "== demo lab =="
cd src/kmcs/examples/vulnerable
make clean >/dev/null 2>&1 || true
make >/dev/null
printf 'AAAAAAAAAAAAAAAAAAAA' | ./heap_overflow >/dev/null 2>/tmp/asan-check.txt || true
if grep -q "ERROR: AddressSanitizer: heap-buffer-overflow" /tmp/asan-check.txt; then
    echo "demo target crashes under ASan: OK"
else
    echo "demo target did not produce expected ASan report"
    exit 1
fi
