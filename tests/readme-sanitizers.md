cd /path/to/kmcs
source .venv/bin/activate

# 1. Static tests: signals, options, sanitizer metadata, parser.
pytest tests/test_signals.py tests/test_sanitizer_options.py \
       tests/test_sanitizers.py tests/test_crash_parser.py -q

# 2. Monitor tests using shell scripts — should pass anywhere POSIX.
pytest tests/test_crash_monitor.py -q -m "not integration"

# 3. Detector tests (uses the DB).
pytest tests/test_crash_detector.py -q

# 4. Real ASan crash detection, if a C compiler is present.
pytest tests/test_crash_monitor.py::TestRealASanCrash -q -m integration

# 5. Sanitizer availability probes against the real toolchain.
python -c "
from kmcs.targets.detector import EnvironmentDetector
from kmcs.sanitizers import SanitizerRegistry
import json
report = SanitizerRegistry.detect_all(EnvironmentDetector())
print(json.dumps({k.value: v.to_dict() for k, v in report.items()}, indent=2))
"

# 6. Full suite.
pytest -q

# 7. Manual end-to-end: compile the demo target, run it, inspect the report.
clang -fsanitize=address -fno-omit-frame-pointer -g \
      tests/fixtures/demo_target/vulnerable.c -o /tmp/kmcs-demo
python -c "
from pathlib import Path
from kmcs.analysis.crash_monitor import CrashMonitor, MonitorConfig
obs = CrashMonitor().run(
    MonitorConfig(target=Path('/tmp/kmcs-demo'), timeout_seconds=5.0),
    input_bytes=b'A'*32,
)
print('exit:', obs.exit_code, 'signal:', obs.signal_number, 'timed_out:', obs.timed_out)
print('classification:', obs.report.classification.value)
print('source location:', obs.report.source_location)
print('frames:', len(obs.report.stack_frames))
print('evidence dir:', obs.evidence_dir)
import json; print(json.dumps(obs.to_dict(), indent=2))
"
