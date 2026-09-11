"""Crash analysis: signals, parsing, classification, fingerprinting, severity,
and deduplication."""

from kmcs.analysis.classifier import (
    ClassificationResult,
    Confidence,
    CrashClassifier,
)
from kmcs.analysis.crash_detector import (
    CrashDetector,
    DetectionResult,
    DetectionError,
)
from kmcs.analysis.crash_monitor import (
    CrashMonitor,
    CrashObservation,
    MonitorConfig,
    MonitorError,
)
from kmcs.analysis.crash_parser import (
    AccessType,
    CrashParser,
    CrashReport,
    SanitizerReport,
    StackFrame,
    parse_crash,
)
from kmcs.analysis.deduplicator import (
    CrashDeduplicator,
    CrashGroup,
    DeduplicationResult,
)
from kmcs.analysis.fingerprint import (
    CrashFingerprint,
    CrashFingerprinter,
    FingerprintConfig,
)
from kmcs.analysis.severity import SeverityAssessment, SeverityAssessor
from kmcs.analysis.signals import (
    SIGNALS,
    SignalInfo,
    signal_description,
    signal_info,
    signal_name,
)

__all__ = [
    # signals
    "SIGNALS", "SignalInfo", "signal_description", "signal_info", "signal_name",
    # parser
    "AccessType", "CrashParser", "CrashReport", "SanitizerReport", "StackFrame",
    "parse_crash",
    # monitor
    "CrashMonitor", "CrashObservation", "MonitorConfig", "MonitorError",
    # detector
    "CrashDetector", "DetectionResult", "DetectionError",
    # classifier
    "ClassificationResult", "Confidence", "CrashClassifier",
    # fingerprint
    "CrashFingerprint", "CrashFingerprinter", "FingerprintConfig",
    # severity
    "SeverityAssessment", "SeverityAssessor",
    # deduplicator
    "CrashDeduplicator", "CrashGroup", "DeduplicationResult",
]
