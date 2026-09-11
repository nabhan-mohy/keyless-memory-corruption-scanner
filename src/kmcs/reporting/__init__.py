"""Report generation for KMCS.

Every renderer consumes the same :class:`~kmcs.reporting.base.ReportContext`
and emits a :class:`~kmcs.reporting.base.RenderedReport`.  Adding a new format
is a matter of implementing one renderer and registering it in
:mod:`kmcs.reporting.generator`.
"""

from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportError,
    ReportFormat,
    ReportRenderer,
    ReportSection,
    ReportSummary,
)
from kmcs.reporting.generator import ReportGenerator

__all__ = [
    "RenderedReport",
    "ReportContext",
    "ReportError",
    "ReportFormat",
    "ReportRenderer",
    "ReportSection",
    "ReportSummary",
    "ReportGenerator",
]
