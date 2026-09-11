"""SARIF 2.1.0 report renderer.

SARIF is the interchange format consumed by GitHub Code Scanning, Azure
DevOps, and other CI security dashboards.  KMCS emits a single run with:

* a tool driver carrying a rule per classification used in the report,
* a taxonomy naming every KMCS classification (used or not), so a consumer can
  map a result back even when the rule is not re-emitted,
* one result per finding, with a location only when the source location is
  a real ``file:line[:column]`` string.

The renderer never fabricates coordinates.  When a location cannot be parsed,
the result is emitted without a ``locations`` array, which is valid SARIF and
is what a "location unknown" result is supposed to look like.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from kmcs.core import models
from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportFormat,
    ReportRenderer,
)

__all__ = ["SARIFReportRenderer"]


_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)

_TOOL_NAME = "KMCS"
_TOOL_FULL_NAME = "Keyless Memory-Corruption Scanner"
_TOOL_URI = "https://github.com/kmcs-project/kmcs"

_TAXONOMY_NAME = "KMCS memory-safety classifications"
_TAXONOMY_GUID = "kmcs-memory-safety"

_LOCATION_PATTERN = re.compile(r"^(?P<file>.+?):(?P<line>\d+)(?::(?P<col>\d+))?$")


_SEVERITY_TO_LEVEL: dict[models.Severity, str] = {
    models.Severity.CRITICAL: "error",
    models.Severity.HIGH: "error",
    models.Severity.MEDIUM: "warning",
    models.Severity.LOW: "note",
    models.Severity.INFO: "note",
    models.Severity.UNKNOWN: "note",
}

_SEVERITY_TO_RANK: dict[models.Severity, str | None] = {
    models.Severity.CRITICAL: "9.0",
    models.Severity.HIGH: "7.5",
    models.Severity.MEDIUM: "5.5",
    models.Severity.LOW: "3.0",
    models.Severity.INFO: "1.0",
    models.Severity.UNKNOWN: None,
}

_SEVERITY_TO_TAXONOMY: dict[models.Severity, str] = {
    models.Severity.CRITICAL: "critical",
    models.Severity.HIGH: "high",
    models.Severity.MEDIUM: "medium",
    models.Severity.LOW: "low",
    models.Severity.INFO: "informational",
    models.Severity.UNKNOWN: "unknown",
}

_CLASSIFICATION_DESCRIPTIONS: dict[models.CrashClassification, str] = {
    models.CrashClassification.HEAP_BUFFER_OVERFLOW: (
        "A heap allocation is accessed outside its bounds."
    ),
    models.CrashClassification.STACK_BUFFER_OVERFLOW: (
        "A stack allocation is accessed outside its bounds."
    ),
    models.CrashClassification.GLOBAL_BUFFER_OVERFLOW: (
        "A static allocation is accessed outside its bounds."
    ),
    models.CrashClassification.USE_AFTER_FREE: (
        "A freed heap object is accessed through a dangling pointer."
    ),
    models.CrashClassification.DOUBLE_FREE: (
        "The same heap object is freed more than once."
    ),
    models.CrashClassification.INVALID_FREE: (
        "Free is called on a pointer that did not come from malloc."
    ),
    models.CrashClassification.OUT_OF_BOUNDS_READ: (
        "A read occurs outside the bounds of its allocation."
    ),
    models.CrashClassification.OUT_OF_BOUNDS_WRITE: (
        "A write occurs outside the bounds of its allocation."
    ),
    models.CrashClassification.NULL_POINTER_DEREFERENCE: (
        "A null pointer is dereferenced."
    ),
    models.CrashClassification.SEGMENTATION_FAULT: (
        "The process terminated with SIGSEGV or SIGBUS."
    ),
    models.CrashClassification.UNDEFINED_BEHAVIOR: (
        "Undefined behavior detected by a sanitizer."
    ),
    models.CrashClassification.MEMORY_LEAK: (
        "Memory allocated during the process was never freed."
    ),
    models.CrashClassification.UNKNOWN: (
        "Crash could not be confidently classified."
    ),
}


class SARIFReportRenderer(ReportRenderer):
    format = ReportFormat.SARIF

    # ------------------------------------------------------------------ public

    def render(self, context: ReportContext) -> str:
        return json.dumps(
            self.build_payload(context), indent=2, ensure_ascii=False
        )

    def build_payload(self, context: ReportContext) -> dict[str, Any]:
        return {
            "version": _SARIF_VERSION,
            "$schema": _SARIF_SCHEMA,
            "runs": [self._run(context)],
        }

    # ------------------------------------------------------------------ run

    def _run(self, context: ReportContext) -> dict[str, Any]:
        rules = self._build_rules(context.findings)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "fullName": _TOOL_FULL_NAME,
                    "informationUri": _TOOL_URI,
                    "version": context.kmcs_version,
                    "rules": rules,
                }
            },
            "taxonomies": [self._build_taxonomy()],
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": context.generated_at.strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            ],
            "results": [
                self._finding_to_result(finding, context)
                for finding in context.findings_sorted()
            ],
            "properties": {
                "generatedBy": "kmcs",
                "reportId": context.report_id,
                "campaignId": context.campaign_id,
                "summary": context.summary.to_dict(),
            },
        }
        return run

    # ------------------------------------------------------------------ rules

    @staticmethod
    def _build_rules(findings: list[models.Finding]) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for finding in findings:
            rule_id = finding.classification.value
            if rule_id in seen:
                continue
            description = _CLASSIFICATION_DESCRIPTIONS.get(
                finding.classification,
                finding.classification.value,
            )
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": finding.classification.value,
                "shortDescription": {"text": finding.classification.value},
                "fullDescription": {"text": description},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL[finding.severity]
                },
                "properties": {
                    "tags": ["memory-safety", "security"],
                    "kind": "memory-safety",
                },
            }
            rank = _SEVERITY_TO_RANK[finding.severity]
            if rank is not None:
                rule["properties"]["security-severity"] = rank
            seen[rule_id] = rule
        return sorted(seen.values(), key=lambda r: r["id"])

    # ------------------------------------------------------------------ taxonomy

    @staticmethod
    def _build_taxonomy() -> dict[str, Any]:
        taxa: list[dict[str, Any]] = []
        for index, classification in enumerate(models.CrashClassification):
            taxa.append(
                {
                    "id": str(index + 1),
                    "name": classification.value,
                    "shortDescription": {"text": classification.value},
                    "fullDescription": {
                        "text": _CLASSIFICATION_DESCRIPTIONS.get(
                            classification, classification.value
                        )
                    },
                }
            )
        return {
            "guid": _TAXONOMY_GUID,
            "name": _TAXONOMY_NAME,
            "shortDescription": {"text": _TAXONOMY_NAME},
            "taxa": taxa,
        }

    # ------------------------------------------------------------------ results

    def _finding_to_result(
        self, finding: models.Finding, context: ReportContext
    ) -> dict[str, Any]:
        crashes = context.crashes_for_finding(finding)
        representative = crashes[0] if crashes else None

        message_text = finding.title
        if len(crashes) > 1:
            message_text = f"{message_text} ({len(crashes)} crashing inputs)"

        result: dict[str, Any] = {
            "ruleId": finding.classification.value,
            "ruleIndex": self._rule_index_for(finding, context),
            "level": _SEVERITY_TO_LEVEL[finding.severity],
            "message": {"text": message_text},
            "fingerprints": {"kmcs/fingerprint": finding.fingerprint},
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint
            },
            "taxa": [
                {
                    "toolComponent": {"name": _TOOL_NAME},
                    "id": self._taxonomy_id_for(finding.classification),
                }
            ],
            "properties": {
                "findingId": finding.id,
                "severity": finding.severity.value,
                "classification": finding.classification.value,
                "occurrences": len(finding.crash_ids),
                "reproductionStatus": finding.reproduction_status.value,
            },
        }

        if representative is not None:
            location = self._location_for(representative)
            if location is not None:
                result["locations"] = [location]

        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation},
                }
            ]

        return result

    @staticmethod
    def _taxonomy_id_for(classification: models.CrashClassification) -> str:
        # The taxonomy lists classifications in enum order, so position + 1 is
        # the ID.  Computing it here means the two stay in sync.
        return str(list(models.CrashClassification).index(classification) + 1)

    @staticmethod
    def _rule_index_for(
        finding: models.Finding, context: ReportContext
    ) -> int:
        rules = sorted(
            {f.classification.value for f in context.findings}
        )
        return rules.index(finding.classification.value)

    @staticmethod
    def _location_for(crash: models.Crash) -> dict[str, Any] | None:
        if not crash.source_location:
            return None
        match = _LOCATION_PATTERN.match(crash.source_location)
        if match is None:
            return None

        file_path = match.group("file")
        line = int(match.group("line"))
        column = match.group("col")

        region: dict[str, Any] = {"startLine": line}
        if column is not None:
            region["startColumn"] = int(column)

        return {
            "physicalLocation": {
                "artifactLocation": {"uri": Path(file_path).as_posix()},
                "region": region,
            }
        }
