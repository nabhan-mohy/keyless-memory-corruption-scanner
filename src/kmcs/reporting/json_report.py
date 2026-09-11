"""JSON report renderer.

The JSON schema is versioned (``"schema": "kmcs.report.v1"``).  Every field
that appears in one report appears in every report of the same schema version,
even when the value is ``null``.  That stability is what lets a downstream
consumer parse the output without guessing.
"""

from __future__ import annotations

import json
from typing import Any

from kmcs.core import models
from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportFormat,
    ReportRenderer,
)

__all__ = ["JSONReportRenderer"]

_SCHEMA_VERSION = "kmcs.report.v1"


class JSONReportRenderer(ReportRenderer):
    format = ReportFormat.JSON

    # ------------------------------------------------------------------ public

    def render(self, context: ReportContext) -> str:
        return json.dumps(
            self.build_payload(context),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )

    def build_payload(self, context: ReportContext) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": _SCHEMA_VERSION,
            "report_id": context.report_id,
            "generated_at": context.generated_at.isoformat(),
            "kmcs_version": context.kmcs_version,
            "title": context.title,
            "summary": context.summary.to_dict(),
        }

        if context.metadata:
            payload["metadata"] = dict(context.metadata)

        if context.section.include_campaigns and context.campaign is not None:
            payload["campaign"] = self._campaign(context.campaign)

        if context.section.include_findings:
            payload["findings"] = [
                self._finding(f, context) for f in context.findings_sorted()
            ]

        if context.section.include_crashes:
            payload["crashes"] = [self._crash(c) for c in context.crashes]

        if context.section.include_campaigns:
            payload["campaigns"] = [self._campaign(c) for c in context.campaigns]

        if context.section.include_targets:
            payload["targets"] = [self._target(t) for t in context.targets]

        if context.section.include_corpora:
            payload["corpora"] = [self._corpus(c) for c in context.corpora]

        if context.section.include_telemetry and context.telemetry is not None:
            payload["telemetry"] = context.telemetry

        return payload

    # ------------------------------------------------------------------ entities

    def _finding(
        self, finding: models.Finding, context: ReportContext
    ) -> dict[str, Any]:
        crashes = context.crashes_for_finding(finding)
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "fingerprint": finding.fingerprint,
            "classification": finding.classification.value,
            "severity": finding.severity.value,
            "reproduction_status": finding.reproduction_status.value,
            "target_id": finding.target_id,
            "crash_ids": list(finding.crash_ids),
            "crash_count": len(finding.crash_ids),
            "remediation": finding.remediation,
            "created_at": finding.created_at.isoformat(),
            "updated_at": finding.updated_at.isoformat(),
            "metadata": dict(finding.metadata),
            "sample_crashes": [
                {
                    "id": c.id,
                    "signal": c.signal,
                    "exit_code": c.exit_code,
                    "source_location": c.source_location,
                    "input_path": str(c.input_path) if c.input_path else None,
                }
                for c in crashes[:5]
            ],
        }

    @staticmethod
    def _crash(crash: models.Crash) -> dict[str, Any]:
        return {
            "id": crash.id,
            "campaign_id": crash.campaign_id,
            "target_id": crash.target_id,
            "description": crash.description,
            "signal": crash.signal,
            "exit_code": crash.exit_code,
            "sanitizer": crash.sanitizer.value if crash.sanitizer else None,
            "classification": crash.classification.value,
            "severity": crash.severity.value,
            "fingerprint": crash.fingerprint,
            "source_location": crash.source_location,
            "reproduction_status": crash.reproduction_status.value,
            "input_path": str(crash.input_path) if crash.input_path else None,
            "evidence_path": str(crash.evidence_path) if crash.evidence_path else None,
            "stack_trace": crash.stack_trace,
            "stdout_excerpt": crash.stdout_excerpt,
            "stderr_excerpt": crash.stderr_excerpt,
            "created_at": crash.created_at.isoformat(),
            "metadata": dict(crash.metadata),
        }

    @staticmethod
    def _campaign(campaign: models.Campaign) -> dict[str, Any]:
        return {
            "id": campaign.id,
            "name": campaign.name,
            "description": campaign.description,
            "target_id": campaign.target_id,
            "corpus_id": campaign.corpus_id,
            "fuzzer": campaign.fuzzer.value,
            "sanitizers": [s.value for s in campaign.sanitizers],
            "workers": campaign.workers,
            "duration_seconds": campaign.duration_seconds,
            "status": campaign.status.value,
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "finished_at": (
                campaign.finished_at.isoformat() if campaign.finished_at else None
            ),
            "created_at": campaign.created_at.isoformat(),
            "metadata": dict(campaign.metadata),
        }

    @staticmethod
    def _target(target: models.Target) -> dict[str, Any]:
        return {
            "id": target.id,
            "name": target.name,
            "description": target.description,
            "source_dir": str(target.source_dir) if target.source_dir else None,
            "build_dir": str(target.build_dir) if target.build_dir else None,
            "executable": str(target.executable) if target.executable else None,
            "compiler": target.compiler,
            "build_configuration": target.build_configuration.value,
            "sanitizers": [s.value for s in target.sanitizers],
            "created_at": target.created_at.isoformat(),
            "metadata": dict(target.metadata),
        }

    @staticmethod
    def _corpus(corpus: models.Corpus) -> dict[str, Any]:
        return {
            "id": corpus.id,
            "name": corpus.name,
            "description": corpus.description,
            "target_id": corpus.target_id,
            "path": str(corpus.path) if corpus.path else None,
            "file_count": corpus.file_count,
            "total_bytes": corpus.total_bytes,
            "created_at": corpus.created_at.isoformat(),
            "metadata": dict(corpus.metadata),
        }
