"""Domain model defaults and validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from kmcs.core import models


def test_target_defaults() -> None:
    target = models.Target(name="libpng")

    assert target.id
    assert target.description == ""
    assert target.build_configuration is models.BuildConfiguration.DEBUG
    assert target.sanitizers == []
    assert target.metadata == {}
    assert target.created_at.tzinfo is not None
    assert target.updated_at.tzinfo is not None


def test_ids_are_unique() -> None:
    assert models.Target(name="a").id != models.Target(name="b").id


def test_target_name_is_trimmed() -> None:
    assert models.Target(name="  libpng  ").name == "libpng"


def test_blank_target_name_is_rejected() -> None:
    with pytest.raises(ValidationError):
        models.Target(name="   ")


def test_touch_advances_updated_at() -> None:
    target = models.Target(name="libpng")
    before = target.updated_at
    target.touch()
    assert target.updated_at >= before


def test_campaign_defaults() -> None:
    campaign = models.Campaign(name="png run", target_id="abc")

    assert campaign.fuzzer is models.FuzzerKind.AFLPP
    assert campaign.status is models.CampaignStatus.PENDING
    assert campaign.workers == 1
    assert campaign.sanitizers == []


def test_campaign_worker_bounds() -> None:
    with pytest.raises(ValidationError):
        models.Campaign(name="x", target_id="abc", workers=0)


def test_crash_defaults_are_conservative() -> None:
    crash = models.Crash()

    assert crash.classification is models.CrashClassification.UNKNOWN
    assert crash.severity is models.Severity.UNKNOWN
    assert crash.reproduction_status is models.ReproductionStatus.NOT_TESTED
    assert crash.fingerprint is None


def test_finding_requires_title_and_fingerprint() -> None:
    with pytest.raises(ValidationError):
        models.Finding(title="", fingerprint="abc")
    with pytest.raises(ValidationError):
        models.Finding(title="ok", fingerprint="")

    finding = models.Finding(title="heap overflow in parse_chunk", fingerprint="deadbeef")
    assert finding.crash_ids == []


def test_report_defaults() -> None:
    report = models.Report(name="campaign summary")
    assert report.format is models.ReportFormat.JSON
    assert report.finding_ids == []


def test_classification_values_match_documented_names() -> None:
    values = {item.value for item in models.CrashClassification}
    assert "heap-buffer-overflow" in values
    assert "use-after-free" in values
    assert "unknown" in values
    assert len(values) == len(models.CrashClassification)
