"""Telemetry aggregator: correctness, missing values, thread safety."""

from __future__ import annotations

import threading

from kmcs.campaigns.telemetry import TelemetryAggregator


class TestUpdates:
    def test_register_and_read(self) -> None:
        agg = TelemetryAggregator(campaign_id="c1")
        record = agg.register_worker(0)
        assert record.worker_index == 0
        assert record.status == "not-started"

    def test_register_is_idempotent(self) -> None:
        agg = TelemetryAggregator()
        a = agg.register_worker(0)
        b = agg.register_worker(0)
        assert a is b

    def test_update_sets_fields(self) -> None:
        agg = TelemetryAggregator()
        agg.update(0, status="running", executions=100)
        worker = agg.worker(0)
        assert worker is not None
        assert worker.status == "running"
        assert worker.executions == 100

    def test_update_rejects_unknown_field(self) -> None:
        agg = TelemetryAggregator()
        try:
            agg.update(0, not_a_field=1)
        except AttributeError:
            pass
        else:  # pragma: no cover
            raise AssertionError("expected AttributeError")

    def test_increment_from_zero(self) -> None:
        agg = TelemetryAggregator()
        agg.increment(0, "artifacts_seen")
        agg.increment(0, "artifacts_seen")
        assert agg.worker(0).artifacts_seen == 2


class TestSnapshot:
    def test_empty_snapshot_has_no_totals(self) -> None:
        snapshot = TelemetryAggregator().snapshot()
        assert snapshot.workers == []
        assert snapshot.total_executions is None
        assert snapshot.total_crashes is None
        assert snapshot.total_artifacts_seen == 0

    def test_missing_values_do_not_become_zero(self) -> None:
        agg = TelemetryAggregator()
        agg.update(0, executions=100)
        agg.update(1, executions=None)
        snapshot = agg.snapshot()
        assert snapshot.total_executions == 100

    def test_totals_sum_correctly(self) -> None:
        agg = TelemetryAggregator()
        agg.update(0, executions=100, executions_per_second=10.0, crashes=1)
        agg.update(1, executions=200, executions_per_second=20.0, crashes=2)
        snapshot = agg.snapshot()
        assert snapshot.total_executions == 300
        assert snapshot.total_executions_per_second == 30.0
        assert snapshot.total_crashes == 3

    def test_coverage_is_a_mean(self) -> None:
        agg = TelemetryAggregator()
        agg.update(0, coverage_percent=10.0)
        agg.update(1, coverage_percent=20.0)
        snapshot = agg.snapshot()
        assert snapshot.mean_coverage_percent == 15.0

    def test_serialisable(self) -> None:
        import json

        agg = TelemetryAggregator(campaign_id="c1")
        agg.update(0, executions=5)
        json.dumps(agg.snapshot().to_dict())


class TestThreadSafety:
    def test_parallel_increments_are_consistent(self) -> None:
        agg = TelemetryAggregator()
        iterations = 1000
        threads = [
            threading.Thread(
                target=lambda: [agg.increment(0, "artifacts_seen") for _ in range(iterations)]
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert agg.worker(0).artifacts_seen == 4 * iterations
