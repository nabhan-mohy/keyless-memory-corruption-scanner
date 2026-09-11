"""Campaign orchestration: workers, scheduler, telemetry, and CRUD."""

from kmcs.campaigns.manager import (
    CampaignError,
    CampaignRunResult,
    CampaignManager,
)
from kmcs.campaigns.scheduler import (
    CampaignScheduler,
    SchedulerConfig,
    SchedulerError,
)
from kmcs.campaigns.telemetry import (
    TelemetryAggregator,
    TelemetrySnapshot,
    WorkerTelemetry,
)
from kmcs.campaigns.worker import (
    CampaignWorker,
    WorkerConfig,
    WorkerResult,
    WorkerStatus,
)

__all__ = [
    "CampaignError",
    "CampaignRunResult",
    "CampaignManager",
    "CampaignScheduler",
    "SchedulerConfig",
    "SchedulerError",
    "TelemetryAggregator",
    "TelemetrySnapshot",
    "WorkerTelemetry",
    "CampaignWorker",
    "WorkerConfig",
    "WorkerResult",
    "WorkerStatus",
]
