"""Lazy application context shared by every CLI command.

Building the context does the *minimum* work needed to answer a command.
``kmcs doctor`` should not open the database if the caller only wants to see
whether the tools are installed.  ``kmcs finding list`` should not touch the
corpus directory.

Managers are exposed as properties that build on first access.  Every manager
shares the same database handle and config.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.manager import CampaignManager
from kmcs.core.config import KMCSConfig, configure_logging
from kmcs.core.events import EventBus
from kmcs.corpus.manager import CorpusManager
from kmcs.database.database import Database
from kmcs.reporting.generator import ReportGenerator
from kmcs.targets.detector import EnvironmentDetector, EnvironmentReport
from kmcs.targets.manager import TargetManager

logger = logging.getLogger(__name__)

__all__ = ["CLIContext"]


@dataclass(slots=True)
class CLIContext:
    """Shared state for one CLI invocation."""

    config: KMCSConfig
    json_output: bool = False
    verbose: bool = False

    _database: Database | None = field(default=None, init=False, repr=False)
    _environment: EnvironmentReport | None = field(default=None, init=False, repr=False)
    _bus: EventBus | None = field(default=None, init=False, repr=False)
    _detector: CrashDetector | None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ build

    @classmethod
    def build(
        cls,
        *,
        base_dir: Path | None,
        log_level: str | None,
        json_output: bool,
        verbose: bool,
    ) -> "CLIContext":
        overrides: dict[str, Any] = {}
        if base_dir is not None:
            overrides["base_dir"] = base_dir

        if log_level is not None:
            overrides["log_level"] = log_level
        elif not verbose:
            # Keep normal CLI runs quiet: the analysis layer logs at INFO.
            overrides["log_level"] = "WARNING"

        config = KMCSConfig.load(**overrides)
        configure_logging(config)
        return cls(config=config, json_output=json_output, verbose=verbose)

    # ------------------------------------------------------------------ resources

    @property
    def database(self) -> Database:
        if self._database is None:
            self.config.ensure_directories()
            db = Database.from_config(self.config)
            db.initialize()
            self._database = db
        return self._database

    @property
    def environment(self) -> EnvironmentReport:
        if self._environment is None:
            self._environment = EnvironmentDetector().detect_all()
        return self._environment

    @property
    def bus(self) -> EventBus:
        if self._bus is None:
            self._bus = EventBus()
        return self._bus

    @property
    def detector(self) -> CrashDetector:
        if self._detector is None:
            self._detector = CrashDetector(database=self.database)
        return self._detector

    # ------------------------------------------------------------------ managers

    @property
    def targets(self) -> TargetManager:
        return TargetManager(self.database)

    @property
    def corpora(self) -> CorpusManager:
        return CorpusManager(self.database, self.config)

    @property
    def campaigns(self) -> CampaignManager:
        return CampaignManager(
            self.database, self.config, detector=self.detector, bus=self.bus
        )

    @property
    def reports(self) -> ReportGenerator:
        return ReportGenerator(self.database, self.config)

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._database is not None:
            try:
                self._database.dispose()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            self._database = None
