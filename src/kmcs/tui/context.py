"""The shared service context for the TUI.

Every screen receives the same :class:`TUIContext`.  It builds the same
managers the CLI uses and holds a single database handle for the lifetime of
the application.

The context is deliberately lazy: the database is not opened until the first
screen asks for something that needs it.  ``kmcs-tui --help`` does not touch
the database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.manager import CampaignManager
from kmcs.core.config import KMCSConfig
from kmcs.corpus.manager import CorpusManager
from kmcs.database.database import Database
from kmcs.reporting import ReportGenerator
from kmcs.targets.manager import TargetManager


@dataclass(slots=True)
class TUIContext:
    """Shared state for one TUI session."""

    config: KMCSConfig

    _database: Database | None = field(default=None, init=False, repr=False)
    _detector: CrashDetector | None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ build

    @classmethod
    def build(cls, base_dir: Path | None = None) -> "TUIContext":
        overrides: dict[str, object] = {}
        if base_dir is not None:
            overrides["base_dir"] = base_dir
        config = KMCSConfig.load(**overrides)
        return cls(config=config)

    # ------------------------------------------------------------------ database

    @property
    def database(self) -> Database:
        if self._database is None:
            self.config.ensure_directories()
            db = Database.from_config(self.config)
            db.initialize()
            self._database = db
        return self._database

    # ------------------------------------------------------------------ managers

    @property
    def detector(self) -> CrashDetector:
        if self._detector is None:
            self._detector = CrashDetector(database=self.database)
        return self._detector

    @property
    def targets(self) -> TargetManager:
        return TargetManager(self.database)

    @property
    def corpora(self) -> CorpusManager:
        return CorpusManager(self.database, self.config)

    @property
    def campaigns(self) -> CampaignManager:
        return CampaignManager(
            self.database, self.config, detector=self.detector
        )

    @property
    def reports(self) -> ReportGenerator:
        return ReportGenerator(self.database, self.config)

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._database is not None:
            try:
                self._database.dispose()
            except Exception:
                pass
            self._database = None
