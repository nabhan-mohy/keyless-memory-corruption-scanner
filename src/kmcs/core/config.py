"""Central configuration for KMCS.

Every component receives its filesystem locations from a single
:class:`KMCSConfig` instance so no module has to guess where data lives.

Environment variables
---------------------
=====================  ==================================================
``KMCS_HOME``          Root directory for all KMCS data
``KMCS_DB_PATH``       Explicit SQLite file path
``KMCS_DB_URL``        Explicit SQLAlchemy URL (overrides the file path)
``KMCS_LOG_DIR``       Log directory
``KMCS_CRASH_DIR``     Crash artefact directory
``KMCS_CORPUS_DIR``    Corpus storage directory
``KMCS_REPORT_DIR``    Report output directory
``KMCS_LOG_LEVEL``     Python logging level name
=====================  ==================================================
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import IO, Any, Mapping

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from kmcs.core.exceptions import ConfigurationError

__all__ = [
    "APPLICATION_NAME",
    "APPLICATION_SLUG",
    "LOGGER_NAME",
    "LOG_LEVELS",
    "default_base_dir",
    "KMCSConfig",
    "configure_logging",
]

APPLICATION_NAME = "KMCS"
APPLICATION_SLUG = "kmcs"
LOGGER_NAME = "kmcs"

LOG_LEVELS: tuple[str, ...] = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET")

_DATABASE_FILENAME = "kmcs.sqlite3"

_ENV_BASE_DIR = "KMCS_HOME"
_ENV_DATABASE_PATH = "KMCS_DB_PATH"
_ENV_DATABASE_URL = "KMCS_DB_URL"
_ENV_LOG_DIR = "KMCS_LOG_DIR"
_ENV_CRASH_DIR = "KMCS_CRASH_DIR"
_ENV_CORPUS_DIR = "KMCS_CORPUS_DIR"
_ENV_REPORT_DIR = "KMCS_REPORT_DIR"
_ENV_LOG_LEVEL = "KMCS_LOG_LEVEL"


def default_base_dir(
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
    home: Path | None = None,
) -> Path:
    """Return the platform-appropriate default data directory.

    The function is pure with respect to the filesystem: it computes a path but
    never creates or reads anything.  That makes it straightforward to test.
    """
    env = {} if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else Path(home)

    override = env.get(_ENV_BASE_DIR)
    if override:
        return Path(override).expanduser()

    if platform.startswith("win"):
        root = env.get("LOCALAPPDATA") or env.get("APPDATA")
        base = Path(root) if root else home / "AppData" / "Local"
        return base / APPLICATION_NAME

    if platform == "darwin":
        return home / "Library" / "Application Support" / APPLICATION_NAME

    root = env.get("XDG_DATA_HOME")
    base = Path(root) if root else home / ".local" / "share"
    return base / APPLICATION_SLUG


class KMCSConfig(BaseModel):
    """Immutable-by-convention view of the KMCS runtime configuration."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    base_dir: Path
    database_path: Path | None = None
    database_url: str | None = None
    logs_dir: Path | None = None
    crashes_dir: Path | None = None
    corpus_dir: Path | None = None
    reports_dir: Path | None = None

    log_level: str = "INFO"
    log_to_file: bool = True
    create_missing_dirs: bool = True

    # ------------------------------------------------------------------ validation

    @field_validator("base_dir", mode="after")
    @classmethod
    def _normalise_base_dir(cls, value: Path) -> Path:
        return Path(value).expanduser().absolute()

    @field_validator(
        "database_path",
        "logs_dir",
        "crashes_dir",
        "corpus_dir",
        "reports_dir",
        mode="after",
    )
    @classmethod
    def _normalise_optional_path(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        return Path(value).expanduser().absolute()

    @field_validator("log_level", mode="after")
    @classmethod
    def _normalise_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        if level not in LOG_LEVELS:
            raise ValueError(
                f"log level must be one of {', '.join(LOG_LEVELS)}; got {value!r}"
            )
        return level

    # ------------------------------------------------------------------ paths

    @property
    def database_file(self) -> Path:
        """Absolute path of the SQLite database file."""
        return self.database_path or (self.base_dir / _DATABASE_FILENAME)

    @property
    def logs_path(self) -> Path:
        return self.logs_dir or (self.base_dir / "logs")

    @property
    def crashes_path(self) -> Path:
        return self.crashes_dir or (self.base_dir / "crashes")

    @property
    def corpus_path(self) -> Path:
        return self.corpus_dir or (self.base_dir / "corpus")

    @property
    def reports_path(self) -> Path:
        return self.reports_dir or (self.base_dir / "reports")

    @property
    def log_file(self) -> Path:
        return self.logs_path / "kmcs.log"

    @property
    def directories(self) -> dict[str, Path]:
        """Named directories KMCS expects to exist."""
        return {
            "base": self.base_dir,
            "logs": self.logs_path,
            "crashes": self.crashes_path,
            "corpus": self.corpus_path,
            "reports": self.reports_path,
        }

    # ------------------------------------------------------------------ lifecycle

    def ensure_directories(self) -> dict[str, Path]:
        """Create every directory KMCS needs, and return the resolved map."""
        directories = dict(self.directories)
        if not self.create_missing_dirs:
            return directories

        for name, path in directories.items():
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ConfigurationError(
                    f"Unable to create the {name} directory",
                    details={"path": str(path), "error": str(exc)},
                ) from exc

        if self.database_url is None:
            try:
                self.database_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ConfigurationError(
                    "Unable to create the database directory",
                    details={"path": str(self.database_file.parent), "error": str(exc)},
                ) from exc

        return directories

    def as_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation, safe to log or embed in a report."""
        return self.model_dump(mode="json")

    # ------------------------------------------------------------------ loading

    @classmethod
    def load(
        cls,
        *,
        base_dir: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> "KMCSConfig":
        """Build a configuration from the environment plus explicit overrides.

        Precedence: ``overrides`` > ``base_dir`` argument > environment > defaults.
        """
        source: dict[str, str] = dict(env) if env is not None else dict(_os_environ())

        resolved_base = (
            Path(base_dir) if base_dir is not None else default_base_dir(env=source)
        )

        values: dict[str, Any] = {"base_dir": resolved_base}

        env_map = {
            _ENV_DATABASE_PATH: "database_path",
            _ENV_DATABASE_URL: "database_url",
            _ENV_LOG_DIR: "logs_dir",
            _ENV_CRASH_DIR: "crashes_dir",
            _ENV_CORPUS_DIR: "corpus_dir",
            _ENV_REPORT_DIR: "reports_dir",
        }
        for env_key, field_name in env_map.items():
            raw = source.get(env_key)
            if raw:
                values[field_name] = raw

        log_level = source.get(_ENV_LOG_LEVEL)
        if log_level:
            values["log_level"] = log_level

        values.update(overrides)

        try:
            return cls(**values)
        except ValidationError as exc:
            raise ConfigurationError(
                "Invalid KMCS configuration",
                details={"errors": exc.errors(include_url=False)},
            ) from exc


def _os_environ() -> Mapping[str, str]:
    """Indirection so tests can monkeypatch the environment cleanly."""
    import os

    return os.environ


def configure_logging(
    config: KMCSConfig,
    *,
    stream: IO[str] | None = None,
) -> logging.Logger:
    """Install KMCS log handlers and return the package logger.

    Safe to call repeatedly: previous handlers owned by KMCS are removed first.
    File logging failures degrade to console-only logging instead of aborting.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, config.log_level, logging.INFO))
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler(sys.stderr if stream is None else stream)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if config.log_to_file:
        try:
            config.logs_path.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(config.log_file, encoding="utf-8")
        except OSError as exc:  # pragma: no cover - depends on host filesystem
            logger.warning("File logging disabled for %s: %s", config.log_file, exc)
        else:
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger
