"""Configuration resolution, validation, and directory creation."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.core.config import KMCSConfig, default_base_dir
from kmcs.core.exceptions import ConfigurationError


class TestDefaultBaseDir:
    def test_kmcs_home_wins(self, tmp_path: Path) -> None:
        result = default_base_dir(
            env={"KMCS_HOME": str(tmp_path), "XDG_DATA_HOME": "/ignored"},
            platform="linux",
            home=Path("/home/other"),
        )
        assert result == tmp_path

    def test_linux_uses_xdg_data_home(self) -> None:
        result = default_base_dir(
            env={"XDG_DATA_HOME": "/data"}, platform="linux", home=Path("/home/tester")
        )
        assert result == Path("/data/kmcs")

    def test_linux_falls_back_to_local_share(self) -> None:
        result = default_base_dir(
            env={}, platform="linux", home=Path("/home/tester")
        )
        assert result == Path("/home/tester/.local/share/kmcs")

    def test_macos_uses_application_support(self) -> None:
        result = default_base_dir(
            env={}, platform="darwin", home=Path("/Users/tester")
        )
        assert result == Path("/Users/tester/Library/Application Support/KMCS")

    def test_windows_uses_localappdata(self) -> None:
        result = default_base_dir(
            env={"LOCALAPPDATA": "C:/Users/tester/AppData/Local"},
            platform="win32",
            home=Path("C:/Users/tester"),
        )
        assert result == Path("C:/Users/tester/AppData/Local/KMCS")


class TestLoading:
    def test_env_overrides_are_applied(self, tmp_path: Path) -> None:
        env = {
            "KMCS_HOME": str(tmp_path / "home"),
            "KMCS_DB_PATH": str(tmp_path / "custom.sqlite3"),
            "KMCS_LOG_DIR": str(tmp_path / "mylogs"),
            "KMCS_LOG_LEVEL": "debug",
        }
        config = KMCSConfig.load(env=env)

        assert config.base_dir == tmp_path / "home"
        assert config.database_file == tmp_path / "custom.sqlite3"
        assert config.logs_path == tmp_path / "mylogs"
        assert config.log_level == "DEBUG"

    def test_explicit_base_dir_beats_environment(self, tmp_path: Path) -> None:
        config = KMCSConfig.load(
            base_dir=tmp_path / "explicit", env={"KMCS_HOME": str(tmp_path / "env")}
        )
        assert config.base_dir == tmp_path / "explicit"

    def test_unknown_log_level_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            KMCSConfig.load(
                env={"KMCS_HOME": str(tmp_path), "KMCS_LOG_LEVEL": "loud"}
            )

    def test_unknown_option_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            KMCSConfig.load(base_dir=tmp_path, not_a_real_option=1)


class TestPaths:
    def test_paths_default_under_base_dir(self, config: KMCSConfig) -> None:
        assert config.logs_path == config.base_dir / "logs"
        assert config.crashes_path == config.base_dir / "crashes"
        assert config.corpus_path == config.base_dir / "corpus"
        assert config.reports_path == config.base_dir / "reports"
        assert config.database_file == config.base_dir / "kmcs.sqlite3"
        assert config.log_file == config.logs_path / "kmcs.log"

    def test_explicit_paths_override_defaults(self, tmp_path: Path) -> None:
        config = KMCSConfig(
            base_dir=tmp_path / "base",
            logs_dir=tmp_path / "elsewhere" / "logs",
            crashes_dir=tmp_path / "elsewhere" / "crashes",
        )
        assert config.logs_path == tmp_path / "elsewhere" / "logs"
        assert config.crashes_path == tmp_path / "elsewhere" / "crashes"

    def test_as_dict_is_json_serialisable(self, config: KMCSConfig) -> None:
        import json

        payload = config.as_dict()
        assert json.loads(json.dumps(payload))["log_level"] == "INFO"


class TestDirectoryCreation:
    def test_ensure_directories_creates_everything(self, config: KMCSConfig) -> None:
        directories = config.ensure_directories()

        assert set(directories) == {"base", "logs", "crashes", "corpus", "reports"}
        for path in directories.values():
            assert path.is_dir()
        assert config.database_file.parent.is_dir()

    def test_ensure_directories_is_idempotent(self, config: KMCSConfig) -> None:
        config.ensure_directories()
        config.ensure_directories()
        assert config.logs_path.is_dir()

    def test_creation_can_be_disabled(self, tmp_path: Path) -> None:
        config = KMCSConfig(base_dir=tmp_path / "never", create_missing_dirs=False)
        config.ensure_directories()
        assert not config.logs_path.exists()
