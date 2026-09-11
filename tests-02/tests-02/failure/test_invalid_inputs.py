"""Invalid inputs must be rejected cleanly."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from kmcs.core.config import KMCSConfig
from kmcs.core.exceptions import ConfigurationError
from kmcs.corpus.validator import (
    CorpusValidator,
    ValidationIssueCode,
    ValidatorConfig,
)


class TestCorpusValidator:
    def test_nonexistent_file(self, tmp_path: Path) -> None:
        result = CorpusValidator().validate(tmp_path / "missing.bin")
        assert result.valid is False
        assert result.has(ValidationIssueCode.NOT_A_FILE)

    def test_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b"")
        result = CorpusValidator().validate(empty)
        assert result.valid is False
        assert result.has(ValidationIssueCode.EMPTY_FILE)

    def test_oversized_file(self, tmp_path: Path) -> None:
        big = tmp_path / "big.bin"
        big.write_bytes(b"x" * 1024)
        validator = CorpusValidator(ValidatorConfig(max_size_bytes=512))
        result = validator.validate(big)
        assert result.valid is False
        assert result.has(ValidationIssueCode.TOO_LARGE)

    def test_directory_is_rejected(self, tmp_path: Path) -> None:
        d = tmp_path / "dir"
        d.mkdir()
        result = CorpusValidator().validate(d)
        assert result.valid is False
        assert result.has(ValidationIssueCode.NOT_A_FILE)

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks differ on Windows")
    def test_symlink_outside_root_is_rejected(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside.txt"
        outside.write_text("secret")
        link = root / "link"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlinks not permitted")

        result = CorpusValidator().validate(link, root=root)
        assert result.valid is False
        assert result.has(
            ValidationIssueCode.SYMLINK_OUTSIDE_ROOT
        ) or result.has(ValidationIssueCode.NOT_A_FILE)

    def test_duplicate_content(self, tmp_path: Path) -> None:
        first = tmp_path / "first.bin"
        first.write_bytes(b"hello")
        second = tmp_path / "second.bin"
        second.write_bytes(b"hello")

        validator = CorpusValidator()
        first_result = validator.validate(first)
        assert first_result.valid
        assert first_result.sha256 is not None

        second_result = validator.validate(
            second, known_hashes=[first_result.sha256]
        )
        assert second_result.valid is False
        assert second_result.has(ValidationIssueCode.DUPLICATE_CONTENT)


class TestConfigValidation:
    def test_invalid_log_level(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            KMCSConfig.load(
                env={"KMCS_HOME": str(tmp_path), "KMCS_LOG_LEVEL": "loud"}
            )

    def test_unknown_field(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            KMCSConfig.load(base_dir=tmp_path, nope=1)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
class TestInaccessibleDirectory:
    def test_permission_denied_is_reported(self, tmp_path: Path) -> None:
        if os.geteuid() == 0:  # pragma: no cover
            pytest.skip("running as root; permission checks are bypassed")
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o000)
        try:
            config = KMCSConfig(base_dir=locked / "sub")
            with pytest.raises(ConfigurationError):
                config.ensure_directories()
        finally:
            locked.chmod(0o700)
