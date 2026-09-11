"""CLI parser: structure, help, and argument validation."""

from __future__ import annotations

import pytest

from kmcs.cli.commands import build_parser


@pytest.fixture()
def parser():
    return build_parser()


class TestGlobalFlags:
    def test_no_command_has_no_func(self, parser) -> None:
        args = parser.parse_args([])
        assert not hasattr(args, "func")

    def test_json_flag(self, parser) -> None:
        args = parser.parse_args(["--json", "doctor"])
        assert args.json is True

    def test_no_color_flag(self, parser) -> None:
        args = parser.parse_args(["--no-color", "doctor"])
        assert args.no_color is True

    def test_base_dir_flag(self, parser, tmp_path) -> None:
        args = parser.parse_args(["--base-dir", str(tmp_path), "doctor"])
        assert args.base_dir == tmp_path

    def test_verbose_flag(self, parser) -> None:
        args = parser.parse_args(["-v", "doctor"])
        assert args.verbose is True


class TestSubcommands:
    def test_version(self, parser) -> None:
        args = parser.parse_args(["version"])
        assert args.command == "version"
        assert args.func

    def test_doctor(self, parser) -> None:
        args = parser.parse_args(["doctor"])
        assert args.command == "doctor"
        assert args.func
        assert args.no_sanitizers is False

    def test_doctor_no_sanitizers(self, parser) -> None:
        args = parser.parse_args(["doctor", "--no-sanitizers"])
        assert args.no_sanitizers is True

    def test_target_list(self, parser) -> None:
        args = parser.parse_args(["target", "list"])
        assert args.command == "target"
        assert args.target_action == "list"
        assert args.func

    def test_target_add_requires_name(self, parser) -> None:
        with pytest.raises(SystemExit):
            parser.parse_args(["target", "add"])

    def test_target_add_parses_options(self, parser) -> None:
        args = parser.parse_args(
            [
                "target", "add", "mytarget",
                "--compiler", "clang",
                "--build-configuration", "asan+ubsan",
                "--sanitizer", "address",
                "--sanitizer", "undefined",
            ]
        )
        assert args.name == "mytarget"
        assert args.compiler == "clang"
        assert args.build_configuration == "asan+ubsan"
        assert args.sanitizers == ["address", "undefined"]

    def test_corpus_create(self, parser) -> None:
        args = parser.parse_args(["corpus", "create", "mycorpus"])
        assert args.command == "corpus"
        assert args.corpus_action == "create"
        assert args.name == "mycorpus"

    def test_campaign_create(self, parser) -> None:
        args = parser.parse_args(
            [
                "campaign", "create", "mycamp",
                "--target", "t1",
                "--fuzzer", "afl++",
                "--workers", "4",
                "--duration-seconds", "60",
            ]
        )
        assert args.target_id == "t1"
        assert args.fuzzer == "afl++"
        assert args.workers == 4
        assert args.duration_seconds == 60

    def test_report_generate_default_format(self, parser) -> None:
        args = parser.parse_args(["report", "generate"])
        assert args.report_format == "markdown"

    def test_report_generate_explicit_format(self, parser) -> None:
        args = parser.parse_args(["report", "generate", "--format", "sarif"])
        assert args.report_format == "sarif"

    def test_crash_list_filters(self, parser) -> None:
        args = parser.parse_args(
            ["crash", "list", "--campaign", "c1", "--classification", "use-after-free"]
        )
        assert args.campaign == "c1"
        assert args.classification == "use-after-free"
