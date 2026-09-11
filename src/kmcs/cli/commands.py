"""The KMCS command surface.

Every subcommand follows the same shape:

1. build a :class:`~kmcs.cli.context.CLIContext` from the global flags,
2. do the minimum work required by the command,
3. print human or JSON output according to ``--json``,
4. return an exit code.

Commands never raise :class:`~kmcs.core.exceptions.KMCSException` to the top
level.  They catch it, print a formatted error, and return an exit code.  This
keeps ``main()`` boring and the CLI's error surface consistent.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

from kmcs import __version__
from kmcs.analysis.crash_monitor import MonitorConfig
from kmcs.analysis.deduplicator import CrashDeduplicator
from kmcs.cli.context import CLIContext
from kmcs.cli.output import ExitCode, Output
from kmcs.core import models
from kmcs.core.exceptions import KMCSException
from kmcs.corpus.validator import ValidationIssueCode
from kmcs.fuzzers import (
    AFLPlusPlusAdapter,
    HonggfuzzAdapter,
    LibFuzzerAdapter,
)
from kmcs.reproduction.regression import RegressionRunner
from kmcs.reproduction.runner import ReproductionRunner
from kmcs.reporting import ReportFormat
from kmcs.reporting.base import ReportSection
from kmcs.sanitizers import SanitizerRegistry
from kmcs.targets.detector import ToolCategory

__all__ = ["build_parser", "main"]


# ====================================================================== parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kmcs",
        description=(
            "Keyless Memory-Corruption Scanner — a defensive fuzzing and "
            "memory-safety research platform."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 success, 1 generic error, 2 usage error, "
            "3 not found, 4 precondition failed, 5 external tool missing."
        ),
    )
    parser.add_argument("--version", action="version", version=f"KMCS {__version__}")
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Override the KMCS data directory.",
    )
    parser.add_argument(
        "--log-level",
        type=str.upper,
        choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
        default=None,
        help="Override the logging level.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable INFO-level logging on stderr.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    _register_version(subparsers)
    _register_doctor(subparsers)
    _register_target(subparsers)
    _register_corpus(subparsers)
    _register_campaign(subparsers)
    _register_crash(subparsers)
    _register_finding(subparsers)
    _register_report(subparsers)

    return parser


def _register_version(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("version", help="Print the KMCS version and exit.")
    p.set_defaults(func=_cmd_version)


def _register_doctor(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "doctor",
        help="Inspect the environment and database health.",
        description=(
            "Report which external tools KMCS can use, whether the database "
            "is healthy, and whether the data directories are present."
        ),
    )
    p.add_argument(
        "--no-sanitizers",
        action="store_true",
        help="Skip the per-sanitizer compile-and-run probe.",
    )
    p.add_argument(
        "--tools",
        nargs="*",
        default=None,
        metavar="NAME",
        help="Restrict the tool check to the named tools.",
    )
    p.set_defaults(func=_cmd_doctor)


def _register_target(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("target", help="Manage targets.")
    sub = p.add_subparsers(dest="target_action", metavar="<action>")

    lst = sub.add_parser("list", help="List registered targets.")
    lst.set_defaults(func=_cmd_target_list)

    show = sub.add_parser("show", help="Show one target.")
    show.add_argument("identifier", help="Target ID or exact name.")
    show.set_defaults(func=_cmd_target_show)

    add = sub.add_parser("add", help="Register a new target.")
    add.add_argument("name", help="Unique target name.")
    add.add_argument("--description", default="", help="Free-form description.")
    add.add_argument("--source-dir", type=Path, default=None)
    add.add_argument("--build-dir", type=Path, default=None)
    add.add_argument("--executable", type=Path, default=None)
    add.add_argument("--compiler", default=None)
    add.add_argument(
        "--build-configuration",
        choices=[c.value for c in models.BuildConfiguration],
        default=models.BuildConfiguration.DEBUG.value,
    )
    add.add_argument(
        "--sanitizer",
        action="append",
        choices=[s.value for s in models.SanitizerKind],
        default=[],
        dest="sanitizers",
        help="Repeat to enable multiple sanitizers.",
    )
    add.set_defaults(func=_cmd_target_add)

    rm = sub.add_parser("remove", help="Remove a target by ID or name.")
    rm.add_argument("identifier")
    rm.set_defaults(func=_cmd_target_remove)


def _register_corpus(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("corpus", help="Manage corpora.")
    sub = p.add_subparsers(dest="corpus_action", metavar="<action>")

    lst = sub.add_parser("list", help="List corpora.")
    lst.set_defaults(func=_cmd_corpus_list)

    show = sub.add_parser("show", help="Show one corpus.")
    show.add_argument("identifier", help="Corpus ID or exact name.")
    show.set_defaults(func=_cmd_corpus_show)

    create = sub.add_parser("create", help="Create a new (empty) corpus.")
    create.add_argument("name")
    create.add_argument("--description", default="")
    create.add_argument("--target", default=None, help="Target ID.")
    create.set_defaults(func=_cmd_corpus_create)

    add = sub.add_parser("add", help="Import files into a corpus.")
    add.add_argument("identifier", help="Corpus ID or exact name.")
    add.add_argument("paths", nargs="+", type=Path)
    add.add_argument("--recursive", action="store_true")
    add.set_defaults(func=_cmd_corpus_add)

    rm = sub.add_parser("remove", help="Remove a corpus.")
    rm.add_argument("identifier")
    rm.add_argument("--with-files", action="store_true")
    rm.set_defaults(func=_cmd_corpus_remove)


def _register_campaign(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("campaign", help="Manage campaigns.")
    sub = p.add_subparsers(dest="campaign_action", metavar="<action>")

    lst = sub.add_parser("list", help="List campaigns.")
    lst.set_defaults(func=_cmd_campaign_list)

    show = sub.add_parser("show", help="Show one campaign.")
    show.add_argument("identifier", help="Campaign ID or exact name.")
    show.set_defaults(func=_cmd_campaign_show)

    create = sub.add_parser("create", help="Create a new campaign.")
    create.add_argument("name")
    create.add_argument("--target", required=True, dest="target_id")
    create.add_argument("--corpus", default=None, dest="corpus_id")
    create.add_argument(
        "--fuzzer",
        choices=[f.value for f in models.FuzzerKind],
        default=models.FuzzerKind.AFLPP.value,
    )
    create.add_argument(
        "--sanitizer",
        action="append",
        choices=[s.value for s in models.SanitizerKind],
        default=[],
        dest="sanitizers",
    )
    create.add_argument("--workers", type=int, default=1)
    create.add_argument("--duration-seconds", type=int, default=None)
    create.add_argument("--description", default="")
    create.set_defaults(func=_cmd_campaign_create)

    start = sub.add_parser("start", help="Run an existing campaign.")
    start.add_argument("identifier")
    start.add_argument("--target-binary", type=Path, required=True)
    start.add_argument("--corpus-dir", type=Path, required=True)
    start.add_argument("--output-root", type=Path, required=True)
    start.add_argument("--poll-interval", type=float, default=1.0)
    start.add_argument("--clear-output", action="store_true")
    start.set_defaults(func=_cmd_campaign_start)

    rm = sub.add_parser("remove", help="Remove a campaign.")
    rm.add_argument("identifier")
    rm.set_defaults(func=_cmd_campaign_remove)


def _register_crash(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("crash", help="Inspect and reproduce crashes.")
    sub = p.add_subparsers(dest="crash_action", metavar="<action>")

    lst = sub.add_parser("list", help="List crashes.")
    lst.add_argument("--campaign", default=None)
    lst.add_argument("--classification", default=None)
    lst.set_defaults(func=_cmd_crash_list)

    show = sub.add_parser("show", help="Show one crash with its raw evidence.")
    show.add_argument("crash_id")
    show.set_defaults(func=_cmd_crash_show)

    repro = sub.add_parser("reproduce", help="Replay a crash input.")
    repro.add_argument("crash_id")
    repro.add_argument("--target-binary", type=Path, required=True)
    repro.add_argument("--attempts", type=int, default=3)
    repro.add_argument("--timeout", type=float, default=10.0)
    repro.set_defaults(func=_cmd_crash_reproduce)


def _register_finding(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("finding", help="Inspect findings.")
    sub = p.add_subparsers(dest="finding_action", metavar="<action>")

    lst = sub.add_parser("list", help="List findings.")
    lst.add_argument("--campaign", default=None)
    lst.set_defaults(func=_cmd_finding_list)

    show = sub.add_parser("show", help="Show one finding.")
    show.add_argument("finding_id")
    show.set_defaults(func=_cmd_finding_show)

    dedup = sub.add_parser(
        "deduplicate",
        help="Rebuild findings for a campaign from its crashes.",
    )
    dedup.add_argument("campaign_id")
    dedup.set_defaults(func=_cmd_finding_deduplicate)


def _register_report(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("report", help="Generate reports.")
    sub = p.add_subparsers(dest="report_action", metavar="<action>")

    generate = sub.add_parser("generate", help="Render a report.")
    generate.add_argument(
        "--format",
        default=ReportFormat.MARKDOWN.value,
        choices=[f.value for f in ReportFormat],
        dest="report_format",
    )
    generate.add_argument("--campaign", default=None)
    generate.add_argument(
        "--finding",
        action="append",
        default=None,
        dest="findings",
        help="Repeat to select specific findings.",
    )
    generate.add_argument("--title", default=None)
    generate.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Write to this directory instead of stdout.",
    )
    generate.add_argument("--filename", default=None)
    generate.add_argument(
        "--findings-only",
        action="store_true",
        help="Include only findings and their crashes.",
    )
    generate.add_argument(
        "--stdout",
        action="store_true",
        help="Print the report to stdout regardless of --output-dir.",
    )
    generate.set_defaults(func=_cmd_report_generate)


# ====================================================================== dispatch


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "func", None):
        parser.print_help()
        return ExitCode.USAGE_ERROR

    output = Output(
        json_mode=bool(getattr(args, "json", False)),
        color=False if getattr(args, "no_color", False) else None,
    )

    try:
        ctx = CLIContext.build(
            base_dir=getattr(args, "base_dir", None),
            log_level=getattr(args, "log_level", None),
            json_output=output.json_mode,
            verbose=bool(getattr(args, "verbose", False)),
        )
    except KMCSException as exc:
        output.error(str(exc), details=exc.details or None)
        return exc.exit_code

    try:
        return int(args.func(ctx, args, output))
    except KMCSException as exc:
        output.error(str(exc), details=exc.details or None)
        return exc.exit_code
    except KeyboardInterrupt:
        output.error("interrupted")
        return ExitCode.GENERIC_ERROR
    except Exception as exc:  # noqa: BLE001 - top-level guard
        output.error(f"{type(exc).__name__}: {exc}")
        if getattr(args, "verbose", False):
            import traceback

            traceback.print_exc()
        return ExitCode.GENERIC_ERROR
    finally:
        ctx.close()


# ====================================================================== commands
# --- meta ---------------------------------------------------------------------


def _cmd_version(ctx: CLIContext, args: argparse.Namespace, output: Output) -> int:
    payload = {
        "version": __version__,
        "base_dir": str(ctx.config.base_dir),
    }
    if output.json_mode:
        output.json(payload)
    else:
        output.line(f"KMCS {__version__}")
    return ExitCode.OK


# --- doctor -------------------------------------------------------------------


def _cmd_doctor(
    ctx: CLIContext, args: argparse.Namespace, output: Output
) -> int:
    tools_filter = args.tools
    environment = (
        ctx.environment
        if tools_filter is None
        else ctx.environment.__class__(
            {name: ctx.environment.detect_all(tools_filter).get(name)
             for name in tools_filter}
        )
    )
    # Rebuild cleanly if a filter was provided.
    if tools_filter is not None:
        from kmcs.targets.detector import EnvironmentDetector

        environment = EnvironmentDetector().detect_all(tools_filter)
    else:
        environment = ctx.environment

    health = ctx.database.health_check()

    sanitizer_report: dict[str, dict[str, Any]] = {}
    if not args.no_sanitizers:
        from kmcs.targets.detector import EnvironmentDetector

        detector = EnvironmentDetector()
        sanitizer_report = {
            kind.value: adapter.availability(detector).to_dict()
            for kind, adapter in (
                (k, SanitizerRegistry.for_kind(k))
                for k in (
                    models.SanitizerKind.ADDRESS,
                    models.SanitizerKind.UNDEFINED,
                    models.SanitizerKind.LEAK,
                    models.SanitizerKind.MEMORY,
                    models.SanitizerKind.THREAD,
                )
            )
        }

    payload = {
        "version": __version__,
        "base_dir": str(ctx.config.base_dir),
        "directories": {
            name: str(path) for name, path in ctx.config.directories.items()
        },
        "database": {
            "url": ctx.database.url,
            "file": str(ctx.config.database_file),
            "health": health.model_dump(),
        },
        "tools": environment.to_dict(),
        "sanitizers": sanitizer_report,
    }

    if output.json_mode:
        output.json(payload)
        return ExitCode.OK if health.ok else ExitCode.PRECONDITION_FAILED

    output.heading(f"KMCS {__version__} — environment report")
    output.blank()

    output.heading("Workspace")
    output.kv(
        [
            ("base dir", str(ctx.config.base_dir)),
            ("database", str(ctx.config.database_file)),
            ("log file", str(ctx.config.log_file)),
            ("crashes dir", str(ctx.config.crashes_path)),
            ("corpus dir", str(ctx.config.corpus_path)),
            ("reports dir", str(ctx.config.reports_path)),
        ]
    )
    output.blank()

    output.heading("Database")
    status = output.green("ok") if health.ok else output.red("FAILED")
    output.kv(
        [
            ("status", status),
            ("schema version", f"{health.schema_version} (expected {health.expected_schema_version})"),
            ("integrity", health.integrity or "—"),
            ("tables present", ", ".join(health.tables_present) or "—"),
        ]
    )
    for message in health.messages:
        output.warning(message)
    output.blank()

    output.heading("External tools")
    categories = [
        ("Compilers", ToolCategory.COMPILER),
        ("Fuzzers", ToolCategory.FUZZER),
        ("Debuggers", ToolCategory.DEBUGGER),
        ("Symbolizers", ToolCategory.SYMBOLIZER),
        ("Binutils", ToolCategory.BINUTILS),
        ("Build tools", ToolCategory.BUILD),
    ]
    for label, category in categories:
        members = environment.by_category(category)
        if not members:
            continue
        output.line(output.bold(label))
        for info in members:
            if info.available:
                version = (info.version or "").strip()
                if len(version) > 60:
                    version = version[:57] + "…"
                output.line(f"  {info.name:<18} {output.green('✓')}  {info.path}")
                if version:
                    output.line(f"  {'':<18}     {output.dim(version)}")
            else:
                reason = info.error or "not found"
                output.line(
                    f"  {info.name:<18} {output.red('✗')}  {output.dim(reason)}"
                )
        output.blank()

    if sanitizer_report:
        output.heading("Sanitizers")
        for kind, info in sorted(sanitizer_report.items()):
            if info["available"]:
                compiler = info.get("compiler") or ""
                output.line(
                    f"  {kind:<18} {output.green('✓')}  {output.dim(compiler)}"
                )
            else:
                reason = info.get("reason") or "unavailable"
                output.line(
                    f"  {kind:<18} {output.red('✗')}  {output.dim(reason)}"
                )
        output.blank()

    if not health.ok:
        return ExitCode.PRECONDITION_FAILED
    return ExitCode.OK


# --- target -------------------------------------------------------------------


def _resolve_target(ctx: CLIContext, identifier: str):
    return ctx.targets.get(identifier) or ctx.targets.get_by_name(identifier)


def _cmd_target_list(ctx, args, output) -> int:
    targets = ctx.targets.list()
    if output.json_mode:
        output.json(
            {
                "command": "target.list",
                "count": len(targets),
                "items": [t.model_dump(mode="json") for t in targets],
            }
        )
        return ExitCode.OK

    output.table(
        ["ID", "Name", "Build", "Sanitizers", "Executable"],
        [
            (
                t.id[:8],
                t.name,
                t.build_configuration.value,
                [s.value for s in t.sanitizers],
                t.executable or "—",
            )
            for t in targets
        ],
    )
    return ExitCode.OK


def _cmd_target_show(ctx, args, output) -> int:
    target = _resolve_target(ctx, args.identifier)
    if target is None:
        output.error(f"Target not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    if output.json_mode:
        output.json({"command": "target.show", "item": target.model_dump(mode="json")})
        return ExitCode.OK

    output.heading(f"Target: {target.name}")
    output.kv(
        [
            ("ID", target.id),
            ("Description", target.description or "—"),
            ("Source directory", target.source_dir or "—"),
            ("Build directory", target.build_dir or "—"),
            ("Executable", target.executable or "—"),
            ("Compiler", target.compiler or "—"),
            ("Build configuration", target.build_configuration.value),
            ("Sanitizers", [s.value for s in target.sanitizers]),
            ("Created", target.created_at.isoformat()),
            ("Updated", target.updated_at.isoformat()),
        ]
    )
    return ExitCode.OK


def _cmd_target_add(ctx, args, output) -> int:
    target = models.Target(
        name=args.name,
        description=args.description,
        source_dir=args.source_dir,
        build_dir=args.build_dir,
        executable=args.executable,
        compiler=args.compiler,
        build_configuration=models.BuildConfiguration(args.build_configuration),
        sanitizers=[models.SanitizerKind(v) for v in args.sanitizers],
    )
    ctx.targets.add(target)

    if output.json_mode:
        output.json(
            {"command": "target.add", "ok": True, "item": target.model_dump(mode="json")}
        )
        return ExitCode.OK

    output.success(f"Registered target {target.name} ({target.id[:8]})")
    return ExitCode.OK


def _cmd_target_remove(ctx, args, output) -> int:
    target = _resolve_target(ctx, args.identifier)
    if target is None:
        output.error(f"Target not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    removed = ctx.targets.remove(target.id)
    if output.json_mode:
        output.json({"command": "target.remove", "ok": removed, "id": target.id})
        return ExitCode.OK if removed else ExitCode.NOT_FOUND

    if removed:
        output.success(f"Removed target {target.name} ({target.id[:8]})")
        return ExitCode.OK
    output.error("Target disappeared during removal")
    return ExitCode.GENERIC_ERROR


# --- corpus -------------------------------------------------------------------


def _resolve_corpus(ctx: CLIContext, identifier: str):
    return ctx.corpora.get(identifier) or ctx.corpora.get_by_name(identifier)


def _cmd_corpus_list(ctx, args, output) -> int:
    corpora = ctx.corpora.list()
    if output.json_mode:
        output.json(
            {
                "command": "corpus.list",
                "count": len(corpora),
                "items": [c.model_dump(mode="json") for c in corpora],
            }
        )
        return ExitCode.OK

    output.table(
        ["ID", "Name", "Files", "Bytes", "Target", "Directory"],
        [
            (
                c.id[:8],
                c.name,
                c.file_count,
                c.total_bytes,
                (c.target_id or "—")[:8],
                c.path or "—",
            )
            for c in corpora
        ],
    )
    return ExitCode.OK


def _cmd_corpus_show(ctx, args, output) -> int:
    corpus = _resolve_corpus(ctx, args.identifier)
    if corpus is None:
        output.error(f"Corpus not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    if output.json_mode:
        output.json({"command": "corpus.show", "item": corpus.model_dump(mode="json")})
        return ExitCode.OK

    output.heading(f"Corpus: {corpus.name}")
    output.kv(
        [
            ("ID", corpus.id),
            ("Description", corpus.description or "—"),
            ("Target", corpus.target_id or "—"),
            ("Directory", corpus.path or "—"),
            ("Files", corpus.file_count),
            ("Total bytes", corpus.total_bytes),
        ]
    )

    files = ctx.corpora.files(corpus.id)
    if files:
        output.blank()
        output.heading(f"Files ({len(files)})")
        for path in files[:20]:
            output.line(f"  {path.name}")
        if len(files) > 20:
            output.line(f"  … {len(files) - 20} more")
    return ExitCode.OK


def _cmd_corpus_create(ctx, args, output) -> int:
    corpus = ctx.corpora.create(
        name=args.name, description=args.description, target_id=args.target
    )
    if output.json_mode:
        output.json(
            {"command": "corpus.create", "ok": True, "item": corpus.model_dump(mode="json")}
        )
        return ExitCode.OK

    output.success(f"Created corpus {corpus.name} ({corpus.id[:8]})")
    return ExitCode.OK


def _cmd_corpus_add(ctx, args, output) -> int:
    corpus = _resolve_corpus(ctx, args.identifier)
    if corpus is None:
        output.error(f"Corpus not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    result = ctx.corpora.import_files(corpus.id, args.paths, recursive=args.recursive)

    if output.json_mode:
        output.json({"command": "corpus.add", **result.to_dict()})
        return ExitCode.OK if result.accepted_count else ExitCode.PRECONDITION_FAILED

    output.success(
        f"Imported {result.accepted_count} file(s) into {corpus.name}; "
        f"{result.rejected_count} rejected"
    )
    if result.rejected:
        output.blank()
        output.heading("Rejected")
        for rejected in result.rejected:
            codes = ", ".join(issue.code.value for issue in rejected.issues)
            output.line(f"  {rejected.path} — {codes}")
    return ExitCode.OK if result.accepted_count else ExitCode.PRECONDITION_FAILED


def _cmd_corpus_remove(ctx, args, output) -> int:
    corpus = _resolve_corpus(ctx, args.identifier)
    if corpus is None:
        output.error(f"Corpus not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    removed = ctx.corpora.remove(corpus.id, remove_files=args.with_files)
    if output.json_mode:
        output.json({"command": "corpus.remove", "ok": removed, "id": corpus.id})
        return ExitCode.OK if removed else ExitCode.NOT_FOUND

    if removed:
        output.success(f"Removed corpus {corpus.name} ({corpus.id[:8]})")
        return ExitCode.OK
    output.error("Corpus disappeared during removal")
    return ExitCode.GENERIC_ERROR


# --- campaign -----------------------------------------------------------------


def _resolve_campaign(ctx: CLIContext, identifier: str):
    return ctx.campaigns.get(identifier) or ctx.campaigns.get_by_name(identifier)


def _cmd_campaign_list(ctx, args, output) -> int:
    campaigns = ctx.campaigns.list()
    if output.json_mode:
        output.json(
            {
                "command": "campaign.list",
                "count": len(campaigns),
                "items": [c.model_dump(mode="json") for c in campaigns],
            }
        )
        return ExitCode.OK

    output.table(
        ["ID", "Name", "Status", "Fuzzer", "Workers", "Duration", "Target"],
        [
            (
                c.id[:8],
                c.name,
                c.status.value,
                c.fuzzer.value,
                c.workers,
                f"{c.duration_seconds}s" if c.duration_seconds is not None else "—",
                c.target_id[:8] if c.target_id else "—",
            )
            for c in campaigns
        ],
    )
    return ExitCode.OK


def _cmd_campaign_show(ctx, args, output) -> int:
    campaign = _resolve_campaign(ctx, args.identifier)
    if campaign is None:
        output.error(f"Campaign not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    if output.json_mode:
        output.json(
            {"command": "campaign.show", "item": campaign.model_dump(mode="json")}
        )
        return ExitCode.OK

    output.heading(f"Campaign: {campaign.name}")
    output.kv(
        [
            ("ID", campaign.id),
            ("Description", campaign.description or "—"),
            ("Status", campaign.status.value),
            ("Target", campaign.target_id),
            ("Corpus", campaign.corpus_id or "—"),
            ("Fuzzer", campaign.fuzzer.value),
            ("Sanitizers", [s.value for s in campaign.sanitizers]),
            ("Workers", campaign.workers),
            (
                "Duration",
                f"{campaign.duration_seconds}s"
                if campaign.duration_seconds is not None
                else "—",
            ),
            ("Started", campaign.started_at.isoformat() if campaign.started_at else "—"),
            (
                "Finished",
                campaign.finished_at.isoformat() if campaign.finished_at else "—",
            ),
        ]
    )
    return ExitCode.OK


def _cmd_campaign_create(ctx, args, output) -> int:
    campaign = models.Campaign(
        name=args.name,
        description=args.description,
        target_id=args.target_id,
        corpus_id=args.corpus_id,
        fuzzer=models.FuzzerKind(args.fuzzer),
        sanitizers=[models.SanitizerKind(v) for v in args.sanitizers],
        workers=args.workers,
        duration_seconds=args.duration_seconds,
    )
    ctx.campaigns.add(campaign)

    if output.json_mode:
        output.json(
            {"command": "campaign.create", "ok": True, "item": campaign.model_dump(mode="json")}
        )
        return ExitCode.OK

    output.success(f"Created campaign {campaign.name} ({campaign.id[:8]})")
    return ExitCode.OK


def _cmd_campaign_start(ctx, args, output) -> int:
    campaign = _resolve_campaign(ctx, args.identifier)
    if campaign is None:
        output.error(f"Campaign not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    output.info(
        f"Starting campaign {campaign.name} with {campaign.workers} worker(s)"
    )
    output.info("Press Ctrl-C to cancel.")

    try:
        result = ctx.campaigns.run(
            campaign.id,
            target_binary=args.target_binary,
            corpus_dir=args.corpus_dir,
            output_root=args.output_root,
            clear_output_root=args.clear_output,
            poll_interval_seconds=args.poll_interval,
        )
    except KeyboardInterrupt:
        output.warning("Campaign interrupted by user")
        return ExitCode.GENERIC_ERROR

    payload = result.to_dict()

    if output.json_mode:
        output.json({"command": "campaign.start", "ok": True, **payload})
        return ExitCode.OK

    output.blank()
    output.success(
        f"Campaign {result.campaign.name} finished "
        f"with status {result.campaign.status.value}"
    )
    output.kv(
        [
            ("Duration", f"{result.scheduler_result.duration_seconds:.2f}s"),
            ("Workers", len(result.scheduler_result.worker_results)),
            (
                "Total executions",
                result.scheduler_result.telemetry.total_executions
                if result.scheduler_result.telemetry
                else None,
            ),
            ("Crashes recorded", result.scheduler_result.total_crashes_recorded),
            ("Unique fingerprints", result.deduplication.total_groups),
            ("Findings", len(result.deduplication.findings)),
        ]
    )
    return ExitCode.OK


def _cmd_campaign_remove(ctx, args, output) -> int:
    campaign = _resolve_campaign(ctx, args.identifier)
    if campaign is None:
        output.error(f"Campaign not found: {args.identifier}")
        return ExitCode.NOT_FOUND

    removed = ctx.campaigns.remove(campaign.id)
    if output.json_mode:
        output.json({"command": "campaign.remove", "ok": removed, "id": campaign.id})
        return ExitCode.OK if removed else ExitCode.NOT_FOUND

    if removed:
        output.success(f"Removed campaign {campaign.name} ({campaign.id[:8]})")
        return ExitCode.OK
    output.error("Campaign disappeared during removal")
    return ExitCode.GENERIC_ERROR


# --- crash --------------------------------------------------------------------


def _load_crash(ctx: CLIContext, crash_id: str):
    from kmcs.database.models import CrashRow

    with ctx.database.session() as session:
        row = session.get(CrashRow, crash_id)
        return None if row is None else row.to_domain()


def _cmd_crash_list(ctx, args, output) -> int:
    from sqlalchemy import select

    from kmcs.database.models import CrashRow

    with ctx.database.session() as session:
        stmt = select(CrashRow).order_by(CrashRow.created_at.desc())
        if args.campaign:
            stmt = stmt.where(CrashRow.campaign_id == args.campaign)
        if args.classification:
            stmt = stmt.where(CrashRow.classification == args.classification)
        rows = session.scalars(stmt).all()
        crashes = [row.to_domain() for row in rows]

    if output.json_mode:
        output.json(
            {
                "command": "crash.list",
                "count": len(crashes),
                "items": [c.model_dump(mode="json") for c in crashes],
            }
        )
        return ExitCode.OK

    output.table(
        ["Crash ID", "Classification", "Severity", "Signal", "Fingerprint", "Location"],
        [
            (
                c.id[:8],
                c.classification.value,
                c.severity.value,
                c.signal if c.signal is not None else "—",
                (c.fingerprint or "—")[:12],
                c.source_location or "—",
            )
            for c in crashes
        ],
    )
    return ExitCode.OK


def _cmd_crash_show(ctx, args, output) -> int:
    crash = _load_crash(ctx, args.crash_id)
    if crash is None:
        output.error(f"Crash not found: {args.crash_id}")
        return ExitCode.NOT_FOUND

    if output.json_mode:
        output.json({"command": "crash.show", "item": crash.model_dump(mode="json")})
        return ExitCode.OK

    output.heading(f"Crash {crash.id[:8]}")
    output.kv(
        [
            ("ID", crash.id),
            ("Description", crash.description),
            ("Classification", crash.classification.value),
            ("Severity", crash.severity.value),
            ("Signal", crash.signal if crash.signal is not None else "—"),
            ("Exit code", crash.exit_code if crash.exit_code is not None else "—"),
            ("Sanitizer", crash.sanitizer.value if crash.sanitizer else "—"),
            ("Fingerprint", crash.fingerprint or "—"),
            ("Source location", crash.source_location or "—"),
            ("Reproduction", crash.reproduction_status.value),
            ("Input", crash.input_path or "—"),
            ("Evidence", crash.evidence_path or "—"),
            ("Created", crash.created_at.isoformat()),
        ]
    )

    if crash.stack_trace:
        output.blank()
        output.heading("Stack trace")
        output.line(crash.stack_trace)

    if crash.stderr_excerpt:
        output.blank()
        output.heading("stderr (last 4 KiB)")
        output.line(crash.stderr_excerpt)
    return ExitCode.OK


def _cmd_crash_reproduce(ctx, args, output) -> int:
    crash = _load_crash(ctx, args.crash_id)
    if crash is None:
        output.error(f"Crash not found: {args.crash_id}")
        return ExitCode.NOT_FOUND

    if crash.input_path is None or not Path(crash.input_path).is_file():
        output.error(f"Crash input is missing: {crash.input_path}")
        return ExitCode.PRECONDITION_FAILED

    runner = ReproductionRunner(attempts=args.attempts)
    result = runner.reproduce(
        target=args.target_binary,
        input_path=Path(crash.input_path),
        timeout_seconds=args.timeout,
        crash_id=crash.id,
    )

    if output.json_mode:
        output.json({"command": "crash.reproduce", **result.to_dict()})
        return ExitCode.OK if result.outcome.value == "reproduced" else ExitCode.PRECONDITION_FAILED

    output.heading(f"Reproduction of {crash.id[:8]}")
    output.kv(
        [
            ("Outcome", result.outcome.value),
            ("Attempts", len(result.attempts)),
            ("Crashes", result.crashes),
            ("Crash rate", f"{result.crash_rate:.0%}"),
            ("Fingerprint", result.expected_fingerprint or "—"),
        ]
    )

    if result.attempts:
        output.blank()
        output.table(
            ["Attempt", "Crashed", "Signal", "Fingerprint", "Duration"],
            [
                (
                    a.attempt,
                    a.crashed,
                    a.signal if a.signal is not None else "—",
                    (a.fingerprint or "—")[:12],
                    f"{a.duration_seconds:.2f}s",
                )
                for a in result.attempts
            ],
        )

    return (
        ExitCode.OK
        if result.outcome.value == "reproduced"
        else ExitCode.PRECONDITION_FAILED
    )


# --- finding ------------------------------------------------------------------


def _load_finding(ctx: CLIContext, finding_id: str):
    from kmcs.database.models import FindingRow

    with ctx.database.session() as session:
        row = session.get(FindingRow, finding_id)
        return None if row is None else row.to_domain()


def _cmd_finding_list(ctx, args, output) -> int:
    from sqlalchemy import select

    from kmcs.database.models import FindingRow

    with ctx.database.session() as session:
        rows = session.scalars(
            select(FindingRow).order_by(FindingRow.created_at.desc())
        ).all()
        findings = [row.to_domain() for row in rows]

    if args.campaign:
        # Filter by crash membership.
        from kmcs.database.models import CrashRow

        with ctx.database.session() as session:
            crash_rows = session.scalars(
                select(CrashRow).where(CrashRow.campaign_id == args.campaign)
            ).all()
            crash_ids = {row.id for row in crash_rows}
        findings = [
            f for f in findings if crash_ids.intersection(f.crash_ids)
        ]

    if output.json_mode:
        output.json(
            {
                "command": "finding.list",
                "count": len(findings),
                "items": [f.model_dump(mode="json") for f in findings],
            }
        )
        return ExitCode.OK

    output.table(
        ["Finding ID", "Severity", "Classification", "Occurrences", "Title"],
        [
            (
                f.id[:8],
                f.severity.value,
                f.classification.value,
                len(f.crash_ids),
                f.title,
            )
            for f in findings
        ],
    )
    return ExitCode.OK


def _cmd_finding_show(ctx, args, output) -> int:
    finding = _load_finding(ctx, args.finding_id)
    if finding is None:
        output.error(f"Finding not found: {args.finding_id}")
        return ExitCode.NOT_FOUND

    if output.json_mode:
        output.json(
            {"command": "finding.show", "item": finding.model_dump(mode="json")}
        )
        return ExitCode.OK

    output.heading(finding.title)
    output.kv(
        [
            ("ID", finding.id),
            ("Classification", finding.classification.value),
            ("Severity", finding.severity.value),
            ("Fingerprint", finding.fingerprint),
            ("Occurrences", len(finding.crash_ids)),
            ("Reproduction", finding.reproduction_status.value),
            ("Target", finding.target_id or "—"),
        ]
    )

    if finding.description:
        output.blank()
        output.heading("Description")
        output.line(finding.description)

    if finding.remediation:
        output.blank()
        output.heading("Remediation")
        output.line(finding.remediation)

    if finding.crash_ids:
        output.blank()
        output.heading(f"Crash IDs ({len(finding.crash_ids)})")
        for cid in finding.crash_ids[:20]:
            output.line(f"  {cid}")
        if len(finding.crash_ids) > 20:
            output.line(f"  … {len(finding.crash_ids) - 20} more")
    return ExitCode.OK


def _cmd_finding_deduplicate(ctx, args, output) -> int:
    result = ctx.campaigns.finalize(args.campaign_id)
    if output.json_mode:
        output.json(
            {"command": "finding.deduplicate", "ok": True, **result.to_dict()}
        )
        return ExitCode.OK

    output.success(
        f"Rebuilt findings for campaign {args.campaign_id[:8]}: "
        f"{result.total_crashes} crashes → "
        f"{result.total_groups} groups → "
        f"{len(result.findings)} findings"
    )
    return ExitCode.OK


# --- report -------------------------------------------------------------------


def _cmd_report_generate(ctx, args, output) -> int:
    section = (
        ReportSection.findings_only()
        if args.findings_only
        else ReportSection()
    )

    rendered, written = ctx.reports.generate(
        args.report_format,
        output_dir=None if args.stdout else args.output_dir,
        filename=args.filename,
        title=args.title,
        campaign_id=args.campaign,
        finding_ids=args.findings,
        section=section,
    )

    if output.json_mode:
        payload = {
            "command": "report.generate",
            "ok": True,
            "rendered": rendered.to_dict(),
            "written_path": str(written) if written else None,
        }
        output.json(payload)
        return ExitCode.OK

    if args.stdout or written is None:
        # Print the report to stdout; no other framing.
        output.stdout.write(rendered.content)
        if not rendered.content.endswith("\n"):
            output.stdout.write("\n")
        return ExitCode.OK

    output.success(
        f"Wrote {rendered.format.value} report "
        f"({rendered.size_bytes} bytes) to {written}"
    )
    return ExitCode.OK
