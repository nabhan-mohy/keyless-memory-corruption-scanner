"""Self-contained HTML report renderer.

The output is a single ``.html`` file with:

* no external assets,
* no JavaScript,
* no network references,

so it can be attached to a ticket, emailed, or opened on an air-gapped
workstation.  Styling is inline in a ``<style>`` block.  Each finding has a
stable anchor (``#finding-<id>``) so other documents can deep-link to it, and
a table of contents at the top links to those anchors.
"""

from __future__ import annotations

import html
import json
from typing import Any

from kmcs.core import models
from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportFormat,
    ReportRenderer,
    SEVERITY_ORDER,
)

__all__ = ["HTMLReportRenderer"]


_SEVERITY_CLASS: dict[models.Severity, str] = {
    models.Severity.CRITICAL: "sev-critical",
    models.Severity.HIGH: "sev-high",
    models.Severity.MEDIUM: "sev-medium",
    models.Severity.LOW: "sev-low",
    models.Severity.INFO: "sev-info",
    models.Severity.UNKNOWN: "sev-unknown",
}

_MAX_SAMPLE_CRASHES = 20


_STYLE = """
:root {
  color-scheme: light dark;
  --fg: #1f2328;
  --fg-muted: #59636e;
  --bg: #ffffff;
  --bg-subtle: #f6f8fa;
  --border: #d1d9e0;
  --accent: #0969da;
  --code-bg: #f6f8fa;
  --shadow: 0 1px 3px rgba(31, 35, 40, 0.08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e6edf3;
    --fg-muted: #9198a1;
    --bg: #0d1117;
    --bg-subtle: #161b22;
    --border: #30363d;
    --accent: #4493f8;
    --code-bg: #161b22;
    --shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
  }
}
* { box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans",
    Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  font-size: 16px;
  line-height: 1.55;
  max-width: 74rem;
  margin: 2rem auto;
  padding: 0 1.5rem;
  color: var(--fg);
  background: var(--bg);
}
h1, h2, h3, h4 { line-height: 1.25; margin-top: 1.8em; }
h1 { border-bottom: 1px solid var(--border); padding-bottom: .4rem; }
h2 { border-bottom: 1px solid var(--border); padding-bottom: .3rem; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre, kbd {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
  font-size: .92em;
}
code { background: var(--code-bg); padding: .1em .3em; border-radius: 3px; }
pre {
  background: var(--code-bg);
  padding: .8rem 1rem;
  border-radius: 6px;
  overflow-x: auto;
  border: 1px solid var(--border);
}
pre code { background: none; padding: 0; }
table {
  border-collapse: collapse;
  width: 100%;
  margin: 1rem 0;
  font-size: .94em;
}
th, td {
  border: 1px solid var(--border);
  padding: .4rem .6rem;
  text-align: left;
  vertical-align: top;
}
th { background: var(--bg-subtle); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge {
  display: inline-block;
  padding: .12rem .55rem;
  border-radius: 999px;
  color: #fff;
  font-size: .78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .03em;
  vertical-align: middle;
}
.sev-critical { background: #b00020; }
.sev-high     { background: #d13438; }
.sev-medium   { background: #c76a00; }
.sev-low      { background: #3d7a3d; }
.sev-info     { background: #4a6c8c; }
.sev-unknown  { background: #6e7781; }
.toc {
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem 1.5rem;
}
.toc ol { margin: .3rem 0; padding-left: 1.4rem; }
.finding {
  margin: 1.5rem 0;
  padding: 1rem 1.4rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-subtle);
  box-shadow: var(--shadow);
}
.finding > h3 { margin-top: 0; }
dl.props {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: .15rem 1rem;
  margin: .6rem 0 1rem;
  font-size: .94em;
}
dl.props dt { color: var(--fg-muted); }
dl.props dd { margin: 0; }
.muted { color: var(--fg-muted); }
details { margin: .6rem 0; }
details > summary { cursor: pointer; font-weight: 600; }
""".strip()


class HTMLReportRenderer(ReportRenderer):
    format = ReportFormat.HTML

    # ------------------------------------------------------------------ public

    def render(self, context: ReportContext) -> str:
        parts: list[str] = [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            '<meta name="generator" content="KMCS">',
            f"<title>{html.escape(context.title)}</title>",
            f"<style>{_STYLE}</style>",
            "</head>",
            "<body>",
        ]

        parts.extend(self._header(context))
        parts.extend(self._summary(context))

        if context.section.include_findings and context.findings:
            parts.extend(self._toc(context))
            parts.extend(self._findings(context))

        if context.section.include_crashes and context.crashes:
            parts.extend(self._crashes(context))

        if context.section.include_campaigns and context.campaigns:
            parts.extend(self._campaigns(context))

        if context.section.include_targets and context.targets:
            parts.extend(self._targets(context))

        if context.section.include_corpora and context.corpora:
            parts.extend(self._corpora(context))

        if context.section.include_telemetry and context.telemetry:
            parts.extend(self._telemetry(context))

        if context.metadata:
            parts.extend(self._metadata(context))

        parts.extend(["</body>", "</html>"])
        return "\n".join(parts) + "\n"

    # ------------------------------------------------------------------ sections

    @staticmethod
    def _header(context: ReportContext) -> list[str]:
        lines = [f"<h1>{html.escape(context.title)}</h1>"]
        lines.append('<dl class="props">')
        lines.append(f"<dt>Report ID</dt><dd><code>{html.escape(context.report_id[:12])}</code></dd>")
        lines.append(
            f"<dt>Generated</dt><dd>{html.escape(context.generated_at.isoformat())}</dd>"
        )
        lines.append(
            f"<dt>KMCS version</dt><dd><code>{html.escape(context.kmcs_version)}</code></dd>"
        )
        if context.campaign is not None:
            lines.append(
                f"<dt>Campaign</dt><dd>{html.escape(context.campaign.name)} "
                f"(<code>{html.escape(context.campaign.id)}</code>, "
                f"{html.escape(context.campaign.status.value)})</dd>"
            )
        lines.append("</dl>")
        return lines

    @staticmethod
    def _summary(context: ReportContext) -> list[str]:
        summary = context.summary
        lines = ["<h2>Summary</h2>", "<table>"]
        lines.append("<thead><tr><th>Metric</th><th class='num'>Count</th></tr></thead>")
        lines.append("<tbody>")
        for label, value in (
            ("Findings", summary.findings),
            ("Crashes", summary.crashes),
            ("Campaigns", summary.campaigns),
            ("Targets", summary.targets),
            ("Corpora", summary.corpora),
        ):
            lines.append(
                f"<tr><td>{html.escape(label)}</td><td class='num'>{value}</td></tr>"
            )
        lines.append("</tbody></table>")

        if summary.findings_by_severity:
            lines.append("<h3>Findings by severity</h3>")
            lines.append("<table>")
            lines.append(
                "<thead><tr><th>Severity</th><th class='num'>Count</th></tr></thead>"
            )
            lines.append("<tbody>")
            for severity in SEVERITY_ORDER:
                count = summary.findings_by_severity.get(severity.value, 0)
                badge = (
                    f'<span class="badge {_SEVERITY_CLASS[severity]}">'
                    f"{html.escape(severity.value)}</span>"
                )
                lines.append(
                    f"<tr><td>{badge}</td><td class='num'>{count}</td></tr>"
                )
            lines.append("</tbody></table>")
        return lines

    @staticmethod
    def _toc(context: ReportContext) -> list[str]:
        lines = ['<div class="toc">', "<h2>Findings</h2>", "<ol>"]
        for finding in context.findings_sorted():
            lines.append(
                f'<li><a href="#finding-{html.escape(finding.id)}">'
                f"{html.escape(finding.title)}</a> "
                f'<span class="badge {_SEVERITY_CLASS[finding.severity]}">'
                f"{html.escape(finding.severity.value)}</span></li>"
            )
        lines.append("</ol>")
        lines.append("</div>")
        return lines

    def _findings(self, context: ReportContext) -> list[str]:
        lines = ["<h2>Findings</h2>"]
        for index, finding in enumerate(context.findings_sorted(), start=1):
            lines.extend(self._finding_card(context, finding, index))
        return lines

    def _finding_card(
        self, context: ReportContext, finding: models.Finding, index: int
    ) -> list[str]:
        anchor = f"finding-{html.escape(finding.id)}"
        badge = (
            f'<span class="badge {_SEVERITY_CLASS[finding.severity]}">'
            f"{html.escape(finding.severity.value)}</span>"
        )

        lines = [f'<section class="finding" id="{anchor}">']
        lines.append(f"<h3>{index}. {html.escape(finding.title)} {badge}</h3>")
        lines.append('<dl class="props">')
        lines.append(
            f"<dt>ID</dt><dd><code>{html.escape(finding.id)}</code></dd>"
        )
        lines.append(
            f"<dt>Classification</dt>"
            f"<dd><code>{html.escape(finding.classification.value)}</code></dd>"
        )
        lines.append(
            f"<dt>Fingerprint</dt>"
            f"<dd><code>{html.escape(finding.fingerprint)}</code></dd>"
        )
        lines.append(
            f"<dt>Occurrences</dt><dd>{len(finding.crash_ids)}</dd>"
        )
        lines.append(
            f"<dt>Reproduction</dt>"
            f"<dd><code>{html.escape(finding.reproduction_status.value)}</code></dd>"
        )
        if finding.target_id:
            lines.append(
                f"<dt>Target</dt>"
                f"<dd><code>{html.escape(finding.target_id)}</code></dd>"
            )
        lines.append("</dl>")

        if finding.description:
            lines.append("<details open>")
            lines.append("<summary>Description</summary>")
            lines.append(
                f"<pre><code>{html.escape(finding.description.rstrip())}</code></pre>"
            )
            lines.append("</details>")

        if finding.remediation:
            lines.append("<h4>Remediation</h4>")
            lines.append(f"<p>{html.escape(finding.remediation)}</p>")

        crashes = context.crashes_for_finding(finding)
        if crashes:
            lines.extend(self._sample_crashes_table(crashes))

        lines.append("</section>")
        return lines

    @staticmethod
    def _sample_crashes_table(crashes: list[models.Crash]) -> list[str]:
        lines = ["<details>", "<summary>Reproducing inputs</summary>", "<table>"]
        lines.append(
            "<thead><tr><th>Crash ID</th><th>Signal</th>"
            "<th>Source location</th><th>Input</th></tr></thead>"
        )
        lines.append("<tbody>")
        for crash in crashes[:_MAX_SAMPLE_CRASHES]:
            signal = crash.signal if crash.signal is not None else "—"
            location = html.escape(crash.source_location or "—")
            input_path = html.escape(
                str(crash.input_path) if crash.input_path else "—"
            )
            lines.append(
                f"<tr><td><code>{html.escape(crash.id)}</code></td>"
                f"<td class='num'>{signal}</td>"
                f"<td><code>{location}</code></td>"
                f"<td><code>{input_path}</code></td></tr>"
            )
        remaining = len(crashes) - _MAX_SAMPLE_CRASHES
        if remaining > 0:
            lines.append(
                f"<tr><td colspan='4' class='muted'>{remaining} more…</td></tr>"
            )
        lines.append("</tbody></table></details>")
        return lines

    @staticmethod
    def _crashes(context: ReportContext) -> list[str]:
        lines = ["<h2>Crashes</h2>", "<table>"]
        lines.append(
            "<thead><tr><th>Crash ID</th><th>Classification</th>"
            "<th>Signal</th><th>Fingerprint</th><th>Source location</th></tr></thead>"
        )
        lines.append("<tbody>")
        for crash in context.crashes:
            signal = crash.signal if crash.signal is not None else "—"
            fingerprint = html.escape(crash.fingerprint or "—")
            location = html.escape(crash.source_location or "—")
            lines.append(
                f"<tr><td><code>{html.escape(crash.id)}</code></td>"
                f"<td><code>{html.escape(crash.classification.value)}</code></td>"
                f"<td class='num'>{signal}</td>"
                f"<td><code>{fingerprint}</code></td>"
                f"<td><code>{location}</code></td></tr>"
            )
        lines.append("</tbody></table>")
        return lines

    @staticmethod
    def _campaigns(context: ReportContext) -> list[str]:
        lines = ["<h2>Campaigns</h2>", "<table>"]
        lines.append(
            "<thead><tr><th>Name</th><th>Fuzzer</th><th class='num'>Workers</th>"
            "<th>Status</th><th class='num'>Duration</th></tr></thead>"
        )
        lines.append("<tbody>")
        for campaign in context.campaigns:
            duration = (
                f"{campaign.duration_seconds}s"
                if campaign.duration_seconds is not None
                else "—"
            )
            lines.append(
                f"<tr><td>{html.escape(campaign.name)}</td>"
                f"<td><code>{html.escape(campaign.fuzzer.value)}</code></td>"
                f"<td class='num'>{campaign.workers}</td>"
                f"<td><code>{html.escape(campaign.status.value)}</code></td>"
                f"<td class='num'>{html.escape(duration)}</td></tr>"
            )
        lines.append("</tbody></table>")
        return lines

    @staticmethod
    def _targets(context: ReportContext) -> list[str]:
        lines = ["<h2>Targets</h2>", "<table>"]
        lines.append(
            "<thead><tr><th>Name</th><th>Compiler</th>"
            "<th>Build configuration</th><th>Sanitizers</th></tr></thead>"
        )
        lines.append("<tbody>")
        for target in context.targets:
            compiler = target.compiler or "—"
            sanitizers = ", ".join(s.value for s in target.sanitizers) or "—"
            lines.append(
                f"<tr><td>{html.escape(target.name)}</td>"
                f"<td><code>{html.escape(compiler)}</code></td>"
                f"<td><code>{html.escape(target.build_configuration.value)}</code></td>"
                f"<td>{html.escape(sanitizers)}</td></tr>"
            )
        lines.append("</tbody></table>")
        return lines

    @staticmethod
    def _corpora(context: ReportContext) -> list[str]:
        lines = ["<h2>Corpora</h2>", "<table>"]
        lines.append(
            "<thead><tr><th>Name</th><th>Target</th>"
            "<th class='num'>Files</th><th class='num'>Bytes</th></tr></thead>"
        )
        lines.append("<tbody>")
        for corpus in context.corpora:
            lines.append(
                f"<tr><td>{html.escape(corpus.name)}</td>"
                f"<td><code>{html.escape(corpus.target_id or '—')}</code></td>"
                f"<td class='num'>{corpus.file_count}</td>"
                f"<td class='num'>{corpus.total_bytes}</td></tr>"
            )
        lines.append("</tbody></table>")
        return lines

    @staticmethod
    def _telemetry(context: ReportContext) -> list[str]:
        assert context.telemetry is not None
        payload = json.dumps(context.telemetry, indent=2, sort_keys=True)
        return [
            "<h2>Telemetry</h2>",
            f"<pre><code>{html.escape(payload)}</code></pre>",
        ]

    @staticmethod
    def _metadata(context: ReportContext) -> list[str]:
        lines = ["<h2>Additional metadata</h2>", '<dl class="props">']
        for key, value in sorted(context.metadata.items()):
            lines.append(f"<dt>{html.escape(key)}</dt><dd><code>{html.escape(str(value))}</code></dd>")
        lines.append("</dl>")
        return lines
