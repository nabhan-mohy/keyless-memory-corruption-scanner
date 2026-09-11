"""The Corpora screen.

Shows every corpus, with file counts and sizes.  The detail pane lists the
first few files inside the corpus so the researcher can see its contents.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.tui.screens.base import KMCSListScreen


class CorporaScreen(KMCSListScreen):
    """A list of every registered corpus."""

    title = "Corpora"
    empty_message = "No corpora yet. Use `kmcs corpus create` to add one."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("id", "ID"),
            ("name", "Name"),
            ("files", "Files"),
            ("bytes", "Bytes"),
            ("target", "Target"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        corpora = self.ctx.corpora.list()
        return [
            (
                c.id[:8],
                c.name,
                str(c.file_count),
                self._human_bytes(c.total_bytes),
                (c.target_id or "—")[:8],
            )
            for c in corpora
        ]

    def summary_line(self) -> str:
        corpora = self.ctx.corpora.list()
        total = len(corpora)
        total_files = sum(c.file_count for c in corpora)
        total_bytes = sum(c.total_bytes for c in corpora)
        return (
            f"{total} corpus/corpora · "
            f"{total_files} file(s) · "
            f"{self._human_bytes(total_bytes)} total"
        )

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        corpus = self._resolve_corpus_by_prefix(row[0])
        if corpus is None:
            return None
        pairs: list[tuple[str, str]] = [
            ("ID", corpus.id),
            ("Name", corpus.name),
            ("Description", corpus.description or "—"),
            ("Target", corpus.target_id or "—"),
            ("Directory", str(corpus.path) if corpus.path else "—"),
            ("File count", str(corpus.file_count)),
            ("Total bytes", f"{corpus.total_bytes} ({self._human_bytes(corpus.total_bytes)})"),
            ("Created", corpus.created_at.isoformat()),
            ("Updated", corpus.updated_at.isoformat()),
        ]

        try:
            files = self.ctx.corpora.files(corpus.id)
        except Exception:
            files = []

        if files:
            lines: list[str] = []
            for f in files[:20]:
                try:
                    size = f.stat().st_size
                    lines.append(f"{f.name}  ({size} B)")
                except OSError:
                    lines.append(f.name)
            if len(files) > 20:
                lines.append(f"… ({len(files) - 20} more)")
            pairs.append(("Files", "\n".join(lines)))
        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard"

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _human_bytes(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 * 1024 * 1024:
            return f"{n / (1024 * 1024):.1f} MB"
        return f"{n / (1024 * 1024 * 1024):.1f} GB"

    def _resolve_corpus_by_prefix(self, prefix: str):
        for corpus in self.ctx.corpora.list():
            if corpus.id.startswith(prefix):
                return corpus
        return None
