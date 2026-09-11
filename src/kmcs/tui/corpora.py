"""The Corpora screen.

Lists every corpus registered with KMCS.  Shows name, target link, file
count, and total size.  The detail pane shows the full record and the
directory path.
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
                str(c.total_bytes),
                (c.target_id or "—")[:8],
            )
            for c in corpora
        ]

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
            ("Total bytes", str(corpus.total_bytes)),
            ("Created", corpus.created_at.isoformat()),
        ]

        # List the first few files, if the directory exists.
        try:
            files = self.ctx.corpora.files(corpus.id)
            if files:
                sample = ", ".join(f.name for f in files[:5])
                if len(files) > 5:
                    sample += f", … ({len(files) - 5} more)"
                pairs.append(("Files (sample)", sample))
        except Exception:
            pass

        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]2[/b] targets"

    # ------------------------------------------------------------------ helpers

    def _resolve_corpus_by_prefix(self, prefix: str):
        for corpus in self.ctx.corpora.list():
            if corpus.id.startswith(prefix):
                return corpus
        return None
