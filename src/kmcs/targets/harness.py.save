"""Harness descriptions and source templates.

A *harness* is the small piece of C/C++ glue that lets a fuzzer feed bytes into
the code under test.  KMCS cannot invent that glue — it depends on the library's
API — but it can:

* describe what kind of harness a target uses,
* generate a correct-by-construction template,
* remember the placeholder that the researcher must replace.

Rendering a harness does not prove it compiles or that it calls the library
correctly.  Only a real build (``targets.build``) proves that.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "HarnessType",
    "HarnessSpec",
    "HarnessError",
    "render_harness_source",
    "AFL_STDIN_TEMPLATE",
    "AFL_FILE_TEMPLATE",
    "LIBFUZZER_TEMPLATE",
]

from kmcs.core.exceptions import KMCSException


class HarnessError(KMCSException):
    exit_code = 12


class HarnessType(str, Enum):
    AFL_STDIN = "afl-stdin"
    AFL_FILE = "afl-file"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"


class HarnessSpec(BaseModel):
    """Description of how KMCS should feed bytes into a target."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    type: HarnessType
    entry_function: str | None = None
    input_file_placeholder: str = "___FILE___"
    source_path: Path | None = None
    description: str = ""
    compile_flags: list[str] = Field(default_factory=list)
    link_flags: list[str] = Field(default_factory=list)

    @field_validator("type", mode="after")
    @classmethod
    def _require_entry_for_libfuzzer(cls, value: HarnessType) -> HarnessType:
        # Entry point only meaningful for libFuzzer, but we don't reject the
        # others because callers may set it opportunistically.
        return value

    @field_validator("input_file_placeholder", mode="after")
    @classmethod
    def _non_empty_placeholder(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("input_file_placeholder must not be empty")
        return cleaned

    def model_post_init(self, _context) -> None:  # type: ignore[override]
        if self.type is HarnessType.LIBFUZZER and not self.entry_function:
            # Default entry point name — libFuzzer itself expects exactly this.
            object.__setattr__(self, "entry_function", "LLVMFuzzerTestOneInput")


AFL_STDIN_TEMPLATE = """\
/*
 * KMCS AFL++ stdin harness.
 *
 * Reads up to BUFFER_SIZE bytes from stdin and passes them to the target
 * function.  Replace the TARGET_CALL(...) line with the actual entry point of
 * the library under test.
 *
 * This file is generated.  Keep the surrounding scaffolding; replace only the
 * marked call site and the buffer size if your library needs a different limit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KMCS_BUFFER_SIZE (1u << 20)  /* 1 MiB */

int main(void) {{
    unsigned char *buffer = (unsigned char *)malloc(KMCS_BUFFER_SIZE);
    if (buffer == NULL) {{
        return 1;
    }}

    size_t length = fread(buffer, 1, KMCS_BUFFER_SIZE, stdin);

    /* --- REPLACE THIS LINE with the library call under test --- */
    {target_call}
    /* --------------------------------------------------------- */

    free(buffer);
    return 0;
}}
"""


AFL_FILE_TEMPLATE = """\
/*
 * KMCS AFL++ file-based harness.
 *
 * Reads a single file whose path is provided as argv[1] (or as the placeholder
 * substituted by the fuzzer) and passes its contents to the target function.
 * File-based input is required when a single execution cannot be expressed as a
 * byte stream on stdin, for example when the library reopens the path itself.
 *
 * This file is generated.  Replace only the marked call site.
 */

#include <stdio.h>
#include <stdlib.h>

#define KMCS_BUFFER_SIZE (1u << 20)  /* 1 MiB */

int main(int argc, char **argv) {{
    if (argc < 2) {{
        fprintf(stderr, "usage: %s <input-file>\\n", argv[0]);
        return 1;
    }}

    FILE *handle = fopen(argv[1], "rb");
    if (handle == NULL) {{
        perror("fopen");
        return 1;
    }}

    unsigned char *buffer = (unsigned char *)malloc(KMCS_BUFFER_SIZE);
    if (buffer == NULL) {{
        fclose(handle);
        return 1;
    }}

    size_t length = fread(buffer, 1, KMCS_BUFFER_SIZE, handle);
    fclose(handle);

    /* --- REPLACE THIS LINE with the library call under test --- */
    {target_call}
    /* --------------------------------------------------------- */

    free(buffer);
    return 0;
}}
"""


LIBFUZZER_TEMPLATE = """\
/*
 * KMCS libFuzzer harness.
 *
 * libFuzzer calls LLVMFuzzerTestOneInput on every candidate input.  It must
 * return 0 for a successful execution; returning non-zero tells libFuzzer to
 * treat the input as "interesting".  A crash (any signal) is a finding.
 *
 * Build with:  clang++ -fsanitize=fuzzer,address -g -O1 {source} -o {binary}
 *
 * Replace only the marked call site.
 */

#include <stddef.h>
#include <stdint.h>

extern "C" int {entry}(const uint8_t *data, size_t size) {{
    /* --- REPLACE THIS LINE with the library call under test --- */
    {target_call}
    /* --------------------------------------------------------- */
    (void)data;
    (void)size;
    return 0;
}}
"""


def render_harness_source(spec: HarnessSpec, target_call: str) -> str:
    """Return the C/C++ source for ``spec`` with ``target_call`` substituted.

    ``target_call`` is a single statement or short block of C/C++ that invokes
    the library under test using the conventional variable names:

    * AFL++ stdin harness: ``buffer`` and ``length``
    * AFL++ file harness:  ``buffer`` and ``length``
    * libFuzzer harness:   ``data`` and ``size``
    """
    if not target_call.strip():
        raise HarnessError(
            "target_call must contain an actual library invocation",
            details={"type": spec.type.value},
        )

    if spec.type is HarnessType.AFL_STDIN:
        return AFL_STDIN_TEMPLATE.format(target_call=target_call.strip())
    if spec.type is HarnessType.AFL_FILE:
        return AFL_FILE_TEMPLATE.format(target_call=target_call.strip())
    if spec.type is HarnessType.LIBFUZZER:
        entry = spec.entry_function or "LLVMFuzzerTestOneInput"
        return LIBFUZZER_TEMPLATE.format(entry=entry, target_call=target_call.strip())

    raise HarnessError(
        "No template is available for this harness type yet",
        details={"type": spec.type.value},
    )
