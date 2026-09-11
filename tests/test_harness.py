"""Harness description and template rendering."""

from __future__ import annotations

import pytest

from kmcs.targets.harness import (
    HarnessError,
    HarnessSpec,
    HarnessType,
    render_harness_source,
)


class TestSpec:
    def test_libfuzzer_default_entry_point(self) -> None:
        spec = HarnessSpec(type=HarnessType.LIBFUZZER)
        assert spec.entry_function == "LLVMFuzzerTestOneInput"

    def test_custom_entry_point_is_kept(self) -> None:
        spec = HarnessSpec(type=HarnessType.LIBFUZZER, entry_function="MyEntry")
        assert spec.entry_function == "MyEntry"

    def test_blank_placeholder_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            HarnessSpec(type=HarnessType.AFL_FILE, input_file_placeholder="   ")


class TestRendering:
    def test_afl_stdin_template_contains_the_call_site(self) -> None:
        spec = HarnessSpec(type=HarnessType.AFL_STDIN)
        source = render_harness_source(spec, "png_parse(buffer, length);")

        assert "png_parse(buffer, length);" in source
        assert "fread(buffer, 1, KMCS_BUFFER_SIZE, stdin)" in source
        assert "REPLACE THIS LINE" in source

    def test_afl_file_template_reads_argv(self) -> None:
        spec = HarnessSpec(type=HarnessType.AFL_FILE)
        source = render_harness_source(spec, "load(argv[1]);")

        assert "fopen(argv[1]" in source
        assert "load(argv[1]);" in source

    def test_libfuzzer_template_uses_the_declared_entry_point(self) -> None:
        spec = HarnessSpec(type=HarnessType.LIBFUZZER, entry_function="FuzzMe")
        source = render_harness_source(spec, "FuzzMe(data, size);")

        assert "int FuzzMe(const uint8_t *data, size_t size)" in source
        assert "FuzzMe(data, size);" in source

    def test_libfuzzer_default_entry_point(self) -> None:
        spec = HarnessSpec(type=HarnessType.LIBFUZZER)
        source = render_harness_source(spec, "parse(data, size);")

        assert "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)" in source

    def test_empty_target_call_is_rejected(self) -> None:
        spec = HarnessSpec(type=HarnessType.AFL_STDIN)
        with pytest.raises(HarnessError):
            render_harness_source(spec, "   ")

    def test_unsupported_type_is_rejected(self) -> None:
        # Honggfuzz has no template yet; the renderer must say so, not guess.
        spec = HarnessSpec(type=HarnessType.HONGGFUZZ)
        with pytest.raises(HarnessError):
            render_harness_source(spec, "anything();")

    def test_output_is_valid_c_looking_text(self) -> None:
        spec = HarnessSpec(type=HarnessType.AFL_STDIN)
        source = render_harness_source(spec, "do_work(buffer, length);")

        # Braces must balance — a simple smoke check that the template wasn't
        # mangled by .format().
        assert source.count("{") == source.count("}")
        assert "int main(void)" in source
